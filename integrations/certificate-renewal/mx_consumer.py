#!/usr/bin/env python3
"""Pull public certificates and transactionally rechain one enrolled Xeams MX.

No ACME orders, DNS credentials, SSH access or private-key distribution belong
in this process. The local key, keystore password and alias remain unchanged.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from renewal_common import (DAY, RenewalError, atomic_json, atomic_write, certificate_info,
    csr_info, operation_lock, public_status, replacement_is_newer, require, run_command, validate_bundle)

ROOT = Path('/opt/Xeams')
SERVICE = 'xeams.service'
PUBLISHER = 'http://10.50.0.80:8099'
PORTS = (443, 25, 465, 587)
HOSTS = {
    'mx1.the-grange.uk': {'ip': '10.44.0.110', 'sans': ('mx1.the-grange.uk',),
        'spki': 'db940183c6fd576736d6dac801a439c6cba44097909b3fb1432369f9f436f082',
        'pair': 'mx2.the-grange.uk', 'window': (35, 45)},
    'mx2.the-grange.uk': {'ip': '10.50.0.110', 'sans': ('mta-sts.the-grange.uk', 'mx2.the-grange.uk'),
        'spki': '658976573ecd31767bacb950b658d5b6b3e88597478f8e7ad34aff3e0b55268a',
        'pair': 'mx1.the-grange.uk', 'window': (5, 15)},
    'mx1.brimstonecottage.uk': {'ip': '10.50.0.100', 'sans': ('mx1.brimstonecottage.uk',),
        'spki': 'cff81f0c1716696f31ccb37ab3726114b1115ae4d1e4cc391f303ba5b26d610c',
        'pair': 'mx2.brimstonecottage.uk', 'window': (35, 45)},
    'mx2.brimstonecottage.uk': {'ip': '10.44.0.10', 'sans': ('mx2.brimstonecottage.uk',),
        'spki': '49b4f177e05405252ea1f803c3df76e781a2bb534c653aecb5038f99c6f41625',
        'pair': 'mx1.brimstonecottage.uk', 'window': (5, 15)},
}
FILES = {'pfx': ROOT / 'config/letenc.pfx', 'chain': ROOT / 'letsEncrypt/domain-chain.crt',
         'dates': ROOT / 'letsEncrypt/properties.dat'}
KEY = ROOT / 'letsEncrypt/domain.key'
CSR = ROOT / 'letsEncrypt/domain.csr'
CONFIG = ROOT / 'config/AppConfig.xml'
PENDING = ROOT / 'config/letenc.pfx.new'


def emit(event, **data):
    print(json.dumps({'event': event, **data}, sort_keys=True), flush=True)


def load_json(path, default=None):
    if not Path(path).exists() and default is not None:
        return default
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        raise RenewalError('local configuration/state could not be read') from None
    require(isinstance(value, dict), 'local configuration/state must be an object')
    return value


def secure_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'expected a regular configuration/helper file')
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'configuration/helper must be root-owned and not publicly writable')


def checked_config(path):
    secure_file(path)
    config = load_json(path)
    require(config.get('schema') == 1 and config.get('hostname') in HOSTS, 'consumer configuration scope invalid')
    require(config.get('publisher', PUBLISHER) == PUBLISHER, 'publisher is outside the approved private endpoint')
    require(config.get('spki_sha256') == HOSTS[config['hostname']]['spki'], 'consumer key enrollment differs from verified inventory')
    for field in ('state_dir', 'backup_dir', 'java_helper_dir'):
        require(isinstance(config.get(field), str) and Path(config[field]).is_absolute(), 'consumer directory configuration invalid')
    helper = Path(config['java_helper_dir']) / 'GrangeRenewalKeystore.class'
    secure_file(helper)
    require(re.fullmatch(r'[0-9a-f]{64}', config.get('java_class_sha256', '')) is not None and
            digest(helper) == config['java_class_sha256'], 'scoped Java helper hash differs from enrollment')
    return config


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def local_identity(host):
    local = socket.gethostname().lower().rstrip('.')
    require(local in (host, host.split('.')[0]), 'local hostname differs from enrolled MX')
    try:
        interfaces = json.loads(run_command(['ip', '-j', 'address', 'show'], timeout=5, stage='read local addresses'))
        addresses = {x.get('local') for interface in interfaces for x in interface.get('addr_info', [])}
    except (ValueError, TypeError):
        raise RenewalError('local interface inventory invalid') from None
    require(HOSTS[host]['ip'] in addresses, 'enrolled MX address is not assigned to this container')


def tls_settings():
    raw = CONFIG.read_bytes()
    require(len(raw) <= 4 * 1024 * 1024 and b'<!DOCTYPE' not in raw.upper(), 'TLS configuration XML format invalid')
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError:
        raise RenewalError('TLS configuration XML could not be parsed') from None
    values = {}
    for name in ('sslCertificateFileName', 'sslCertificatePassword', 'sslCertKeystoreType'):
        nodes = [node for node in tree.iter() if node.tag.rsplit('}', 1)[-1] == name]
        require(len(nodes) == 1, 'expected exactly one configured TLS setting')
        values[name] = {'text': nodes[0].text or '', 'attributes': dict(nodes[0].attrib)}
    require(values['sslCertKeystoreType']['text'].strip().upper() == 'PKCS12', 'configured TLS store type changed')
    require((ROOT / values['sslCertificateFileName']['text'].strip()).resolve() == FILES['pfx'], 'configured TLS store path changed')
    # This hash guards the encrypted TLS password/attributes without exposing it
    # or rejecting normal unrelated AppConfig writes during Xeams shutdown.
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def regular_inputs():
    for path in (*FILES.values(), KEY, CSR, CONFIG):
        require(path.is_file() and not path.is_symlink(), 'expected regular enrolled Xeams TLS file')
    require(not PENDING.exists() and not PENDING.is_symlink(), 'native Xeams renewal has a pending PFX; defer deployment')


def reference(host):
    regular_inputs()
    item = HOSTS[host]
    current = certificate_info(FILES['chain'].read_bytes())
    csr = csr_info(CSR)
    key_public = run_command(['openssl', 'pkey', '-in', KEY, '-pubout', '-outform', 'DER'],
                             timeout=10, stage='check existing key public half')
    require(current['sans'] == item['sans'] and not current['non_dns_sans'] and
            current['spki_sha256'] == item['spki'], 'current certificate differs from enrolled identity')
    require(csr['sans'] == item['sans'] and not csr['non_dns_sans'] and
            csr['spki_der'] == current['spki_der'] == key_public, 'existing CSR/private-key binding failed')
    return current


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def parse_envelope(data, host):
    require(isinstance(data, bytes) and len(data) <= 131072 and b'PRIVATE KEY' not in data,
            'public envelope size/content invalid')
    try:
        value = json.loads(data)
        require(value.get('schema') == 1 and value.get('hostname') == host, 'public envelope host/version invalid')
        info = validate_bundle(value['fullchain_pem'].encode('ascii'), HOSTS[host]['sans'], HOSTS[host]['spki'])
        require(value.get('certificate', {}).get('sha256') == info['sha256'], 'public envelope fingerprint differs from its certificate')
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise RenewalError('public envelope format invalid') from None
    return info


def fetch_candidate(config, apply):
    host = config['hostname']
    cache = Path(config['state_dir']) / 'validated-public-envelope.json'
    request = urllib.request.Request(PUBLISHER + '/v1/' + host + '.json',
                                     headers={'Accept': 'application/json', 'User-Agent': 'Grange-Certificate-Renewal/1'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    source = 'publisher'
    try:
        with opener.open(request, timeout=8) as response:
            require(response.status == 200, 'publisher returned unexpected HTTP status')
            data = response.read(131073)
    except (urllib.error.URLError, OSError):
        require(cache.is_file(), 'publisher unavailable and no previously validated bundle is cached')
        data = cache.read_bytes()
        source = 'validated_cache'
        emit('publisher_unavailable_using_cache', hostname=host)
    info = parse_envelope(data, host)
    if apply and source == 'publisher':
        atomic_write(cache, data)
    return info, source


def smtp_response(raw, reader, expected, deadline):
    for unused in range(40):
        require(time.monotonic() < deadline, 'SMTP TLS probe deadline exceeded')
        raw.settimeout(max(0.05, deadline - time.monotonic()))
        line = reader.readline(8193)
        require(4 <= len(line) <= 8192 and line[:3].isdigit() and int(line[:3]) == expected,
                'unexpected SMTP reply during TLS probe')
        if line[3:4] == b' ':
            return
        require(line[3:4] == b'-', 'malformed multiline SMTP reply')
    raise RenewalError('SMTP reply line limit exceeded')


def peer_certificate(host, port, trusted=True):
    context = ssl.create_default_context() if trusted else ssl._create_unverified_context()
    deadline = time.monotonic() + 5
    raw = socket.create_connection((HOSTS[host]['ip'], port), timeout=5)
    try:
        if port in (25, 587):
            reader = raw.makefile('rb')
            try:
                smtp_response(raw, reader, 220, deadline)
                raw.sendall(b'EHLO certificate-check.the-grange.uk\r\n')
                smtp_response(raw, reader, 250, deadline)
                raw.sendall(b'STARTTLS\r\n')
                smtp_response(raw, reader, 220, deadline)
            finally:
                reader.close()
        require(time.monotonic() < deadline, 'TLS probe deadline exceeded')
        raw.settimeout(max(0.05, deadline - time.monotonic()))
        with context.wrap_socket(raw, server_hostname=host) as connection:
            return connection.getpeercert(binary_form=True)
    finally:
        raw.close()


def verify_peers(host, expected_sha, wait_seconds=0, trusted=True):
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            for port in PORTS:
                require(hashlib.sha256(peer_certificate(host, port, trusted)).hexdigest() == expected_sha,
                        'live MX endpoint has a different certificate')
            return
        except (OSError, RenewalError):
            if time.monotonic() >= deadline:
                raise RenewalError('live certificate verification failed on one or more MX ports') from None
            time.sleep(2)


def pair_healthy(host):
    pair = HOSTS[host]['pair']
    raw = peer_certificate(pair, 25, True)
    info = certificate_info(ssl.DER_cert_to_PEM_cert(raw).encode('ascii'))
    require(info['spki_sha256'] == HOSTS[pair]['spki'] and info['sans'] == HOSTS[pair]['sans'],
            'paired MX identity differs from enrollment')
    emit('paired_mx_healthy', hostname=host, paired_hostname=pair)


def in_install_window(host, now=None):
    minute = (dt.datetime.now(dt.timezone.utc) if now is None else
              dt.datetime.fromtimestamp(now, dt.timezone.utc)).minute
    start, end = HOSTS[host]['window']
    return start <= minute < end


def java_runtime():
    runtime = ROOT / 'jre/bin/java'
    require(runtime.is_file() and os.access(runtime, os.X_OK), 'inspected local Xeams Java runtime missing')
    return runtime


def run_adapter(config, temporary, inspect=False):
    helper_dir = Path(config['java_helper_dir'])
    classpath = ':'.join(map(str, (helper_dir, ROOT / 'patches/Xeams.jar', ROOT / 'patches/SynametricsCommon.jar',
                                  ROOT / 'lib/Xeams.jar', ROOT / 'lib/SynametricsCommon.jar', ROOT / 'patches/*', ROOT / 'lib/*')))
    args = [java_runtime(), '-cp', classpath, 'GrangeRenewalKeystore']
    output = temporary / 'old-leaf.pem'
    if inspect:
        args += ['--inspect', CONFIG, FILES['pfx'], output]
    else:
        args += [CONFIG, FILES['pfx'], temporary / 'fullchain.pem', temporary / 'replacement.pfx', output]
    data = run_command(args, timeout=30, cwd=ROOT, stage='validate existing Xeams TLS keystore')
    try:
        result = json.loads(data)
    except ValueError:
        raise RenewalError('scoped Java validation result malformed') from None
    require(result.get('event') == ('java_keystore_inspected' if inspect else 'java_keystore_validated'),
            'scoped Java validation did not complete')
    return certificate_info(output.read_bytes())


def native_dates(original, candidate, now):
    values = {'expDate': int(candidate['not_after'] * 1000), 'notAfter': int(candidate['not_after'] * 1000),
              'notBefore': int(candidate['not_before'] * 1000), 'regDate': int(now * 1000),
              'renewalAfter': int(min(now + 40 * DAY,
                  candidate['not_after'] - (candidate['not_after'] - candidate['not_before']) / 3) * 1000)}
    result = original
    for name, value in values.items():
        pattern = rb'(?m)^' + name.encode() + rb'=[0-9]+(?=\r?$)'
        result, count = re.subn(pattern, name.encode() + b'=' + str(value).encode(), result)
        require(count == 1, 'native certificate date field is missing or ambiguous')
    return result


def snapshot(path):
    info = path.stat()
    return {'sha256': digest(path), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}


def preflight_guard():
    regular_inputs()
    return {'files': {name: snapshot(path) for name, path in FILES.items()},
            'key_sha256': digest(KEY), 'csr_sha256': digest(CSR), 'tls_settings_sha256': tls_settings()}


def unchanged(expected):
    regular_inputs()
    for name, metadata in expected['files'].items():
        require(snapshot(FILES[name]) == metadata, 'Xeams certificate file changed during preflight')
    require(digest(KEY) == expected['key_sha256'] and digest(CSR) == expected['csr_sha256'], 'existing key or CSR changed')
    require(tls_settings() == expected['tls_settings_sha256'], 'configured TLS settings changed during preflight')


def stop_service():
    run_command(['systemctl', 'stop', SERVICE], timeout=60, stage='stop scoped Xeams service')
    pid = run_command(['systemctl', 'show', '-p', 'MainPID', '--value', SERVICE], timeout=5, stage='verify Xeams stopped').strip()
    require(pid == b'0', 'Xeams process remains active; refusing certificate replacement')


def start_service():
    run_command(['systemctl', 'start', SERVICE], timeout=60, stage='start scoped Xeams service')


def verified_backup_payloads(backup, manifest):
    payloads = {}
    for name, metadata in manifest['original']['files'].items():
        path = backup / (name + '.backup')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024,
                'rollback backup file invalid')
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == metadata['sha256'], 'rollback backup integrity failed')
        payloads[name] = raw
    return payloads


def restore_files(payloads, manifest):
    for name, metadata in manifest['original']['files'].items():
        atomic_write(FILES[name], payloads[name], metadata['mode'], metadata['uid'], metadata['gid'])


def verify_identity_guard(manifest):
    regular_inputs()
    require(digest(KEY) == manifest['original']['key_sha256'] and digest(CSR) == manifest['original']['csr_sha256'],
            'private key/CSR changed during certificate transaction')
    require(tls_settings() == manifest['original']['tls_settings_sha256'], 'TLS settings changed during certificate transaction')


def transaction_state(config, manifest):
    atomic_json(Path(config['state_dir']) / 'transaction.json', manifest)


def rollback(config, backup, manifest):
    # Never overwrite an unrelated administrator/native renewal. Restore only
    # the exact original/new bytes belonging to this transaction.
    verify_identity_guard(manifest)
    def allowed_transaction_bytes():
        for name, path in FILES.items():
            require(digest(path) in (manifest['original']['files'][name]['sha256'], manifest['replacement_hashes'][name]),
                    'unexpected third-party certificate write; automatic rollback stopped')
    allowed_transaction_bytes()
    # Validate the complete rollback set before stopping or writing anything.
    # A corrupt later file must not leave an avoidable partial restore/outage.
    payloads = verified_backup_payloads(backup, manifest)
    stop_service()
    try:
        verify_identity_guard(manifest)
        allowed_transaction_bytes()
    except BaseException:
        # No restore has happened yet. Refuse an unrelated write while bringing
        # the existing service back up; do not leave a shutdown-race outage.
        start_service()
        raise
    restore_files(payloads, manifest)
    start_service()
    verify_peers(config['hostname'], manifest['old_certificate']['sha256'], 90,
                 trusted=manifest['old_certificate']['not_after'] > time.time())
    manifest['phase'] = 'rolled_back'
    transaction_state(config, manifest)
    emit('deployment_rolled_back', hostname=config['hostname'], backup=str(backup))


def recover_transaction(config, apply):
    manifest = load_json(Path(config['state_dir']) / 'transaction.json', {})
    if not manifest or manifest.get('phase') in ('committed', 'rolled_back', 'aborted_before_replace'):
        return
    require(manifest.get('schema') == 1 and manifest.get('hostname') == config['hostname'], 'pending transaction scope invalid')
    backup = Path(manifest['backup']).resolve()
    root = Path(config['backup_dir']).resolve()
    require(root in backup.parents, 'pending transaction backup lies outside enrolled directory')
    require(set(manifest['original']['files']) == set(FILES) and set(manifest['replacement_hashes']) == set(FILES),
            'pending transaction file scope invalid')
    verify_identity_guard(manifest)
    if all(snapshot(path) == manifest['original']['files'][name] for name, path in FILES.items()):
        require(apply, 'interrupted unchanged-original service needs recovery with --apply')
        # systemctl start is idempotent and does not interrupt an active Xeams.
        # If a crash occurred just after stop, restart unchanged original files
        # immediately instead of waiting almost an hour for the next window.
        start_service()
        verify_peers(config['hostname'], manifest['old_certificate']['sha256'], 90,
                     trusted=manifest['old_certificate']['not_after'] > time.time())
        verify_identity_guard(manifest)
        manifest['phase'] = 'aborted_before_replace'
        transaction_state(config, manifest)
        emit('interrupted_original_service_recovered', hostname=config['hostname'])
        return
    if all(digest(path) == manifest['replacement_hashes'][name] for name, path in FILES.items()):
        try:
            verify_peers(config['hostname'], manifest['new_certificate']['sha256'])
        except RenewalError:
            pass
        else:
            emit('interrupted_deployment_already_verified', hostname=config['hostname'], will_apply=apply)
            if apply:
                manifest['phase'] = 'committed'
                transaction_state(config, manifest)
            return
    require(apply, 'interrupted deployment requires guarded recovery with --apply')
    require(in_install_window(config['hostname']), 'interrupted deployment recovery waits for the paired-MX schedule')
    pair_healthy(config['hostname'])
    rollback(config, backup, manifest)


def install(config, current, candidate, temporary, before):
    host = config['hostname']
    new_bytes = {'pfx': (temporary / 'replacement.pfx').read_bytes(), 'chain': candidate['fullchain_pem'],
                 'dates': native_dates(FILES['dates'].read_bytes(), candidate, time.time())}
    unchanged(before)
    require(in_install_window(host), 'outside the staggered MX installation window')
    pair_healthy(host)
    verify_peers(host, current['sha256'], trusted=current['not_after'] > time.time())
    backup_root = Path(config['backup_dir'])
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + host + '-', dir=backup_root))
    for name, path in FILES.items():
        atomic_write(backup / (name + '.backup'), path.read_bytes())
    manifest = {'schema': 1, 'hostname': host, 'phase': 'prepared', 'backup': str(backup), 'original': before,
                'old_certificate': public_status(current), 'new_certificate': public_status(candidate),
                'replacement_hashes': {name: hashlib.sha256(raw).hexdigest() for name, raw in new_bytes.items()}}
    atomic_json(backup / 'manifest.json', manifest)
    transaction_state(config, manifest)
    changed_service = False
    replacement_started = False
    try:
        unchanged(before)
        require(in_install_window(host), 'installation window elapsed during preflight')
        pair_healthy(host)
        changed_service = True
        stop_service()
        unchanged(before)
        manifest['phase'] = 'stopped'
        transaction_state(config, manifest)
        replacement_started = True
        for name, raw in new_bytes.items():
            metadata = before['files'][name]
            atomic_write(FILES[name], raw, metadata['mode'], metadata['uid'], metadata['gid'])
        manifest['phase'] = 'files_installed'
        transaction_state(config, manifest)
        start_service()
        verify_peers(host, candidate['sha256'], 90, trusted=True)
        verify_identity_guard(manifest)
        for name, metadata in before['files'].items():
            actual = snapshot(FILES[name])
            require(actual['sha256'] == manifest['replacement_hashes'][name] and
                    all(actual[field] == metadata[field] for field in ('mode', 'uid', 'gid')), 'installed ownership/content verification failed')
        manifest['phase'] = 'committed'
        transaction_state(config, manifest)
        emit('mx_certificate_installed_and_verified', hostname=host, certificate=public_status(candidate),
             ports=PORTS, original_private_key_preserved=True, backup=str(backup))
    except BaseException:
        if replacement_started:
            try:
                rollback(config, backup, manifest)
            except BaseException:
                emit('rollback_requires_attention', hostname=host, backup=str(backup))
                raise RenewalError('certificate transaction and guarded rollback did not complete') from None
        elif changed_service:
            # A concurrent native/operator write detected after stopping Xeams
            # must not leave it stopped or be overwritten by our older backup.
            # No certificate replacement has started on this branch.
            start_service()
            manifest['phase'] = 'aborted_before_replace'
            transaction_state(config, manifest)
            raise RenewalError('deployment aborted before replacement; Xeams restarted with existing files') from None
        else:
            manifest['phase'] = 'rolled_back'
            transaction_state(config, manifest)
        raise RenewalError('certificate deployment failed; previous certificate restored') from None


def process(config, apply=False):
    host = config['hostname']
    local_identity(host)
    recover_transaction(config, apply)
    before = preflight_guard()
    current = reference(host)
    candidate, source = fetch_candidate(config, apply)
    newer = replacement_is_newer(current, candidate)
    with tempfile.TemporaryDirectory(prefix='grange-mx-renewal-', dir='/run') as directory:
        temporary = Path(directory)
        if newer:
            atomic_write(temporary / 'fullchain.pem', candidate['fullchain_pem'])
        store = run_adapter(config, temporary, inspect=not newer)
        require(store['sha256'] == current['sha256'] and store['spki_sha256'] == HOSTS[host]['spki'],
                'active keystore differs from enrolled public reference')
        unchanged(before)
        if not newer:
            verify_peers(host, current['sha256'])
            status = 'current_certificate_verified'
            emit(status, hostname=host, certificate=public_status(current), ports=PORTS, source=source)
        elif not apply or not in_install_window(host):
            status = 'validated_deployment_pending'
            emit(status, hostname=host, certificate=public_status(candidate), will_apply=apply,
                 within_install_window=in_install_window(host))
        else:
            install(config, current, candidate, temporary, before)
            status = 'new_certificate_deployed'
        if apply:
            atomic_json(Path(config['state_dir']) / 'health.json', {'schema': 1, 'hostname': host,
                        'checked_at': time.time(), 'status': status, 'source': source, 'publisher_reachable': source == 'publisher',
                        'active_certificate_sha256': candidate['sha256'] if status == 'new_certificate_deployed' else current['sha256'],
                        'available_certificate_sha256': candidate['sha256'], 'certificate_issuance_is_separate': True})


def interrupted(signum, frame):
    raise RenewalError('renewal interrupted; guarded rollback will run if deployment started')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'MX consumer must run locally as root')
    os.umask(0o077)
    config = checked_config(args.config)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        with operation_lock(Path(config['state_dir']) / 'consumer.lock'):
            process(config, args.apply)
    except BaseException as error:
        if args.apply:
            atomic_json(Path(config['state_dir']) / 'health.json', {'schema': 1, 'hostname': config['hostname'],
                        'checked_at': time.time(), 'status': 'failed', 'error_type': type(error).__name__})
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        emit('mx_consumer_failed', error_type=type(error).__name__)
        raise SystemExit(1)
