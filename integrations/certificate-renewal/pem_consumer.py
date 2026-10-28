#!/usr/bin/env python3
"""Deploy only the MX2 public certificate to the existing CT250 MTA-STS vhost.

The existing private key stays in place. This consumer creates no ACME order,
copies no private key, changes no Nginx route, and never restarts Nginx.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import tempfile
import time

from renewal_common import (RenewalError, atomic_json, atomic_write, certificate_info, operation_lock,
    public_status, replacement_is_newer, require, run_command)
from mx_consumer import HOSTS, digest, fetch_candidate, load_json, secure_file, snapshot

SOURCE = 'mx2.the-grange.uk'
TLS_NAME = 'mta-sts.the-grange.uk'
ADDRESS = '10.50.0.250'
CERTIFICATE = Path('/data/custom_ssl/grange-mtasts/fullchain.pem')
PRIVATE_KEY = Path('/data/custom_ssl/grange-mtasts/privkey.pem')
VHOST_CONFIG = Path('/data/nginx/custom/http.conf')


def emit(event, **data):
    print(json.dumps({'event': event, 'hostname': TLS_NAME, **data}, sort_keys=True), flush=True)


def checked_config(path):
    secure_file(path)
    config = load_json(path)
    require(config.get('schema') == 1 and config.get('role') == 'germany-ct250-grange-mtasts', 'PEM consumer role invalid')
    require(config.get('source_hostname') == SOURCE and config.get('spki_sha256') == HOSTS[SOURCE]['spki'],
            'PEM consumer enrollment differs from inspected MX2 identity')
    for name in ('state_dir', 'backup_dir'):
        require(isinstance(config.get(name), str) and Path(config[name]).is_absolute(), 'PEM consumer directory invalid')
    return config


def local_identity():
    interfaces = json.loads(run_command(['ip', '-j', 'address', 'show'], timeout=5, stage='read proxy addresses'))
    require(ADDRESS in {x.get('local') for interface in interfaces for x in interface.get('addr_info', [])},
            'CT250 address is not assigned locally')


def guard():
    for path in (CERTIFICATE, PRIVATE_KEY, VHOST_CONFIG):
        require(path.is_file() and not path.is_symlink(), 'expected existing regular MTA-STS file')
    return {'certificate': snapshot(CERTIFICATE), 'key_sha256': digest(PRIVATE_KEY),
            'vhost_sha256': digest(VHOST_CONFIG)}


def check_guard(expected, allowed_certificate_hashes=None):
    actual = guard()
    require(actual['key_sha256'] == expected['key_sha256'], 'MTA-STS private key changed concurrently')
    require(actual['vhost_sha256'] == expected['vhost_sha256'], 'MTA-STS proxy configuration changed concurrently')
    previous, current = expected['certificate'], actual['certificate']
    require(all(previous[x] == current[x] for x in ('uid', 'gid', 'mode')), 'MTA-STS certificate ownership changed concurrently')
    allowed = [previous['sha256']] if allowed_certificate_hashes is None else allowed_certificate_hashes
    require(current['sha256'] in allowed, 'MTA-STS certificate changed outside the active transaction')


def public_reference():
    current = certificate_info(CERTIFICATE.read_bytes())
    public = run_command(['openssl', 'pkey', '-in', PRIVATE_KEY, '-pubout', '-outform', 'DER'],
                         timeout=10, stage='verify existing MTA-STS key public half')
    require(current['sans'] == HOSTS[SOURCE]['sans'] and not current['non_dns_sans'] and
            current['spki_sha256'] == HOSTS[SOURCE]['spki'] and public == current['spki_der'],
            'MTA-STS public certificate/private-key identity differs from MX2 enrollment')
    return current


def peer_and_policy(expected_fingerprint, trusted=True):
    context = ssl.create_default_context() if trusted else ssl._create_unverified_context()
    deadline = time.monotonic() + 8
    with socket.create_connection((ADDRESS, 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=TLS_NAME) as connection:
            require(hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest() == expected_fingerprint,
                    'loaded MTA-STS certificate fingerprint differs')
            connection.sendall(('GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: ' + TLS_NAME +
                                '\r\nConnection: close\r\n\r\n').encode('ascii'))
            data = b''
            while len(data) <= 32768:
                require(time.monotonic() < deadline, 'MTA-STS policy read deadline exceeded')
                connection.settimeout(max(0.05, deadline - time.monotonic()))
                chunk = connection.recv(min(4096, 32769 - len(data)))
                if not chunk:
                    break
                data += chunk
            require(len(data) <= 32768 and b'\r\n\r\n' in data, 'MTA-STS policy response invalid')
            headers, body = data.split(b'\r\n\r\n', 1)
            require(headers.split(b'\r\n', 1)[0].split()[1:2] == [b'200'] and b'version: STSv1' in body,
                    'MTA-STS policy endpoint did not return the expected policy')


def verify_loaded(info, wait_seconds=0):
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            peer_and_policy(info['sha256'], trusted=info['not_after'] > time.time())
            return
        except (OSError, RenewalError):
            if time.monotonic() >= deadline:
                raise RenewalError('MTA-STS TLS/policy verification failed') from None
            time.sleep(1)


def nginx_check():
    run_command(['nginx', '-t'], timeout=15, stage='validate existing Nginx configuration')


def nginx_reload():
    nginx_check()
    run_command(['nginx', '-s', 'reload'], timeout=15, stage='reload existing Nginx workers')


def write_certificate(data, expected):
    metadata = expected['certificate']
    atomic_write(CERTIFICATE, data, metadata['mode'], metadata['uid'], metadata['gid'])


def record_transaction(config, manifest):
    atomic_json(Path(config['state_dir']) / 'transaction.json', manifest)


def rollback(config, manifest):
    backup = Path(manifest['backup']).resolve()
    require(Path(config['backup_dir']).resolve() in backup.parents, 'MTA-STS backup outside configured directory')
    require(backup.is_file() and not backup.is_symlink() and backup.stat().st_size <= 131072, 'MTA-STS backup file invalid')
    old = backup.read_bytes()
    expected = manifest['original']
    require(hashlib.sha256(old).hexdigest() == expected['certificate']['sha256'], 'MTA-STS rollback backup hash differs')
    check_guard(expected, [expected['certificate']['sha256'], manifest['new_file_sha256']])
    write_certificate(old, expected)
    nginx_reload()
    verify_loaded(manifest['old_certificate'], 30)
    check_guard(expected)
    manifest['phase'] = 'rolled_back'
    record_transaction(config, manifest)
    emit('mtasts_certificate_rolled_back', backup=str(backup))


def recover_transaction(config, apply):
    manifest = load_json(Path(config['state_dir']) / 'transaction.json', {})
    if not manifest or manifest.get('phase') in ('committed', 'rolled_back', 'aborted_before_replace'):
        return
    require(manifest.get('schema') == 1 and manifest.get('hostname') == TLS_NAME, 'pending MTA-STS transaction scope invalid')
    expected = manifest['original']
    check_guard(expected, [expected['certificate']['sha256'], manifest['new_file_sha256']])
    new_installed = digest(CERTIFICATE) == manifest['new_file_sha256']
    info = manifest['new_certificate'] if new_installed else manifest['old_certificate']
    try:
        verify_loaded(info)
    except RenewalError:
        require(apply, 'interrupted MTA-STS transaction needs guarded reload with --apply')
        try:
            nginx_reload()
            verify_loaded(info, 30)
        except BaseException:
            if new_installed:
                rollback(config, manifest)
            raise RenewalError('MTA-STS interrupted reload did not complete') from None
    emit('interrupted_mtasts_transaction_verified', will_apply=apply)
    if apply:
        manifest['phase'] = 'committed' if new_installed else 'aborted_before_replace'
        record_transaction(config, manifest)


def install(config, current, candidate, expected):
    check_guard(expected)
    nginx_check()
    verify_loaded(current)
    root = Path(config['backup_dir'])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-'), dir=root))
    backup = directory / 'fullchain.pem'
    atomic_write(backup, CERTIFICATE.read_bytes())
    require(digest(backup) == expected['certificate']['sha256'], 'MTA-STS reference changed while backing up')
    manifest = {'schema': 1, 'hostname': TLS_NAME, 'phase': 'prepared', 'original': expected,
                'backup': str(backup), 'old_certificate': public_status(current), 'new_certificate': public_status(candidate),
                'new_file_sha256': hashlib.sha256(candidate['fullchain_pem']).hexdigest()}
    atomic_json(directory / 'manifest.json', manifest)
    record_transaction(config, manifest)
    replaced = False
    try:
        check_guard(expected)
        replaced = True
        write_certificate(candidate['fullchain_pem'], expected)
        check_guard(expected, [manifest['new_file_sha256']])
        manifest['phase'] = 'file_installed'
        record_transaction(config, manifest)
        nginx_reload()
        verify_loaded(candidate, 30)
        check_guard(expected, [manifest['new_file_sha256']])
        manifest['phase'] = 'committed'
        record_transaction(config, manifest)
        emit('mtasts_certificate_installed_and_verified', certificate=public_status(candidate),
             original_private_key_preserved=True, backup=str(backup))
    except BaseException:
        if replaced:
            try:
                rollback(config, manifest)
            except BaseException:
                emit('mtasts_rollback_requires_attention', backup=str(backup))
                raise RenewalError('MTA-STS certificate transaction and rollback did not complete') from None
        else:
            manifest['phase'] = 'aborted_before_replace'
            record_transaction(config, manifest)
        raise RenewalError('MTA-STS certificate transaction failed; previous certificate restored') from None


def process(config, apply=False):
    local_identity()
    recover_transaction(config, apply)
    expected = guard()
    current = public_reference()
    candidate, source = fetch_candidate({'hostname': SOURCE, 'state_dir': config['state_dir']}, apply)
    newer = replacement_is_newer(current, candidate)
    check_guard(expected)
    if newer and apply:
        install(config, current, candidate, expected)
        active, status = candidate, 'new_certificate_deployed'
    elif newer:
        nginx_check()
        verify_loaded(current)
        active, status = current, 'validated_deployment_pending'
    else:
        verify_loaded(current)
        active, status = current, 'current_certificate_verified'
    emit(status, certificate=public_status(active), available_certificate_sha256=candidate['sha256'], source=source)
    if apply:
        atomic_json(Path(config['state_dir']) / 'health.json', {'schema': 1, 'hostname': TLS_NAME,
                    'status': status, 'checked_at': time.time(), 'active_certificate': public_status(active),
                    'publisher_reachable': source == 'publisher', 'private_key_preserved': True})


def interrupted(signum, frame):
    raise RenewalError('MTA-STS renewal interrupted; guarded rollback will run if replacement started')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'PEM consumer must run locally as root')
    os.umask(0o077)
    config = checked_config(args.config)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        with operation_lock(Path(config['state_dir']) / 'consumer.lock'):
            process(config, args.apply)
    except BaseException as error:
        if args.apply:
            atomic_json(Path(config['state_dir']) / 'health.json', {'schema': 1, 'hostname': TLS_NAME,
                        'status': 'failed', 'checked_at': time.time(), 'error_type': type(error).__name__})
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        emit('pem_consumer_failed', error_type=type(error).__name__)
        raise SystemExit(1)
