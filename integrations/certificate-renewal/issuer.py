#!/usr/bin/env python3
"""Central CSR issuance and atomic publication; no MX private keys or remote shell."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from renewal_common import (DAY, RenewalError, atomic_json, certificate_info, csr_info,
    operation_lock, public_status, renewal_due, replacement_is_newer, require, retry_at, validate_bundle)

SCOPES = {
    'mx1.the-grange.uk': ('mx1.the-grange.uk',),
    'mx2.the-grange.uk': ('mta-sts.the-grange.uk', 'mx2.the-grange.uk'),
    'mx1.brimstonecottage.uk': ('mx1.brimstonecottage.uk',),
    'mx2.brimstonecottage.uk': ('mx2.brimstonecottage.uk',),
}
PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory'
STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'


def emit(event, **data):
    print(json.dumps({'event': event, **data}, sort_keys=True), flush=True)


def load_json(path, default=None):
    path = Path(path)
    if not path.exists() and default is not None:
        return default
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        raise RenewalError('stored configuration/state could not be read') from None
    require(isinstance(value, dict), 'stored configuration/state is not an object')
    return value


def checked_config(path):
    config = load_json(path)
    require(config.get('schema') == 1, 'issuer configuration version invalid')
    require(config.get('interval_days', 28) == 28, 'issuer interval must be 28 days')
    hosts = config.get('hosts')
    require(isinstance(hosts, dict) and hosts and set(hosts) <= set(SCOPES), 'issuer host scope invalid')
    for name, item in hosts.items():
        require(tuple(sorted(item.get('sans', []))) == SCOPES[name], 'issuer SAN configuration invalid')
        require(re.fullmatch(r'[0-9a-f]{64}', item.get('spki_sha256', '')) is not None, 'issuer SPKI pin invalid')
        require(item.get('authenticator') in ('cloudflare', 'webroot'), 'unsupported CSR authenticator')
        if item['authenticator'] == 'cloudflare':
            require(item.get('cloudflare_account') in ('personal', 'support'), 'Cloudflare account route invalid')
            require(item.get('zone') in ('the-grange.uk', 'brimstonecottage.uk') and
                    name.endswith('.' + item['zone']), 'DNS zone outside host scope')
        else:
            require(name.endswith('.brimstonecottage.uk'), 'HTTP challenge outside approved Brimstone scope')
        csr = csr_info(item['csr_path'])
        require(csr['sans'] == SCOPES[name] and not csr['non_dns_sans'] and
                csr['spki_sha256'] == item['spki_sha256'], 'enrolled CSR SAN/key binding failed')
    return config


def envelope(host, certificate, issued_at):
    return {'schema': 1, 'hostname': host, 'certificate': public_status(certificate),
            'issued_at': issued_at, 'fullchain_pem': certificate['fullchain_pem'].decode('ascii')}


def published(config, host, item):
    path = Path(config['public_dir']) / (host + '.json')
    obj = load_json(path)
    require(obj.get('schema') == 1 and obj.get('hostname') == host, 'published envelope scope invalid')
    # Published bytes are root-written and may be old/expired when recovering
    # issuance. Their pinned identity remains mandatory; current-time trust is
    # enforced before any new publication or consumer installation.
    data = obj.get('fullchain_pem', '').encode('ascii')
    info = certificate_info(data)
    require(info['sans'] == SCOPES[host] and not info['non_dns_sans'] and
            info['spki_sha256'] == item['spki_sha256'], 'published identity differs from enrollment')
    require(obj.get('certificate', {}).get('sha256') == info['sha256'], 'published envelope fingerprint mismatch')
    return info


def publish(config, host, info, issued_at):
    directory = Path(config['public_dir'])
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(directory, 0o755)
    atomic_json(directory / (host + '.json'), envelope(host, info, issued_at), mode=0o644)


def recover_bundle(config, host, item, state, current):
    attempt = state.get('attempt_directory')
    if not attempt:
        return None
    root = (Path(config['state_dir']) / 'attempts' / host).resolve()
    path = Path(attempt).resolve()
    require(root in path.parents, 'issuance attempt path outside state root')
    fullchain = path / 'fullchain.pem'
    if not fullchain.is_file():
        return None
    # Incomplete ACME attempts are normal after a timeout, failed challenge or
    # interrupted write. Keep their private evidence, but do not let malformed,
    # stale or expired output permanently prevent a later eligible retry. The
    # attempt-directory boundary above remains a hard configuration failure.
    try:
        require(not fullchain.is_symlink(), 'attempt certificate must be a regular local file')
        require(fullchain.stat().st_size <= 131072, 'attempt certificate is too large')
        info = validate_bundle(fullchain.read_bytes(), SCOPES[host], item['spki_sha256'])
        if info['sha256'] != current['sha256']:
            replacement_is_newer(current, info)
        return info
    except (RenewalError, OSError, UnicodeError, ValueError):
        emit('prior_attempt_not_recoverable', hostname=host, retained_for_diagnosis=True)
        return None


def completed_state(info, issued_at):
    return {'schema': 1, 'phase': 'issued_and_published', 'certificate_sha256': info['sha256'],
            'last_successful_issuance_at': issued_at, 'failures': 0, 'next_attempt_at': 0}


def cloudflare_token(config, item):
    path = Path(config.get('controller_path', '/opt/grange-mail-dns-controller/controller.py'))
    require(path.is_file(), 'existing authorised DNS controller missing')
    spec = importlib.util.spec_from_file_location('existing_grange_dns_controller', path)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    # Route selection is explicit in this new issuer's private configuration.
    # It never rewrites the existing controller/environment or distributes tokens.
    token_path = (controller.CF_PERSONAL_TOKEN_FILE if item['cloudflare_account'] == 'personal'
                  else controller.CF_SUPPORT_TOKEN_FILE)
    token = token_path.read_text().strip()
    require(bool(token) and not any(c.isspace() for c in token), 'authorised DNS credential format invalid')
    return token


def parse_retry_after(path):
    try:
        data = Path(path).read_text(errors='replace')[-40000:]
    except OSError:
        return None
    candidates = []
    for raw in re.findall(r'(?i)retry after\s+(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:Z| UTC|[+-]\d\d:\d\d)?)', data):
        try:
            parsed = dt.datetime.fromisoformat(raw.replace(' UTC', '+00:00').replace('Z', '+00:00'))
            parsed = parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed.astimezone(dt.timezone.utc)
            candidates.append(parsed.timestamp())
        except ValueError:
            pass
    return max(candidates) if candidates else None


def run_certbot(config, host, item, output, staging=False):
    with tempfile.TemporaryDirectory(prefix='grange-acme-', dir='/run') as temporary:
        args = ['certbot', 'certonly', '--non-interactive', '--agree-tos', '--server', STAGING if staging else PRODUCTION,
                '--csr', item['csr_path'], '--cert-path', str(output / 'cert.pem'),
                '--chain-path', str(output / 'chain.pem'), '--fullchain-path', str(output / 'fullchain.pem')]
        if config.get('email'):
            args += ['--email', config['email']]
        else:
            args += ['--register-unsafely-without-email']
        if item['authenticator'] == 'cloudflare':
            credential = Path(temporary) / 'cloudflare.ini'
            credential.write_text('dns_cloudflare_api_token = ' + cloudflare_token(config, item) + '\n')
            os.chmod(credential, 0o600)
            args += ['--dns-cloudflare', '--dns-cloudflare-credentials', str(credential),
                     '--dns-cloudflare-propagation-seconds', '60']
        else:
            base = Path(config['challenge_dir']) / host
            for directory in (Path(config['challenge_dir']), base, base / '.well-known', base / '.well-known/acme-challenge'):
                directory.mkdir(parents=True, exist_ok=True, mode=0o755)
                os.chmod(directory, 0o755)
            args += ['--webroot', '--webroot-path', str(base)]
        log = output / 'issuance.log'
        with log.open('wb') as handle:
            os.chmod(handle.fileno(), 0o600)
            process = subprocess.Popen(args, stdout=handle, stderr=subprocess.STDOUT,
                                       umask=0o022 if item['authenticator'] == 'webroot' else 0o077)
            try:
                return process.wait(timeout=360)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise RenewalError('ACME issuance timeout; private log retained') from None


def seed(config, apply):
    for host, item in config['hosts'].items():
        info = validate_bundle(Path(item['reference_fullchain']).read_bytes(), SCOPES[host], item['spki_sha256'])
        destination = Path(config['public_dir']) / (host + '.json')
        if destination.exists():
            existing = published(config, host, item)
            require(existing['sha256'] == info['sha256'], 'seed would replace an existing different publication')
        emit('seed_validated', hostname=host, certificate=public_status(info), will_apply=apply)
        if apply:
            publish(config, host, info, info['not_before'])
            state = Path(config['state_dir']) / 'issuance' / (host + '.json')
            if not state.exists():
                atomic_json(state, completed_state(info, info['not_before']))


def process_host(config, host, apply=False, retry_only=False, staging=False):
    item = config['hosts'][host]
    current = published(config, host, item)
    state_path = Path(config['state_dir']) / 'issuance' / (host + '.json')
    state = load_json(state_path, {})
    now = time.time()
    if not staging:
        recovered = recover_bundle(config, host, item, state, current)
        if recovered:
            emit('completed_issuance_recovered', hostname=host, certificate=public_status(recovered), will_apply=apply)
            if apply:
                issued_at = float(state.get('attempt_started_at', recovered['not_before']))
                publish(config, host, recovered, issued_at)
                atomic_json(state_path, completed_state(recovered, issued_at))
            return
        if state.get('certificate_sha256') != current['sha256']:
            # Publication precedes the success-state write. A crash between the
            # two must not trigger another order, even if an operator has since
            # removed the attempt directory. Revalidate the published bundle
            # before adopting its issuance clock; deployment time is irrelevant.
            obj = load_json(Path(config['public_dir']) / (host + '.json'))
            try:
                verified = validate_bundle(obj['fullchain_pem'].encode('ascii'), SCOPES[host], item['spki_sha256'])
            except RenewalError:
                # An expired or nearly expired root-written reference still
                # needs replacement; do not turn lost state into a renewal ban.
                emit('published_state_reconciliation_deferred', hostname=host)
            else:
                state = completed_state(verified, verified['not_before'])
                emit('published_issuance_state_reconciled', hostname=host, will_apply=apply)
                if apply:
                    atomic_json(state_path, state)
    last_success = state.get('last_successful_issuance_at') if state.get('certificate_sha256') == current['sha256'] else None
    policy = renewal_due(current['not_before'], current['not_after'], last_success, now)
    if not staging:
        # An unclean stop may leave a persisted in-flight attempt before a
        # caught failure increments its counter. The hourly job must retry that
        # eligible attempt after recovery/backoff checks, not wait another day.
        retry_pending = bool(state.get('failures')) or state.get('phase') in ('issuing', 'retry_pending')
        if retry_only and not retry_pending:
            emit('no_issuance_retry_pending', hostname=host)
            return
        if float(state.get('next_attempt_at', 0)) > now:
            emit('issuance_backoff', hostname=host, next_attempt_at=state['next_attempt_at'])
            return
        # The daily run orders during its final check horizon before the maximum
        # deadline. Hourly retries run only for previously failed due attempts.
        if policy['next_due_at'] > now + DAY:
            emit('certificate_not_due', hostname=host, policy=policy)
            return
    emit('issuance_due' if not staging else 'staging_validation_due', hostname=host, policy=policy, will_apply=apply)
    if not apply:
        return
    attempts = Path(config['state_dir']) / ('staging' if staging else 'attempts') / host
    attempts.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = Path(tempfile.mkdtemp(prefix=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-'), dir=attempts))
    if not staging:
        state = {**state, 'schema': 1, 'phase': 'issuing', 'attempt_directory': str(output), 'attempt_started_at': now}
        atomic_json(state_path, state)
    emit('issuance_started', hostname=host, staging=staging)
    try:
        status = run_certbot(config, host, item, output, staging)
        fullchain = (output / 'fullchain.pem').read_bytes()
        if staging:
            info = certificate_info(fullchain)
            require(status == 0 and info['sans'] == SCOPES[host] and not info['non_dns_sans'] and
                    info['spki_sha256'] == item['spki_sha256'], 'staging challenge/CSR validation failed')
            atomic_json(output / 'result.json', {'schema': 1, 'hostname': host, 'staging_only': True,
                                               'certificate': public_status(info)})
            emit('staging_validated_not_published', hostname=host)
            return
        info = validate_bundle(fullchain, SCOPES[host], item['spki_sha256'])
        replacement_is_newer(current, info)
        # Publication failure retains the completed attempt for recovery, rather
        # than issuing a duplicate certificate on the next invocation.
        publish(config, host, info, now)
        atomic_json(state_path, completed_state(info, now))
        emit('issued_and_published', hostname=host, certificate=public_status(info),
             acme_process_returncode=status, deployment_is_separate=True)
    except Exception as error:
        if not staging:
            failures = int(state.get('failures', 0)) + 1
            next_attempt = retry_at(failures, current['not_after'] - now, now,
                                    parse_retry_after(output / 'issuance.log'))
            atomic_json(state_path, {**state, 'phase': 'retry_pending', 'failures': failures,
                                    'next_attempt_at': next_attempt, 'last_error_type': type(error).__name__})
        raise RenewalError('issuance/publication did not complete; private attempt retained for retry') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--apply', action='store_true')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--seed', action='store_true')
    modes.add_argument('--retry-only', action='store_true')
    modes.add_argument('--staging-check', choices=sorted(SCOPES))
    args = parser.parse_args()
    require(os.geteuid() == 0, 'issuer must run as root locally')
    os.umask(0o077)
    config = checked_config(args.config)
    failures = 0
    with operation_lock(Path(config['state_dir']) / 'issuer.lock'):
        if args.seed:
            seed(config, args.apply)
            return 0
        hosts = [args.staging_check] if args.staging_check else list(config['hosts'])
        for host in hosts:
            require(host in config['hosts'], 'requested host is not enrolled')
            try:
                process_host(config, host, args.apply, args.retry_only, bool(args.staging_check))
            except Exception as error:
                failures += 1
                emit('issuer_host_failed', hostname=host, error_type=type(error).__name__)
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        emit('issuer_failed', error_type=type(error).__name__)
        raise SystemExit(1)
