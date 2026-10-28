#!/usr/bin/env python3
"""Renew an enrolled Certbot lineage and deploy it to its local consumers.

The configured command prefixes allow the Derby coordinator to cover CT400
web/mail and CT300 BulkMail as one transaction. Canada CT102 runs natively.
Private keys stay where they are: renewal reuses the enrolled key and deployment
changes only public certificate files. Issuance and deployment retries have
separate durable state, so a failed reload never requests another certificate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import time

from renewal_common import (DAY, RenewalError, atomic_json, atomic_write,
    certificate_info, operation_lock, public_status, renewal_due,
    replacement_is_newer, require, retry_at, run_command, validate_bundle)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path, default=None):
    try:
        if not Path(path).exists() and default is not None:
            return default
        data = Path(path).read_bytes()
        require(len(data) <= 1024 * 1024, 'local state/configuration is too large')
        result = json.loads(data)
        require(isinstance(result, dict), 'local state/configuration must be an object')
        return result
    except (OSError, ValueError):
        raise RenewalError('local state/configuration could not be read') from None


def secure_regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'expected regular enrolled file')
    item = path.stat()
    require(item.st_uid == 0 and not item.st_mode & 0o022,
            'configuration must be root-owned and not writable by other users')


def command_list(value, empty=False):
    require(isinstance(value, list) and (empty or bool(value)) and
            all(isinstance(part, str) and part and not re.search(r'[\x00-\x1f\x7f]', part) for part in value),
            'configured command must be an argument list')
    return value


def checked_config(path):
    secure_regular(path)
    cfg = load_json(path)
    require(cfg.get('schema') == 1, 'configuration schema is unsupported')
    require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,100}', cfg.get('lineage', '')) is not None,
            'lineage name invalid')
    require(re.fullmatch(r'[0-9a-f]{64}', cfg.get('spki_sha256', '')) is not None,
            'enrolled public-key fingerprint invalid')
    require(isinstance(cfg.get('sans'), list) and bool(cfg['sans']) and all(
        isinstance(name, str) and re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}', name) for name in cfg['sans']),
        'enrolled DNS names invalid')
    for field in ('lineage_dir', 'renewal_config', 'state_dir', 'lock_path', 'certbot_executable'):
        require(isinstance(cfg.get(field), str) and Path(cfg[field]).is_absolute(),
                'required absolute path is missing')
    require(Path(cfg['lineage_dir']).name == cfg['lineage'] and
            Path(cfg['renewal_config']).name == cfg['lineage'] + '.conf',
            'named Certbot lineage paths do not agree')
    command_list(cfg.get('command_prefix', []), empty=True)
    require(re.fullmatch(r'certbot [0-9]+\.[0-9]+\.[0-9]+', cfg.get('certbot_version', '')) is not None,
            'verified Certbot version missing')
    require(isinstance(cfg.get('webroot'), str) and cfg['webroot'].startswith('/'), 'verified webroot missing')
    require(0 <= cfg.get('lookahead_seconds', DAY) <= DAY, 'daily look-ahead cannot exceed one day')
    require(isinstance(cfg.get('consumers'), list) and 1 <= len(cfg['consumers']) <= 8,
            'consumer inventory missing or excessive')
    names, targets = set(), set()
    for consumer in cfg['consumers']:
        name = consumer.get('name', '')
        require(re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name) is not None and name not in names,
                'consumer name invalid or repeated')
        names.add(name)
        require(isinstance(consumer.get('key_path'), str) and Path(consumer['key_path']).is_absolute(),
                'consumer key path must be absolute')
        files = consumer.get('files')
        require(isinstance(files, dict) and 'fullchain_pem' in files and set(files) <= {'fullchain_pem', 'chain_pem'},
                'consumer public-certificate file mapping invalid')
        for target in files.values():
            require(isinstance(target, str) and Path(target).is_absolute() and target not in targets,
                    'consumer certificate paths must be absolute and unique')
            require(target != consumer['key_path'], 'certificate deployment cannot overwrite a private key')
            targets.add(target)
        command_list(consumer.get('activate'))
        command_list(consumer.get('validate', []), empty=True)
        endpoints = consumer.get('endpoints')
        require(isinstance(endpoints, list) and 1 <= len(endpoints) <= 8, 'consumer TLS probes missing')
        for endpoint in endpoints:
            require(endpoint.get('protocol') in ('tls', 'smtp-starttls') and
                    isinstance(endpoint.get('address'), str) and
                    isinstance(endpoint.get('port'), int) and 1 <= endpoint['port'] <= 65535 and
                    endpoint.get('server_name') in cfg['sans'], 'consumer TLS probe configuration invalid')
    return cfg


def smtp_reply(sock, reader, expected, deadline):
    for unused in range(40):
        require(time.monotonic() < deadline, 'SMTP TLS probe deadline exceeded')
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        line = reader.readline(8193)
        require(4 <= len(line) <= 8192 and line[:3].isdigit() and int(line[:3]) == expected,
                'SMTP TLS probe received an unexpected reply')
        if line[3:4] == b' ':
            return
        require(line[3:4] == b'-', 'SMTP TLS probe received a malformed multiline reply')
    raise RenewalError('SMTP TLS probe exceeded its reply limit')


def endpoint_fingerprint(endpoint, timeout=5, trusted=True):
    # Relaxed validation is used only when restoring a journaled, exact DER
    # fingerprint. It permits an expired previous certificate to be restored
    # before a due renewal; fresh deployments always require normal trust.
    context = ssl.create_default_context() if trusted else ssl._create_unverified_context()
    deadline = time.monotonic() + timeout
    raw = socket.create_connection((endpoint['address'], endpoint['port']), timeout=timeout)
    try:
        if endpoint['protocol'] == 'smtp-starttls':
            reader = raw.makefile('rb')
            try:
                smtp_reply(raw, reader, 220, deadline)
                raw.sendall(b'EHLO certificate-check.the-grange.uk\r\n')
                smtp_reply(raw, reader, 250, deadline)
                raw.sendall(b'STARTTLS\r\n')
                smtp_reply(raw, reader, 220, deadline)
            finally:
                reader.close()
        require(time.monotonic() < deadline, 'TLS probe deadline exceeded')
        raw.settimeout(max(0.05, deadline - time.monotonic()))
        with context.wrap_socket(raw, server_hostname=endpoint['server_name']) as secured:
            return sha(secured.getpeercert(binary_form=True))
    finally:
        raw.close()


class Native:
    def __init__(self, cfg):
        self.cfg = cfg
        self.directory = Path(cfg['state_dir'])
        self.state_path = self.directory / 'state.json'
        self.consumers = {item['name']: item for item in cfg['consumers']}

    def now(self):
        return time.time()

    def read_state(self):
        return load_json(self.state_path, {})

    def save_state(self, state):
        atomic_json(self.state_path, state)

    def bind(self, info):
        require(info['sans'] == tuple(sorted(set(self.cfg['sans']))) and not info.get('non_dns_sans', False)
                and info['spki_sha256'] == self.cfg['spki_sha256'], 'certificate differs from enrolled DNS names/key')

    def key_matches(self, path):
        public = run_command(['openssl', 'pkey', '-in', path, '-pubout', '-outform', 'DER'],
                             timeout=10, stage='check enrolled key public half')
        require(sha(public) == self.cfg['spki_sha256'], 'existing private key differs from enrolled public key')

    def reference(self):
        lineage = Path(self.cfg['lineage_dir'])
        raw = (lineage / 'fullchain.pem').read_bytes()
        info = certificate_info(raw)
        self.bind(info)
        self.key_matches(lineage / 'privkey.pem')
        require((lineage / 'fullchain.pem').read_bytes() == raw, 'lineage changed during identity validation')
        return info, raw

    def validate(self, raw):
        return validate_bundle(raw, self.cfg['sans'], self.cfg['spki_sha256'], now=self.now(),
                               ca_file=self.cfg.get('ca_file'))

    def cache(self, info):
        name = 'certificate-' + info['sha256'] + '.pem'
        atomic_write(self.directory / name, info['fullchain_pem'])
        return name

    def pending_info(self, pending):
        require(re.fullmatch(r'[0-9a-f]{64}', pending.get('sha256', '')) is not None,
                'pending certificate fingerprint invalid')
        expected = 'certificate-' + pending['sha256'] + '.pem'
        require(pending.get('cache') == expected, 'pending certificate cache path invalid')
        info = self.validate((self.directory / expected).read_bytes())
        require(info['sha256'] == pending['sha256'], 'pending certificate cache fingerprint changed')
        return info

    def issue(self):
        # This invocation bypasses only the inspected directory hook; the new
        # certificate is validated before any consumer files can be replaced.
        text = Path(self.cfg['renewal_config']).read_text()
        for match in re.finditer(r'(?m)^\s*(?:pre_hook|post_hook|renew_hook|deploy_hook)\s*=\s*(.*?)\s*$', text):
            require(not match[1], 'unreviewed per-lineage Certbot hook is configured')
        require(re.search(r'(?m)^\s*authenticator\s*=\s*webroot\s*$', text) is not None,
                'Certbot authenticator changed from the inspected webroot')
        require(re.search(r'(?m)^\s*server\s*=\s*https://acme-v02\.api\.letsencrypt\.org/directory\s*$', text) is not None,
                'Certbot ACME directory changed')
        roots = re.findall(r'(?m)^\s*webroot_path\s*=\s*(.*?)\s*$', text)
        require(len(roots) == 1 and roots[0].rstrip(',').strip() == self.cfg['webroot'],
                'Certbot webroot differs from inspected enrollment')
        prefix, executable = self.cfg.get('command_prefix', []), self.cfg['certbot_executable']
        version = run_command(prefix + [executable, '--version'], timeout=15, stage='verify Certbot version').decode().strip()
        require(version == self.cfg['certbot_version'], 'Certbot version changed; review capability inventory')
        args = prefix + ['/usr/bin/timeout', '--signal=TERM', '--kill-after=30', '900', executable,
                         'renew', '--cert-name', self.cfg['lineage'], '--reuse-key', '--force-renewal',
                         '--non-interactive', '--no-directory-hooks']
        # The inner timeout is inside Docker/pct, so a disconnected outer
        # command cannot leave an unbounded Certbot process issuing later.
        try:
            run_command(args, timeout=950, stage='named Certbot renewal')
            return True
        except RenewalError:
            # Certbot may have saved a valid certificate before an ancillary
            # failure. The caller always rereads and validates the lineage.
            return False

    def source_unchanged(self, info):
        current, unused = self.reference()
        require(current['sha256'] == info['sha256'], 'lineage changed concurrently; defer consumer deployment')

    def files_current(self, consumer, info):
        return all(Path(path).read_bytes() == info[field] for field, path in consumer['files'].items())

    def verify(self, consumer, fingerprint, wait_seconds=0, trusted=True):
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                for endpoint in consumer['endpoints']:
                    require(endpoint_fingerprint(endpoint, trusted=trusted) == fingerprint,
                            'consumer TLS endpoint presents a different certificate')
                return True
            except (OSError, RenewalError):
                if time.monotonic() >= deadline:
                    return False
                time.sleep(2)

    def healthy(self, info):
        self.key_matches(Path(self.cfg['lineage_dir']) / 'privkey.pem')
        for consumer in self.consumers.values():
            self.key_matches(consumer['key_path'])
            if not self.files_current(consumer, info) or not self.verify(consumer, info['sha256']):
                return False
        return True

    def activate(self, consumer):
        if consumer.get('validate'):
            run_command(consumer['validate'], timeout=30, stage='validate consumer configuration')
        run_command(consumer['activate'], timeout=90, stage='activate consumer certificate')

    def prepare(self, info, state):
        self.source_unchanged(info)
        entries = []
        backup = self.directory / ('transaction-' + secrets.token_hex(12))
        backup.mkdir(mode=0o700, parents=True)
        for name, consumer in self.consumers.items():
            self.key_matches(consumer['key_path'])
            if self.files_current(consumer, info) and self.verify(consumer, info['sha256']):
                continue
            old = certificate_info(Path(consumer['files']['fullchain_pem']).read_bytes())
            self.bind(old)
            if old['sha256'] != info['sha256']:
                require(replacement_is_newer(old, info), 'consumer has a newer certificate than the proposed source')
            entry = {'name': name, 'old_fingerprint': old['sha256'], 'files': []}
            for field, path in consumer['files'].items():
                target = Path(path)
                require(target.is_file() and not target.is_symlink(), 'consumer certificate must be an existing regular file')
                metadata = target.stat()
                content = target.read_bytes()
                stored = backup / str(sum(len(item['files']) for item in entries) + len(entry['files']))
                atomic_write(stored, content)
                entry['files'].append({'field': field, 'target': path, 'backup': str(stored.relative_to(self.directory)),
                    'old_sha256': sha(content), 'new_sha256': sha(info[field]), 'mode': stat.S_IMODE(metadata.st_mode),
                    'uid': metadata.st_uid, 'gid': metadata.st_gid})
            entries.append(entry)
        state['transaction'] = {'candidate_sha256': info['sha256'], 'phase': 'prepared', 'consumers': entries}
        self.save_state(state)
        return entries

    def rollback(self, state):
        transaction = state.get('transaction')
        require(isinstance(transaction, dict), 'rollback transaction missing')
        failures = []
        for entry in transaction['consumers']:
            try:
                consumer = self.consumers[entry['name']]
                self.key_matches(consumer['key_path'])
                prepared = []
                for item in entry['files']:
                    require(consumer['files'].get(item['field']) == item['target'], 'rollback target is outside enrollment')
                    stored = self.directory / item['backup']
                    require(stored.resolve().is_relative_to(self.directory.resolve()) and not stored.is_symlink(),
                            'rollback backup path is outside private state')
                    old = stored.read_bytes()
                    require(sha(old) == item['old_sha256'], 'rollback backup content changed')
                    target = Path(item['target'])
                    require(target.is_file() and not target.is_symlink() and
                            sha(target.read_bytes()) in (item['old_sha256'], item['new_sha256']),
                            'consumer certificate changed outside transaction; preserve it for review')
                    if item['field'] == 'fullchain_pem':
                        old_info = certificate_info(old)
                        self.bind(old_info)
                        require(old_info['sha256'] == entry['old_fingerprint'], 'rollback identity differs from snapshot')
                    prepared.append((item, old))
                require({item['field'] for item, unused in prepared} == set(consumer['files']),
                        'rollback snapshot is not a complete consumer file set')
                # Validate the entire backup/target set before replacing its
                # first public file. A corrupt chain cannot cause a partial
                # restoration of this consumer's certificate set.
                for item, old in prepared:
                    atomic_write(item['target'], old, item['mode'], item['uid'], item['gid'])
                self.activate(consumer)
                require(self.verify(consumer, entry['old_fingerprint'], 45, trusted=False),
                        'restored consumer TLS fingerprint verification failed')
            except (OSError, KeyError, ValueError, RenewalError):
                failures.append(entry.get('name', 'unknown'))
        if failures:
            transaction['phase'] = 'rollback_failed'
            self.save_state(state)
            raise RenewalError('one or more consumers could not be rolled back; transaction retained')
        state.pop('transaction', None)
        self.save_state(state)

    def deploy(self, info, state):
        entries = self.prepare(info, state)
        try:
            # Keys are never replaced. Every intermediate public-file state
            # therefore still belongs to the exact unchanged consumer key.
            for entry in entries:
                self.source_unchanged(info)
                for item in entry['files']:
                    target = Path(item['target'])
                    require(not target.is_symlink() and sha(target.read_bytes()) == item['old_sha256'],
                            'consumer certificate changed after snapshot')
                    atomic_write(target, info[item['field']], item['mode'], item['uid'], item['gid'])
            state['transaction']['phase'] = 'files_installed'
            self.save_state(state)
            for entry in entries:
                self.source_unchanged(info)
                consumer = self.consumers[entry['name']]
                self.activate(consumer)
                require(self.verify(consumer, info['sha256'], 45), 'new consumer TLS verification failed')
            self.source_unchanged(info)
            require(self.healthy(info), 'final consumer certificate verification failed')
        except Exception:
            self.rollback(state)
            raise RenewalError('consumer deployment failed and previous certificates were restored') from None


def record_pending(native, state, info, source):
    state['issued'] = public_status(info)
    state['issued_at'] = info['not_before']
    state['pending'] = {**public_status(info), 'cache': native.cache(info), 'source': source}
    native.save_state(state)


def completed(native, state, info):
    state['deployed'] = {'sha256': info['sha256'], 'verified_at': native.now()}
    for field in ('pending', 'transaction', 'failure_count', 'retry_at', 'last_failure'):
        state.pop(field, None)
    native.save_state(state)


def run(native, deploy_only=False, retry_only=False, check_only=False):
    cfg, now = native.cfg, native.now()
    state = native.read_state()
    current, raw = native.reference()
    if state:
        require(state.get('schema') == 1 and state.get('lineage') == cfg['lineage'] and
                state.get('spki_sha256') == cfg['spki_sha256'], 'state belongs to another lineage/key')
    policy = renewal_due(current['not_before'], current['not_after'],
                         state.get('issued_at') if state.get('issued', {}).get('sha256') == current['sha256'] else None,
                         now=now)
    eligible = policy['next_due_at'] <= now + cfg.get('lookahead_seconds', DAY)
    if check_only:
        return {'event': 'check', 'lineage': cfg['lineage'], 'certificate': public_status(current),
                'policy': policy, 'renewal_eligible': eligible, 'consumers_healthy': native.healthy(native.validate(raw)),
                'pending_deployment': bool(state.get('pending')), 'transaction_pending': bool(state.get('transaction'))}
    if retry_only and not (state.get('pending') or state.get('failure_count') or state.get('transaction')):
        return {'event': 'no_retry_pending', 'lineage': cfg['lineage']}
    if state.get('retry_at', 0) > now:
        return {'event': 'retry_deferred', 'lineage': cfg['lineage'], 'retry_at': state['retry_at']}
    if not state:
        state = {'schema': 1, 'lineage': cfg['lineage'], 'spki_sha256': cfg['spki_sha256'],
                 'issued': public_status(current), 'issued_at': current['not_before']}
        native.save_state(state)
    try:
        if state.get('pending'):
            previous = dict(state['pending']); previous['sans'] = tuple(previous['sans'])
            native.bind(previous)
            if current['sha256'] != previous['sha256']:
                require(replacement_is_newer(previous, current), 'lineage regressed while deployment was pending')
            remaining = current['not_after'] - now
            too_old = remaining < min(14 * DAY, (current['not_after'] - current['not_before']) / 3)
            # The live lineage is independently validated, so a corrupted or
            # expired cache cannot block adoption of its newer certificate.
            pending = None if too_old else native.validate(raw)
            if state.get('transaction'):
                if pending and state['transaction']['candidate_sha256'] == pending['sha256'] and native.healthy(pending):
                    completed(native, state, pending)
                    return {'event': 'recovered_completed_deployment', 'lineage': cfg['lineage']}
                native.rollback(state)
            if too_old:
                require(eligible and not deploy_only, 'pending certificate is too old to deploy; a due renewal is required')
                # The pending candidate has reached its normal renewal window.
                # Its transaction is reconciled, so one new due order is now
                # appropriate instead of retrying an unusable cache forever.
                state.pop('pending', None)
                native.save_state(state)
            else:
                source = 'external_renewal' if current['sha256'] != previous['sha256'] else state['pending']['source']
                record_pending(native, state, pending, source)
                native.source_unchanged(pending)
                if not native.healthy(pending):
                    native.deploy(pending, state)
                completed(native, state, pending)
                return {'event': 'deployment_completed', 'lineage': cfg['lineage'], 'certificate': public_status(pending),
                        'acme_order_requested': False}
        require(not state.get('transaction'), 'transaction has no matching cached certificate')
        if state['issued']['sha256'] != current['sha256']:
            prior = dict(state['issued']); prior['sans'] = tuple(prior['sans'])
            require(replacement_is_newer(prior, current), 'external lineage replacement is not newer')
            too_old = current['not_after'] - now < min(14 * DAY,
                (current['not_after'] - current['not_before']) / 3)
            if not too_old:
                info = native.validate(raw)
                record_pending(native, state, info, 'external_renewal')
                if not native.healthy(info):
                    native.deploy(info, state)
                completed(native, state, info)
                return {'event': 'external_renewal_deployed', 'lineage': cfg['lineage'], 'acme_order_requested': False}
            # An external renewal may itself have expired while the managed
            # job was offline. It must not trap this lineage in validation
            # retries forever. The strict identity/ordering checks still
            # apply, and no expired candidate is deployed: only one normally
            # due order below can supply a trusted replacement.
            require(eligible and not deploy_only,
                    'external certificate is too old to deploy; a due renewal is required')
        ordered = False
        if eligible and not deploy_only:
            state['last_order_attempt_at'] = now
            native.save_state(state)
            result = native.issue()
            after, after_raw = native.reference()
            require(after['sha256'] != current['sha256'],
                    'named renewal returned without a new certificate' if result else 'named renewal failed before a new certificate was saved')
            require(replacement_is_newer(current, after), 'issued certificate does not advance the enrolled lineage')
            info = native.validate(after_raw)
            record_pending(native, state, info, 'managed_renewal')
            ordered = True
        else:
            info = native.validate(raw)
            if native.healthy(info):
                completed(native, state, info)
                return {'event': 'already_current', 'lineage': cfg['lineage'], 'policy': policy,
                        'renewal_eligible': eligible, 'acme_order_requested': False}
            record_pending(native, state, info, 'consumer_drift')
        if not native.healthy(info):
            native.deploy(info, state)
        completed(native, state, info)
        return {'event': 'renewed_and_deployed' if ordered else 'consumer_drift_repaired',
                'lineage': cfg['lineage'], 'certificate': public_status(info), 'acme_order_requested': ordered}
    except Exception as error:
        state['failure_count'] = int(state.get('failure_count', 0)) + 1
        state['retry_at'] = retry_at(state['failure_count'], current['not_after'] - now, now=now)
        state['last_failure'] = 'rollback_pending' if state.get('transaction') else ('deployment_pending' if state.get('pending') else 'renewal_failed')
        native.save_state(state)
        if isinstance(error, RenewalError):
            raise
        raise RenewalError('local certificate operation failed; private state retained for retry') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', action='store_true', help='read-only policy and TLS status; no orders, file writes or reloads')
    modes.add_argument('--deploy-only', action='store_true', help='repair consumers without requesting an ACME order')
    modes.add_argument('--retry-only', action='store_true', help='run only an existing due failure/deployment retry')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'run as root using the installed private configuration')
        cfg = checked_config(args.config)
        native = Native(cfg)
        if args.check:
            result = run(native, check_only=True)
        else:
            with operation_lock(cfg['lock_path']):
                result = run(native, deploy_only=args.deploy_only, retry_only=args.retry_only)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except RenewalError as error:
        print(json.dumps({'event': 'failed', 'reason': str(error)}), flush=True)
        return 1
    except Exception:
        print(json.dumps({'event': 'failed', 'reason': 'unexpected local failure; review private service state'}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
