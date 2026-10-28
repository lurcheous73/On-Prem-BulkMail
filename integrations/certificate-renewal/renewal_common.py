"""Shared certificate validation and maximum-28-day renewal policy.

All timestamps are UTC epoch seconds. This module has no network or mutation
side effects on import. Certificate issuance and deployment state are separate.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

DAY = 86400
PEM_CERT = re.compile(rb'-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----', re.S)


class RenewalError(RuntimeError):
    """A fixed, safe operational diagnostic; no credential data is included."""


def require(condition, message):
    if not condition:
        raise RenewalError(message)


def run_command(args, input_bytes=None, timeout=30, env=None, cwd=None, stage='command'):
    child_env = (os.environ if env is None else env).copy()
    child_env['LC_ALL'] = 'C'
    try:
        result = subprocess.run([str(x) for x in args], input=input_bytes, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, env=child_env, cwd=cwd)
    except subprocess.TimeoutExpired:
        raise RenewalError(stage + ': timeout') from None
    except OSError:
        raise RenewalError(stage + ': execution failed') from None
    if result.returncode:
        raise RenewalError(stage + ': nonzero exit')
    return result.stdout


def pem_certificates(data):
    require(isinstance(data, bytes) and len(data) <= 131072, 'certificate payload size/type invalid')
    require(b'PRIVATE KEY' not in data, 'certificate payload contains private-key material')
    result = [x + b'\n' for x in PEM_CERT.findall(data)]
    require(1 <= len(result) <= 8, 'certificate count invalid')
    return result


def certificate_info(pem_bytes):
    leaf = pem_certificates(pem_bytes)[0]
    public = run_command(['openssl', 'x509', '-pubkey', '-noout'], leaf, stage='read certificate public key')
    spki = run_command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public, stage='encode public key')
    der = run_command(['openssl', 'x509', '-outform', 'DER'], leaf, stage='encode certificate')
    text = run_command(['openssl', 'x509', '-noout', '-dates', '-ext', 'subjectAltName'],
                       leaf, stage='read certificate dates/names').decode('ascii', errors='strict')
    dates = dict(re.findall(r'^(notBefore|notAfter)=(.+)$', text, re.M))
    try:
        parse = lambda value: dt.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc).timestamp()
        before, after = parse(dates['notBefore']), parse(dates['notAfter'])
    except (KeyError, ValueError):
        raise RenewalError('certificate dates invalid') from None
    require(after > before, 'certificate lifetime invalid')
    sans = tuple(sorted(set(re.findall(r'DNS:([^,\s]+)', text))))
    other_names = bool(re.search(r'(?:IP Address|URI|email|othername|DirName|Registered ID):', text, re.I))
    return {'der': der, 'pem': leaf, 'sans': sans, 'non_dns_sans': other_names,
            'not_before': before, 'not_after': after, 'sha256': hashlib.sha256(der).hexdigest(),
            'spki_der': spki, 'spki_sha256': hashlib.sha256(spki).hexdigest()}


def csr_info(path):
    path = Path(path)
    raw = path.read_bytes()
    require(len(raw) < 32768 and b'PRIVATE KEY' not in raw, 'CSR input invalid')
    run_command(['openssl', 'req', '-in', path, '-verify', '-noout'], stage='verify CSR self-signature')
    text = run_command(['openssl', 'req', '-in', path, '-noout', '-text'], stage='read CSR names').decode('ascii', errors='strict')
    public = run_command(['openssl', 'req', '-in', path, '-pubkey', '-noout'], stage='read CSR public key')
    spki = run_command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public, stage='encode CSR key')
    return {'sans': tuple(sorted(set(re.findall(r'DNS:([^,\s]+)', text)))),
            'non_dns_sans': bool(re.search(r'(?:IP Address|URI|email|othername|DirName|Registered ID):', text, re.I)),
            'spki_sha256': hashlib.sha256(spki).hexdigest(), 'spki_der': spki}


def validate_bundle(fullchain_bytes, expected_sans, expected_spki_sha256, now=None, ca_file=None):
    now = time.time() if now is None else float(now)
    certificates = pem_certificates(fullchain_bytes)
    require(len(certificates) >= 2, 'public bundle must contain leaf and issuing chain')
    info = certificate_info(certificates[0])
    require(info['sans'] == tuple(sorted(set(expected_sans))) and not info['non_dns_sans'],
            'certificate SAN set differs from enrolled names')
    require(info['spki_sha256'] == expected_spki_sha256, 'certificate public key differs from enrolled key')
    require(info['not_before'] <= now, 'certificate is not valid yet')
    require(info['not_after'] > now, 'certificate has expired')
    # A cached replacement remains useful while at least one third of its life
    # remains. This also accepts the published 45/64-day profiles and short lives.
    lifetime = info['not_after'] - info['not_before']
    require(info['not_after'] - now >= min(14 * DAY, lifetime / 3),
            'certificate has insufficient remaining deployment lifetime')
    chain = b''.join(certificates[1:])
    with tempfile.TemporaryDirectory(prefix='grange-cert-verify-') as temporary:
        directory = Path(temporary)
        leaf_file, chain_file = directory / 'cert.pem', directory / 'chain.pem'
        leaf_file.write_bytes(info['pem'])
        chain_file.write_bytes(chain)
        args = ['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', info['sans'][0],
                '-attime', str(int(now))]
        if ca_file is not None:
            args += ['-CAfile', str(ca_file)]
        args += ['-untrusted', chain_file, leaf_file]
        run_command(args, stage='verify trusted certificate chain')
        # The server must present an ordered chain, not merely a bag from which
        # OpenSSL can find some path. Validate each immediate issuing link.
        for index in range(len(certificates) - 1):
            lower, upper = directory / 'lower.pem', directory / 'upper.pem'
            lower.write_bytes(certificates[index])
            upper.write_bytes(certificates[index + 1])
            run_command(['openssl', 'verify', '-partial_chain', '-no-CAfile', '-no-CApath',
                         '-trusted', upper, '-attime', str(int(now)), lower],
                        stage='verify ordered certificate chain')
    info['chain_pem'] = chain
    info['fullchain_pem'] = b''.join(certificates)
    return info


def replacement_is_newer(current, candidate):
    if candidate['sha256'] == current['sha256']:
        return False
    require(candidate['spki_sha256'] == current['spki_sha256'], 'replacement key changed')
    require(candidate['sans'] == current['sans'], 'replacement SANs changed')
    require(candidate['not_before'] > current['not_before'], 'replacement issuance date did not advance')
    # A 28-day renewal across the documented 90 -> 64 day transition can
    # legitimately advance expiry by only two days; do not require +7 days.
    require(candidate['not_after'] > current['not_after'], 'replacement expiry did not advance')
    return True


def renewal_due(not_before, not_after, last_success_at=None, now=None, interval_days=28):
    before, after = float(not_before), float(not_after)
    now = time.time() if now is None else float(now)
    require(all(math.isfinite(x) for x in (before, after, now)), 'non-finite certificate time')
    require(after > before and 1 <= interval_days <= 28, 'invalid renewal policy/lifetime')
    # notBefore is authoritative and cannot be shifted by late deployment or
    # reconstructed state. A bound issuance record can only bring it earlier.
    anchor = before
    if last_success_at is not None:
        value = float(last_success_at)
        require(math.isfinite(value), 'non-finite issuance time')
        if before - DAY <= value <= now:
            anchor = min(anchor, value)
    age_deadline = anchor + interval_days * DAY
    expiry_deadline = after - (after - before) / 3
    next_due = min(age_deadline, expiry_deadline)
    policy = 'maximum_interval' if age_deadline <= expiry_deadline else 'expiry_safeguard'
    return {'due': now >= next_due, 'next_due_at': next_due,
            'reason': policy if now >= next_due else 'not_due', 'policy_reason': policy,
            'age_seconds': now - before, 'remaining_seconds': after - now}


def retry_at(failures, remaining_seconds, now=None, retry_after=None):
    now = time.time() if now is None else float(now)
    count = max(1, min(int(failures), 10))
    cap = 3 * 3600 if remaining_seconds < 7 * DAY else 12 * 3600
    delay = min(cap, 3600 * (2 ** (count - 1)))
    return max(now + delay, float(retry_after or 0))


def public_status(info):
    return {key: info[key] for key in ('sans', 'not_before', 'not_after', 'sha256', 'spki_sha256')}


def atomic_write(path, contents, mode=0o600, uid=None, gid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            if uid is not None or gid is not None:
                os.fchown(handle.fileno(), -1 if uid is None else uid, -1 if gid is None else gid)
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_json(path, value, mode=0o600):
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode(), mode)


@contextlib.contextmanager
def operation_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('a') as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RenewalError('another renewal operation holds the lock') from None
        yield
