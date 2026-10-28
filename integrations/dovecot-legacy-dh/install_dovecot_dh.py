#!/usr/bin/env python3
"""Guarded CT400 Docker-host installation of the reviewed public DH correction.

Default mode validates and plans only. --apply stops/starts only Dovecot.
--rollback TRANSACTION restores a previously journaled complete file set.
No Python, compiler, new package, mail authentication, or client TLS weakening
is required inside the mail container. Native command output is kept private.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import time

CONTAINER = 'onlyoffice-mail-server'
IMAGE = 'onlyoffice/mailserver:1.6.75'
CANDIDATE_SHA = 'f8d823cb32adfc3f3ff11f52e0754c89b996dd01aae6896b9aa690f67bebee42'
BUILDER_SHA = 'cd073ab78ae877744373cba03b112cd8c8f0985b61c48a3364f0e0a998406f82'
SOURCES = {
    'main': {'path': '/etc/dovecot/dovecot.conf', 'sha256': '332a9e294ea1ed2e2d3ac1b1f43413ef819cd93fdfa1be066d7986631b8a02d9', 'mode': 0o644, 'uid': 0, 'gid': 0},
    'template': {'path': '/usr/src/iRedMail/samples/dovecot/dovecot2.conf', 'sha256': 'ee61c1bf479996b8c73b4fb82b2413166e84e7785d0342566fb2fcc322018d4b', 'mode': 0o664, 'uid': 0, 'gid': 0},
    'parameters': {'path': '/var/lib/dovecot/ssl-parameters.dat', 'sha256': '3748ae64860d81ec2c4806bc31a0a0a50019269a9c5a765ac9c0eb4edf364947', 'mode': 0o644, 'uid': 0, 'gid': 0},
}
APPEND = b'\n# Grange: retain the reviewed strong public DH parameters.\nssl_parameters_regenerate = 0\n'
PROCESS_NAMES = {'dovecot', 'imap-login', 'pop3-login', 'ssl-params', 'imap', 'pop3'}


class InstallError(Exception): pass


def require(ok, message):
    if not ok: raise InstallError(message)


def sha(data): return hashlib.sha256(data).hexdigest()


def atomic_private(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def save(directory, state):
    atomic_private(Path(directory) / 'transaction.json', json.dumps(state, sort_keys=True, indent=2).encode() + b'\n')


def load_builder():
    path = Path(__file__).with_name('dovecot_legacy_dh.py')
    require(sha(path.read_bytes()) == BUILDER_SHA, 'reviewed public-parameter builder hash differs')
    spec = importlib.util.spec_from_file_location('reviewed_legacy_dh', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def dh_proof(output):
    text = output.decode('utf-8', 'replace')
    require(re.search(r'(?m)^\s*CONNECTION ESTABLISHED\s*$', text) is not None,
            'native TLS proof did not establish a completed handshake')
    require(re.search(r'(?m)^\s*Verification:\s*OK\s*$', text) is not None,
            'native TLS proof did not establish certificate verification')
    groups = re.findall(r'(?m)^\s*(?:Server|Peer) Temp Key:\s*DH,\s*([0-9]+) bits\s*$', text)
    require(groups == ['3072'],
            'native TLS proof did not establish an actual 3072-bit DH group')


def process_inventory(output):
    try:
        lines = output.decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise InstallError('native process inventory is malformed') from None
    require(bool(lines), 'native process inventory is empty')
    rows, seen = [], set()
    for line in lines:
        parts = line.split()
        require(len(parts) == 3 and parts[0].isdigit(), 'native process inventory is malformed')
        pid, name, state = int(parts[0]), parts[1], parts[2]
        require(pid > 0 and pid not in seen and re.fullmatch(r'[!-~]+', name)
                and re.fullmatch(r'[RSDTtZXxWI][<NLsl+]*', state),
                'native process inventory is malformed')
        seen.add(pid)
        rows.append((pid, name, state))
    return rows


class Native:
    specs = SOURCES

    def __init__(self):
        self.stage = '/var/run/grange-dovecot-dh-' + secrets.token_hex(12)
        self.quiescence_until = 0.0

    def wait_quiescent(self):
        while True:
            remaining = self.quiescence_until - time.monotonic()
            if remaining <= 0: break
            time.sleep(min(1, remaining))
        self.quiescence_until = 0.0

    def command(self, args, data=None, timeout=20, allow_failure=False):
        try:
            result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise InstallError('bounded native command did not complete') from None
        require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024,
                'native command output exceeded its limit')
        if not allow_failure: require(result.returncode == 0, 'native command failed; private output withheld')
        return result

    def docker(self, args, data=None, timeout=15, allow_failure=False, mutating=False):
        self.wait_quiescent()
        # An early Docker transport failure is not proof that its remote shell
        # exited. Keep the inner hard timeout plus a conservative six-second
        # quiescence margin. Coreutils 8.4 has no --kill-after option.
        # outstanding until completion is acknowledged or that bound elapses.
        # Every later native command, including recovery, waits for it first.
        if mutating: self.quiescence_until = time.monotonic() + timeout + 6
        try:
            result = self.command(['docker', 'exec', '-i', CONTAINER, '/usr/bin/timeout', '--signal=KILL',
                                   str(timeout)] + args,
                                  data=data, timeout=timeout + 10, allow_failure=True)
        except BaseException:
            if mutating: self.wait_quiescent()
            raise
        if result.returncode == 0:
            self.quiescence_until = 0.0
        elif mutating:
            self.wait_quiescent()
        if not allow_failure: require(result.returncode == 0, 'native command failed after bounded quiescence; private output withheld')
        return result

    def identity(self):
        template = '{{json .Id}}\n{{json .Config.Image}}\n{{json .State.Running}}\n{{json .State.StartedAt}}'
        result = self.command(['docker', 'inspect', '--format', template, CONTAINER])
        parts = [json.loads(line) for line in result.stdout.splitlines()]
        require(len(parts) == 4 and parts[1] == IMAGE and parts[2] is True,
                'mail container is not the inspected running image')
        return {'id': parts[0], 'image': parts[1], 'started_at': parts[3]}

    def same(self, identity): require(self.identity() == identity, 'container restarted or changed during maintenance')

    def read(self, path):
        expected = next(({key: item[key] for key in ('mode', 'uid', 'gid')}
                         for item in self.specs.values() if item['path'] == path), None)
        require(expected is not None, 'native file path is outside enrollment')
        script = 'test -f "$1"\ntest ! -L "$1"\nstat -c "%a %u %g %s" "$1"'
        before = self.docker(['sh', '-eu', '-c', script, 'sh', path]).stdout.strip()
        raw = self.docker(['cat', path]).stdout
        after = self.docker(['sh', '-eu', '-c', script, 'sh', path]).stdout.strip()
        require(before == after, 'native file metadata changed during snapshot')
        parts = before.split(); require(len(parts) == 4, 'native file metadata is malformed')
        mode, uid, gid, size = int(parts[0], 8), int(parts[1]), int(parts[2]), int(parts[3])
        metadata = {'mode': mode, 'uid': uid, 'gid': gid}
        require(metadata == expected and size == len(raw), 'native file ownership/mode/size changed')
        return raw, metadata

    def validate_stage(self, patched_main):
        self.docker(['mkdir', '-m', '0700', self.stage], mutating=True)
        self.docker(['sh', '-eu', '-c', 'umask 077\ncat > "$1"', 'sh', self.stage + '/main.conf'], data=patched_main, mutating=True)
        self.docker(['doveconf', '-c', self.stage + '/main.conf', '-n'])
        require(self.docker(['doveconf', '-c', self.stage + '/main.conf', '-h', 'ssl_parameters_regenerate']).stdout.strip()
                in (b'0', b'0 secs', b'0 seconds'), 'staged native regeneration setting is not zero')

    def cleanup(self):
        self.docker(['rm', '-f', self.stage + '/main.conf'], allow_failure=True, mutating=True)
        self.docker(['rmdir', self.stage], allow_failure=True, mutating=True)

    def service(self, action): self.docker(['service', 'dovecot', action], timeout=35, mutating=action in ('stop', 'start'))

    def process_inventory(self):
        # Procps 3.2.8 silently drops fields after a comma when an empty header
        # is requested. The separate -o form was verified on this exact image.
        return process_inventory(self.docker(['ps', '-e', '-o', 'pid=', '-o', 'comm=', '-o', 'stat=']).stdout)

    def processes(self):
        # A zombie has already released its address space and descriptors, so
        # it cannot retain old DH parameters or rewrite the installed files.
        return [pid for pid, name, state in self.process_inventory()
                if name in PROCESS_NAMES and not state.startswith('Z')]

    def require_running_master(self):
        self.service('status')
        masters = [pid for pid, name, state in self.process_inventory()
                   if name == 'dovecot' and not state.startswith('Z')]
        require(len(masters) == 1, 'running Dovecot service lacks one discovered live master')
        return masters[0]

    def stop(self):
        if self.processes():
            self.docker(['service', 'dovecot', 'stop'], timeout=35, allow_failure=True, mutating=True)
        deadline = time.monotonic() + 20
        while self.processes():
            require(time.monotonic() < deadline, 'old Dovecot/login/ssl-params processes did not stop')
            time.sleep(0.5)

    def replace(self, path, data, metadata):
        script = ('target=$1\nmode=$2\nowner=$3\numask 077\n'
                  'temporary=$(mktemp "${target}.grange-dh.XXXXXX")\n'
                  'trap \'rm -f "$temporary"\' EXIT HUP INT TERM\n'
                  'cat > "$temporary"\nchmod "$mode" "$temporary"\nchown "$owner" "$temporary"\n'
                  'sync\nmv -f "$temporary" "$target"\nsync')
        self.docker(['sh', '-eu', '-c', script, 'sh', path, format(metadata['mode'], 'o'),
                     str(metadata['uid']) + ':' + str(metadata['gid'])], data=data, timeout=20, mutating=True)
        require(self.read(path) == (data, metadata), 'installed native file did not match staged bytes/metadata')

    def verify(self, expected_certificate):
        require(self.docker(['doveconf', '-h', 'ssl_parameters_regenerate']).stdout.strip()
                in (b'0', b'0 secs', b'0 seconds'), 'effective native regeneration is not zero')
        self.require_running_master()
        results = []
        for port in (993, 995):
            context = ssl.create_default_context()
            with socket.create_connection(('192.168.1.5', port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname='work.the-grange.uk') as secured:
                    require(sha(secured.getpeercert(binary_form=True)) == expected_certificate,
                            'trusted native endpoint presents an unexpected certificate')
                    protocol = secured.version()
            proof = self.command(['openssl', 's_client', '-connect', '192.168.1.5:' + str(port),
                '-servername', 'work.the-grange.uk', '-verify_hostname', 'work.the-grange.uk',
                '-verify_return_error', '-CApath', '/etc/ssl/certs', '-tls1_2', '-brief',
                '-cipher', 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256'],
                data=b'', timeout=10, allow_failure=True)
            # -brief puts OpenSSL's diagnostic proof on stderr. Application
            # data on stdout cannot masquerade as a cryptographic diagnostic.
            dh_proof(proof.stderr)
            results.append({'port': port, 'trusted': True, 'certificate_sha256': expected_certificate,
                            'dh_bits': 3072, 'protocol': protocol})
        return results

    def verify_previous_service(self):
        # The original DH group is known to fail modern trusted TLS. Prove
        # restoration/service availability without weakening any TLS client.
        self.require_running_master()
        for port in (993, 995):
            with socket.create_connection(('192.168.1.5', port), timeout=5): pass


def prepare(native, candidate):
    require(sha(candidate) == CANDIDATE_SHA, 'reviewed public candidate hash differs')
    builder = load_builder()
    require(all(x['bits'] == 3072 for x in builder.parse_native(candidate)), 'candidate groups are not strong')
    builder.validate_strong_der(builder.parse_native(candidate)[0]['der'])
    identity = native.identity()
    version = native.docker(['dovecot', '--version']).stdout.decode('ascii', 'replace').strip()
    require(version == '2.1.17' or version.startswith('2.1.17 '), 'native Dovecot version differs')
    native.require_running_master()
    records = []
    for name, spec in native.specs.items():
        raw, metadata = native.read(spec['path'])
        require(sha(raw) == spec['sha256'], 'native source file hash differs from inspected baseline')
        updated = candidate if name == 'parameters' else raw + APPEND
        records.append({'name': name, 'path': spec['path'], 'old': raw, 'new': updated, **metadata})
    native.validate_stage(next(item['new'] for item in records if item['name'] == 'main'))
    native.same(identity)
    return identity, records


def recover(native, directory, state):
    require(state.get('schema') == 1 and len(state['files']) == len(native.specs)
            and set(item['name'] for item in state['files']) == set(native.specs),
            'recovery journal has an unexpected schema/file set')
    native.same(state['container'])
    ready = []
    # Validate every backup and current target before stopping or changing any
    # consumer file. Do not overwrite an unrelated concurrent configuration.
    for item in state['files']:
        require(item['path'] == native.specs[item['name']]['path'], 'recovery target is outside enrollment')
        require(item['old_sha256'] == native.specs[item['name']]['sha256'], 'recovery original fingerprint differs')
        backup = Path(directory) / (item['name'] + '.original')
        require(backup.is_file() and not backup.is_symlink(), 'recovery backup is not a regular file')
        raw = backup.read_bytes()
        require(sha(raw) == item['old_sha256'], 'recovery backup bytes changed')
        current, metadata = native.read(item['path'])
        require(sha(current) in (item['old_sha256'], item['new_sha256']), 'native file changed outside transaction')
        require(metadata == {key: item[key] for key in ('mode', 'uid', 'gid')}, 'native ownership/mode changed outside transaction')
        ready.append((item, raw))
    native.stop(); native.same(state['container'])
    for item, raw in ready:
        current, metadata = native.read(item['path'])
        require(sha(current) in (item['old_sha256'], item['new_sha256'])
                and metadata == {key: item[key] for key in ('mode', 'uid', 'gid')},
                'native file changed before rollback replacement')
        native.replace(item['path'], raw, {key: item[key] for key in ('mode', 'uid', 'gid')})
    native.service('start')
    native.verify_previous_service()
    for item, raw in ready: require(native.read(item['path'])[0] == raw, 'restored native file changed after service start')
    state['phase'] = 'restored_previous_weak_dh'; save(directory, state)


def install(native, directory, identity, records, expected_certificate):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    state = {'schema': 1, 'container': identity, 'phase': 'prepared',
             'expected_certificate_sha256': expected_certificate, 'files': []}
    for record in records:
        atomic_private(directory / (record['name'] + '.original'), record['old'])
        atomic_private(directory / (record['name'] + '.candidate'), record['new'])
        item = {key: record[key] for key in ('name', 'path', 'mode', 'uid', 'gid')}
        item.update(old_sha256=sha(record['old']), new_sha256=sha(record['new']))
        state['files'].append(item)
    save(directory, state)
    try:
        native.same(identity)
        for record in records:
            require(native.read(record['path']) == (record['old'], {key: record[key] for key in ('mode', 'uid', 'gid')}),
                    'native source changed after staging')
        state['phase'] = 'stopping'; save(directory, state)
        native.stop(); native.same(identity)
        for record in records:
            require(native.read(record['path']) == (record['old'], {key: record[key] for key in ('mode', 'uid', 'gid')}),
                    'native file bytes or metadata changed before atomic replacement')
            native.replace(record['path'], record['new'], {key: record[key] for key in ('mode', 'uid', 'gid')})
        state['phase'] = 'installed'; save(directory, state)
        native.service('start')
        deadline = time.monotonic() + 45
        while True:
            try:
                result = native.verify(expected_certificate); break
            except (OSError, InstallError):
                require(time.monotonic() < deadline, 'trusted native DH3072 verification failed')
                time.sleep(1)
        native.same(identity)
        for record in records:
            require(native.read(record['path']) == (record['new'], {key: record[key] for key in ('mode', 'uid', 'gid')}),
                    'native file changed after activation')
        state['phase'] = 'verified'; state['endpoints'] = result; save(directory, state)
        return state
    except BaseException:
        state['failed_phase'] = state['phase']
        state['phase'] = 'rollback_required'; save(directory, state)
        try: recover(native, directory, state)
        except BaseException:
            state['phase'] = 'rollback_failed'; save(directory, state)
            raise InstallError('installation failed; guarded rollback incomplete; private journal retained') from None
        raise InstallError('installation failed; previous files/service restored with their known weak-DH limitation') from None


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), 'private directory is missing or invalid')
    metadata = path.stat()
    require(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o700,
            'transaction directory must be root-owned 0700')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--rollback', metavar='TRANSACTION')
    parser.add_argument('--candidate')
    parser.add_argument('--expected-certificate-sha256')
    parser.add_argument('--backup-root', default='/var/backups/grange-dovecot-dh')
    args = parser.parse_args()
    native = Native()
    try:
        require(os.geteuid() == 0, 'run on the CT400 Docker host as root')
        # Shares the original mail certificate-copy lock, preventing its
        # independent container restart during this scoped service operation.
        with open('/run/lock/onlyoffice-mail-cert.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.rollback:
                directory = private_directory(args.rollback)
                state = json.loads((directory / 'transaction.json').read_bytes())
                # A new controller cannot inherit the previous process's
                # monotonic deadline after SIGTERM/SIGKILL. Cover the longest
                # possible surviving mutating command plus its conservative
                # margin before manual recovery.
                native.quiescence_until = time.monotonic() + 41
                native.wait_quiescent()
                recover(native, directory, state)
                result = {'event': 'restored_previous_weak_dh', 'transaction': str(directory)}
            else:
                require(args.candidate and re.fullmatch(r'[0-9a-f]{64}', args.expected_certificate_sha256 or ''),
                        'candidate and expected certificate fingerprint are required')
                identity, records = prepare(native, Path(args.candidate).read_bytes())
                result = {'event': 'validated_plan', 'candidate_sha256': CANDIDATE_SHA,
                          'files': {item['name']: {'old_sha256': sha(item['old']), 'new_sha256': sha(item['new'])} for item in records}}
                if args.apply:
                    root = Path(args.backup_root)
                    root.mkdir(mode=0o700, exist_ok=True)
                    private_directory(root)
                    directory = root / ('transaction-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(6))
                    state = install(native, directory, identity, records, args.expected_certificate_sha256)
                    result = {'event': 'verified_dh3072', 'transaction': str(directory), 'endpoints': state['endpoints']}
        print(json.dumps(result, sort_keys=True)); return 0
    except InstallError as error:
        print(json.dumps({'event': 'failed', 'reason': str(error)})); return 1
    except (Exception, KeyboardInterrupt):
        print(json.dumps({'event': 'failed', 'reason': 'guarded operation failed; review private transaction state'})); return 1
    finally:
        try: native.cleanup()
        except Exception: pass


if __name__ == '__main__': raise SystemExit(main())
