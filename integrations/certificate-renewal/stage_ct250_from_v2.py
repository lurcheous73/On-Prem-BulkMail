#!/usr/bin/env python3
"""Stage the reviewed CT250 public-certificate consumer; do not apply a cert."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace

MANIFEST = 'c440a9b78a2a6729d6c0f36a050f906d0b481759fc4a720c73f3bb4598261896'
OLD_UNIT = '76c7f8366bd8a54be2e4a08f698c240dd5efef708b0447aa7e5f14d914d17f9c'
NETLINK_UNIT = 'fc4098e640c7798ce658df5d3da59788bce1c9fbae05b5d9ef77de8c35edba5c'
NEW_UNIT = '61f3176f4f8a0eea495aa16d93abc2f8925444f02fce4aea936725369d59e4ae'
SERVICE = 'grange-mtasts-certificate-consumer.service'
TIMER = 'grange-mtasts-certificate-consumer.timer'
CODE = Path('/opt/grange-certificate-renewal')
CONFIG = Path('/etc/grange-certificate-renewal/consumer-mtasts.json')
UNITS = Path('/etc/systemd/system')
SOURCES = {
    'renewal_common.py': CODE / 'renewal_common.py',
    'mx_consumer.py': CODE / 'mx_consumer.py',
    'pem_consumer.py': CODE / 'pem_consumer.py',
    'config/consumer-germany-ct250-mtasts.json': CONFIG,
    'systemd/' + SERVICE: UNITS / SERVICE,
    'systemd/' + TIMER: UNITS / TIMER,
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    require(path.is_file() and not path.is_symlink(), 'expected regular reviewed file')
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022 and info.st_size < 2 * 1024 * 1024,
            'reviewed file ownership/size invalid')
    return path.read_bytes(), info


def run(args, timeout=20):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'bounded staging/preflight command failed')
    return result.stdout


def atomic(path, data, info):
    fd, name = tempfile.mkstemp(prefix='.mtasts-stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(data)
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


def reviewed_service_unit(data):
    require(sha(data) == OLD_UNIT, 'unexpected packaged CT250 unit')
    old = b'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
    require(data.count(old) == 1, 'expected exact address-family directive')
    data = data.replace(old, b'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n')
    require(sha(data) == NETLINK_UNIT, 'netlink-only CT250 unit delta differs')
    user = b'User=root\n'
    require(data.count(user) == 1, 'expected exact root service directive')
    data = data.replace(user, user + b'ExecStartPre=/usr/bin/mkdir -p /tmp/nginx\n')
    require(sha(data) == NEW_UNIT, 'private temporary directory CT250 unit delta differs')
    return data


def prepare(package):
    manifest_bytes = read_file(package / 'REVIEWED-MANIFEST.json')[0]
    require(sha(manifest_bytes) == MANIFEST, 'package is not the exact reviewed v2 manifest')
    manifest = json.loads(manifest_bytes)
    desired = {}
    for source, destination in SOURCES.items():
        data = read_file(package / source)[0]
        require(sha(data) == manifest['files'][source], 'package artifact differs from frozen manifest')
        if source == 'systemd/' + SERVICE:
            data = reviewed_service_unit(data)
        desired[destination] = data
    return desired


def stage(package, apply=False):
    addresses = json.loads(run(['ip', '-j', 'address', 'show']))
    require('10.50.0.250' in {row.get('local') for interface in addresses for row in interface.get('addr_info', [])},
            'this is not the inspected CT250 container')
    for unit in (SERVICE, TIMER):
        result = subprocess.run(['systemctl', 'show', unit, '--property=LoadState,ActiveState,MainPID'],
                                capture_output=True, timeout=20)
        fields = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        require(result.returncode == 0 or fields.get('LoadState') == 'not-found', 'could not inspect staging unit state')
        require(fields.get('ActiveState') in ('inactive', 'failed') and fields.get('MainPID', '0') == '0',
                'existing MTA-STS consumer is active; fresh staging refused')
    desired = prepare(package)
    original = {}
    for path, data in desired.items():
        if path.exists() or path.is_symlink():
            previous, info = read_file(path)
            require(previous == data or (path == UNITS / SERVICE and sha(previous) in (OLD_UNIT, NETLINK_UNIT)),
                    'existing target differs from reviewed staging bytes')
            original[path] = (previous, info)
        else:
            original[path] = None
    print(json.dumps({'event': 'ct250_staging_validated', 'will_apply': apply,
                      'certificate_key_and_nginx_routes_unchanged': True}), flush=True)
    if not apply:
        return
    for path, mode in ((CODE, 0o755), (CONFIG.parent, 0o755),
                       (Path('/var/lib/grange-certificate-renewal/mtasts'), 0o700),
                       (Path('/var/backups/grange-mtasts-tls-automatic'), 0o700)):
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        require(path.stat().st_uid == 0 and not path.stat().st_mode & 0o022, 'staging directory ownership unsafe')
    backup_root = Path('/var/backups/grange-certificate-code')
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix='ct250-v2-stage-', dir=backup_root))
    metadata = {}
    for index, (path, previous) in enumerate(original.items()):
        if previous is not None:
            data, info = previous
            saved = backup / (str(index) + '.backup')
            atomic(saved, data, SimpleNamespace(st_mode=0o600, st_uid=0, st_gid=0))
            metadata[str(path)] = {'file': saved.name, 'sha256': sha(data), 'mode': stat.S_IMODE(info.st_mode),
                                   'uid': info.st_uid, 'gid': info.st_gid}
    atomic(backup / 'manifest.json', (json.dumps(metadata, indent=2) + '\n').encode(),
           SimpleNamespace(st_mode=0o600, st_uid=0, st_gid=0))
    changed = []
    try:
        for path, data in desired.items():
            previous = original[path]
            if previous is None:
                require(not path.exists() and not path.is_symlink(), 'new staging target appeared concurrently')
                info = SimpleNamespace(st_mode=0o644, st_uid=0, st_gid=0)
            else:
                old, info = previous
                require(read_file(path)[0] == old, 'existing staging target changed concurrently')
            changed.append(path)
            atomic(path, data, info)
        run(['systemd-analyze', 'verify', '--man=no', str(UNITS / SERVICE), str(UNITS / TIMER)])
        run(['systemctl', 'daemon-reload'])
        output = run(['/usr/bin/python3', '-B', str(CODE / 'pem_consumer.py'), '--config', str(CONFIG)], timeout=120)
        events = [json.loads(line).get('event') for line in output.splitlines() if line.startswith(b'{')]
        require(any(event in ('validated_deployment_pending', 'current_certificate_verified') for event in events),
                'CT250 read-only certificate preflight did not complete')
        print(json.dumps({'event': 'ct250_staged_readonly_preflight_passed', 'backup': str(backup),
                          'certificate_applied': False, 'timer_enabled': False}), flush=True)
    except BaseException:
        for path in reversed(changed):
            previous = original[path]
            if not path.exists() and not path.is_symlink():
                require(previous is None, 'existing staging target disappeared; rollback halted')
                continue
            current = read_file(path)[0]
            if previous is not None and current == previous[0]:
                continue
            require(current == desired[path], 'outside staging writer detected; rollback halted')
            if previous is None:
                path.unlink()
            else:
                atomic(path, previous[0], previous[1])
        run(['systemctl', 'daemon-reload'])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'stage locally on CT250 as root')
    os.umask(0o077)
    def interrupt(signum, frame):
        raise RuntimeError('staging interrupted; reviewed file rollback will run')
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    stage(Path(args.package).resolve(), args.apply)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({'event': 'ct250_staging_failed', 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
