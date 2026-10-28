#!/usr/bin/env python3
"""Guarded one-time adapter/config/netlink-unit update; never controls Xeams."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import time

CODE = Path('/opt/grange-certificate-renewal')
CONFIG = Path('/etc/grange-certificate-renewal/consumer.json')
CLASS = CODE / 'java/GrangeRenewalKeystore.class'
UNIT = Path('/etc/systemd/system/grange-mx-certificate-consumer.service')
SERVICE = 'grange-mx-certificate-consumer.service'
STATE = Path('/var/lib/grange-certificate-renewal/mx')
BACKUPS = Path('/var/backups/grange-certificate-code')
OLD_CLASS = 'b2c66b20f5177eed1544d448ea0acdaa54e59696291e7d5c149af7199f771625'
NEW_CLASS = '5cac7bd6866c87fd8621bc911cbb21150692822a4fe3ae82b7d9474ed4a0e010'
OLD_UNIT = '4c9e2d1dd71d75b0aa9886704441fb4ae068e0da3e91a48700cf31c11bcbebd9'
NEW_UNIT = '6ff737612c38423bc95d3be6a442c017bd3a8f6b8941f67a877af414d6fc903a'
SOURCE_PINS = {
    'issuer.py': 'a6e5a709370ab8cbc66bdb664e56165fb71f299fbdb6028b8d8c5c1a0f18279f',
    'mx_consumer.py': 'c6bfb779ba7405604a44c4ed85aaf1d7c8d09908a26caf42de1f9fcfee4e9c36',
    'public_server.py': '3ac64ee2e94783c1a15f38c6bb41e71ec6b093d42a25f711871a40187d4b1888',
    'renewal_common.py': '2d1519619ee2e94a8a8dea054b28772fe4ea95e3acf63ce71864122bd725d392',
}
CONFIG_PINS = {
    'mx1.brimstonecottage.uk': ('286932315d0c4d70d7b027c707c3a8d413bd56306adf9bc26c3f87c6c2c35619', '4a62219c840ca3e38865d8bf0edcc4f781c4d8ed2a954dfd1b8b8ca2826a4e09'),
    'mx1.the-grange.uk': ('9fc8e3f6cd59f554638375f1838f0394d7c17ef20e444be77317ba6b74d0f07f', '658f5a8594a27e2d89794aa2561f49d4c3f61f6e00eb07d593ab6b67e6de802f'),
    'mx2.brimstonecottage.uk': ('23fa52a37d6d81643e9e4c6bee756fb44cedc2e6c7f9faaf8ae8f6387af2724f', '3c83423c43dde69d76f25d0ae09beeaab00ab2e6071aea5408ad840549f708b8'),
    'mx2.the-grange.uk': ('cb965ee847ec7862634fa77272424f50b2ea3f95fe7e2e40f74a23f92cd6657c', 'f9c81017a79ffab4d516026f29849faa9d6d3786cb61c26b1c294cf0494c72bc'),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_guarded(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'expected a regular reviewed file')
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'reviewed code/config must be root-owned and not publicly writable')
    require(info.st_size < 2 * 1024 * 1024, 'reviewed file size invalid')
    return path.read_bytes(), info


def run(args, timeout=20):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, 'bounded deployment command failed')
    return result.stdout


def atomic(path, data, info):
    fd, temporary = tempfile.mkstemp(prefix='.reviewed-update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def idle_service():
    fields = dict(line.split('=', 1) for line in run(['systemctl', 'show', SERVICE,
                  '--property=ActiveState,MainPID']).decode().splitlines() if '=' in line)
    require(fields.get('ActiveState') in ('inactive', 'failed') and fields.get('MainPID') == '0',
            'renewal consumer is running; no update was made')


def timer_state(timer):
    value = run(['systemctl', 'show', timer, '--property=ActiveState', '--value']).decode().strip()
    require(value in ('active', 'inactive', 'failed'), 'renewal timer state is not stable')
    return value == 'active'


def core_sources(package):
    for name, expected in SOURCE_PINS.items():
        require(sha(read_guarded(package / name)[0]) == expected, 'package core source pin differs')
        live = CODE / name
        if name in ('mx_consumer.py', 'renewal_common.py') or live.exists():
            require(sha(read_guarded(live)[0]) == expected, 'installed core source pin differs')


def candidate(package, host):
    core_sources(package)
    class_bytes = read_guarded(package / 'java/GrangeRenewalKeystore.class')[0]
    config_bytes = read_guarded(package / ('config/consumer-' + host + '.json'))[0]
    require(sha(class_bytes) == NEW_CLASS and sha(config_bytes) == CONFIG_PINS[host][1], 'reviewed adapter/config bytes differ')
    unit_bytes = read_guarded(package / 'systemd/grange-mx-certificate-consumer.service')[0]
    require(sha(unit_bytes) in (OLD_UNIT, NEW_UNIT), 'reviewed consumer unit pin differs')
    if sha(unit_bytes) == OLD_UNIT:
        old = b'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
        require(unit_bytes.count(old) == 1, 'expected exact address-family directive')
        unit_bytes = unit_bytes.replace(old, b'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n')
    require(sha(unit_bytes) == NEW_UNIT, 'netlink-only unit delta differs')
    return {CLASS: class_bytes, CONFIG: config_bytes, UNIT: unit_bytes}


def readonly_preflight():
    # The parent holds the same consumer flock throughout the update. Invoke
    # the identical verified checked_config/process path with apply=False,
    # avoiding a second nonblocking attempt at our already-held lock.
    program = ("import sys; sys.path.insert(0, '/opt/grange-certificate-renewal'); "
               "import mx_consumer as m; "
               "c=m.checked_config('/etc/grange-certificate-renewal/consumer.json'); m.process(c, False)")
    output = run(['/usr/bin/python3', '-B', '-c', program], timeout=150)
    events = []
    for line in output.splitlines():
        try:
            event = json.loads(line).get('event')
        except (ValueError, AttributeError):
            continue
        if event in ('current_certificate_verified', 'validated_deployment_pending'):
            events.append(event)
    require(bool(events), 'read-only consumer preflight did not verify its expected result')
    return events


def originals_match(original):
    try:
        for path, (data, info) in original.items():
            actual, actual_info = read_guarded(path)
            if actual != data or any(getattr(info, field) != getattr(actual_info, field)
                    for field in ('st_uid', 'st_gid', 'st_mode')):
                return False
        return True
    except (OSError, RuntimeError):
        return False


def guarded_update(package, host, apply=False):
    desired = candidate(package, host)
    original = {path: read_guarded(path) for path in desired}
    old_config, new_config = CONFIG_PINS[host]
    pair = (sha(original[CLASS][0]), sha(original[CONFIG][0]))
    require(pair in ((OLD_CLASS, old_config), (NEW_CLASS, new_config)), 'installed adapter/config is not an exact reviewed version pair')
    require(sha(original[UNIT][0]) in (OLD_UNIT, NEW_UNIT), 'installed consumer unit has an unreviewed change')
    timer = 'grange-mx-certificate-' + ('primary' if host.startswith('mx1.') else 'secondary') + '.timer'
    was_active = timer_state(timer)
    idle_service()
    print(json.dumps({'event': 'adapter_update_preflight', 'hostname': host, 'will_apply': apply,
                      'timer_was_active': was_active, 'xeams_service_actions': False}), flush=True)
    if not apply:
        return
    paused, success, restored, replacement_started, backup = False, False, False, False, None
    try:
        if was_active:
            paused = True
            run(['systemctl', 'stop', timer])
        idle_service()
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (STATE / 'consumer.lock').open('a') as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            idle_service()
            core_sources(package)
            for path, (data, info) in original.items():
                actual, actual_info = read_guarded(path)
                require(actual == data and all(getattr(info, field) == getattr(actual_info, field)
                        for field in ('st_uid', 'st_gid', 'st_mode')), 'installed update input changed concurrently')
            BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
            backup = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-', time.gmtime()) + host + '-', dir=BACKUPS))
            metadata = {}
            for index, (path, (data, info)) in enumerate(original.items()):
                stored = backup / (str(index) + '.backup')
                with stored.open('wb') as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                metadata[str(path)] = {'backup': stored.name, 'sha256': sha(data),
                                       'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            with (backup / 'manifest.json').open('w') as handle:
                handle.write(json.dumps({'hostname': host, 'files': metadata}, indent=2) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            try:
                require(originals_match(original), 'captured update files changed while backups were written')
                core_sources(package)
                replacement_started = True
                for path, data in desired.items():
                    atomic(path, data, original[path][1])
                run(['systemctl', 'daemon-reload'])
                idle_service()
                families = set(run(['systemctl', 'show', SERVICE, '--property=RestrictAddressFamilies', '--value']).decode().split())
                require(families == {'AF_INET', 'AF_INET6', 'AF_UNIX', 'AF_NETLINK'}, 'effective consumer socket-family policy differs')
                core_sources(package)
                events = readonly_preflight()
                for path, data in desired.items():
                    require(read_guarded(path)[0] == data, 'updated artifact changed during verification')
                success = True
                print(json.dumps({'event': 'adapter_update_verified', 'hostname': host, 'backup': str(backup),
                                  'read_only_preflight_events': events, 'xeams_restarted': False}), flush=True)
            except BaseException:
                if replacement_started:
                    idle_service()
                    for path, (data, info) in original.items():
                        require(read_guarded(path)[0] in (data, desired[path]), 'outside code writer detected; rollback halted')
                    for path, (data, info) in original.items():
                        atomic(path, data, info)
                    run(['systemctl', 'daemon-reload'])
                    restored = True
                    print(json.dumps({'event': 'adapter_update_rolled_back', 'hostname': host, 'backup': str(backup),
                                      'xeams_restarted': False}), flush=True)
                raise
    finally:
        # A failed precondition before any replacement also permits restoring
        # the prior timer runtime state. Do not resume after an unsafe rollback.
        if paused and (success or restored or (not replacement_started and originals_match(original))):
            run(['systemctl', 'start', timer])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--hostname', choices=sorted(CONFIG_PINS), required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run the local code updater as root')
    os.umask(0o077)
    def interrupt(signum, frame):
        raise RuntimeError('code update interrupted; guarded rollback will run if replacement started')
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    guarded_update(Path(args.package).resolve(), args.hostname, args.apply)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({'event': 'adapter_update_failed', 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
