# CT280 interrupted-issuance retry correction

This changes only `/opt/grange-certificate-renewal/issuer.py` on CT280. An
interrupted attempt can leave `phase=issuing` before its failure counter is
incremented. The hourly retry now also admits `issuing` and `retry_pending`
phases. Completed-output recovery, the existing retry deadline and the normal
certificate due window still run before any new order. No new certificate is
ordered by this deployment procedure.

| File | SHA256 |
| --- | --- |
| Existing live issuer | `a6e5a709370ab8cbc66bdb664e56165fb71f299fbdb6028b8d8c5c1a0f18279f` |
| Reviewed replacement issuer | `ce21e755f68c131d0a82ef9417f41ff85a87b1d46bc1ba3fd042d5f56bfab87f` |
| Unchanged shared runtime | `2d1519619ee2e94a8a8dea054b28772fe4ea95e3acf63ce71864122bd725d392` |

`tests/test_issuer_interrupted_retry.py` has seven passing actual-flow cases:
both interrupted phases, completed-output recovery without another order,
existing backoff, the normal due window, completed-state exclusion and a
read-only invocation. The change and these fixtures were independently
reviewed. The immutable v2 release archive still contains the earlier issuer;
this is an explicit, separately pinned deployment delta.

## Guarded one-file deployment

Transfer the reviewed replacement as
`/root/renewal28-issuer-retry/issuer.py` on CT280 and verify its replacement hash.
Record the active/enabled states of `grange-certificate-issuer.timer` and
`grange-certificate-issuer-retry.timer`, then pause only those two timers.
Do not interrupt an issuing service: wait for both corresponding services to
be inactive, with `MainPID=0`. Keep the publisher and all consumers running.

The following command holds the existing issuer lock, refuses unexpected
source bytes or ownership, creates a private backup, atomically replaces one
file with its existing owner/mode, and exercises the real read-only plan under
that same lock. It calls the imported functions instead of `main()` to avoid
trying to acquire the lock a second time. It does not load the Cloudflare token
or invoke Certbot. A failed plan restores only its own reviewed replacement;
an outside writer is preserved and requires inspection before timers resume.

```sh
flock -n /var/lib/grange-certificate-renewal/issuer/issuer.lock \
  python3 -B - /root/renewal28-issuer-retry/issuer.py <<'PY'
import hashlib, json, os, signal, stat, subprocess, sys, tempfile
from pathlib import Path

old_sha = 'a6e5a709370ab8cbc66bdb664e56165fb71f299fbdb6028b8d8c5c1a0f18279f'
new_sha = 'ce21e755f68c131d0a82ef9417f41ff85a87b1d46bc1ba3fd042d5f56bfab87f'
common_sha = '2d1519619ee2e94a8a8dea054b28772fe4ea95e3acf63ce71864122bd725d392'
target = Path('/opt/grange-certificate-renewal/issuer.py')
os.umask(0o077)
def require(condition, message):
    if not condition:
        raise RuntimeError(message)
def sha(data):
    return hashlib.sha256(data).hexdigest()
def ownership(info):
    return (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
def read(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022 and info.st_size < 2 * 1024 * 1024,
            'reviewed source must be a bounded root-owned regular file')
    return path.read_bytes(), info
def idle():
    for unit in ('grange-certificate-issuer.service', 'grange-certificate-issuer-retry.service'):
        result = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState,MainPID'],
                                capture_output=True, timeout=15)
        fields = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        require(result.returncode == 0 and fields.get('ActiveState') in ('inactive', 'failed') and
                fields.get('MainPID') == '0', 'issuer service is not idle')
def atomic(data, info):
    fd, name = tempfile.mkstemp(prefix='.issuer-retry-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, target)
        directory = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)
def interrupt(signum, frame):
    raise RuntimeError('issuer source update interrupted')
require(os.geteuid() == 0, 'run this local deployment as root on CT280')
signal.signal(signal.SIGTERM, interrupt)
signal.signal(signal.SIGINT, interrupt)
replacement, _ = read(Path(sys.argv[1]))
original, info = read(target)
require(sha(replacement) == new_sha and sha(original) == old_sha, 'issuer source hash differs')
require(sha(read(target.parent / 'renewal_common.py')[0]) == common_sha, 'shared runtime hash differs')
compile(replacement, str(target), 'exec')
idle()
backup_root = Path('/var/backups/grange-certificate-code')
backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
require(backup_root.stat().st_uid == 0 and not backup_root.stat().st_mode & 0o022,
        'code backup directory ownership is unsafe')
backup = Path(tempfile.mkdtemp(prefix='issuer-retry-v3-', dir=backup_root))
with (backup / 'issuer.py').open('xb') as saved:
    saved.write(original); saved.flush(); os.fsync(saved.fileno())
with (backup / 'metadata.json').open('x') as saved:
    json.dump({'sha256': old_sha, 'mode': ownership(info)[0], 'uid': info.st_uid, 'gid': info.st_gid}, saved)
    saved.write('\n'); saved.flush(); os.fsync(saved.fileno())
for path in (backup, backup_root):
    directory = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
current, current_info = read(target)
require(current == original and ownership(current_info) == ownership(info), 'issuer changed during backup')
idle()
try:
    atomic(replacement, info)
    current, current_info = read(target)
    require(current == replacement and ownership(current_info) == ownership(info), 'installed source differs')
    plan = '''import runpy,sys
sys.path.insert(0, '/opt/grange-certificate-renewal')
m = runpy.run_path('/opt/grange-certificate-renewal/issuer.py')
c = m['checked_config']('/etc/grange-certificate-renewal/issuer.json')
for h in c['hosts']:
    m['process_host'](c, h, apply=False)
'''
    result = subprocess.run(['/usr/bin/python3', '-B', '-c', plan], capture_output=True, timeout=120)
    require(result.returncode == 0, 'new issuer read-only plan failed')
    current, current_info = read(target)
    require(current == replacement and ownership(current_info) == ownership(info), 'issuer changed during plan')
except BaseException:
    current, current_info = read(target)
    require(current in (original, replacement) and ownership(current_info) == ownership(info),
            'outside issuer writer detected; leave timers paused')
    if current == replacement:
        atomic(original, info)
    raise
print(json.dumps({'event': 'issuer_retry_source_updated', 'sha256': new_sha,
                  'backup': str(backup), 'acme_order_requested': False}))
PY
```

After a successful plan, restore the recorded runtime states of the two
timers, leaving their enablement unchanged. Verify the source hash and timer
states. No systemd daemon reload or service restart is needed for this source
update. If the command fails before replacement, the old source is intact;
if it reports an outside writer, retain the paused state until that difference
has been reviewed. The command deliberately refuses a repeat application
against an already updated issuer rather than treating unknown history as an
implicit success.
