#!/usr/bin/env python3
"""Bounded activity maintenance with cooperative archive admission checks.

Run on the Derby host beside the reviewed archive helper. Default mode is the
archive's read-only preflight. --apply maintains normal IMAP activity every 20s.
At 1800s no further move or activity request is admitted. An already admitted
journal/MOVE/verification unit finishes normally; it is never killed midway.
"""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import signal
import subprocess
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
ARCHIVE_SHA = '99106de97abcfe76ca32da28550e086dfe1e275bb913bbca220c14797c105c34'
COMPARE_SHA = 'a1e69227a5de293be87c992f02d325999db40be74dafeb06e5422af3f1825589'
ACTIVITY_SHA = 'b31f457644a7be4878927b6410ab128a85bf96812abafd7ff8968e410fc072da'
COMMUNITY = ['pct', 'exec', '400', '--', 'docker', 'exec', 'onlyoffice-community-server']
NATIVE_LOG = '/var/log/onlyoffice/mail/mail-imapsync.log'
INTERVAL, REQUEST_TIMEOUT, MAX_ACK_AGE, LIMIT = 20, 12, 30, 1800

ACTIVITY_EXEC = r'''
import hashlib,json,os,pathlib,sys
p=pathlib.Path(sys.argv[1])
if hashlib.sha256(p.read_bytes()).hexdigest()!=sys.argv[2]:
 print(json.dumps({'phase':'stopped','reason':'Activity helper hash mismatch'}));raise SystemExit(1)
os.execv(sys.executable,[sys.executable,'-B',str(p),'--user-guid',sys.argv[3],'--publish'])
'''

READINESS_SCRIPT = r'''
import datetime,json,os,pathlib,re,subprocess,sys,time

def markers(lines,started,folders,owner,error_since=None):
 error_since=max(started,started if error_since is None else error_since)
 result={name:{'loaded':False,'selected':False,'errors':0,'cancelled':False} for name in folders}
 times={name:{'load':None,'select':None,'cancel':None} for name in folders}
 user_errors=0
 pattern=re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+)\s+(\w+)\s+\[[^]]*\]\s+(.*?) - (.*)$')
 for line in lines:
  match=pattern.match(line)
  if not match:continue
  when=datetime.datetime.strptime(match[1],'%Y-%m-%d %H:%M:%S,%f').timestamp()
  if when<started:continue
  level,category,message=match.group(2,3,4)
  if category=='ASC.Mail.User_'+owner and level in ('WARN','ERROR','FATAL') and when>=error_since:user_errors+=1
  for folder,state in result.items():
   if category!='ASC.Mail.SImap_22_'+folder.replace('/','_'):continue
   if level in ('WARN','ERROR','FATAL') and when>=error_since:state['errors']+=1
   if re.fullmatch(r'UpdateMessagesList: Load [0-9]+ messages from IMAP\.\s*',message):times[folder]['load']=max(when,times[folder]['load'] or when)
   if message.strip()=='SetNewImapWorkFolder: Work folder changed to '+folder+'.':times[folder]['select']=max(when,times[folder]['select'] or when)
   if any(word in message.casefold() for word in ('cancellation requested','disconect','disconnect','try reconnect')):
    times[folder]['cancel']=max(when,times[folder]['cancel'] or when)
 for folder,state in result.items():
  last=times[folder]
  state['loaded']=last['load'] is not None
  state['selected']=last['select'] is not None and state['loaded'] and last['select']>=last['load']
  ended=last['cancel'] is not None and (not state['loaded'] or last['cancel']>=last['load'])
  # A pre-maintenance ended generation is pending, so the caller may wait for
  # its asynchronous replacement. Any cancellation during this window is fatal.
  state['cancelled']=last['cancel'] is not None and last['cancel']>=error_since
  state['ready']=state['loaded'] and state['selected'] and not ended and not state['errors'] and not state['cancelled']
 return {'folders':result,'user_errors':user_errors,'ready':not user_errors and all(s['ready'] for s in result.values())}

def main():
 owner,expected_pid,logpath,folder_json,error_since=sys.argv[1:]
 expected_pid=int(expected_pid);folders=json.loads(folder_json)
 p=subprocess.run(['systemctl','show','onlyofficeMailImap.service','--property=MainPID','--value'],capture_output=True,timeout=4)
 if p.returncode or int(p.stdout)!=expected_pid:raise RuntimeError('PID changed')
 proc=pathlib.Path('/proc')/str(expected_pid)
 for item in (proc/'environ').read_bytes().split(b'\0'):
  if item.startswith(b'TZ='):
   os.environ['TZ']=item[3:].decode();time.tzset()
 stat=(proc/'stat').read_text().rsplit(')',1)[1].split()
 boot=int(re.search(r'^btime ([0-9]+)$',pathlib.Path('/proc/stat').read_text(),re.M)[1])
 started=boot+int(stat[19])/os.sysconf('SC_CLK_TCK')
 path=pathlib.Path(logpath);size=path.stat().st_size
 with path.open('rb') as stream:
  offset=max(0,size-2*1024*1024);stream.seek(offset)
  if offset:stream.readline()
  lines=stream.read().decode('utf-8',errors='replace').splitlines()
 result=markers(lines,started,folders,owner,float(error_since))
 result.update(phase='folder_readiness',service_pid=expected_pid)
 print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
 try:main()
 except Exception as exc:
  print(json.dumps({'phase':'readiness_failed','error_type':type(exc).__name__}));raise SystemExit(1)
'''


class Stop(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Stop(reason)


def emit(phase, **values):
    print(json.dumps({'phase': phase, **values}, sort_keys=True), flush=True)


def acknowledged(result):
    require(result.returncode == 0 and len(result.stdout) <= 65536,
            'Activity request failed or timed out; no retry is permitted')
    try:
        rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.strip()]
    except (UnicodeError, ValueError):
        raise Stop('Activity acknowledgment was not valid JSON; no retry is permitted') from None
    metadata = [row for row in rows if row.get('phase') == 'native_configuration_verified']
    acks = [row for row in rows if row.get('phase') == 'activity_requested']
    require(len(rows) == 2 and len(metadata) == 1 and len(acks) == 1,
            'Activity acknowledgment was incomplete; no retry is permitted')
    ack, info = acks[0], metadata[0]
    require(ack.get('published') is True and type(ack.get('subscribers_notified')) is int
            and ack['subscribers_notified'] >= 1 and ack.get('tracking_ready') is False,
            'Activity publication was not acknowledged; no retry is permitted')
    require(type(info.get('service_pid')) is int and info['service_pid'] > 0,
            'Acknowledged activity has no verified service PID')
    return {'service_pid': info['service_pid'], 'subscribers': ack['subscribers_notified']}


class NativeMaintenance:
    def __init__(self, user, activity_path):
        self.user, self.activity_path = user, activity_path
        self.error_since = time.time()

    def heartbeat(self, timeout):
        try:
            result = subprocess.run(COMMUNITY + ['python3', '-B', '-c', ACTIVITY_EXEC,
                self.activity_path, ACTIVITY_SHA, self.user], stdin=subprocess.DEVNULL,
                capture_output=True, timeout=timeout)
        except Exception:
            raise Stop('Activity publication outcome is uncertain; no retry is permitted') from None
        return acknowledged(result)

    def readiness(self, pid, folders):
        try:
            result = subprocess.run(COMMUNITY + ['python3', '-B', '-c', READINESS_SCRIPT,
                self.user, str(pid), NATIVE_LOG, json.dumps(folders), str(self.error_since)], stdin=subprocess.DEVNULL,
                capture_output=True, timeout=REQUEST_TIMEOUT)
            require(result.returncode == 0 and len(result.stdout) <= 65536, 'Readiness inspection failed')
            value = json.loads(result.stdout)
            require(value.get('phase') == 'folder_readiness' and value.get('service_pid') == pid,
                    'Readiness inspection has the wrong service identity')
            require(set(value.get('folders', {})) == set(folders), 'Readiness inspection omitted a requested folder')
            return value
        except Stop:
            raise
        except Exception:
            raise Stop('Readiness inspection could not be verified') from None


class Controller:
    def __init__(self, native, duration=LIMIT, clock=time.monotonic):
        require(0 < duration <= LIMIT, 'Maintenance duration must be within the 1800-second limit')
        self.native, self.clock, self.started = native, clock, clock()
        self.deadline = self.started + duration
        self.lock, self.stopped = threading.RLock(), threading.Event()
        self.reason, self.pid, self.last_ack, self.acks = None, None, None, 0
        self.admitted, self.completed, self.critical = 0, 0, False
        self.thread = None

    def stop(self, reason):
        with self.lock:
            if self.reason is None:
                self.reason = reason
            self.stopped.set()

    def pulse(self):
        with self.lock:
            if self.reason:
                raise Stop(self.reason)
            remaining = self.deadline - self.clock()
        try:
            require(remaining > 0, 'Maintenance admission deadline reached')
            ack = self.native.heartbeat(min(REQUEST_TIMEOUT, remaining))
            with self.lock:
                require(self.pid is None or self.pid == ack['service_pid'], 'ImapSync restarted during maintenance')
                self.pid, self.last_ack = ack['service_pid'], self.clock()
                self.acks += 1
                expired = self.last_ack >= self.deadline
            if expired:
                raise Stop('Maintenance admission deadline reached')
        except Exception as exc:
            reason = str(exc) if isinstance(exc, Stop) else 'Activity publication outcome is uncertain; no retry is permitted'
            self.stop(reason)
            raise Stop(reason) from None

    def start(self):
        self.pulse()
        def loop():
            while not self.stopped.is_set():
                with self.lock:
                    wait = min(INTERVAL, max(0, self.deadline - self.clock()))
                if self.stopped.wait(wait):
                    return
                try:
                    self.pulse()
                except Stop:
                    return
        self.thread = threading.Thread(target=loop, name='bounded-imap-activity', daemon=True)
        self.thread.start()
        emit('maintenance_started', service_pid=self.pid, activity_interval_seconds=INTERVAL,
             activity_timeout_seconds=REQUEST_TIMEOUT, admission_limit_seconds=self.deadline - self.started)

    def check(self, before_move=False):
        with self.lock:
            now = self.clock()
            require(not self.reason, self.reason or 'Maintenance stopped')
            require(now < self.deadline, 'Maintenance admission deadline reached')
            require(self.last_ack is not None and now - self.last_ack <= MAX_ACK_AGE,
                    'No sufficiently recent acknowledged activity; stop before another move')
            if before_move:
                self.admitted += 1
                self.critical = True

    def finish_unit(self, completed=False):
        with self.lock:
            self.critical = False
            if completed:
                self.completed += 1

    def wait_ready(self, folders, seconds=120):
        until = min(self.deadline, self.clock() + seconds)
        while True:
            self.check()
            report = self.native.readiness(self.pid, folders)
            require(not report['user_errors'] and not any(
                row['errors'] or row['cancelled'] for row in report['folders'].values()),
                'Scoped ImapSync errors/cancellation prevent archive admission')
            if report['ready']:
                emit('folders_ready', folders=folders, service_pid=self.pid)
                return
            require(self.clock() < until, 'Folder readiness did not complete within its bounded wait')
            self.stopped.wait(min(2, max(0, until - self.clock())))

    def ready_now(self, folders):
        self.check()
        report = self.native.readiness(self.pid, folders)
        require(report['ready'] and not report['user_errors'] and all(
            row['ready'] and not row['errors'] and not row['cancelled'] for row in report['folders'].values()),
            'Fresh folder readiness is required immediately before MOVE')
        self.check()

    def close(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(REQUEST_TIMEOUT + 2)
            require(not self.thread.is_alive(), 'The bounded activity request did not terminate as expected')
        elapsed = self.clock() - self.started
        emit('maintenance_finished', acknowledged_requests=self.acks, admitted_moves=self.admitted,
             completed_units=self.completed, elapsed_seconds=round(elapsed, 3),
             completion_tail_seconds=round(max(0, self.clock() - self.deadline), 3),
             stop_reason=self.reason, further_activity=False)


def run_archive(module, arguments, controller=None):
    """Use the original archive implementation, adding only cooperative gates."""
    original_native, original_apply, original_argv = module.Native, module.apply_one, sys.argv
    if controller:
        class GuardedNative(original_native):
            def assert_owner(self):
                controller.check()
                return super().assert_owner()
            def assert_service(self):
                controller.check()
                return super().assert_service()
            def ensure_archive(self):
                controller.check()
                result = super().ensure_archive()
                controller.wait_ready([module.ARCHIVE])
                return result
            def move(self, proof):
                # The original apply_one has just completed fresh verification
                # and fsynced its prepared journal. This is the final admission.
                controller.ready_now(['Drafts', 'Sent', module.ARCHIVE])
                controller.check(before_move=True)
                return super().move(proof)
        def guarded_apply(*args, **kwargs):
            controller.check()
            controller.wait_ready(['Drafts', 'Sent', module.ARCHIVE])
            completed = False
            try:
                result = original_apply(*args, **kwargs)
                completed = True
                return result
            finally:
                controller.finish_unit(completed)
        module.Native, module.apply_one = GuardedNative, guarded_apply
    try:
        sys.argv = [str(module.__file__), *arguments]
        module.main()
    finally:
        module.Native, module.apply_one, sys.argv = original_native, original_apply, original_argv


def load_archive(path):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == ARCHIVE_SHA, 'Archive helper hash differs from the reviewed v3 helper')
    require(hashlib.sha256(path.with_name('compare-sent-drafts.py').read_bytes()).hexdigest() == COMPARE_SHA,
            'Archive comparison dependency hash differs from review')
    spec = importlib.util.spec_from_file_location('maintained_archive', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--expected-owner-guid', required=True)
    parser.add_argument('--expected-count', type=int, required=True)
    parser.add_argument('--journal')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--max-seconds', type=int, default=LIMIT)
    parser.add_argument('--archive-helper', type=pathlib.Path, default=pathlib.Path(__file__).with_name('archive-sent-drafts.py'))
    parser.add_argument('--activity-helper', default='/root/request-imap-activity-v3.py')
    args = parser.parse_args()
    user = str(uuid.UUID(args.expected_owner_guid))
    require(0 < args.max_seconds <= LIMIT, 'Maintenance duration exceeds the reviewed bound')
    module = load_archive(args.archive_helper)
    require(len(module.read_pairs(args.report)) == args.expected_count, 'Candidate count differs from the reviewed report')
    arguments = ['--report', args.report, '--expected-owner-guid', user, '--expected-count', str(args.expected_count)]
    if not args.apply:
        run_archive(module, arguments)
        return
    require(bool(args.journal), 'An explicit private archive journal is required')
    # Validate ownership/service before requesting any maintenance activity.
    backend = module.Native(user)
    backend.assert_service()
    arguments += ['--apply', '--journal', args.journal]
    controller = Controller(NativeMaintenance(user, args.activity_helper), args.max_seconds)
    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, lambda signum, frame: controller.stop('Operator requested a cooperative stop'))
    try:
        controller.start()
        controller.wait_ready(['Drafts', 'Sent'])
        run_archive(module, arguments, controller)
    except Exception as exc:
        controller.stop(str(exc) if isinstance(exc, Stop) else 'Archive stopped; inspect its private journal')
        raise
    finally:
        controller.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        emit('maintenance_stopped', error_type=type(exc).__name__,
             reason=str(exc) if isinstance(exc, (Stop, RuntimeError)) else 'Private archive operation failed; inspect its journal',
             automatic_retry=False)
        raise SystemExit(1)
