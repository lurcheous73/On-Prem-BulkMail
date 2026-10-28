import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
root = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


maintenance = load('maintenance', root / 'maintain-and-archive.py')
fixtures = load('archive_fixtures', root / 'tests/test_archive_safety.py')
archive = fixtures.archive
GUID = '00000000-0000-0000-0000-000000000001'


class FakeNative:
    def __init__(self, clock):
        self.clock, self.calls, self.pid, self.fail, self.ready = clock, 0, 123, False, True
        self.probed = []

    def heartbeat(self, timeout):
        self.calls += 1
        if self.fail:
            raise TimeoutError('private details must not escape')
        return {'service_pid': self.pid, 'subscribers': 1}

    def readiness(self, pid, folders):
        self.probed.append(folders)
        if not self.ready:
            self.clock[0] += 2
        return {'phase': 'folder_readiness', 'service_pid': pid, 'user_errors': 0, 'ready': self.ready,
                'folders': {name: {'loaded': self.ready, 'selected': self.ready, 'errors': 0,
                                  'cancelled': False, 'ready': self.ready} for name in folders}}


def controller():
    clock = [0.0]
    native = FakeNative(clock)
    value = maintenance.Controller(native, clock=lambda: clock[0])
    value.pulse()
    return value, native, clock


def ack(pid=123, published=True):
    rows = [{'phase': 'native_configuration_verified', 'service_pid': pid},
            {'phase': 'activity_requested', 'published': published, 'subscribers_notified': 1, 'tracking_ready': False}]
    return subprocess.CompletedProcess([], 0, ('\n'.join(json.dumps(row) for row in rows)).encode(), b'')


class MaintenanceSafety(unittest.TestCase):
    def test_acknowledgment_must_be_complete_and_positive(self):
        self.assertEqual(maintenance.acknowledged(ack()), {'service_pid': 123, 'subscribers': 1})
        for result in (ack(published=False), subprocess.CompletedProcess([], 1, b'', b'private'),
                       subprocess.CompletedProcess([], 0, b'not JSON', b'')):
            with self.assertRaises(maintenance.Stop):
                maintenance.acknowledged(result)

    def test_native_publication_timeout_is_one_attempt_with_no_leaked_detail(self):
        native = maintenance.NativeMaintenance(GUID, '/root/reviewed.py')
        with patch.object(maintenance.subprocess, 'run', side_effect=subprocess.TimeoutExpired('private', 12)) as run:
            with self.assertRaises(maintenance.Stop) as caught:
                native.heartbeat(12)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['timeout'], 12)
        self.assertNotIn('private', str(caught.exception))

    def test_uncertain_heartbeat_stops_and_cannot_retry(self):
        ctrl, native, _ = controller()
        native.fail = True
        with self.assertRaises(maintenance.Stop):
            ctrl.pulse()
        with self.assertRaises(maintenance.Stop):
            ctrl.pulse()
        with self.assertRaises(maintenance.Stop):
            ctrl.check(before_move=True)
        self.assertEqual(native.calls, 2)
        self.assertEqual(ctrl.admitted, 0)
        self.assertTrue(ctrl.stopped.is_set())

    def test_deadline_blocks_new_moves_and_activity(self):
        ctrl, native, clock = controller()
        clock[0] = 1800
        with self.assertRaises(maintenance.Stop):
            ctrl.check(before_move=True)
        with self.assertRaises(maintenance.Stop):
            ctrl.pulse()
        self.assertEqual(native.calls, 1)
        self.assertEqual(ctrl.admitted, 0)

    def test_stale_acknowledgment_cannot_admit_move(self):
        ctrl, _, clock = controller()
        clock[0] = 31
        with self.assertRaises(maintenance.Stop):
            ctrl.check(before_move=True)
        self.assertEqual(ctrl.admitted, 0)

    def test_service_restart_stops_admission(self):
        ctrl, native, _ = controller()
        native.pid = 124
        with self.assertRaises(maintenance.Stop):
            ctrl.pulse()
        with self.assertRaises(maintenance.Stop):
            ctrl.check(before_move=True)

    def test_operator_stop_is_safe_inside_state_lock(self):
        ctrl, _, _ = controller()
        with ctrl.lock:
            ctrl.stop('operator stop')
        with self.assertRaises(maintenance.Stop):
            ctrl.check()

    def test_worker_stops_on_first_uncertain_reply_without_another_attempt(self):
        class Native:
            calls = 0
            def heartbeat(self, timeout):
                self.calls += 1
                if self.calls == 3:
                    raise TimeoutError('fixture uncertainty')
                return {'service_pid': 123, 'subscribers': 1}
        native = Native()
        ctrl = maintenance.Controller(native, duration=10)
        with patch.object(maintenance, 'INTERVAL', 0.01), contextlib.redirect_stdout(io.StringIO()):
            ctrl.start()
            ctrl.thread.join(1)
            ctrl.close()
        self.assertEqual(native.calls, 3)
        self.assertFalse(ctrl.thread.is_alive())
        self.assertTrue(ctrl.stopped.is_set())

    def test_completion_stops_periodic_activity_immediately(self):
        native = FakeNative([0])
        ctrl = maintenance.Controller(native, duration=10)
        with contextlib.redirect_stdout(io.StringIO()):
            ctrl.start()
            ctrl.close()
        self.assertEqual(native.calls, 1)
        self.assertFalse(ctrl.thread.is_alive())

    def test_recovery_readiness_gate_is_bounded(self):
        ctrl, native, _ = controller()
        native.ready = False
        with self.assertRaisesRegex(maintenance.Stop, 'readiness'):
            ctrl.wait_ready([archive.ARCHIVE], seconds=2)
        self.assertEqual(ctrl.admitted, 0)

    def test_markers_are_scoped_to_process_epoch_owner_and_exact_folder(self):
        namespace = {'__name__': 'readiness_fixture'}
        exec(maintenance.READINESS_SCRIPT, namespace)
        parse = namespace['markers']
        started = datetime.datetime(2026, 10, 28, 19, 30).timestamp()
        def line(timestamp, folder, message, level='DEBUG'):
            return f'{timestamp} {level} [13] ASC.Mail.SImap_22_{folder} - {message}'
        folder = archive.ARCHIVE
        ready = [line('2026-10-28 19:34:52,001', folder, 'UpdateMessagesList: Load 0 messages from IMAP.'),
                 line('2026-10-28 19:34:52,002', folder, 'SetNewImapWorkFolder: Work folder changed to ' + folder + '.')]
        self.assertTrue(parse(ready, started, [folder], GUID)['ready'])
        self.assertFalse(parse(ready, started + 600, [folder], GUID)['ready'])
        self.assertFalse(parse(ready, started, ['Drafts'], GUID)['ready'])
        self.assertFalse(parse(ready + [line('2026-10-28 19:35:01,000', folder, 'TaskManager Cancellation Requested, folder ' + folder + '.')], started, [folder], GUID)['ready'])
        error = '2026-10-28 19:35:01,000 ERROR [13] ASC.Mail.User_' + GUID + ' - fixture database failure'
        self.assertFalse(parse(ready + [error], started, [folder], GUID)['ready'])

    def test_historical_expiry_does_not_poison_a_newly_loaded_client(self):
        namespace = {'__name__': 'readiness_fixture'}
        exec(maintenance.READINESS_SCRIPT, namespace)
        parse = namespace['markers']
        started = datetime.datetime(2026, 10, 28, 19, 30).timestamp()
        maintenance_started = datetime.datetime(2026, 10, 28, 19, 40).timestamp()
        lines = [
            '2026-10-28 19:34:00,000 ERROR [13] ASC.Mail.User_' + GUID + ' - historical error',
            '2026-10-28 19:35:00,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - TaskManager Cancellation Requested, folder Drafts.',
            '2026-10-28 19:40:01,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - UpdateMessagesList: Load 32 messages from IMAP.',
            '2026-10-28 19:40:01,001 DEBUG [13] ASC.Mail.SImap_22_Drafts - SetNewImapWorkFolder: Work folder changed to Drafts.']
        self.assertTrue(parse(lines, started, ['Drafts'], GUID, maintenance_started)['ready'])
        lines.append('2026-10-28 19:40:02,000 ERROR [13] ASC.Mail.User_' + GUID + ' - current failure')
        self.assertFalse(parse(lines, started, ['Drafts'], GUID, maintenance_started)['ready'])

    def test_old_ended_generation_waits_for_async_replacement_but_current_cancel_stops(self):
        namespace = {'__name__': 'readiness_fixture'}
        exec(maintenance.READINESS_SCRIPT, namespace)
        parse = namespace['markers']
        started = datetime.datetime(2026, 10, 28, 19, 30).timestamp()
        window = datetime.datetime(2026, 10, 28, 19, 40).timestamp()
        old = [
            '2026-10-28 19:34:00,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - UpdateMessagesList: Load 32 messages from IMAP.',
            '2026-10-28 19:34:00,001 DEBUG [13] ASC.Mail.SImap_22_Drafts - SetNewImapWorkFolder: Work folder changed to Drafts.',
            '2026-10-28 19:35:00,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - TaskManager Cancellation Requested, folder Drafts.']
        new = old + [
            '2026-10-28 19:40:01,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - UpdateMessagesList: Load 32 messages from IMAP.',
            '2026-10-28 19:40:01,001 DEBUG [13] ASC.Mail.SImap_22_Drafts - SetNewImapWorkFolder: Work folder changed to Drafts.']
        pending = parse(old, started, ['Drafts'], GUID, window)
        ready = parse(new, started, ['Drafts'], GUID, window)
        self.assertFalse(pending['ready'])
        self.assertFalse(pending['folders']['Drafts']['cancelled'])
        ctrl, native, _ = controller()
        with patch.object(native, 'readiness', side_effect=[pending, ready]) as probe, \
                patch.object(ctrl.stopped, 'wait', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()):
            ctrl.wait_ready(['Drafts'])
        self.assertEqual(probe.call_count, 2)
        failed = parse(new + ['2026-10-28 19:40:02,000 DEBUG [13] ASC.Mail.SImap_22_Drafts - TaskManager Cancellation Requested, folder Drafts.'], started, ['Drafts'], GUID, window)
        with patch.object(native, 'readiness', return_value=failed), self.assertRaises(maintenance.Stop):
            ctrl.wait_ready(['Drafts'])

    def execute_archive(self, mode, count=2, apply=True):
        ctrl, native, clock = controller()
        instances = []
        class Backend(fixtures.FakeBackend):
            def __init__(self, owner):
                super().__init__()
                instances.append(self)
                self.records[11] = {'id': 11, 'folder': 3, 'uid': 101, 'mid': 'other@example.test', 'date_sent': 1}
                self.records[21] = {'id': 21, 'folder': 2, 'uid': 201, 'mid': 'other@example.test', 'date_sent': 2}
            def fingerprint(self, folder, row):
                value = super().fingerprint(folder, row)
                # Two-pair preflight uses four calls, first pair's complete
                # double verification uses another four. Fail at its end.
                if mode == 'during_verification' and self.fp_calls == count * 2 + 4:
                    ctrl.stop('heartbeat failed during fresh verification')
                if mode == 'readiness_lost' and self.fp_calls == count * 2 + 4:
                    native.ready = False
                return value
            def move(self, proof):
                super().move(proof)
                if mode == 'during_move':
                    ctrl.stop('heartbeat failed during admitted move')
                elif mode == 'deadline_during_move':
                    clock[0] = 1810
            def locate(self, proof):
                value = super().locate(proof)
                if not self.moves:
                    value.update(source_present=True, archive_verified=False)
                return value
        pair2 = {**fixtures.PAIR, 'draft_id': 11, 'draft_uid': 101, 'sent_id': 21, 'sent_uid': 201,
                 'message_id_sha256': hashlib.sha256(b'other@example.test').hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            report, journal = pathlib.Path(directory, 'report.jsonl'), pathlib.Path(directory, 'journal.jsonl')
            report.write_text('\n'.join(json.dumps(value) for value in
                ([fixtures.PAIR, pair2][:count] + [{'phase': 'complete', 'mailbox_id': 22, 'read_only': True}])) + '\n')
            args = ['--report', str(report), '--expected-owner-guid', GUID, '--expected-count', str(count)]
            if apply:
                args += ['--apply', '--journal', str(journal)]
            error = None
            with patch.object(archive, 'Native', Backend), contextlib.redirect_stdout(io.StringIO()):
                try:
                    maintenance.run_archive(archive, args, ctrl if apply else None)
                except RuntimeError as exc:
                    error = exc
            rows = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
        return ctrl, native, instances[0], rows, error

    def test_failure_after_fresh_verification_cannot_admit_move(self):
        ctrl, _, backend, rows, error = self.execute_archive('during_verification')
        self.assertIsNotNone(error)
        self.assertEqual(backend.moves, 0)
        self.assertEqual(ctrl.admitted, 0)
        self.assertIn('prepared', [row['event'] for row in rows])
        self.assertNotIn('portal_converged', [row['event'] for row in rows])

    def test_failure_during_move_finishes_verification_then_blocks_next(self):
        ctrl, _, backend, rows, error = self.execute_archive('during_move')
        self.assertIsNotNone(error)
        self.assertEqual(backend.moves, 1)
        self.assertEqual(ctrl.completed, 1)
        self.assertEqual([row['event'] for row in rows], ['start', 'prepared', 'move_verified', 'portal_converged'])

    def test_last_readiness_probe_fails_without_waiting_or_moving(self):
        ctrl, native, backend, rows, error = self.execute_archive('readiness_lost')
        self.assertIsNotNone(error)
        self.assertEqual(backend.moves, 0)
        self.assertEqual(ctrl.admitted, 0)
        self.assertEqual(native.probed, [[archive.ARCHIVE], ['Drafts', 'Sent', archive.ARCHIVE],
                                        ['Drafts', 'Sent', archive.ARCHIVE]])
        self.assertEqual(rows[-1]['event'], 'move_error_no_retry')

    def test_deadline_during_move_finishes_unit_but_admits_no_next_move(self):
        ctrl, _, backend, rows, error = self.execute_archive('deadline_during_move')
        self.assertIsNotNone(error)
        self.assertEqual(backend.moves, 1)
        self.assertEqual(ctrl.completed, 1)
        self.assertEqual(ctrl.admitted, 1)
        self.assertEqual(rows[-1]['event'], 'portal_converged')

    def test_recovery_folder_load_is_checked_before_first_move(self):
        ctrl, native, backend, _, error = self.execute_archive('normal', count=1)
        self.assertIsNone(error)
        self.assertEqual(native.probed, [[archive.ARCHIVE], ['Drafts', 'Sent', archive.ARCHIVE],
                                        ['Drafts', 'Sent', archive.ARCHIVE]])
        self.assertEqual(backend.moves, 1)

    def test_dry_run_has_no_activity_folder_or_move_mutation(self):
        _, native, backend, rows, error = self.execute_archive('normal', count=1, apply=False)
        self.assertIsNone(error)
        self.assertEqual(native.calls, 1)  # Fixture setup only; run_archive made none.
        self.assertEqual(backend.folder_writes, 0)
        self.assertEqual(backend.moves, 0)
        self.assertEqual(rows, [])


if __name__ == '__main__':
    unittest.main()
