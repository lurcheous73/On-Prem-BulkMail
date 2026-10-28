"""Offline transaction failure tests. No service/network calls or live paths."""
from __future__ import annotations
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mx_consumer as mx
from renewal_common import RenewalError


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mx-transaction-test-')
        self.root = Path(self.temporary.name)
        self.files = {name: self.root / (name + '.live') for name in ('pfx', 'chain', 'dates')}
        self.original = {'pfx': b'original-encrypted-store', 'chain': b'original-public-chain',
                         'dates': b'challengeType=xeams\nexpDate=10\nnotAfter=10\nnotBefore=1\nregDate=2\nrenewalAfter=3\nhostName=unchanged\n'}
        for name, path in self.files.items():
            path.write_bytes(self.original[name])
            path.chmod(0o600 if name == 'pfx' else 0o644)
        self.key, self.csr, self.appconfig = [self.root / name for name in ('key', 'csr', 'config')]
        for path in (self.key, self.csr, self.appconfig):
            path.write_bytes(b'fixture-only')
        self.state, self.backups = self.root / 'state', self.root / 'backups'
        self.state.mkdir()
        self.backups.mkdir()
        self.host = 'mx2.brimstonecottage.uk'
        self.config = {'hostname': self.host, 'state_dir': str(self.state), 'backup_dir': str(self.backups)}
        now = time.time()
        self.current = {'sans': (self.host,), 'not_before': now - 28 * 86400,
                        'not_after': now + 62 * 86400, 'sha256': 'old-leaf', 'spki_sha256': 'unchanged-key'}
        self.candidate = {**self.current, 'not_before': now - 3600, 'not_after': now + 64 * 86400,
                          'sha256': 'new-leaf', 'fullchain_pem': b'new-public-fullchain'}
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        (self.stage / 'replacement.pfx').write_bytes(b'new-encrypted-store')
        self.stack = contextlib.ExitStack()
        for name, value in [('FILES', self.files), ('KEY', self.key), ('CSR', self.csr),
                            ('CONFIG', self.appconfig), ('PENDING', self.root / 'pending.new')]:
            self.stack.enter_context(patch.object(mx, name, value))
        self.stack.enter_context(patch.object(mx, 'tls_settings', return_value='stable-tls-settings-hash'))
        self.window = self.stack.enter_context(patch.object(mx, 'in_install_window', return_value=True))
        self.pair = self.stack.enter_context(patch.object(mx, 'pair_healthy'))
        self.stop = self.stack.enter_context(patch.object(mx, 'stop_service'))
        self.start = self.stack.enter_context(patch.object(mx, 'start_service'))
        self.peers = self.stack.enter_context(patch.object(mx, 'verify_peers'))
        self.stack.enter_context(patch.object(mx, 'emit'))
        self.before = mx.preflight_guard()

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def install(self):
        mx.install(self.config, self.current, self.candidate, self.stage, self.before)

    def assert_original(self):
        self.assertEqual({name: path.read_bytes() for name, path in self.files.items()}, self.original)
        self.assertEqual({name: mx.snapshot(path) for name, path in self.files.items()}, self.before['files'])
        self.assertEqual(self.key.read_bytes(), b'fixture-only')
        self.assertEqual(self.csr.read_bytes(), b'fixture-only')

    def test_success_preserves_original_owner_modes_and_key(self):
        self.install()
        self.assertEqual(self.files['pfx'].read_bytes(), b'new-encrypted-store')
        self.assertEqual(self.files['chain'].read_bytes(), b'new-public-fullchain')
        self.assertIn(b'hostName=unchanged\n', self.files['dates'].read_bytes())
        for name, path in self.files.items():
            actual = mx.snapshot(path)
            self.assertEqual({k: actual[k] for k in ('mode', 'uid', 'gid')},
                             {k: self.before['files'][name][k] for k in ('mode', 'uid', 'gid')})
        self.stop.assert_called_once()
        self.start.assert_called_once()
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'committed')

    def test_nonroot_xeams_owner_is_passed_to_each_atomic_replacement(self):
        # The test container maps only uid 0. Model the inventoried Xeams
        # 999:991 metadata and observe exact ownership arguments, while actual
        # fixture writes retain the test process's mapped uid/gid.
        actual_snapshot, actual_write = mx.snapshot, mx.atomic_write
        ownership_calls = []
        def xeams_snapshot(path):
            result = actual_snapshot(path)
            if Path(path) in self.files.values():
                result.update(uid=999, gid=991)
            return result
        def capture_write(path, raw, mode=0o600, uid=None, gid=None):
            if Path(path) in self.files.values():
                ownership_calls.append((Path(path), uid, gid))
                return actual_write(path, raw, mode, os.geteuid(), os.getegid())
            return actual_write(path, raw, mode, uid, gid)
        with patch.object(mx, 'snapshot', side_effect=xeams_snapshot), patch.object(mx, 'atomic_write', side_effect=capture_write):
            self.before = mx.preflight_guard()
            self.install()
        self.assertEqual(len(ownership_calls), 3)
        self.assertTrue(all(uid == 999 and gid == 991 for path, uid, gid in ownership_calls))

    def test_new_live_tls_failure_restores_originals_and_restarts(self):
        self.peers.side_effect = [None, RenewalError('synthetic new TLS failure'), None]
        with self.assertRaises(RenewalError):
            self.install()
        self.assert_original()
        self.assertEqual(self.stop.call_count, 2)
        self.assertEqual(self.start.call_count, 2)
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'rolled_back')

    def test_pair_failure_never_stops_or_writes(self):
        self.pair.side_effect = RenewalError('synthetic paired MX failure')
        with self.assertRaises(RenewalError):
            self.install()
        self.stop.assert_not_called()
        self.start.assert_not_called()
        self.assert_original()

    def test_outside_schedule_never_stops(self):
        self.window.return_value = False
        with self.assertRaises(RenewalError):
            self.install()
        self.stop.assert_not_called()
        self.assert_original()

    def test_native_pending_store_blocks_before_shutdown(self):
        mx.PENDING.write_bytes(b'pending-native-store')
        with self.assertRaises(RenewalError):
            self.install()
        self.stop.assert_not_called()
        self.assert_original()

    def test_preflight_file_change_blocks_before_shutdown(self):
        self.files['chain'].write_bytes(b'concurrent-native-chain')
        with self.assertRaises(RenewalError):
            self.install()
        self.stop.assert_not_called()
        self.assertEqual(self.files['chain'].read_bytes(), b'concurrent-native-chain')

    def test_shutdown_race_restarts_without_overwriting_native_write(self):
        self.stop.side_effect = lambda: self.files['pfx'].write_bytes(b'native-write-during-stop')
        with self.assertRaises(RenewalError):
            self.install()
        self.start.assert_called_once()
        self.assertEqual(self.files['pfx'].read_bytes(), b'native-write-during-stop')
        self.assertEqual(self.files['chain'].read_bytes(), self.original['chain'])
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'aborted_before_replace')

    def test_interrupt_after_first_replace_rolls_back(self):
        actual_write, raised = mx.atomic_write, [False]
        def interrupt_once(path, *args, **kwargs):
            if Path(path) == self.files['chain'] and not raised[0]:
                raised[0] = True
                raise KeyboardInterrupt()
            return actual_write(path, *args, **kwargs)
        with patch.object(mx, 'atomic_write', side_effect=interrupt_once), self.assertRaises(RenewalError):
            self.install()
        self.assert_original()
        self.assertEqual(self.stop.call_count, 2)

    def manifest(self):
        backup = self.backups / 'retained'
        backup.mkdir()
        for name in self.files:
            (backup / (name + '.backup')).write_bytes(self.original[name])
        manifest = {'schema': 1, 'hostname': self.host, 'phase': 'stopped', 'backup': str(backup),
                    'original': self.before, 'old_certificate': self.current, 'new_certificate': self.candidate.copy(),
                    'replacement_hashes': {name: hashlib.sha256(b'new-' + name.encode()).hexdigest() for name in self.files}}
        manifest['new_certificate'].pop('fullchain_pem')
        return backup, manifest

    def test_corrupt_later_backup_does_not_stop_or_restore(self):
        backup, manifest = self.manifest()
        (backup / 'dates.backup').write_bytes(b'corrupt-last-file')
        with self.assertRaises(RenewalError):
            mx.rollback(self.config, backup, manifest)
        self.stop.assert_not_called()
        self.start.assert_not_called()
        self.assert_original()

    def test_rollback_shutdown_race_does_not_overwrite_other_writer(self):
        backup, manifest = self.manifest()
        self.stop.side_effect = lambda: self.files['dates'].write_bytes(b'concurrent-date-update')
        with self.assertRaises(RenewalError):
            mx.rollback(self.config, backup, manifest)
        self.start.assert_called_once()
        self.assertEqual(self.files['dates'].read_bytes(), b'concurrent-date-update')
        self.assertEqual(self.files['pfx'].read_bytes(), self.original['pfx'])

    def test_interrupted_originals_restart_immediately_outside_window(self):
        backup, manifest = self.manifest()
        (self.state / 'transaction.json').write_text(json.dumps(manifest))
        self.window.return_value = False
        mx.recover_transaction(self.config, True)
        self.start.assert_called_once()
        self.stop.assert_not_called()
        self.pair.assert_not_called()
        self.assert_original()

    def test_recovery_rejects_backup_outside_scope(self):
        backup, manifest = self.manifest()
        manifest['backup'] = str(self.root / 'outside-backup-scope')
        (self.state / 'transaction.json').write_text(json.dumps(manifest))
        with self.assertRaises(RenewalError):
            mx.recover_transaction(self.config, True)
        self.stop.assert_not_called()
        self.start.assert_not_called()


class Schedules(unittest.TestCase):
    def test_primary_and_secondary_windows_never_overlap(self):
        for minute in range(60):
            stamp = 3600 * 24 + minute * 60
            primary = mx.in_install_window('mx1.the-grange.uk', stamp)
            secondary = mx.in_install_window('mx2.the-grange.uk', stamp)
            self.assertFalse(primary and secondary)

    def test_native_dates_preserve_all_nondates(self):
        before = b'# original\nchallengeType=dns\nexpDate=1\nnotAfter=1\nnotBefore=1\nregDate=1\nrenewalAfter=1\nhostName=keep\n'
        candidate = {'not_before': 1000000, 'not_after': 1000000 + 45 * 86400}
        result = mx.native_dates(before, candidate, 1000000)
        self.assertIn(b'challengeType=dns\n', result)
        self.assertIn(b'hostName=keep\n', result)
        # Shorter lifetimes still leave one-third of the certificate in reserve.
        self.assertIn(('renewalAfter=' + str((1000000 + 30 * 86400) * 1000)).encode(), result)


if __name__ == '__main__':
    unittest.main()
