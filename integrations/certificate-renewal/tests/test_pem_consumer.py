"""Offline CT250 fullchain-only deployment and recovery regressions."""
import contextlib
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pem_consumer as pem
from renewal_common import RenewalError


class PemTransactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mtasts-consumer-test-')
        self.root = Path(self.temporary.name)
        self.cert, self.key, self.vhost = [self.root / name for name in ('cert.pem', 'key.pem', 'http.conf')]
        self.cert.write_bytes(b'old-public-certificate')
        self.cert.chmod(0o644)
        self.key.write_bytes(b'fixture-private-key-never-copied')
        self.key.chmod(0o600)
        self.vhost.write_bytes(b'existing-proxy-routes')
        self.state, self.backups = self.root / 'state', self.root / 'backups'
        self.state.mkdir()
        self.backups.mkdir()
        self.config = {'state_dir': str(self.state), 'backup_dir': str(self.backups)}
        self.stack = contextlib.ExitStack()
        for name, value in [('CERTIFICATE', self.cert), ('PRIVATE_KEY', self.key), ('VHOST_CONFIG', self.vhost)]:
            self.stack.enter_context(patch.object(pem, name, value))
        self.check = self.stack.enter_context(patch.object(pem, 'nginx_check'))
        self.reload = self.stack.enter_context(patch.object(pem, 'nginx_reload'))
        self.verify = self.stack.enter_context(patch.object(pem, 'verify_loaded'))
        self.stack.enter_context(patch.object(pem, 'emit'))
        now = time.time()
        self.old = {'sans': ('mta-sts.the-grange.uk', 'mx2.the-grange.uk'), 'spki_sha256': 'original-key',
                    'sha256': 'old-leaf', 'not_before': now - 60 * 86400, 'not_after': now + 30 * 86400}
        self.new = {**self.old, 'sha256': 'new-leaf', 'not_before': now - 3600,
                    'not_after': now + 90 * 86400, 'fullchain_pem': b'new-public-certificate'}
        self.expected = pem.guard()

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def install(self):
        pem.install(self.config, self.old, self.new, self.expected)

    def assert_unmoved_key_and_routes(self):
        self.assertEqual(self.key.read_bytes(), b'fixture-private-key-never-copied')
        self.assertEqual(self.vhost.read_bytes(), b'existing-proxy-routes')
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        for path in self.backups.rglob('*'):
            if path.is_file():
                self.assertNotIn(b'fixture-private-key-never-copied', path.read_bytes())

    def test_success_changes_only_public_chain_and_reloads(self):
        self.install()
        self.assertEqual(self.cert.read_bytes(), b'new-public-certificate')
        self.reload.assert_called_once()
        self.assertEqual(self.cert.stat().st_mode & 0o777, 0o644)
        self.assert_unmoved_key_and_routes()
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'committed')

    def test_failed_tls_policy_verification_rolls_back_public_chain(self):
        self.verify.side_effect = [None, RenewalError('synthetic policy failure'), None]
        with self.assertRaises(RenewalError):
            self.install()
        self.assertEqual(self.cert.read_bytes(), b'old-public-certificate')
        self.assertEqual(self.reload.call_count, 2)
        self.assert_unmoved_key_and_routes()
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'rolled_back')

    def test_failed_reload_restores_old_chain_before_retry_reload(self):
        self.reload.side_effect = [RenewalError('synthetic reload failure'), None]
        with self.assertRaises(RenewalError):
            self.install()
        self.assertEqual(self.cert.read_bytes(), b'old-public-certificate')
        self.assertEqual(self.reload.call_count, 2)
        self.assert_unmoved_key_and_routes()

    def test_concurrent_key_change_blocks_before_certificate_write(self):
        self.key.write_bytes(b'another-writer-key')
        with self.assertRaises(RenewalError):
            self.install()
        self.assertEqual(self.cert.read_bytes(), b'old-public-certificate')
        self.reload.assert_not_called()

    def test_other_certificate_writer_is_not_overwritten_on_failed_reload(self):
        def outside_write():
            self.cert.write_bytes(b'outside-writer-certificate')
            raise RenewalError('synthetic concurrent reload failure')
        self.reload.side_effect = outside_write
        with self.assertRaises(RenewalError):
            self.install()
        self.assertEqual(self.cert.read_bytes(), b'outside-writer-certificate')
        self.reload.assert_called_once()
        self.assert_unmoved_key_and_routes()

    def pending(self, installed):
        backup = self.backups / 'old.pem'
        backup.write_bytes(b'old-public-certificate')
        manifest = {'schema': 1, 'hostname': pem.TLS_NAME, 'phase': 'file_installed', 'original': self.expected,
                    'backup': str(backup), 'old_certificate': self.old,
                    'new_certificate': {key: value for key, value in self.new.items() if key != 'fullchain_pem'},
                    'new_file_sha256': hashlib.sha256(b'new-public-certificate').hexdigest()}
        if installed:
            self.cert.write_bytes(b'new-public-certificate')
        (self.state / 'transaction.json').write_text(json.dumps(manifest))
        return manifest

    def test_crash_after_file_write_recovers_by_reload_without_new_write(self):
        self.pending(True)
        self.verify.side_effect = [RenewalError('old worker still loaded'), None]
        with patch.object(pem, 'write_certificate') as writer:
            pem.recover_transaction(self.config, True)
        writer.assert_not_called()
        self.reload.assert_called_once()
        self.assertEqual(self.cert.read_bytes(), b'new-public-certificate')
        self.assert_unmoved_key_and_routes()
        self.assertEqual(json.loads((self.state / 'transaction.json').read_text())['phase'], 'committed')

    def test_healthy_interrupted_new_certificate_requires_no_reload(self):
        self.pending(True)
        pem.recover_transaction(self.config, True)
        self.reload.assert_not_called()
        self.assert_unmoved_key_and_routes()

    def test_dry_recovery_does_not_reload_or_write(self):
        self.pending(True)
        self.verify.side_effect = RenewalError('old worker still loaded')
        with patch.object(pem, 'write_certificate') as writer, self.assertRaises(RenewalError):
            pem.recover_transaction(self.config, False)
        writer.assert_not_called()
        self.reload.assert_not_called()

    def test_corrupt_backup_never_overwrites_loaded_candidate(self):
        manifest = self.pending(True)
        Path(manifest['backup']).write_bytes(b'corrupt-public-backup')
        with patch.object(pem, 'write_certificate') as writer, self.assertRaises(RenewalError):
            pem.rollback(self.config, manifest)
        writer.assert_not_called()
        self.reload.assert_not_called()
        self.assertEqual(self.cert.read_bytes(), b'new-public-certificate')


if __name__ == '__main__':
    unittest.main()
