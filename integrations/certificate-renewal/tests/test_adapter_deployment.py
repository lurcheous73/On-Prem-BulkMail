"""Local code-update safety tests; no services, network or Xeams files touched."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy_mx_adapter_v2 as update


class AdapterDeployment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='adapter-update-test-')
        self.root = Path(self.tmp.name)
        self.package, self.code = self.root / 'package', self.root / 'code'
        self.config, self.unit = self.root / 'consumer.json', self.root / 'consumer.service'
        self.class_file = self.code / 'java/GrangeRenewalKeystore.class'
        self.host = 'mx2.brimstonecottage.uk'
        for directory in (self.package / 'java', self.package / 'config', self.package / 'systemd', self.class_file.parent):
            directory.mkdir(parents=True)
        self.old_class, self.new_class = b'old-fixture-class', b'new-fixture-class'
        self.old_config, self.new_config = b'{"fixture":"old"}\n', b'{"fixture":"new"}\n'
        self.old_unit = b'[Service]\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
        self.new_unit = self.old_unit.replace(b'AF_UNIX\n', b'AF_UNIX AF_NETLINK\n')
        self.class_file.write_bytes(self.old_class)
        self.config.write_bytes(self.old_config)
        self.unit.write_bytes(self.old_unit)
        (self.package / 'java/GrangeRenewalKeystore.class').write_bytes(self.new_class)
        (self.package / ('config/consumer-' + self.host + '.json')).write_bytes(self.new_config)
        (self.package / 'systemd/grange-mx-certificate-consumer.service').write_bytes(self.old_unit)
        self.stack = contextlib.ExitStack()
        for name, value in [('CODE', self.code), ('CONFIG', self.config), ('CLASS', self.class_file), ('UNIT', self.unit),
                            ('STATE', self.root / 'state'), ('BACKUPS', self.root / 'backups'),
                            ('OLD_CLASS', update.sha(self.old_class)), ('NEW_CLASS', update.sha(self.new_class)),
                            ('OLD_UNIT', update.sha(self.old_unit)), ('NEW_UNIT', update.sha(self.new_unit)),
                            ('CONFIG_PINS', {self.host: (update.sha(self.old_config), update.sha(self.new_config))})]:
            self.stack.enter_context(patch.object(update, name, value))
        self.stack.enter_context(patch.object(update, 'core_sources'))
        self.calls, self.active, self.running = [], True, False
        self.runner = self.stack.enter_context(patch.object(update, 'run', side_effect=self.fake_run))
        self.preflight = self.stack.enter_context(patch.object(update, 'readonly_preflight', return_value=['current_certificate_verified']))

    def tearDown(self):
        self.stack.close()
        self.tmp.cleanup()

    def fake_run(self, args, timeout=20):
        self.calls.append(args)
        if '--property=RestrictAddressFamilies' in args:
            return b'AF_INET AF_INET6 AF_UNIX AF_NETLINK\n'
        if '--property=ActiveState,MainPID' in args:
            return b'ActiveState=active\nMainPID=42\n' if self.running else b'ActiveState=failed\nMainPID=0\n'
        if '--property=ActiveState' in args:
            return b'active\n' if self.active else b'inactive\n'
        return b''

    def apply(self):
        update.guarded_update(self.package, self.host, True)

    def assert_original(self):
        self.assertEqual(self.class_file.read_bytes(), self.old_class)
        self.assertEqual(self.config.read_bytes(), self.old_config)
        self.assertEqual(self.unit.read_bytes(), self.old_unit)

    def test_success_updates_exact_three_files_and_resumes_only_our_timer(self):
        self.apply()
        self.assertEqual(self.class_file.read_bytes(), self.new_class)
        self.assertEqual(self.config.read_bytes(), self.new_config)
        self.assertEqual(self.unit.read_bytes(), self.new_unit)
        self.preflight.assert_called_once()
        controlled = [args for args in self.calls if len(args) > 1 and args[1] in ('stop', 'start')]
        self.assertEqual(controlled, [['systemctl', 'stop', 'grange-mx-certificate-secondary.timer'],
                                      ['systemctl', 'start', 'grange-mx-certificate-secondary.timer']])
        self.assertFalse(any('xeams' in ' '.join(args).lower() for args in self.calls))

    def test_failed_readonly_preflight_restores_code_config_unit(self):
        self.preflight.side_effect = RuntimeError('synthetic preflight failure')
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assert_original()
        self.assertIn(['systemctl', 'start', 'grange-mx-certificate-secondary.timer'], self.calls)

    def test_initially_inactive_timer_remains_inactive(self):
        self.active = False
        self.apply()
        self.assertFalse(any(args[1] in ('stop', 'start') for args in self.calls))

    def test_running_consumer_is_not_interrupted(self):
        self.running = True
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assert_original()
        self.assertFalse(any(args[1] in ('stop', 'start') for args in self.calls))

    def test_unexpected_old_config_blocks_before_pause(self):
        self.config.write_bytes(b'unknown-config')
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual(self.class_file.read_bytes(), self.old_class)
        self.assertFalse(any(args[1] in ('stop', 'start') for args in self.calls))

    def test_external_code_write_is_preserved_and_timer_stays_paused(self):
        def change():
            self.class_file.write_bytes(b'outside-writer')
            raise RuntimeError('synthetic concurrent writer')
        self.preflight.side_effect = change
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual(self.class_file.read_bytes(), b'outside-writer')
        self.assertNotIn(['systemctl', 'start', 'grange-mx-certificate-secondary.timer'], self.calls)

    def test_plan_never_mutates_or_pauses_timer(self):
        update.guarded_update(self.package, self.host, False)
        self.assert_original()
        self.preflight.assert_not_called()
        self.assertFalse(any(args[1] in ('stop', 'start') for args in self.calls))

    def test_backup_write_failure_resumes_timer_without_live_replacement(self):
        original_open = Path.open
        def failed_backup(path, *args, **kwargs):
            if path.suffix == '.backup':
                raise OSError('synthetic backup write failure')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', failed_backup), self.assertRaises(OSError):
            self.apply()
        self.assert_original()
        self.preflight.assert_not_called()
        self.assertIn(['systemctl', 'start', 'grange-mx-certificate-secondary.timer'], self.calls)

    def test_lost_stop_acknowledgement_restores_prior_timer_state(self):
        def lost_ack(args, timeout=20):
            result = self.fake_run(args, timeout)
            if args[:2] == ['systemctl', 'stop']:
                raise RuntimeError('synthetic stop acknowledgement failure')
            return result
        self.runner.side_effect = lost_ack
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assert_original()
        self.assertIn(['systemctl', 'start', 'grange-mx-certificate-secondary.timer'], self.calls)

    def test_captured_config_changed_during_backup_is_never_overwritten(self):
        original_mkdtemp = tempfile.mkdtemp
        def outside_write(*args, **kwargs):
            value = original_mkdtemp(*args, **kwargs)
            self.config.write_bytes(b'outside-config-during-backup')
            return value
        with patch.object(update.tempfile, 'mkdtemp', side_effect=outside_write), self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual(self.config.read_bytes(), b'outside-config-during-backup')
        self.assertEqual(self.class_file.read_bytes(), self.old_class)
        self.assertEqual(self.unit.read_bytes(), self.old_unit)
        self.preflight.assert_not_called()
        self.assertNotIn(['systemctl', 'start', 'grange-mx-certificate-secondary.timer'], self.calls)


if __name__ == '__main__':
    unittest.main()
