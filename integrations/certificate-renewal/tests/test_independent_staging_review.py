"""Independent staging interruption checks using only temporary local files.

The reviewed package validation and service probes are substituted; the real
stage transaction, backup, atomic write, and rollback paths run unchanged.
No native host directories, certificates, services, or sockets are accessed.
"""
import contextlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'stage_ct250_from_v2.py'
SPEC = importlib.util.spec_from_file_location('independent_ct250_stage', SOURCE)
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class IndependentStagingReview(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ct250-stage-review-')
        self.root = Path(self.temporary.name)
        self.code = self.root / 'code'
        self.config = self.root / 'etc' / 'consumer.json'
        self.units = self.root / 'units'
        self.units.mkdir()
        self.desired = {
            self.code / 'renewal_common.py': b'fixture-common',
            self.code / 'mx_consumer.py': b'fixture-mx',
            self.code / 'pem_consumer.py': b'fixture-pem',
            self.config: b'fixture-config',
            self.units / stage.SERVICE: b'fixture-service',
            self.units / stage.TIMER: b'fixture-timer',
        }
        self.calls = []
        self.stack = contextlib.ExitStack()
        for name, value in [('CODE', self.code), ('CONFIG', self.config), ('UNITS', self.units)]:
            self.stack.enter_context(patch.object(stage, name, value))
        self.stack.enter_context(patch.object(stage, 'Path', side_effect=self.mapped_path))
        self.stack.enter_context(patch.object(stage, 'prepare', return_value=self.desired))
        self.stack.enter_context(patch.object(stage.subprocess, 'run', return_value=SimpleNamespace(
            returncode=0, stdout=b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n')))
        self.stack.enter_context(patch.object(stage, 'run', side_effect=self.fake_run))

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def mapped_path(self, value):
        if str(value).startswith('/var/'):
            return self.root / 'private' / str(value).lstrip('/')
        return Path(value)

    def fake_run(self, args, timeout=20):
        self.calls.append(args)
        if args[0] == 'ip':
            return b'[{"addr_info":[{"local":"10.50.0.250"}]}]'
        return b'{"event":"validated_deployment_pending"}\n'

    def apply(self):
        stage.stage(self.root / 'package', True)

    def assert_no_service_or_certificate_action(self):
        self.assertFalse(any(args[0] == 'systemctl' and args[1] in
                             ('start', 'stop', 'restart', 'reload', 'enable', 'disable')
                             for args in self.calls))
        self.assertFalse(any('--apply' in args for args in self.calls))

    def test_success_stages_only_reviewed_targets_and_runs_readonly_preflight(self):
        self.apply()
        for path, data in self.desired.items():
            self.assertEqual(path.read_bytes(), data)
        self.assert_no_service_or_certificate_action()

    def test_interruption_after_atomic_rename_removes_every_fresh_target(self):
        atomic = stage.atomic
        interrupted = False

        def write_then_interrupt(path, data, info):
            nonlocal interrupted
            atomic(path, data, info)
            if path == self.config and not interrupted:
                interrupted = True
                raise RuntimeError('fixture interruption after rename before return')

        with patch.object(stage, 'atomic', side_effect=write_then_interrupt):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertTrue(interrupted)
        self.assertFalse(any(path.exists() for path in self.desired))
        self.assert_no_service_or_certificate_action()

    def test_interruption_before_atomic_rename_removes_earlier_fresh_targets(self):
        atomic = stage.atomic

        def interrupt_before_write(path, data, info):
            if path == self.config:
                raise RuntimeError('fixture interruption before rename')
            atomic(path, data, info)

        with patch.object(stage, 'atomic', side_effect=interrupt_before_write):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertFalse(any(path.exists() for path in self.desired))
        self.assert_no_service_or_certificate_action()

    def test_outside_writer_after_rename_is_preserved(self):
        atomic = stage.atomic

        def outside_write_then_interrupt(path, data, info):
            atomic(path, data, info)
            if path == self.config:
                path.write_bytes(b'outside-writer-preserved')
                raise RuntimeError('fixture outside writer after rename')

        with patch.object(stage, 'atomic', side_effect=outside_write_then_interrupt):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertEqual(self.config.read_bytes(), b'outside-writer-preserved')
        self.assert_no_service_or_certificate_action()


if __name__ == '__main__':
    unittest.main()
