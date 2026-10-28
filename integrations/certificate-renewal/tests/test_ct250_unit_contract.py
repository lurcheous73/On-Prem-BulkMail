"""Regressions for the two observed CT250 systemd sandbox prerequisites."""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ct250_stage_unit_contract', ROOT / 'stage_ct250_from_v2.py')
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class Ct250UnitContract(unittest.TestCase):
    def setUp(self):
        self.final = (ROOT / 'systemd' / stage.SERVICE).read_bytes()
        self.original = self.final.replace(b'ExecStartPre=/usr/bin/mkdir -p /tmp/nginx\n', b'').replace(
            b'AF_INET AF_INET6 AF_UNIX AF_NETLINK\n', b'AF_INET AF_INET6 AF_UNIX\n')

    def test_exact_reviewed_delta_rebuilds_final_unit(self):
        self.assertEqual(stage.sha(self.original), stage.OLD_UNIT)
        self.assertEqual(stage.reviewed_service_unit(self.original), self.final)
        self.assertEqual(stage.sha(self.final), stage.NEW_UNIT)

    def test_private_workspace_parent_is_created_without_relaxing_isolation(self):
        lines = self.final.decode('ascii').splitlines()
        self.assertEqual([line for line in lines if line.startswith('ExecStartPre=')],
                         ['ExecStartPre=/usr/bin/mkdir -p /tmp/nginx'])
        for required in ('PrivateTmp=true', 'PrivateDevices=true', 'ProtectHome=true',
                         'ProtectSystem=strict', 'NoNewPrivileges=true',
                         'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK'):
            self.assertEqual(lines.count(required), 1)
        self.assertNotIn('PrivateTmp=false', lines)
        self.assertNotIn('PrivateTmp=disconnected', lines)

    def test_unknown_or_already_changed_packaged_unit_is_rejected(self):
        for data in (self.original + b'PrivateTmp=false\n', self.final,
                     self.original.replace(b'User=root\n', b'User=nobody\n')):
            with self.assertRaises(RuntimeError):
                stage.reviewed_service_unit(data)


if __name__ == '__main__':
    unittest.main()
