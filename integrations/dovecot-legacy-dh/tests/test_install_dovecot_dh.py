"""Offline transaction/rollback checks; no Docker, network, mail or real keys."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_dovecot_dh', ROOT / 'install_dovecot_dh.py')
install = importlib.util.module_from_spec(spec); spec.loader.exec_module(install)
DER = (ROOT / 'ffdhe3072.der').read_bytes()
CANDIDATE = b''.join(struct.pack('<ii', selector, len(DER)) + DER for selector in (512, 1024)) + b'\0' * 4
CERTIFICATE = 'a' * 64


class FakeNative(install.Native):
    def __init__(self):
        self.stage = '/fixture/stage'
        self.specs = copy.deepcopy(install.SOURCES)
        originals = {'main': b'ssl = yes\n# original main\n', 'template': b'ssl = yes\n# original template\n',
                     'parameters': b'original public parameters fixture'}
        self.files = {}
        for name, item in self.specs.items():
            item['sha256'] = install.sha(originals[name])
            self.files[item['path']] = (originals[name], {key: item[key] for key in ('mode', 'uid', 'gid')})
        self.original = copy.deepcopy(self.files)
        self.container = {'id': 'fixture-container', 'image': install.IMAGE, 'started_at': 'fixture-start'}
        self.actions = []
        self.writes = []
        self.running = True
        self.fail_write = None
        self.fail_verification = False
        self.fail_start_once = False
        self.verified_previous = 0
        self.staged = None

    def identity(self):
        install.require(self.container['image'] == install.IMAGE, 'mail container is not the inspected running image')
        return copy.deepcopy(self.container)

    def docker(self, args, **kwargs):
        if args == ['dovecot', '--version']: return subprocess.CompletedProcess(args, 0, b'2.1.17\n', b'')
        raise AssertionError('unexpected fake native command')

    def read(self, path): return copy.deepcopy(self.files[path])
    def validate_stage(self, main): self.staged = main
    def cleanup(self): pass
    def process_inventory(self):
        return [(1, 'init', 'Ss'), (185, 'dovecot', 'Ss')] if self.running else [(1, 'init', 'Ss')]

    def service(self, action):
        self.actions.append(action)
        if action == 'start':
            if self.fail_start_once:
                self.fail_start_once = False
                raise install.InstallError('fixture forward start failed')
            self.running = True
        elif action == 'status': install.require(self.running, 'fixture service is not running')

    def stop(self): self.actions.append('stop'); self.running = False

    def replace(self, path, data, metadata):
        self.files[path] = (data, copy.deepcopy(metadata))
        self.writes.append(path)
        if len(self.writes) == self.fail_write: raise install.InstallError('fixture uncertain replacement result')

    def verify(self, certificate):
        install.require(not self.fail_verification, 'fixture trusted verification failed')
        install.require(self.running, 'fixture service not started')
        return [{'port': port, 'trusted': True, 'dh_bits': 3072, 'certificate_sha256': certificate} for port in (993, 995)]

    def verify_previous_service(self):
        install.require(self.running, 'fixture original service not started')
        self.verified_previous += 1


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dovecot-install-fixture-')
        self.transaction = Path(self.temp.name) / 'transaction'
        self.native = FakeNative()
        self.identity, self.records = install.prepare(self.native, CANDIDATE)

    def tearDown(self): self.temp.cleanup()

    def apply(self):
        return install.install(self.native, self.transaction, self.identity, self.records, CERTIFICATE)

    def state(self): return json.loads((self.transaction / 'transaction.json').read_bytes())

    def test_plan_preserves_all_originals_and_does_not_stop(self):
        self.assertEqual(self.native.files, self.native.original)
        self.assertNotIn('stop', self.native.actions)
        self.assertEqual(self.native.writes, [])

    def test_both_config_candidates_preserve_prefix_and_only_append_supported_setting(self):
        for record in self.records:
            if record['name'] != 'parameters': self.assertEqual(record['new'], record['old'] + install.APPEND)
        self.assertEqual(self.native.staged, self.records[0]['new'])

    def test_changed_source_hash_stops_before_service_mutation(self):
        name = self.native.specs['template']['path']
        self.native.files[name] = (b'concurrent edit', self.native.files[name][1])
        with self.assertRaisesRegex(install.InstallError, 'hash differs'):
            install.prepare(self.native, CANDIDATE)
        self.assertNotIn('stop', self.native.actions)

    def test_unexpected_image_is_rejected(self):
        self.native.container['image'] = 'unreviewed/image:new'
        with self.assertRaises(install.InstallError): install.prepare(self.native, CANDIDATE)

    def test_changed_candidate_is_rejected(self):
        with self.assertRaisesRegex(install.InstallError, 'candidate hash'):
            install.prepare(self.native, CANDIDATE + b'changed')

    def test_success_preserves_private_complete_backup_and_verifies_both_ports(self):
        state = self.apply()
        self.assertEqual(state['phase'], 'verified')
        self.assertEqual([item['port'] for item in state['endpoints']], [993, 995])
        self.assertEqual(self.transaction.stat().st_mode & 0o777, 0o700)
        for record in self.records:
            backup = self.transaction / (record['name'] + '.original')
            self.assertEqual(backup.read_bytes(), record['old'])
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.native.files[record['path']][0], record['new'])

    def test_partial_native_write_error_restores_every_original_and_service(self):
        self.native.fail_write = 2
        with self.assertRaisesRegex(install.InstallError, 'known weak-DH limitation'): self.apply()
        self.assertEqual(self.native.files, self.native.original)
        self.assertTrue(self.native.running)
        self.assertEqual(self.state()['phase'], 'restored_previous_weak_dh')

    def test_metadata_changed_during_stop_is_preserved_without_any_write(self):
        original_stop = self.native.stop
        target = self.native.specs['main']['path']
        def outside_change():
            original_stop()
            data, metadata = self.native.files[target]
            metadata['mode'] = 0o640
            self.native.files[target] = (data, metadata)
        self.native.stop = outside_change
        with self.assertRaisesRegex(install.InstallError, 'rollback incomplete'): self.apply()
        self.assertEqual(self.native.writes, [])
        self.assertEqual(self.native.files[target][1]['mode'], 0o640)
        self.assertFalse(self.native.running)
        self.assertEqual(self.state()['phase'], 'rollback_failed')
        self.assertEqual(self.state()['failed_phase'], 'stopping')

    def test_failed_strict_verification_restores_baseline_without_weakened_tls(self):
        self.native.fail_verification = True
        with patch.object(install.time, 'monotonic', side_effect=[0, 50]):
            with self.assertRaisesRegex(install.InstallError, 'known weak-DH limitation'): self.apply()
        self.assertEqual(self.native.files, self.native.original)
        self.assertEqual(self.native.verified_previous, 1)

    def test_failed_forward_start_is_rolled_back_and_original_is_started(self):
        self.native.fail_start_once = True
        with self.assertRaises(install.InstallError): self.apply()
        self.assertEqual(self.native.files, self.native.original)
        self.assertTrue(self.native.running)

    def test_explicit_recovery_restores_complete_file_set(self):
        self.apply()
        install.recover(self.native, self.transaction, self.state())
        self.assertEqual(self.native.files, self.native.original)
        self.assertEqual(self.state()['phase'], 'restored_previous_weak_dh')

    def test_corrupt_backup_is_rejected_before_any_stop_or_restore(self):
        self.apply()
        (self.transaction / 'template.original').write_bytes(b'corrupt backup')
        before = copy.deepcopy(self.native.files)
        self.native.actions.clear(); self.native.writes.clear()
        with self.assertRaisesRegex(install.InstallError, 'backup bytes changed'):
            install.recover(self.native, self.transaction, self.state())
        self.assertEqual(self.native.files, before)
        self.assertEqual((self.native.actions, self.native.writes), ([], []))

    def test_concurrent_configuration_edit_is_never_overwritten_by_recovery(self):
        self.apply()
        target = self.native.specs['main']['path']
        self.native.files[target] = (b'unrelated later edit', self.native.files[target][1])
        self.native.actions.clear(); self.native.writes.clear()
        with self.assertRaisesRegex(install.InstallError, 'outside transaction'):
            install.recover(self.native, self.transaction, self.state())
        self.assertEqual(self.native.files[target][0], b'unrelated later edit')
        self.assertEqual((self.native.actions, self.native.writes), ([], []))

    def test_changed_container_blocks_recovery_before_service_action(self):
        self.apply(); self.native.container['started_at'] = 'new-start'
        self.native.actions.clear()
        with self.assertRaisesRegex(install.InstallError, 'container restarted'):
            install.recover(self.native, self.transaction, self.state())
        self.assertEqual(self.native.actions, [])

    def test_journal_target_cannot_escape_enrolled_files(self):
        self.apply(); state = self.state(); state['files'][0]['path'] = '/etc/unrelated'
        self.native.actions.clear()
        with self.assertRaisesRegex(install.InstallError, 'outside enrollment'):
            install.recover(self.native, self.transaction, state)
        self.assertEqual(self.native.actions, [])

    def test_duplicate_journal_entries_are_rejected_before_restore(self):
        self.apply(); state = self.state(); state['files'].append(copy.deepcopy(state['files'][0]))
        self.native.actions.clear()
        with self.assertRaises(install.InstallError): install.recover(self.native, self.transaction, state)
        self.assertEqual(self.native.actions, [])

    def test_native_stop_is_idempotent_when_already_stopped(self):
        native = install.Native()
        with patch.object(native, 'processes', return_value=[]), patch.object(native, 'docker') as command:
            native.stop(); command.assert_not_called()

    def test_native_stage_uses_existing_legacy_var_run_parent(self):
        native = install.Native()
        self.assertEqual(Path(native.stage).parent, Path('/var/run'))
        self.assertTrue(Path(native.stage).name.startswith('grange-dovecot-dh-'))

    def test_native_stop_accepts_nonzero_wrapper_only_after_processes_are_gone(self):
        native = install.Native()
        with patch.object(native, 'processes', side_effect=[[185, 906845], []]), patch.object(native, 'docker') as command:
            native.stop()
            self.assertTrue(command.call_args.kwargs['allow_failure'])

    def test_native_processes_use_verified_legacy_separate_output_arguments(self):
        native = install.Native()
        actual_shape = (b'      1 init Ss\n    185 dovecot Ss\n 906845 ssl-params S\n'
                        b' 906846 imap-login S\n 906847 imap S\n 906848 pop3-login S\n'
                        b' 906849 pop3 S\n 906850 unrelated S\n 906851 imap-login Z\n')
        with patch.object(native, 'docker', return_value=subprocess.CompletedProcess([], 0, actual_shape, b'')) as command:
            self.assertEqual(native.processes(), [185, 906845, 906846, 906847, 906848, 906849])
            self.assertEqual(command.call_args.args[0], ['ps', '-e', '-o', 'pid=', '-o', 'comm=', '-o', 'stat='])

    def test_native_inventory_rejects_pid_only_empty_or_any_malformed_row(self):
        for output in (b'', b'\n', b'1\n185\n906845\n', b'185 dovecot\n',
                       b'0 dovecot Ss\n', b'bad dovecot Ss\n', b'185 dovecot unknown\n',
                       b'185 dovecot Ss\n185 dovecot S\n', b'185 dovecot Ss\nmalformed\n',
                       b'185 dovecot Ss extra\n', b'185 dove\x00cot Ss\n', b'185 \xff Ss\n'):
            with self.subTest(output=output), self.assertRaises(install.InstallError):
                install.process_inventory(output)

    def test_running_status_alone_cannot_pass_without_exactly_one_live_master(self):
        native = install.Native()
        for rows in ([(1, 'init', 'Ss')], [(185, 'dovecot', 'Z')],
                     [(185, 'dovecot', 'Ss'), (186, 'dovecot', 'S')]):
            with self.subTest(rows=rows), patch.object(native, 'service'), \
                 patch.object(native, 'process_inventory', return_value=rows):
                with self.assertRaisesRegex(install.InstallError, 'one discovered live master'):
                    native.require_running_master()
        with patch.object(native, 'service') as service, \
             patch.object(native, 'process_inventory', return_value=[(185, 'dovecot', 'Ss')]):
            self.assertEqual(native.require_running_master(), 185)
            service.assert_called_once_with('status')

    def test_preflight_missing_live_master_stops_before_staging_or_installed_writes(self):
        with patch.object(self.native, 'process_inventory', return_value=[(1, 'init', 'Ss')]), \
             patch.object(self.native, 'validate_stage') as stage, patch.object(self.native, 'read') as read:
            with self.assertRaisesRegex(install.InstallError, 'one discovered live master'):
                install.prepare(self.native, CANDIDATE)
            stage.assert_not_called(); read.assert_not_called()
        self.assertNotIn('stop', self.native.actions)
        self.assertEqual(self.native.writes, [])

    def test_real_native_stop_parses_legacy_rows_calls_stop_and_waits_for_worker_exit(self):
        native = install.Native()
        snapshots = iter((b'1 init Ss\n185 dovecot Ss\n906845 ssl-params S\n',
                          b'1 init Ss\n906845 ssl-params S\n',
                          b'1 init Ss\n906845 ssl-params Z\n'))
        calls = []
        def command(args, **kwargs):
            calls.append((args, kwargs))
            output = next(snapshots) if args[0] == 'ps' else b''
            return subprocess.CompletedProcess(args, 0, output, b'')
        with patch.object(native, 'docker', side_effect=command), patch.object(install.time, 'sleep') as sleep:
            native.stop()
        self.assertEqual([args[0] for args, _ in calls], ['ps', 'service', 'ps', 'ps'])
        self.assertEqual(calls[1][0], ['service', 'dovecot', 'stop'])
        self.assertTrue(calls[1][1]['mutating'])
        sleep.assert_called_once_with(0.5)

    def test_real_native_stop_rejects_live_survivor_or_malformed_after_stop(self):
        for after in (b'1 init Ss\n906845 ssl-params S\n', b'1\n906845\n'):
            with self.subTest(after=after):
                native = install.Native()
                replies = [subprocess.CompletedProcess([], 0, data, b'') for data in
                           (b'1 init Ss\n185 dovecot Ss\n', b'', after)]
                with patch.object(native, 'docker', side_effect=replies), \
                     patch.object(install.time, 'monotonic', side_effect=[0, 21]):
                    with self.assertRaises(install.InstallError): native.stop()

    def test_inner_timeout_uses_only_proven_legacy_kill_option(self):
        native = install.Native()
        with patch.object(native, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as command:
            native.docker(['sh', '-c', 'fixture'], data=b'private configuration', timeout=20)
            args = command.call_args.args[0]
            self.assertIn('/usr/bin/timeout', args)
            self.assertIn('--signal=KILL', args)
            self.assertNotIn('--signal=TERM', args)
            self.assertFalse(any(part.startswith('--kill-after') for part in args))
            self.assertEqual(command.call_args.kwargs['timeout'], 30)

    def test_early_uncertain_mutation_waits_for_remote_bound_before_recovery_command(self):
        for exception in (False, True):
            with self.subTest(exception=exception):
                native = install.Native()
                clock = [0.0]; calls = []
                def command(args, **kwargs):
                    calls.append(clock[0]); clock[0] += 2
                    if len(calls) == 1:
                        if exception: raise install.InstallError('fixture disconnected Docker transport')
                        return subprocess.CompletedProcess(args, 1, b'', b'fixture disconnected transport')
                    return subprocess.CompletedProcess(args, 0, b'', b'')
                with patch.object(install.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(install.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                     patch.object(native, 'command', side_effect=command):
                    with self.assertRaises(install.InstallError):
                        native.docker(['sh', '-c', 'fixture mutation'], timeout=20, mutating=True)
                    self.assertGreaterEqual(clock[0], 26)
                    native.docker(['sh', '-c', 'fixture recovery'], timeout=20, mutating=True)
                self.assertGreaterEqual(calls[1], 26)

    def test_native_error_does_not_include_captured_sensitive_output(self):
        native = install.Native()
        output = subprocess.CompletedProcess(['fixture'], 1, b'private configuration', b'secret fixture password')
        with patch.object(install.subprocess, 'run', return_value=output):
            with self.assertRaises(install.InstallError) as raised: native.command(['fixture'])
        self.assertNotIn('password', str(raised.exception))
        self.assertNotIn('configuration', str(raised.exception))

    def test_native_read_pins_each_actual_file_mode_and_owner_without_generic_relaxation(self):
        native = install.Native()
        raw = b'fixture public configuration'
        for name, mode, uid, gid, accepted in (
                ('main', 0o644, 0, 0, True), ('template', 0o664, 0, 0, True),
                ('parameters', 0o644, 0, 0, True), ('main', 0o664, 0, 0, False),
                ('template', 0o644, 0, 0, False), ('template', 0o664, 1, 0, False),
                ('template', 0o664, 0, 1, False)):
            with self.subTest(name=name, mode=mode, uid=uid, gid=gid):
                metadata = (format(mode, 'o') + ' ' + str(uid) + ' ' + str(gid) + ' ' + str(len(raw))).encode()
                replies = [subprocess.CompletedProcess([], 0, data, b'') for data in (metadata, raw, metadata)]
                with patch.object(native, 'docker', side_effect=replies):
                    if accepted:
                        self.assertEqual(native.read(native.specs[name]['path']),
                                         (raw, {'mode': mode, 'uid': uid, 'gid': gid}))
                    else:
                        with self.assertRaisesRegex(install.InstallError, 'ownership/mode/size'):
                            native.read(native.specs[name]['path'])

    def test_dh_proof_accepts_verified_real_3072_diagnostic(self):
        install.dh_proof(b'CONNECTION ESTABLISHED\nVerification: OK\nServer Temp Key: DH, 3072 bits\n')

    def test_dh_proof_rejects_weak_untrusted_or_conflicting_diagnostics(self):
        outputs = [b'Verification: OK\nServer Temp Key: DH, 1024 bits\n',
                   b'Verification error: untrusted\nServer Temp Key: DH, 3072 bits\n',
                   b'Verification: OK\nServer Temp Key: ECDH, 3072 bits\n',
                   b'Verification: OK\nServer Temp Key: DH, 2048 bits\nServer Temp Key: DH, 3072 bits\n']
        for output in outputs:
            with self.subTest(output=output), self.assertRaises(install.InstallError):
                install.dh_proof(b'CONNECTION ESTABLISHED\n' + output)

    def test_secondary_proof_requires_completed_handshake_not_only_parsed_parameters(self):
        with self.assertRaisesRegex(install.InstallError, 'completed handshake'):
            install.dh_proof(b'Verification: OK\nServer Temp Key: DH, 3072 bits\nhandshake failed\n')


if __name__ == '__main__': unittest.main(verbosity=2)
