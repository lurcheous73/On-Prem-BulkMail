"""Offline real-certificate and failure-path fixtures for named lineages.

No ACME server, live service, SMTP delivery, real credential, or network socket
is used. Native file snapshot/cache/rollback and certificate validation run;
only Certbot issuance, reload commands, and live TLS peers are synthetic.
"""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import local_lineage as local
from renewal_common import DAY, RenewalError, atomic_write, certificate_info

NOW = 1800000000


def date(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc)


class CertificateFixtures:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.other_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Local fixture authority')])
        self.ca = (x509.CertificateBuilder().subject_name(self.ca_name).issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(date(NOW - 1000 * DAY)).not_valid_after(date(NOW + 1000 * DAY))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
            .sign(self.ca_key, hashes.SHA256()))
        self.ca_pem = self.ca.public_bytes(serialization.Encoding.PEM)
        self.due = self.leaf(NOW - 40 * DAY, NOW + 50 * DAY)
        self.fresh = self.leaf(NOW - DAY, NOW + 89 * DAY)
        self.new = self.leaf(NOW - 60, NOW + 90 * DAY)
        self.wrong_key = self.leaf(NOW - 60, NOW + 90 * DAY, key=self.other_key)
        self.wrong_name = self.leaf(NOW - 60, NOW + 90 * DAY, host='other.example.invalid')

    def leaf(self, before, after, key=None, host='work.example.invalid'):
        key = key or self.key
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(date(before)).not_valid_after(date(after))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.ca_key, hashes.SHA256()))
        return leaf.public_bytes(serialization.Encoding.PEM) + self.ca_pem

    def private(self, key=None):
        return (key or self.key).private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class FixtureNative(local.Native):
    def __init__(self, cfg, replacement):
        super().__init__(cfg)
        self.clock = NOW
        self.replacement = replacement
        self.orders = 0
        self.reloads = []
        self.issuer_exit = True
        self.issuer_writes = True
        self.forward_failure = set()
        self.rollback_failure = set()
        self.verifications = []
        self.presented = {name: certificate_info(Path(item['files']['fullchain_pem']).read_bytes())['sha256']
                          for name, item in self.consumers.items()}
        self.initial = dict(self.presented)
        self.peer_info = {certificate_info(Path(item['files']['fullchain_pem']).read_bytes())['sha256']:
                          certificate_info(Path(item['files']['fullchain_pem']).read_bytes())
                          for item in self.consumers.values()}

    def now(self):
        return self.clock

    def issue(self):
        self.orders += 1
        if self.issuer_writes:
            Path(self.cfg['lineage_dir'], 'fullchain.pem').write_bytes(self.replacement)
        return self.issuer_exit

    def activate(self, consumer):
        info = certificate_info(Path(consumer['files']['fullchain_pem']).read_bytes())
        fingerprint = info['sha256']
        self.peer_info[fingerprint] = info
        self.reloads.append((consumer['name'], fingerprint))
        self.presented[consumer['name']] = fingerprint

    def verify(self, consumer, fingerprint, wait_seconds=0, trusted=True):
        name = consumer['name']
        self.verifications.append((name, fingerprint, trusted))
        if fingerprint != self.initial[name] and name in self.forward_failure:
            return False
        if fingerprint == self.initial[name] and name in self.rollback_failure:
            return False
        actual = self.peer_info.get(self.presented[name])
        if trusted and (not actual or not actual['not_before'] <= self.clock < actual['not_after']):
            return False
        return self.presented[name] == fingerprint


class LocalLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = CertificateFixtures()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='local-lineage-fixture-')
        self.root = Path(self.temporary.name)
        self.lineage = self.root / 'live' / 'fixture'
        self.lineage.mkdir(parents=True)
        self.ca = self.root / 'ca.pem'; self.ca.write_bytes(self.cert.ca_pem)
        (self.lineage / 'fullchain.pem').write_bytes(self.cert.due)
        (self.lineage / 'privkey.pem').write_bytes(self.cert.private())
        (self.lineage / 'privkey.pem').chmod(0o600)
        self.cfg = {'schema': 1, 'lineage': 'fixture', 'sans': ['work.example.invalid'],
            'spki_sha256': certificate_info(self.cert.due)['spki_sha256'],
            'lineage_dir': str(self.lineage), 'renewal_config': str(self.root / 'fixture.conf'),
            'state_dir': str(self.root / 'state'), 'lock_path': str(self.root / 'operation.lock'),
            'certbot_executable': '/usr/bin/certbot', 'certbot_version': 'certbot 1.21.0',
            'command_prefix': ['pct', 'exec', '400', '--', 'docker', 'exec', 'fixture-container'],
            'webroot': '/fixture/webroot', 'ca_file': str(self.ca), 'consumers': [], 'lookahead_seconds': DAY}
        Path(self.cfg['renewal_config']).write_text('version = 1.21.0\n[renewalparams]\nauthenticator = webroot\n'
            'server = https://acme-v02.api.letsencrypt.org/directory\nwebroot_path = /fixture/webroot,\n')
        for name in ('web', 'mail', 'bulkmail'):
            folder = self.root / name; folder.mkdir()
            (folder / 'fullchain.pem').write_bytes(self.cert.due)
            (folder / 'chain.pem').write_bytes(self.cert.ca_pem)
            (folder / 'privkey.pem').write_bytes(self.cert.private())
            (folder / 'privkey.pem').chmod(0o600)
            self.cfg['consumers'].append({'name': name, 'key_path': str(folder / 'privkey.pem'),
                'files': {'fullchain_pem': str(folder / 'fullchain.pem'), 'chain_pem': str(folder / 'chain.pem')},
                'validate': ['fixture-validate', name], 'activate': ['fixture-reload', name],
                'endpoints': [{'address': '127.0.0.1', 'port': 443, 'server_name': 'work.example.invalid', 'protocol': 'tls'}]})
        self.native = FixtureNative(self.cfg, self.cert.new)
        self.keys = {item['key_path']: Path(item['key_path']).read_bytes() for item in self.cfg['consumers']}

    def tearDown(self):
        self.temporary.cleanup()

    def set_current(self, data):
        (self.lineage / 'fullchain.pem').write_bytes(data)
        for item in self.cfg['consumers']:
            Path(item['files']['fullchain_pem']).write_bytes(data)
        self.native = FixtureNative(self.cfg, self.cert.new)

    def assert_keys_unchanged(self):
        for path, data in self.keys.items():
            self.assertEqual(Path(path).read_bytes(), data)

    def test_not_due_and_healthy_does_not_order_or_reload(self):
        self.set_current(self.cert.fresh)
        self.assertEqual(local.run(self.native)['event'], 'already_current')
        self.assertEqual((self.native.orders, self.native.reloads), (0, []))

    def test_daily_lookahead_renews_before_twenty_eight_day_deadline(self):
        self.set_current(self.cert.leaf(NOW - 27 * DAY, NOW + 63 * DAY))
        self.assertEqual(local.run(self.native)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(len(self.native.reloads), 3)
        self.assert_keys_unchanged()

    def test_short_lifetime_uses_proportional_expiry_safeguard(self):
        self.set_current(self.cert.leaf(NOW - 3 * DAY, NOW + 3 * DAY))
        result = local.run(self.native)
        self.assertEqual(result['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)

    def test_successful_issuance_survives_nonzero_certbot_exit(self):
        self.native.issuer_exit = False
        self.assertEqual(local.run(self.native)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(self.native.read_state()['issued']['sha256'], certificate_info(self.cert.new)['sha256'])

    def test_no_new_certificate_records_backoff_and_does_not_reload(self):
        self.native.issuer_writes = False; self.native.issuer_exit = False
        with self.assertRaisesRegex(RenewalError, 'before a new certificate'):
            local.run(self.native)
        state = self.native.read_state()
        self.assertGreater(state['retry_at'], NOW)
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'retry_deferred')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(self.native.reloads, [])

    def test_changed_key_or_names_never_reach_consumer_files(self):
        for data in (self.cert.wrong_key, self.cert.wrong_name):
            with self.subTest(data=certificate_info(data)['sha256']):
                self.native.replacement = data
                with self.assertRaisesRegex(RenewalError, 'enrolled DNS names/key'):
                    local.run(self.native)
                self.assertEqual(self.native.reloads, [])
                self.assertTrue(all(Path(item['files']['fullchain_pem']).read_bytes() == self.cert.due for item in self.cfg['consumers']))
                (self.lineage / 'fullchain.pem').write_bytes(self.cert.due)
                self.native.clock += 4000

    def test_failed_live_verification_restores_all_files_and_retains_new_certificate(self):
        self.native.forward_failure.add('mail')
        with self.assertRaisesRegex(RenewalError, 'previous certificates were restored'):
            local.run(self.native)
        state = self.native.read_state()
        self.assertIn('pending', state)
        self.assertNotIn('transaction', state)
        self.assertEqual((self.lineage / 'fullchain.pem').read_bytes(), self.cert.new)
        for consumer in self.cfg['consumers']:
            self.assertEqual(Path(consumer['files']['fullchain_pem']).read_bytes(), self.cert.due)
            self.assertEqual(self.native.presented[consumer['name']], self.native.initial[consumer['name']])
        self.assert_keys_unchanged()

    def test_deployment_retry_never_requests_second_acme_order_or_moves_issuance_anchor(self):
        self.native.forward_failure.add('mail')
        with self.assertRaises(RenewalError): local.run(self.native)
        issued_at = self.native.read_state()['issued_at']
        self.native.forward_failure.clear(); self.native.clock += 4000
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'deployment_completed')
        self.assertEqual(self.native.orders, 1)
        state = self.native.read_state()
        self.assertEqual(state['issued_at'], issued_at)
        self.assertNotIn('pending', state)
        self.assertNotIn('failure_count', state)
        self.assert_keys_unchanged()

    def test_rollback_failure_keeps_journal_and_never_requests_second_order(self):
        self.native.forward_failure.add('mail'); self.native.rollback_failure.add('mail')
        with self.assertRaisesRegex(RenewalError, 'could not be rolled back'):
            local.run(self.native)
        self.assertEqual(self.native.read_state()['transaction']['phase'], 'rollback_failed')
        self.native.clock += 4000
        with self.assertRaisesRegex(RenewalError, 'could not be rolled back'):
            local.run(self.native, retry_only=True)
        self.assertEqual(self.native.orders, 1)

    def test_deploy_only_can_repair_drift_without_an_order_even_when_due(self):
        consumer = self.native.consumers['bulkmail']
        self.native.presented['bulkmail'] = '0' * 64
        self.assertEqual(local.run(self.native, deploy_only=True)['event'], 'consumer_drift_repaired')
        self.assertEqual(self.native.orders, 0)
        self.assertEqual([name for name, unused in self.native.reloads], ['bulkmail'])

    def test_read_only_check_has_no_state_or_consumer_mutations(self):
        result = local.run(self.native, check_only=True)
        self.assertTrue(result['renewal_eligible'])
        self.assertTrue(result['consumers_healthy'])
        self.assertFalse(self.native.directory.exists())
        self.assertEqual((self.native.orders, self.native.reloads), (0, []))

    def test_hourly_retry_without_work_does_not_create_state(self):
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'no_retry_pending')
        self.assertFalse(self.native.directory.exists())
        self.assertEqual(self.native.orders, 0)

    def test_external_renewal_is_deployed_without_another_order(self):
        self.set_current(self.cert.fresh)
        local.run(self.native)
        (self.lineage / 'fullchain.pem').write_bytes(self.cert.new)
        self.assertEqual(local.run(self.native)['event'], 'external_renewal_deployed')
        self.assertEqual(self.native.orders, 0)

    def test_expired_external_renewal_permits_one_fresh_due_order(self):
        self.set_current(self.cert.fresh)
        local.run(self.native)
        self.native.clock += 100 * DAY
        external = self.cert.leaf(NOW + DAY, NOW + 91 * DAY)
        (self.lineage / 'fullchain.pem').write_bytes(external)
        self.native.replacement = self.cert.leaf(self.native.clock - 60, self.native.clock + 90 * DAY)
        self.assertEqual(local.run(self.native)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)
        external_fingerprint = certificate_info(external)['sha256']
        self.assertNotIn(external_fingerprint, [fingerprint for unused, fingerprint in self.native.reloads])
        self.assert_keys_unchanged()

    def test_expired_external_replacement_of_pending_candidate_can_renew(self):
        self.pending_transaction()
        self.native.clock += 100 * DAY
        external = self.cert.leaf(NOW + DAY, NOW + 91 * DAY)
        (self.lineage / 'fullchain.pem').write_bytes(external)
        self.native.replacement = self.cert.leaf(self.native.clock - 60, self.native.clock + 90 * DAY)
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(len([item for item in self.native.verifications if not item[2]]), 3)
        self.assertNotIn('transaction', self.native.read_state())

    def test_deploy_only_never_orders_or_deploys_an_expired_external_leaf(self):
        self.set_current(self.cert.fresh)
        local.run(self.native)
        self.native.clock += 100 * DAY
        (self.lineage / 'fullchain.pem').write_bytes(self.cert.leaf(NOW + DAY, NOW + 91 * DAY))
        with self.assertRaisesRegex(RenewalError, 'external certificate is too old'):
            local.run(self.native, deploy_only=True)
        self.assertEqual((self.native.orders, self.native.reloads), (0, []))
        self.assertTrue(all(Path(item['files']['fullchain_pem']).read_bytes() == self.cert.fresh
                            for item in self.cfg['consumers']))

    def pending_transaction(self, fully_installed=False):
        before = certificate_info(self.cert.due)
        state = {'schema': 1, 'lineage': 'fixture', 'spki_sha256': self.cfg['spki_sha256'],
                 'issued': local.public_status(before), 'issued_at': before['not_before']}
        (self.lineage / 'fullchain.pem').write_bytes(self.cert.new)
        info = self.native.validate(self.cert.new)
        local.record_pending(self.native, state, info, 'managed_renewal')
        entries = self.native.prepare(info, state)
        selected = entries if fully_installed else entries[:1]
        for entry in selected:
            for item in entry['files']:
                atomic_write(item['target'], info[item['field']], item['mode'], item['uid'], item['gid'])
            self.native.activate(self.native.consumers[entry['name']])
        self.native.reloads.clear()
        return state, info

    def test_interrupted_partial_transaction_rolls_back_then_retries_without_order(self):
        self.pending_transaction()
        self.assertEqual(local.run(self.native)['event'], 'deployment_completed')
        self.assertEqual(self.native.orders, 0)
        self.assertEqual(len(self.native.reloads), 6)
        self.assert_keys_unchanged()

    def test_crash_after_successful_activation_is_committed_without_reload(self):
        self.pending_transaction(fully_installed=True)
        self.assertEqual(local.run(self.native)['event'], 'recovered_completed_deployment')
        self.assertEqual((self.native.orders, self.native.reloads), (0, []))
        self.assertNotIn('transaction', self.native.read_state())

    def test_concurrent_consumer_edit_is_preserved_during_rollback(self):
        state, unused = self.pending_transaction()
        edited = Path(self.cfg['consumers'][0]['files']['fullchain_pem'])
        edited.write_bytes(self.cert.fresh)
        with self.assertRaisesRegex(RenewalError, 'could not be rolled back'):
            self.native.rollback(state)
        self.assertEqual(edited.read_bytes(), self.cert.fresh)
        self.assertEqual(state['transaction']['phase'], 'rollback_failed')

    def test_wrong_existing_consumer_key_is_not_replaced_or_activated(self):
        target = Path(self.cfg['consumers'][0]['key_path'])
        changed_key = self.cert.private(self.cert.other_key)
        target.write_bytes(changed_key)
        with self.assertRaisesRegex(RenewalError, 'private key differs'):
            local.run(self.native)
        self.assertEqual(target.read_bytes(), changed_key)
        self.assertEqual(self.native.reloads, [])

    def test_newer_existing_consumer_certificate_is_never_downgraded(self):
        newer = self.cert.leaf(NOW - 30, NOW + 91 * DAY)
        target = Path(self.cfg['consumers'][0]['files']['fullchain_pem'])
        target.write_bytes(newer)
        with self.assertRaisesRegex(RenewalError, 'issuance date did not advance'):
            local.run(self.native)
        self.assertEqual(target.read_bytes(), newer)
        self.assertEqual(self.native.reloads, [])

    def test_corrupt_cached_pending_bytes_are_rebuilt_from_valid_live_lineage(self):
        self.native.forward_failure.add('mail')
        with self.assertRaises(RenewalError): local.run(self.native)
        state = self.native.read_state()
        cache = self.native.directory / state['pending']['cache']
        cache.write_bytes(b'corrupt cached certificate')
        self.native.forward_failure.clear(); self.native.clock += 4000
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'deployment_completed')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(cache.read_bytes(), self.cert.new)

    def test_newer_live_lineage_supersedes_expired_and_corrupt_pending_cache(self):
        self.native.forward_failure.add('mail')
        with self.assertRaises(RenewalError): local.run(self.native)
        state = self.native.read_state()
        (self.native.directory / state['pending']['cache']).write_bytes(b'corrupt old cache')
        self.native.clock += 100 * DAY
        newer = self.cert.leaf(self.native.clock - 60, self.native.clock + 90 * DAY)
        (self.lineage / 'fullchain.pem').write_bytes(newer)
        self.native.forward_failure.clear()
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'deployment_completed')
        self.assertEqual(self.native.orders, 1)
        self.assertEqual(self.native.read_state()['issued']['sha256'], certificate_info(newer)['sha256'])

    def test_expired_pending_leaf_gets_a_normally_due_order_without_permanent_retry_trap(self):
        self.native.forward_failure.add('mail')
        with self.assertRaises(RenewalError): local.run(self.native)
        self.native.clock += 100 * DAY
        self.native.replacement = self.cert.leaf(self.native.clock - 60, self.native.clock + 90 * DAY)
        self.native.forward_failure.clear()
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 2)
        self.assertNotIn('pending', self.native.read_state())

    def test_expired_interrupted_transaction_is_restored_before_a_fresh_due_order(self):
        self.pending_transaction()
        self.native.clock += 100 * DAY
        self.native.replacement = self.cert.leaf(self.native.clock - 60, self.native.clock + 90 * DAY)
        self.assertEqual(local.run(self.native, retry_only=True)['event'], 'renewed_and_deployed')
        self.assertEqual(self.native.orders, 1)
        relaxed = [item for item in self.native.verifications if not item[2]]
        self.assertEqual(len(relaxed), 3)
        for name, fingerprint, unused in relaxed:
            self.assertEqual(fingerprint, self.native.initial[name])
        self.assertNotIn('transaction', self.native.read_state())

    def test_corrupt_chain_backup_cannot_partially_restore_that_consumer(self):
        state, unused = self.pending_transaction(fully_installed=True)
        first = state['transaction']['consumers'][0]
        chain = next(item for item in first['files'] if item['field'] == 'chain_pem')
        (self.native.directory / chain['backup']).write_bytes(b'corrupt chain backup')
        target = Path(self.native.consumers[first['name']]['files']['fullchain_pem'])
        self.assertEqual(target.read_bytes(), self.cert.new)
        with self.assertRaisesRegex(RenewalError, 'could not be rolled back'):
            self.native.rollback(state)
        self.assertEqual(target.read_bytes(), self.cert.new)
        self.assertNotIn(first['name'], [name for name, unused in self.native.reloads])

    def test_relaxed_peer_check_is_used_only_for_exact_previous_rollback_identity(self):
        self.native.forward_failure.add('mail')
        with self.assertRaises(RenewalError): local.run(self.native)
        relaxed = [item for item in self.native.verifications if not item[2]]
        self.assertEqual(len(relaxed), 3)
        for name, fingerprint, trusted in relaxed:
            self.assertEqual(fingerprint, self.native.initial[name])
        for name, fingerprint, trusted in self.native.verifications:
            if fingerprint != self.native.initial[name]: self.assertTrue(trusted)
        consumer = self.cfg['consumers'][0]
        with patch.object(local, 'endpoint_fingerprint', return_value='0' * 64) as peer:
            self.assertFalse(local.Native(self.cfg).verify(consumer, self.native.initial[consumer['name']], trusted=False))
            self.assertEqual(peer.call_args.kwargs, {'trusted': False})

    def test_certbot_command_is_named_reuses_key_and_disables_directory_hooks(self):
        recorded = []
        def runner(args, **kwargs):
            recorded.append(args)
            return b'certbot 1.21.0\n' if '--version' in args else b''
        with patch.object(local, 'run_command', runner):
            self.assertTrue(local.Native(self.cfg).issue())
        actual = recorded[-1]
        for required in ('--cert-name', 'fixture', '--reuse-key', '--force-renewal', '--no-directory-hooks'):
            self.assertIn(required, actual)
        self.assertEqual(actual[:len(self.cfg['command_prefix'])], self.cfg['command_prefix'])
        self.assertIn('/usr/bin/timeout', actual)
        self.assertNotIn('--duplicate', actual)

    def test_unreviewed_lineage_hook_blocks_certbot_invocation(self):
        with Path(self.cfg['renewal_config']).open('a') as handle:
            handle.write('deploy_hook = unreviewed-command\n')
        with patch.object(local, 'run_command') as runner:
            with self.assertRaisesRegex(RenewalError, 'unreviewed per-lineage'):
                local.Native(self.cfg).issue()
            runner.assert_not_called()

    def test_unknown_certbot_version_blocks_issuance(self):
        with patch.object(local, 'run_command', return_value=b'certbot 9.9.9\n') as runner:
            with self.assertRaisesRegex(RenewalError, 'version changed'):
                local.Native(self.cfg).issue()
            self.assertEqual(runner.call_count, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
