"""Actual issuer-flow regressions for interrupted attempts; no ACME/network.

Certificates and the trust root are generated locally. The real certificate
validation, attempt recovery, due/backoff policy and publication paths run;
only the ACME order and the clock are substituted.
"""
import contextlib
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuer
import renewal_common as common


class InterruptedIssuerRetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = 'mx1.the-grange.uk'
        cls.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        day = dt.timedelta(days=1)
        ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Offline interrupted-issuer fixture CA')])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(cls.now - 100 * day).not_valid_after(cls.now + 365 * day)
              .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
              .sign(ca_key, hashes.SHA256()))
        cls.ca_pem = ca.public_bytes(serialization.Encoding.PEM)

        def leaf(before, after):
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cls.host)]))
                    .issuer_name(ca_name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(before).not_valid_after(after)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(cls.host)]), False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                    .sign(ca_key, hashes.SHA256()))
            return cert.public_bytes(serialization.Encoding.PEM) + cls.ca_pem

        cls.old_raw = leaf(cls.now - 28 * day, cls.now + 62 * day)
        cls.new_raw = leaf(cls.now - dt.timedelta(seconds=60), cls.now + 64 * day)
        cls.fresh_raw = leaf(cls.now - day, cls.now + 89 * day)
        cls.spki = hashlib.sha256(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='issuer-interruption-review-')
        self.root = Path(self.temporary.name)
        self.ca = self.root / 'ca.pem'
        self.ca.write_bytes(self.ca_pem)
        self.config = {'state_dir': str(self.root / 'state'), 'public_dir': str(self.root / 'public'),
                       'hosts': {self.host: {'sans': [self.host], 'spki_sha256': self.spki}}}
        self.attempt = self.root / 'state' / 'attempts' / self.host / 'interrupted'
        self.attempt.mkdir(parents=True)
        (self.attempt / 'fullchain.pem').write_bytes(b'incomplete prior attempt')
        self.state_path = self.root / 'state' / 'issuance' / (self.host + '.json')
        self.orders = []
        self.events = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(issuer, 'validate_bundle', side_effect=self.validate))
        self.stack.enter_context(patch.object(issuer.time, 'time', return_value=self.now.timestamp()))
        self.stack.enter_context(patch.object(issuer, 'run_certbot', side_effect=self.order))
        self.stack.enter_context(contextlib.redirect_stdout(self.events))
        self.enrol(self.old_raw)

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def validate(self, raw, names, pin):
        return common.validate_bundle(raw, names, pin, now=self.now.timestamp(), ca_file=self.ca)

    def enrol(self, raw, phase='issuing', next_attempt_at=0):
        info = self.validate(raw, [self.host], self.spki)
        issuer.publish(self.config, self.host, info, info['not_before'])
        state = issuer.completed_state(info, info['not_before'])
        state.update(phase=phase, failures=0, attempt_directory=str(self.attempt),
                     attempt_started_at=self.now.timestamp() - 3600, next_attempt_at=next_attempt_at)
        common.atomic_json(self.state_path, state)

    def order(self, config, hostname, item, output, staging):
        self.orders.append(hostname)
        (output / 'fullchain.pem').write_bytes(self.new_raw)
        return 0

    def retry(self, apply=True):
        issuer.process_host(self.config, self.host, apply=apply, retry_only=True)

    def test_interrupted_issuing_without_recorded_failure_gets_one_due_retry(self):
        self.retry()
        self.assertEqual(self.orders, [self.host])
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'issued_and_published')

    def test_retry_pending_without_counter_still_reaches_one_due_retry(self):
        self.enrol(self.old_raw, phase='retry_pending')
        self.retry()
        self.assertEqual(self.orders, [self.host])

    def test_complete_interrupted_output_is_recovered_without_another_order(self):
        (self.attempt / 'fullchain.pem').write_bytes(self.new_raw)
        self.retry()
        self.assertEqual(self.orders, [])
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'issued_and_published')
        actual = issuer.published(self.config, self.host, self.config['hosts'][self.host])
        self.assertEqual(actual['sha256'], common.certificate_info(self.new_raw)['sha256'])

    def test_interrupted_attempt_still_honours_recorded_backoff(self):
        self.enrol(self.old_raw, next_attempt_at=self.now.timestamp() + 3600)
        self.retry()
        self.assertEqual(self.orders, [])
        self.assertIn('issuance_backoff', self.events.getvalue())

    def test_interrupted_flag_does_not_override_the_normal_due_window(self):
        self.enrol(self.fresh_raw)
        self.retry()
        self.assertEqual(self.orders, [])
        self.assertIn('certificate_not_due', self.events.getvalue())

    def test_readonly_retry_does_not_order_or_rewrite_state(self):
        before = self.state_path.read_bytes()
        self.retry(apply=False)
        self.assertEqual(self.orders, [])
        self.assertEqual(self.state_path.read_bytes(), before)

    def test_completed_state_without_failure_remains_ineligible_for_hourly_retry(self):
        self.enrol(self.old_raw, phase='issued_and_published')
        self.retry()
        self.assertEqual(self.orders, [])
        self.assertIn('no_issuance_retry_pending', self.events.getvalue())


if __name__ == '__main__':
    unittest.main()
