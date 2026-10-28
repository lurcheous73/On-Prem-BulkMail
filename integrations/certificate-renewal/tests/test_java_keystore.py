"""Actual Java/PKCS12 fixture checks; generated test keys only, no production I/O."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

SOURCE = Path(__file__).resolve().parents[1] / 'java/GrangeRenewalKeystore.java'
PASSWORD = b'local-test-fixture-only'


def signed_certificate(key, issuer_key, issuer, before, after, ca=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture CA' if ca else 'mx2.brimstonecottage.uk')])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(before).not_valid_after(after)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('mx2.brimstonecottage.uk')]), False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    return builder.sign(issuer_key or key, hashes.SHA256())


@unittest.skipUnless(shutil.which('java'), 'a local JDK is needed for the offline Java adapter test')
class JavaKeystore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='java-pfx-test-')
        cls.base = Path(cls.temporary.name)
        result = subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '--release', '8',
                                 '-d', str(cls.base), str(SOURCE)], capture_output=True, timeout=30)
        if result.returncode:
            raise unittest.SkipTest('local Java compiler module unavailable')
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.ca = signed_certificate(cls.ca_key, None, None, now - dt.timedelta(days=100), now + dt.timedelta(days=365), True)
        cls.old = signed_certificate(cls.key, cls.ca_key, cls.ca.subject, now - dt.timedelta(days=28), now + dt.timedelta(days=62))
        cls.new = signed_certificate(cls.key, cls.ca_key, cls.ca.subject, now - dt.timedelta(seconds=1), now + dt.timedelta(days=64))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.base))
        self.config, self.pfx, self.fullchain, self.output, self.oldleaf = [self.work / name for name in
            ('config.xml', 'old.pfx', 'new-chain.pem', 'new.pfx', 'old-leaf.pem')]
        self.config.write_text('<AppConfig><sslCertKeystoreType>PKCS12</sslCertKeystoreType><sslCertificatePassword encrypted="false">' +
                               PASSWORD.decode() + '</sslCertificatePassword></AppConfig>')
        self.pfx.write_bytes(pkcs12.serialize_key_and_certificates(b'preserved-alias', self.key, self.old, [self.ca],
                            serialization.BestAvailableEncryption(PASSWORD)))
        self.pfx.chmod(0o600)
        self.original_pfx = self.pfx.read_bytes()
        self.fullchain.write_bytes(self.new.public_bytes(serialization.Encoding.PEM) + self.ca.public_bytes(serialization.Encoding.PEM))
        self.java_classpath = str(self.base)

    def invoke(self, inspect=False):
        args = ['java', '-cp', self.java_classpath, 'GrangeRenewalKeystore']
        args += ['--inspect', str(self.config), str(self.pfx), str(self.oldleaf)] if inspect else [
            str(self.config), str(self.pfx), str(self.fullchain), str(self.output), str(self.oldleaf)]
        return subprocess.run(args, capture_output=True, timeout=20)

    def test_inspect_validates_store_without_replacing_it(self):
        result = self.invoke(True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['event'], 'java_keystore_inspected')
        self.assertEqual(self.pfx.read_bytes(), self.original_pfx)
        self.assertFalse(self.output.exists())
        self.assertEqual(x509.load_pem_x509_certificate(self.oldleaf.read_bytes()).fingerprint(hashes.SHA256()), self.old.fingerprint(hashes.SHA256()))

    def test_rechain_plus_two_days_preserves_alias_key_password(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        original, changed = pkcs12.load_pkcs12(self.original_pfx, PASSWORD), pkcs12.load_pkcs12(self.output.read_bytes(), PASSWORD)
        self.assertEqual(original.key.private_numbers(), changed.key.private_numbers())
        self.assertEqual(original.cert.friendly_name, changed.cert.friendly_name)
        self.assertEqual(changed.cert.certificate.fingerprint(hashes.SHA256()), self.new.fingerprint(hashes.SHA256()))
        self.assertEqual(self.pfx.read_bytes(), self.original_pfx)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_wrong_key_is_rejected_without_output_store(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong = signed_certificate(other, self.ca_key, self.ca.subject, self.new.not_valid_before_utc, self.new.not_valid_after_utc)
        self.fullchain.write_bytes(wrong.public_bytes(serialization.Encoding.PEM) + self.ca.public_bytes(serialization.Encoding.PEM))
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.pfx.read_bytes(), self.original_pfx)

    def test_wrong_password_emits_fixed_stage_without_secret(self):
        self.config.write_text(self.config.read_text().replace(PASSWORD.decode(), 'incorrect-fixture-password'))
        result = self.invoke(True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['stage'], 'load_existing_pkcs12')
        self.assertNotIn(b'incorrect-fixture-password', result.stdout + result.stderr)
        self.assertFalse(self.oldleaf.exists())

    def test_nonadvancing_expiry_is_rejected(self):
        wrong = signed_certificate(self.key, self.ca_key, self.ca.subject, self.new.not_valid_before_utc, self.old.not_valid_after_utc)
        self.fullchain.write_bytes(wrong.public_bytes(serialization.Encoding.PEM) + self.ca.public_bytes(serialization.Encoding.PEM))
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.output.exists())

    def decoder_fixture(self, named=False, pin_fixture=False, wrong_static=False, wrong_decoder_pin=False):
        directory = self.work / 'native-fixture'
        util = directory / 'com/synametrics/commons/util'
        parser = directory / 'com/synametrics/xeams/util'
        util.mkdir(parents=True)
        parser.mkdir(parents=True)
        api = '''if (mode != 8 || !value.equals("fixture-configured-value")) throw new IllegalArgumentException();
                 System.out.println("discarded-native-diagnostic");
                 return "local-test-fixture-only";'''
        sources = []
        if named:
            # Reproduce Canada CT100's unrelated, nonpublic obfuscated B name.
            (util / 'B.java').write_text('package com.synametrics.commons.util; class B { B() {} }')
            static = '' if wrong_static else 'static '
            (util / 'TGlob.java').write_text('package com.synametrics.commons.util; public class TGlob { public ' +
                static + 'String decryptPassword(String value, int mode) {' + api + '} }')
            (parser / 'AppConfigAdapter.java').write_text('package com.synametrics.xeams.util; public class AppConfigAdapter {}')
            sources.extend([util / 'B.java', util / 'TGlob.java', parser / 'AppConfigAdapter.java'])
        else:
            (util / 'B.java').write_text('package com.synametrics.commons.util; public class B { public B() {} public String e(String value, int mode) {' + api + '} }')
            sources.append(util / 'B.java')
        result = subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '--release', '8', '-d', str(directory),
                                 *map(str, sources)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        if pin_fixture:
            # Substitute ONLY the two enrollment fingerprints in a temporary
            # test build. The production source/class and actual native class
            # hashes stay unchanged; no proprietary class bytes are required.
            source = SOURCE.read_text()
            pins = {'NAMED_ADAPTER_SHA256': hashlib.sha256((parser / 'AppConfigAdapter.class').read_bytes()).hexdigest(),
                    'NAMED_DECODER_SHA256': hashlib.sha256((util / 'TGlob.class').read_bytes()).hexdigest()}
            if wrong_decoder_pin:
                pins['NAMED_DECODER_SHA256'] = '0' * 64
            for name, value in pins.items():
                source, count = re.subn('(' + name + ' = ")[0-9a-f]{64}(";)', r'\g<1>' + value + r'\2', source)
                self.assertEqual(count, 1)
            adapter = directory / 'GrangeRenewalKeystore.java'
            adapter.write_text(source)
            result = subprocess.run(['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '--release', '8',
                                     '-d', str(directory), str(adapter)], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0)
        self.java_classpath = str(directory) + ':' + str(self.base)
        self.config.write_text(self.config.read_text().replace('encrypted="false"', 'encrypted="true"').replace(PASSWORD.decode(), 'fixture-configured-value'))

    def test_inspected_legacy_public_instance_api_decodes_only_tls_field(self):
        self.decoder_fixture()
        result = self.invoke(True)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b'discarded-native-diagnostic', result.stdout + result.stderr)
        self.assertEqual(self.pfx.read_bytes(), self.original_pfx)

    def test_pinned_named_static_api_handles_nonpublic_unrelated_B(self):
        self.decoder_fixture(named=True, pin_fixture=True)
        result = self.invoke(True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['event'], 'java_keystore_inspected')
        self.assertNotIn(b'discarded-native-diagnostic', result.stdout + result.stderr)
        self.assertEqual(self.pfx.read_bytes(), self.original_pfx)

    def test_unpinned_named_parser_does_not_guess_decoder_or_change_accessibility(self):
        self.decoder_fixture(named=True)
        result = self.invoke(True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['stage'], 'decode_configured_tls_password')
        self.assertFalse(self.oldleaf.exists())

    def test_changed_named_decoder_hash_is_rejected(self):
        self.decoder_fixture(named=True, pin_fixture=True, wrong_decoder_pin=True)
        result = self.invoke(True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.oldleaf.exists())

    def test_named_method_must_have_inspected_static_signature(self):
        self.decoder_fixture(named=True, pin_fixture=True, wrong_static=True)
        result = self.invoke(True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.oldleaf.exists())


if __name__ == '__main__':
    unittest.main()
