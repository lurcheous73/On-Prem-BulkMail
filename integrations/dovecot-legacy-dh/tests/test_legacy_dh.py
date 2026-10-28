"""Offline framing, public-group and real OpenSSL loader checks; no sockets."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_dh', ROOT / 'dovecot_legacy_dh.py')
dh = importlib.util.module_from_spec(spec); spec.loader.exec_module(dh)


def length(value):
    if value < 128: return bytes([value])
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return bytes([128 + len(raw)]) + raw


def integer(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if raw[0] & 128: raw = b'\0' + raw
    return b'\2' + length(len(raw)) + raw


def framing_der(bits):
    # Synthetic values test the original file's framing, not their security.
    # The replacement group is an actual independently validated safe prime.
    content = integer((1 << bits) - 1) + integer(2)
    return b'\x30' + length(len(content)) + content


def packed(records):
    return b''.join(struct.pack('<ii', selector, len(der)) + der for selector, der in records) + b'\0' * 4


class LegacyDHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.strong = (ROOT / 'ffdhe3072.der').read_bytes()
        cls.original = packed([(512, framing_der(512)), (1024, framing_der(1024))])
        cls.candidate = dh.build(cls.original, dh.digest(cls.original), cls.strong)
        cls.temp = tempfile.TemporaryDirectory(prefix='legacy-dh-proof-')
        cls.binary = Path(cls.temp.name) / 'loader'
        subprocess.run(['cc', '-O2', '-Wno-deprecated-declarations', str(ROOT / 'native_loader_probe.c'),
                        '-lcrypto', '-o', str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def test_both_legacy_slots_contain_actual_3072_bit_group(self):
        self.assertEqual(len(self.candidate), 812)
        self.assertEqual([(x['selector'], x['bits'], x['generator']) for x in dh.parse_native(self.candidate)],
                         [(512, 3072, 2), (1024, 3072, 2)])

    def test_pinned_group_passes_actual_openssl_dh_check(self): dh.validate_strong_der(self.strong)

    def test_changed_original_hash_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.build(self.original, '0' * 64, self.strong)

    def test_different_group_is_rejected_even_with_valid_der_shape(self):
        with self.assertRaises(dh.ParameterError): dh.validate_strong_der(framing_der(3072))

    def test_weaker_group_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.validate_strong_der(framing_der(1024))

    def test_unexpected_actual_slot_label_is_rejected(self):
        data = packed([(512, self.strong), (3072, self.strong)])
        with self.assertRaises(dh.ParameterError): dh.parse_native(data)

    def test_duplicate_slot_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.parse_native(packed([(1024, self.strong), (1024, self.strong)]))

    def test_missing_terminator_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.parse_native(self.original[:-4])

    def test_trailing_data_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.parse_native(self.original + b'extra')

    def test_oversize_native_file_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.parse_native(self.original + b'\0' * 1024)

    def test_negative_or_truncated_lengths_are_rejected(self):
        for size in (-1, 1024):
            with self.subTest(size=size), self.assertRaises(dh.ParameterError):
                dh.parse_native(struct.pack('<ii', 512, size) + b'\x30\0')

    def test_noncanonical_der_is_rejected(self):
        with self.assertRaises(dh.ParameterError): dh.dh_values(b'\x30\x81\x06\x02\x01\x03\x02\x01\x02')

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'candidate'; output.write_bytes(b'preserved')
            with self.assertRaises(FileExistsError): dh.write_new_candidate(output, self.candidate)
            self.assertEqual(output.read_bytes(), b'preserved')

    def test_actual_openssl_loader_and_nonexport_callback_receive_3072_bits(self):
        output = Path(self.temp.name) / 'candidate.dat'; output.write_bytes(self.candidate)
        result = subprocess.run([str(self.binary), str(output)], check=True, capture_output=True)
        self.assertIn(b'non_export_selector_1024_actual_bits=3072', result.stdout)

    def test_actual_loader_rejects_unrecognized_selector(self):
        output = Path(self.temp.name) / 'wrong-selector.dat'
        output.write_bytes(packed([(512, self.strong), (3072, self.strong)]))
        self.assertEqual(subprocess.run([str(self.binary), str(output)], capture_output=True).returncode, 5)


if __name__ == '__main__': unittest.main(verbosity=2)
