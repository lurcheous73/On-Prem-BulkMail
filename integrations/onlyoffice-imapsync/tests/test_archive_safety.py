import contextlib
import copy
import email.parser
import email.policy
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('archive_helper', root / 'archive-sent-drafts.py')
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)

def message(body=b'Hello\r\n', additional=b''):
    raw = (b'From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\n'
           b'Subject: Fixture\r\nMessage-ID: <fixture@example.test>\r\n'
           b'Content-Type: text/plain; charset=utf-8\r\n' + additional + b'\r\n' + body)
    return email.parser.BytesParser(policy=email.policy.default).parsebytes(raw)

PAIR = {'phase': 'pair', 'read_only': True, 'draft_id': 10, 'sent_id': 20,
        'draft_uid': 100, 'sent_uid': 200, 'confirmed_same_payload': True,
        'draft_date_not_after_sent': True,
        'message_id_sha256': hashlib.sha256(b'fixture@example.test').hexdigest()}

class FakeBackend:
    def __init__(self):
        self.moves = 0
        self.folder_writes = 0
        self.owner_ok = True
        self.edit_during_verification = False
        self.fp_calls = 0
        self.move_error = False
        self.convergence = True
        self.state = {'source_present': False, 'archive_verified': True, 'sent_preserved': True,
                      'archive_identity': {'folder_guid': 'c' * 32, 'uid': 1}}
        self.records = {
            10: {'id': 10, 'folder': 3, 'uid': 100, 'mid': 'fixture@example.test', 'date_sent': 1},
            20: {'id': 20, 'folder': 2, 'uid': 200, 'mid': 'fixture@example.test', 'date_sent': 2}}
    def assert_owner(self):
        archive.require(self.owner_ok, 'Owner changed')
    def assert_service(self):
        pass
    def rows(self):
        return copy.deepcopy(self.records)
    def identity(self, folder, row):
        return {'folder_guid': ('a' if folder == 'Drafts' else 'b') * 32,
                'message_guid': '1793186578.M787920P1365672.host,S=5958,W=6132',
                'uid': row['uid'], 'uidvalidity': 7}
    def fingerprint(self, folder, row):
        self.fp_calls += 1
        changed = self.edit_during_verification and self.fp_calls > 2 and folder == 'Drafts'
        return archive.strict_fingerprint(message(b'Edited\r\n' if changed else b'Hello\r\n'))
    def archive_matches(self, mid, fingerprint):
        return []
    def move(self, proof):
        self.moves += 1
        if self.move_error:
            raise TimeoutError('Simulated interrupted native move')
    def locate(self, proof):
        return copy.deepcopy(self.state)
    def converged(self, proof):
        return self.convergence
    def status(self, folder):
        return {'messages': 1, 'uidvalidity': 7}
    def ensure_archive(self):
        self.folder_writes += 1
        return self.status('Archive')

class ArchiveSafety(unittest.TestCase):
    def test_native_fetch_preserves_trailing_message_body_newlines(self):
        native = object.__new__(archive.Native)
        native.mailbox = 'fixture@example.test'
        row = {'uid': 100, 'mid': 'fixture@example.test'}
        def frame(raw):
            return b'size.physical: ' + str(len(raw)).encode() + b'\ntext:\n' + raw + b'\x0c\n'
        first = message(b'Hello\n').as_bytes()
        edited = message(b'Hello\n\n').as_bytes()
        with patch.object(native, 'dove', return_value=frame(first)):
            original = native.fingerprint('Sent', row)
        with patch.object(native, 'dove', return_value=frame(edited)):
            modified = native.fingerprint('Drafts', row)
        self.assertNotEqual(original, modified)
        self.assertEqual(archive.parse_sized_message(frame(edited), row['mid']).get_payload(decode=True), b'Hello\n\n')

    def test_native_fetch_rejects_bad_size_or_extra_record(self):
        raw = message().as_bytes()
        frame = b'size.physical: ' + str(len(raw)).encode() + b'\ntext:\n' + raw + b'\x0c\n'
        with self.assertRaises(RuntimeError):
            archive.parse_sized_message(frame + b'text:\nsecond message', 'fixture@example.test')
        with self.assertRaises(RuntimeError):
            archive.parse_sized_message(b'size.physical: 999999\ntext:\n' + raw, 'fixture@example.test')

    def test_body_transport_line_endings_only(self):
        self.assertEqual(archive.strict_fingerprint(message(b'Hello\r\n')), archive.strict_fingerprint(message(b'Hello\n')))
        self.assertNotEqual(archive.strict_fingerprint(message(b'Hello\n')), archive.strict_fingerprint(message(b'Hello\n\n')))
        self.assertNotEqual(archive.strict_fingerprint(message(b'Hello\n')), archive.strict_fingerprint(message(b'Hello \n')))

    def test_part_order_preserved(self):
        first = message()
        first.add_alternative('<p>Hello</p>', subtype='html')
        second = copy.deepcopy(first)
        second.set_payload(list(reversed(second.get_payload())))
        self.assertNotEqual(archive.strict_fingerprint(first), archive.strict_fingerprint(second))

    def test_text_attachment_bytes_and_metadata_preserved(self):
        first = message()
        first.add_attachment(b'A\r\n', maintype='text', subtype='plain', filename='fixture.txt')
        second = copy.deepcopy(first)
        second.get_payload()[1].set_payload('QQo=')
        self.assertNotEqual(archive.strict_fingerprint(first), archive.strict_fingerprint(second))
        second = copy.deepcopy(first)
        second.get_payload()[1].replace_header('Content-Disposition', 'attachment; filename="changed.txt"')
        self.assertNotEqual(archive.strict_fingerprint(first), archive.strict_fingerprint(second))

    def test_modified_recipient_preserved(self):
        first, second = message(), message()
        second.replace_header('To', 'Other <other@example.test>')
        self.assertNotEqual(archive.strict_fingerprint(first), archive.strict_fingerprint(second))

    def test_move_query_binds_all_native_identities(self):
        backend = FakeBackend()
        proof = archive.verify_pair(backend, PAIR)
        query = archive.bound_query(proof['draft_identity'], proof['mid'])
        self.assertEqual(query, ['mailbox-guid', 'a' * 32, 'uid', '100', 'guid',
                                proof['draft_identity']['message_guid'], 'HEADER', 'Message-ID', 'fixture@example.test'])
        self.assertNotIn('200', query)

    def test_changed_owner_stops_before_move(self):
        backend = FakeBackend()
        backend.owner_ok = False
        with self.assertRaises(RuntimeError):
            archive.apply_one(backend, PAIR, lambda row: None)
        self.assertEqual(backend.moves, 0)

    def test_edited_after_first_check_stays_in_drafts(self):
        backend = FakeBackend()
        backend.edit_during_verification = True
        journal = []
        with self.assertRaisesRegex(RuntimeError, 'strict MIME'):
            archive.apply_one(backend, PAIR, journal.append)
        self.assertEqual(backend.moves, 0)
        self.assertEqual(journal, [])

    def test_newer_draft_preserved(self):
        backend = FakeBackend()
        backend.records[10]['date_sent'] = 3
        with self.assertRaises(RuntimeError):
            archive.apply_one(backend, PAIR, lambda row: None)
        self.assertEqual(backend.moves, 0)

    def test_move_error_is_located_and_never_retried(self):
        backend = FakeBackend()
        backend.move_error = True
        journal = []
        with self.assertRaisesRegex(RuntimeError, 'no retry'):
            archive.apply_one(backend, PAIR, journal.append)
        self.assertEqual(backend.moves, 1)
        self.assertEqual([row['event'] for row in journal], ['prepared', 'move_error_no_retry'])
        self.assertTrue(journal[-1]['state']['archive_verified'])
        self.assertFalse(journal[-1]['state']['source_present'])

    def test_unmoved_timeout_is_also_reported_without_retry(self):
        backend = FakeBackend()
        backend.move_error = True
        backend.state.update(source_present=True, archive_verified=False)
        journal = []
        with self.assertRaises(RuntimeError):
            archive.apply_one(backend, PAIR, journal.append)
        self.assertEqual(backend.moves, 1)
        self.assertTrue(journal[-1]['state']['source_present'])
        self.assertFalse(journal[-1]['state']['archive_verified'])

    def test_sent_loss_stops_after_one_move(self):
        backend = FakeBackend()
        backend.state['sent_preserved'] = False
        with self.assertRaisesRegex(RuntimeError, 'Post-move'):
            archive.apply_one(backend, PAIR, lambda row: None)
        self.assertEqual(backend.moves, 1)

    def test_db_nonconvergence_stops_after_one_move(self):
        backend = FakeBackend()
        backend.convergence = False
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'synchronization'):
            archive.apply_one(backend, PAIR, lambda row: None, wait_seconds=0)
        self.assertEqual(backend.moves, 1)

    def test_verified_move_records_native_and_portal_completion(self):
        backend, journal = FakeBackend(), []
        with contextlib.redirect_stdout(io.StringIO()):
            archive.apply_one(backend, PAIR, journal.append)
        self.assertEqual([row['event'] for row in journal], ['prepared', 'move_verified', 'portal_converged'])
        self.assertEqual(backend.moves, 1)

    def test_dry_run_creates_no_folder_journal_or_move(self):
        backend = FakeBackend()
        with tempfile.TemporaryDirectory() as directory:
            report = pathlib.Path(directory, 'report.jsonl')
            report.write_text(json.dumps(PAIR) + '\n' + json.dumps({'phase': 'complete', 'mailbox_id': 22, 'read_only': True}) + '\n')
            args = ['archive', '--report', str(report), '--expected-owner-guid', '00000000-0000-0000-0000-000000000001', '--expected-count', '1']
            with patch.object(sys, 'argv', args), patch.object(archive, 'Native', return_value=backend), \
                    patch.object(archive.os, 'open', side_effect=AssertionError('dry run attempted journal write')), \
                    contextlib.redirect_stdout(io.StringIO()):
                archive.main()
        self.assertEqual(backend.moves, 0)
        self.assertEqual(backend.folder_writes, 0)

if __name__ == '__main__':
    unittest.main()
