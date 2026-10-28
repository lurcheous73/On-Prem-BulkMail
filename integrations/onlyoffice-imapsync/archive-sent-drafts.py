#!/usr/bin/env python3
"""Guarded, reversible IMAP archive of freshly verified Draft/Sent duplicates.

Dry-run is the default. No SMTP operation or SQL mutation exists in this helper.
Run only after the reviewed ImapSync service has been restarted and verified.
"""
import argparse
import email.parser
import email.policy
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('mail_compare', pathlib.Path(__file__).with_name('compare-sent-drafts.py'))
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)

ARCHIVE = 'Recovered sent drafts 2026-10-28'
SERVICE_HASH = 'ffeef42868c9dc0c190ddb56b4dda2b384145bc9f6ef51d09af17f3bf2583b16'
COMMUNITY = ['pct', 'exec', '400', '--', 'docker', 'exec', 'onlyoffice-community-server']
HEADER_FIELDS = ('From', 'Sender', 'Reply-To', 'To', 'Cc', 'Bcc', 'Subject',
                 'In-Reply-To', 'References', 'Disposition-Notification-To',
                 'Return-Receipt-To', 'X-Priority', 'Priority', 'Importance', 'Sensitivity')

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def parse_sized_message(data, expected_mid):
    header = re.match(br'\Asize\.physical: ([0-9]+)\r?\ntext:\r?\n', data)
    require(header is not None, 'Unexpected length-framed Dovecot fetch response')
    size = int(header[1])
    require(0 < size <= 25 * 1024 * 1024, 'Message size exceeds the bounded archive gate')
    body = data[header.end():]
    # This configured Dovecot pager emits exactly FF+LF after the record.
    require(len(body) >= size and body[size:] == b'\x0c\n',
            'Physical message size and Dovecot framing do not agree')
    # Never strip bytes from the message. Only the formatter suffix is excluded.
    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(body[:size])
    require(str(message.get('Message-ID', '')).strip().strip('<>') == expected_mid,
            'Fetched message identity changed')
    require(bool(message.get('From')) and not message.defects, 'Message parse is not suitable for exact comparison')
    return message

def strict_fingerprint(message):
    """Preserve MIME order, metadata and whitespace; normalize CRLF in text only."""
    def tree(part):
        parameters = tuple(sorted((str(key).lower(), str(value))
                                  for key, value in (part.get_params() or [])[1:]
                                  if str(key).lower() != 'boundary'))
        disposition_parameters = tuple(sorted((str(key).lower(), str(value))
                                              for key, value in (part.get_params(header='content-disposition') or [])[1:]))
        metadata = (part.get_content_type(), parameters, part.get_content_disposition(), disposition_parameters,
                    part.get_filename(), tuple(str(part.get(name, '')) for name in
                    ('Content-ID', 'Content-Location', 'Content-Description', 'Content-Language')))
        if part.get_content_type() == 'message/rfc822':
            payload = b'\x00'.join(child.as_bytes() for child in part.get_payload())
            return metadata, hashlib.sha256(payload).hexdigest(), len(payload)
        if part.is_multipart():
            return metadata, part.preamble, part.epilogue, tuple(tree(child) for child in part.iter_parts())
        payload = part.get_payload(decode=True)
        require(payload is not None, 'Undecodable MIME part; preserve this draft')
        require(not part.defects, 'Malformed MIME part; preserve this draft')
        if part.get_content_maintype() == 'text' and part.get_filename() is None and part.get_content_disposition() is None:
            payload = payload.replace(b'\r\n', b'\n')
        return metadata, hashlib.sha256(payload).hexdigest(), len(payload)
    value = (tuple((name, tuple(str(value) for value in message.get_all(name, [])))
                   for name in HEADER_FIELDS), tree(message))
    return hashlib.sha256(json.dumps(value, ensure_ascii=True).encode()).hexdigest()

def parse_search(data):
    result = []
    for line in data.decode('ascii').splitlines():
        fields = line.split()
        require(len(fields) == 2 and re.fullmatch(r'[a-fA-F0-9]{32}', fields[0])
                and fields[1].isdigit(), 'Unexpected Dovecot search response')
        result.append((fields[0].lower(), int(fields[1])))
    return result

def bound_query(identity, mid):
    return ['mailbox-guid', identity['folder_guid'], 'uid', str(identity['uid']),
            'guid', identity['message_guid'], 'HEADER', 'Message-ID', mid]

def emit(phase, **data):
    print(json.dumps({'phase': phase, **data}, sort_keys=True), flush=True)

class Native:
    def __init__(self, expected_owner):
        self.owner = str(uuid.UUID(expected_owner))
        self.mailbox = None
        self.assert_owner()

    def sql(self, query):
        result = subprocess.run(compare.MYSQL, input=(query + '\n').encode(), capture_output=True, timeout=25)
        require(result.returncode == 0, 'Read-only SQL check failed; inspect privately')
        return result.stdout.decode('ascii').strip()

    def assert_owner(self):
        php = ('$db=new PDO("sqlite:/var/lib/bulkmail/bulkmail.sqlite");'
               '$db->exec("PRAGMA query_only=ON");'
               '$q=$db->query("SELECT s.email,l.external_id FROM sender_identities s '
               'JOIN users u ON u.id=s.owner_user_id JOIN user_identity_links l ON l.user_id=u.id '
               'WHERE s.id=2 AND u.id=2 AND s.active=1 AND u.active=1 AND l.active=1 AND l.provider=\'ct400\'");'
               'echo json_encode($q->fetchAll(PDO::FETCH_ASSOC));')
        rows = json.loads(compare.run(['pct', 'exec', '300', '--', 'runuser', '-u', 'www-data', '--', 'php', '-r', php]))
        require(len(rows) == 1 and str(uuid.UUID(rows[0]['external_id'])) == self.owner,
                'Approved sender/account link changed; stop')
        address = rows[0]['email'].strip()
        require(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", address), 'Invalid approved sender')
        value = self.sql('SELECT HEX(address),HEX(id_user) FROM onlyoffice.mail_mailbox '
                         'WHERE id=22 AND tenant=1 AND enabled=1 AND is_removed=0 '
                         'AND is_server_mailbox=1 AND imap=1;').split('\t')
        require(len(value) == 2, 'Configured mailbox unavailable')
        require(bytes.fromhex(value[0]).decode().casefold() == address.casefold()
                and str(uuid.UUID(bytes.fromhex(value[1]).decode())) == self.owner,
                'Mailbox address or verified owner changed; stop')
        require(self.mailbox is None or self.mailbox.casefold() == address.casefold(), 'Approved sender changed during run')
        self.mailbox = address

    def assert_service(self):
        require(compare.run(COMMUNITY + ['systemctl', 'is-active', 'onlyofficeMailImap.service']).strip() == b'active',
                'IMAP synchronization service is not active')
        value = compare.run(COMMUNITY + ['sha256sum', '/var/www/onlyoffice/Services/MailImap/ASC.Mail.ImapSync.Service.dll'])
        require(value.decode().split()[0] == SERVICE_HASH, 'The reviewed v3 service is not installed')

    def dove(self, *arguments):
        return compare.run(compare.DOCKER + ['doveadm', *arguments])

    def status(self, folder):
        value = self.dove('mailbox', 'status', '-u', self.mailbox, 'messages uidvalidity', folder).decode()
        fields = dict(re.findall(r'\b(messages|uidvalidity)=(\d+)', value))
        require(set(fields) == {'messages', 'uidvalidity'}, 'Unexpected mailbox status response')
        return {key: int(number) for key, number in fields.items()}

    def search(self, query):
        return parse_search(self.dove('search', '-u', self.mailbox, *query))

    def identity(self, folder, row):
        matches = self.search(['mailbox', folder, 'uid', str(row['uid']), 'HEADER', 'Message-ID', row['mid']])
        require(len(matches) == 1 and matches[0][1] == row['uid'], 'Source message identity is no longer unique/present')
        value = self.dove('-f', 'pager', 'fetch', '-u', self.mailbox, 'guid',
                          'mailbox', folder, 'uid', str(row['uid'])).decode().strip()
        require(value.startswith('guid: '), 'Unexpected message GUID response')
        guid = value[6:].strip()
        require(re.fullmatch(r'[A-Za-z0-9._,=-]{1,256}', guid), 'Unsupported message GUID format')
        identity = {'folder_guid': matches[0][0], 'message_guid': guid, 'uid': row['uid'],
                    'uidvalidity': self.status(folder)['uidvalidity']}
        require(self.search(bound_query(identity, row['mid'])) == matches,
                'Dovecot identity-bound search is not supported or changed')
        return identity

    def fingerprint(self, folder, row):
        data = self.dove('-f', 'pager', 'fetch', '-u', self.mailbox, 'size.physical text',
                         'mailbox', folder, 'uid', str(row['uid']))
        return strict_fingerprint(parse_sized_message(data, row['mid']))

    def rows(self):
        return {row['id']: row for row in compare.inventory(self.mailbox)}

    def ensure_archive(self):
        folders = self.dove('mailbox', 'list', '-u', self.mailbox).decode().splitlines()
        if ARCHIVE not in folders:
            self.dove('mailbox', 'create', '-u', self.mailbox, ARCHIVE)
        self.dove('mailbox', 'subscribe', '-u', self.mailbox, ARCHIVE)
        return self.status(ARCHIVE)

    def archive_matches(self, mid, fingerprint):
        matches = self.search(['mailbox', ARCHIVE, 'HEADER', 'Message-ID', mid])
        require(len(matches) <= 5, 'Ambiguous archive matches; stop')
        exact = []
        for folder_guid, uid in matches:
            row = {'mid': mid, 'uid': uid}
            if self.fingerprint(ARCHIVE, row) == fingerprint:
                identity = self.identity(ARCHIVE, row)
                exact.append(identity)
        return exact

    def move(self, proof):
        self.dove('move', '-u', self.mailbox, ARCHIVE, *bound_query(proof['draft_identity'], proof['mid']))

    def locate(self, proof):
        state = {'source_present': None, 'archive_verified': None, 'sent_preserved': None}
        try:
            state['source_present'] = bool(self.search(bound_query(proof['draft_identity'], proof['mid'])))
            archive = self.archive_matches(proof['mid'], proof['fingerprint'])
            state['archive_verified'] = len(archive) == 1
            if len(archive) == 1:
                state['archive_identity'] = archive[0]
            state['sent_preserved'] = (self.search(bound_query(proof['sent_identity'], proof['mid']))
                == [(proof['sent_identity']['folder_guid'], proof['sent_identity']['uid'])]
                and self.fingerprint('Sent', proof['sent']) == proof['fingerprint'])
        except Exception:
            state['verification_incomplete'] = True
        return state

    def converged(self, proof):
        owner = self.owner.encode().hex()
        mid = proof['mid'].encode().hex()
        folder = ARCHIVE.encode().hex()
        query = ("SELECT (SELECT COUNT(*) FROM onlyoffice.mail_mail WHERE id=" + str(proof['draft']['id']) +
                 " AND folder=3 AND is_removed=0),(SELECT COUNT(*) FROM onlyoffice.mail_mail WHERE id=" +
                 str(proof['sent']['id']) + " AND folder=2 AND is_removed=0),(SELECT COUNT(*) "
                 "FROM onlyoffice.mail_mail m JOIN onlyoffice.mail_user_folder_x_mail x ON x.id_mail=m.id "
                 "AND x.tenant=m.tenant AND x.id_user=m.id_user JOIN onlyoffice.mail_user_folder f "
                 "ON f.id=x.id_folder AND f.tenant=x.tenant AND f.id_user=x.id_user "
                 "WHERE m.id_mailbox=22 AND m.tenant=1 AND m.folder=6 AND m.is_removed=0 "
                 "AND m.id_user=CONVERT(UNHEX('" + owner + "') USING utf8mb4) "
                 "AND REPLACE(REPLACE(m.mime_message_id,'<',''),'>','')=CONVERT(UNHEX('" + mid + "') USING utf8mb4) "
                 "AND f.name=CONVERT(UNHEX('" + folder + "') USING utf8mb4));")
        values = [int(value) for value in self.sql(query).split('\t')]
        return len(values) == 3 and values[0] == 0 and values[1] == 1 and values[2] >= 1

def verify_pair(backend, pair):
    backend.assert_owner()
    rows = backend.rows()
    draft, sent = rows.get(pair['draft_id']), rows.get(pair['sent_id'])
    require(draft is not None and sent is not None, 'A selected portal row changed; preserve it and rescan')
    require(draft['folder'] == 3 and sent['folder'] == 2 and draft['uid'] == pair['draft_uid']
            and sent['uid'] == pair['sent_uid'] and draft['mid'] == sent['mid'], 'Selected row identity changed')
    require(draft['date_sent'] > 0 and sent['date_sent'] >= draft['date_sent'], 'Draft is newer than Sent; preserve it')
    require(hashlib.sha256(draft['mid'].encode()).hexdigest() == pair['message_id_sha256'], 'Message identity changed')
    draft_identity = backend.identity('Drafts', draft)
    sent_identity = backend.identity('Sent', sent)
    draft_fp = backend.fingerprint('Drafts', draft)
    sent_fp = backend.fingerprint('Sent', sent)
    require(draft_fp == sent_fp, 'Fresh strict MIME comparison differs; preserve this draft')
    return {'draft': draft, 'sent': sent, 'mid': draft['mid'], 'fingerprint': draft_fp,
            'draft_identity': draft_identity, 'sent_identity': sent_identity}

def apply_one(backend, pair, journal, wait_seconds=45):
    backend.assert_service()
    proof = verify_pair(backend, pair)
    require(not backend.archive_matches(proof['mid'], proof['fingerprint']), 'Archive already contains this identity; inspect journal before continuing')
    # Repeat the complete strict check immediately before the identity-bound move.
    fresh = verify_pair(backend, pair)
    require(fresh == proof, 'Message changed during verification; preserve it')
    journal({'event': 'prepared', 'archive_folder': ARCHIVE, 'proof': proof})
    try:
        backend.move(proof)
    except Exception:
        state = backend.locate(proof)
        journal({'event': 'move_error_no_retry', 'draft_id': proof['draft']['id'], 'state': state})
        raise RuntimeError('MOVE returned an error; verified state was journaled and no retry was attempted')
    state = backend.locate(proof)
    journal({'event': 'move_verified', 'draft_id': proof['draft']['id'], 'state': state})
    require(state.get('source_present') is False and state.get('archive_verified') is True
            and state.get('sent_preserved') is True, 'Post-move verification incomplete; stop and inspect journal')
    emit('archived', draft_id=proof['draft']['id'], sent_id=proof['sent']['id'], archive_uid=state['archive_identity']['uid'])
    deadline = time.monotonic() + wait_seconds
    while True:
        if backend.converged(proof):
            journal({'event': 'portal_converged', 'draft_id': proof['draft']['id']})
            return state
        require(time.monotonic() < deadline, 'Normal portal synchronization did not converge; no further moves attempted')
        time.sleep(2)

def read_pairs(path):
    data = [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]
    require(any(row.get('phase') == 'complete' and row.get('mailbox_id') == 22 and row.get('read_only') is True for row in data),
            'A complete read-only comparison report is required')
    pairs = {}
    for row in data:
        if row.get('phase') == 'pair' and row.get('confirmed_same_payload') is True and row.get('draft_date_not_after_sent') is True:
            for key in ('draft_id', 'draft_uid', 'sent_id', 'sent_uid'):
                require(type(row.get(key)) is int and row[key] > 0, 'Invalid report identity')
            require(re.fullmatch(r'[a-f0-9]{64}', row.get('message_id_sha256', '')), 'Invalid report message hash')
            pairs.setdefault(row['draft_id'], row)
    require(0 < len(pairs) <= 64, 'No eligible pairs or scan exceeds limit')
    return list(pairs.values())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--expected-owner-guid', required=True)
    parser.add_argument('--expected-count', type=int, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--journal')
    args = parser.parse_args()
    pairs = read_pairs(args.report)
    require(len(pairs) == args.expected_count, 'Candidate count differs from the reviewed report')
    backend = Native(args.expected_owner_guid)
    backend.assert_service()
    before = {folder: backend.status(folder) for folder in ('Drafts', 'Sent')}
    # Complete preflight before creating any folder or journal.
    for pair in pairs:
        proof = verify_pair(backend, pair)
        emit('verified', draft_id=pair['draft_id'], sent_id=pair['sent_id'], fingerprint=proof['fingerprint'])
    if not args.apply:
        emit('dry_run_complete', exact_pairs=len(pairs), before=before, mutations=0)
        return
    require(bool(args.journal), '--journal is required with --apply')
    descriptor = os.open(args.journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, 'a') as stream:
        def journal(row):
            stream.write(json.dumps(row, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        journal({'event': 'start', 'candidate_count': len(pairs), 'before': before, 'archive_folder': ARCHIVE})
        backend.ensure_archive()
        for pair in pairs:
            apply_one(backend, pair, journal)
        after = {folder: backend.status(folder) for folder in ('Drafts', 'Sent', ARCHIVE)}
        journal({'event': 'complete', 'moved': len(pairs), 'after': after})
        emit('complete', moved=len(pairs), before=before, after=after,
             sent_count_unchanged=after['Sent']['messages'] == before['Sent']['messages'],
             expected_draft_count=before['Drafts']['messages'] - len(pairs))

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        emit('stopped', error_type=type(exc).__name__,
             reason=str(exc) if isinstance(exc, RuntimeError) else 'Private operation failed; inspect the journal')
        raise SystemExit(1)
