#!/usr/bin/env python3
"""Read-only, narrow MIME comparison on Derby. Prints no message content or addresses."""
import email.policy
import email.parser
import email.utils
import hashlib
import json
import re
import subprocess

DOCKER = ['pct', 'exec', '400', '--', 'docker', 'exec', '-i', 'onlyoffice-mail-server']

def run(args):
    result = subprocess.run(args, capture_output=True, timeout=25, check=False)
    if result.returncode:
        raise RuntimeError('Read-only command failed; inspect privately')
    if len(result.stdout) > 25 * 1024 * 1024:
        raise RuntimeError('Read limit exceeded')
    return result.stdout

def sender():
    php = ('$db=new PDO("sqlite:/var/lib/bulkmail/bulkmail.sqlite");'
           '$db->exec("PRAGMA query_only=ON");'
           '$s=$db->query("SELECT email FROM sender_identities WHERE id=2 '
           'AND owner_user_id=2 AND active=1");echo $s->fetchColumn();')
    value = run(['pct', 'exec', '300', '--', 'runuser', '-u', 'www-data', '--', 'php', '-r', php]).decode().strip()
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", value):
        raise RuntimeError('Approved sender not found')
    return value

def fetch(mailbox, folder, uid, expected_id):
    data = run(DOCKER + ['doveadm', '-f', 'pager', 'fetch', '-u', mailbox, 'text',
                         'mailbox', folder, 'uid', str(uid)])
    if data.startswith(b'text:\r\n'):
        data = data[7:]
    elif data.startswith(b'text:\n'):
        data = data[6:]
    else:
        raise RuntimeError('Unexpected Dovecot fetch format; no message content printed')
    data = data.rstrip(b'\r\n\x0c')
    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(data)
    actual_id = str(message.get('Message-ID', '')).strip().strip('<>')
    if actual_id != expected_id or not message.get('From'):
        raise RuntimeError('The target UID does not have the expected message identity')
    if message.defects:
        raise RuntimeError('MIME parser defects require private inspection')
    return message

def addresses(message, name):
    # Display-name/format variations do not alter destination identity.
    return sorted(address.casefold() for _, address in
                  email.utils.getaddresses(message.get_all(name, [])))

def parts(message):
    body, attachments = [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True)
        if data is None:
            data = str(part.get_payload()).encode('utf-8')
        if part.get_content_maintype() == 'text' and not part.get_filename():
            text = data.decode(part.get_content_charset() or 'utf-8', errors='strict')
            data = text.replace('\r\n', '\n').replace('\r', '\n').rstrip('\n').encode('utf-8')
            body.append((part.get_content_type(), hashlib.sha256(data).hexdigest()))
        else:
            attachments.append((part.get_content_type(), part.get_content_disposition(),
                                part.get_filename(), str(part.get('Content-ID', '')),
                                hashlib.sha256(data).hexdigest()))
    return sorted(body), sorted(attachments, key=repr)


MYSQL = ['pct', 'exec', '400', '--', 'docker', 'exec', '-i',
         'onlyoffice-mysql-server', 'sh', '-c',
         'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --batch --raw --skip-column-names']

def inventory(mailbox):
    # Address stays inside this subprocess; hex encoding avoids SQL string interpolation.
    address_hex = mailbox.encode('utf-8').hex()
    sql = ("SELECT m.id,m.folder,HEX(m.uidl),HEX(m.mime_message_id),"
           "COALESCE(UNIX_TIMESTAMP(m.date_sent),0) "
           "FROM onlyoffice.mail_mail m JOIN onlyoffice.mail_mailbox b ON b.id=m.id_mailbox "
           "AND b.tenant=m.tenant AND b.id_user=m.id_user "
           "WHERE b.id=22 AND b.tenant=1 AND b.enabled=1 AND b.is_removed=0 "
           "AND LOWER(b.address)=LOWER(CONVERT(UNHEX('" + address_hex + "') USING utf8mb4)) "
           "AND m.is_removed=0 AND m.folder IN(2,3) ORDER BY m.id;\n")
    result = subprocess.run(MYSQL, input=sql.encode(), capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('Read-only inventory query failed; inspect privately')
    rows = []
    for line in result.stdout.decode('ascii').splitlines():
        columns = line.split('\t')
        if len(columns) != 5:
            raise RuntimeError('Unexpected inventory row')
        mid = bytes.fromhex(columns[3]).decode('utf-8').strip().strip('<>')
        uidl = bytes.fromhex(columns[2]).decode('ascii')
        match = re.fullmatch(r'(\d+)-([23])', uidl)
        rows.append({'id': int(columns[0]), 'folder': int(columns[1]),
                     'uid': int(match[1]) if match and int(match[2]) == int(columns[1]) else None,
                     'mid': mid, 'date_sent': int(columns[4])})
    if not rows or len(rows) > 250:
        raise RuntimeError('Inventory empty or exceeds the bounded scan limit')
    return rows

def fingerprint(mailbox, row):
    if row['uid'] is None or not row['mid'] or len(row['mid']) > 1024:
        raise RuntimeError('Unsupported UID or message identity')
    message = fetch(mailbox, 'Sent' if row['folder'] == 2 else 'Drafts', row['uid'], row['mid'])
    body, attachment = parts(message)
    result = {'subject': str(message.get('Subject', '')), 'body': body, 'attachment': attachment}
    for name in ('From', 'To', 'Cc', 'Bcc', 'Reply-To'):
        result[name.casefold().replace('-', '_')] = addresses(message, name)
    return result

def main():
    mailbox = sender()
    rows = inventory(mailbox)
    drafts = [row for row in rows if row['folder'] == 3]
    sent = [row for row in rows if row['folder'] == 2]
    pairs = [(draft, copy) for draft in drafts for copy in sent if draft['mid'] and draft['mid'] == copy['mid']]
    if len(pairs) > 250:
        raise RuntimeError('Too many candidate pairs; no comparison attempted')
    matched_draft_ids = {draft['id'] for draft, _ in pairs}
    print(json.dumps({'phase': 'inventory', 'read_only': True, 'mailbox_id': 22,
                      'draft_rows': len(drafts), 'sent_rows': len(sent), 'candidate_pairs': len(pairs),
                      'unpaired_draft_ids': [row['id'] for row in drafts if row['id'] not in matched_draft_ids]}), flush=True)
    cache, reports = {}, []
    for draft, copy in pairs:
        report = {'draft_id': draft['id'], 'draft_uid': draft['uid'],
                  'sent_id': copy['id'], 'sent_uid': copy['uid'],
                  'message_id_sha256': hashlib.sha256(draft['mid'].encode()).hexdigest(),
                  'draft_date_not_after_sent': draft['date_sent'] > 0 and copy['date_sent'] >= draft['date_sent']}
        try:
            for row in (draft, copy):
                if row['id'] not in cache:
                    cache[row['id']] = fingerprint(mailbox, row)
            d, s = cache[draft['id']], cache[copy['id']]
            report['checks'] = {key + '_equal': d[key] == s[key] for key in d}
            report['draft_body_parts'] = len(d['body'])
            report['sent_body_parts'] = len(s['body'])
            report['draft_attachment_parts'] = len(d['attachment'])
            report['sent_attachment_parts'] = len(s['attachment'])
            report['confirmed_same_payload'] = all(report['checks'].values())
        except Exception as exc:
            report['confirmed_same_payload'] = False
            report['read_error_type'] = type(exc).__name__
        reports.append(report)
        print(json.dumps({'phase': 'pair', 'read_only': True, **report}, sort_keys=True), flush=True)
    exact = [row for row in reports if row['confirmed_same_payload']]
    print(json.dumps({'phase': 'complete', 'read_only': True, 'mailbox_id': 22,
                      'compared_pairs': len(reports), 'exact_pairs': len(exact),
                      'exact_draft_ids': sorted({row['draft_id'] for row in exact}),
                      'older_or_equal_exact_draft_ids': sorted({row['draft_id'] for row in exact if row['draft_date_not_after_sent']}),
                      'unverified_draft_ids': sorted({row['id'] for row in drafts} - {row['draft_id'] for row in exact})}, sort_keys=True), flush=True)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'phase': 'failed', 'read_only': True, 'error_type': type(exc).__name__,
                          'error': str(exc) if isinstance(exc, RuntimeError) else 'Private read/parse failed'}), flush=True)
        raise SystemExit(1)
