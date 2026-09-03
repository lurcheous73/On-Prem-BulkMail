#!/usr/bin/env php
<?php
declare(strict_types=1);

const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';
define(
    'PUBLIC_BASE',
    rtrim(
        getenv('BULKMAIL_PUBLIC_BASE')
        ?: 'http://localhost/',
        '/'
    ) . '/'
);

function open_db(): PDO {
    $db = new PDO('sqlite:' . DB_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('PRAGMA busy_timeout=10000');
    return $db;
}

function logmsg(string $s): void {
    fwrite(STDOUT, date('c') . ' ' . $s . PHP_EOL);
}

function valid_email(string $email): bool {
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL)
        && !preg_match('/[\r\n]/', $email);
}

function mime_header(string $value): string {
    $value = preg_replace('/[\r\n]+/', ' ', $value);
    return mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n");
}

function safe_filename(string $name): string {
    $name = basename($name);
    $name = preg_replace('/[\r\n"]+/', '_', $name);
    return $name !== '' ? $name : 'attachment';
}

function base64_file(string $path): string {
    $data = file_get_contents($path);
    if ($data === false) {
        throw new RuntimeException("Cannot read file: $path");
    }
    return chunk_split(base64_encode($data), 76, "\r\n");
}

function text_from_html(string $html): string {
    $html = preg_replace('#<br\s*/?>#i', "\n", $html);
    $html = preg_replace('#</p>#i', "\n\n", $html);
    $text = html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace("/[ \t]+\n/", "\n", $text);
    $text = preg_replace("/\n{3,}/", "\n\n", $text);
    return trim($text);
}

function build_message(PDO $db, array $mailing, array $recipient): string {
    $from = strtolower(trim((string)$mailing['sender_email']));
    $to   = strtolower(trim((string)$recipient['email']));

    if (!valid_email($from) || !valid_email($to)) {
        throw new RuntimeException('Invalid sender or recipient email address');
    }

    $subject = mime_header((string)$mailing['subject']);
    $toName  = trim((string)($recipient['name'] ?? ''));

    $toHeader = $toName !== ''
        ? mime_header($toName) . ' <' . $to . '>'
        : $to;

    $messageId = sprintf(
        '<bulk-%d-%d-%s@' . (getenv('BULKMAIL_MESSAGE_DOMAIN') ?: 'localhost') . '>',
        (int)$mailing['id'],
        (int)$recipient['id'],
        bin2hex(random_bytes(6))
    );

    $body = (string)$mailing['body_html'];

    if (str_contains($body, '{{UNSUBSCRIBE_URL}}')) {
        $token = (string)($recipient['unsubscribe_token'] ?? '');
        $url = PUBLIC_BASE . '?page=unsubscribe&t=' . rawurlencode($token);
        $body = str_replace('{{UNSUBSCRIBE_URL}}', htmlspecialchars($url, ENT_QUOTES), $body);
    }

    $plain = text_from_html($body);

    $assetStmt = $db->prepare(
        'SELECT * FROM mailing_assets WHERE mailing_id=? ORDER BY page_number,id'
    );
    $assetStmt->execute([(int)$mailing['id']]);
    $assets = $assetStmt->fetchAll();

    $attStmt = $db->prepare(
        'SELECT * FROM mailing_attachments WHERE mailing_id=? ORDER BY id'
    );
    $attStmt->execute([(int)$mailing['id']]);
    $attachments = $attStmt->fetchAll();

    $mixed   = '=_mixed_' . bin2hex(random_bytes(12));
    $alt     = '=_alt_' . bin2hex(random_bytes(12));
    $related = '=_rel_' . bin2hex(random_bytes(12));

    $headers = [];
    $headers[] = 'From: ' . $from;
    $headers[] = 'To: ' . $toHeader;
    $headers[] = 'Subject: ' . $subject;
    $headers[] = 'Date: ' . date(DATE_RFC2822);
    $headers[] = 'Message-ID: ' . $messageId;
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'X-Bulk-Mailer: Brimstone On-Prem BulkMail v2.1.2';

    if (str_contains((string)$mailing['body_html'], '{{UNSUBSCRIBE_URL}}')) {
        $token = (string)($recipient['unsubscribe_token'] ?? '');
        $url = PUBLIC_BASE . '?page=unsubscribe&t=' . rawurlencode($token);
        $headers[] = 'List-Unsubscribe: <' . $url . '>';
    }

    $headers[] = 'Content-Type: multipart/mixed; boundary="' . $mixed . '"';

    $out = implode("\r\n", $headers) . "\r\n\r\n";

    $out .= '--' . $mixed . "\r\n";
    $out .= 'Content-Type: multipart/alternative; boundary="' . $alt . '"' . "\r\n\r\n";

    $out .= '--' . $alt . "\r\n";
    $out .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $out .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $out .= quoted_printable_encode($plain) . "\r\n\r\n";

    $out .= '--' . $alt . "\r\n";
    $out .= 'Content-Type: multipart/related; boundary="' . $related . '"' . "\r\n\r\n";

    $out .= '--' . $related . "\r\n";
    $out .= "Content-Type: text/html; charset=UTF-8\r\n";
    $out .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $out .= quoted_printable_encode($body) . "\r\n\r\n";

    foreach ($assets as $asset) {
        $path = (string)$asset['stored_path'];
        if (!is_file($path)) {
            throw new RuntimeException('Missing inline asset: ' . $path);
        }

        $mime = trim((string)$asset['mime_type']) ?: 'image/jpeg';
        $cid  = preg_replace('/[^A-Za-z0-9_.@-]/', '', (string)$asset['cid']);
        if ($cid === '') {
            throw new RuntimeException('Invalid inline asset CID');
        }

        $out .= '--' . $related . "\r\n";
        $out .= 'Content-Type: ' . $mime . "\r\n";
        $out .= "Content-Transfer-Encoding: base64\r\n";
        $out .= 'Content-ID: <' . $cid . ">\r\n";
        $out .= 'Content-Disposition: inline; filename="page-' .
                (int)($asset['page_number'] ?? 0) . ".jpg\"\r\n\r\n";
        $out .= base64_file($path) . "\r\n";
    }

    $out .= '--' . $related . "--\r\n";
    $out .= '--' . $alt . "--\r\n";

    foreach ($attachments as $att) {
        $path = (string)$att['stored_path'];
        if (!is_file($path)) {
            throw new RuntimeException('Missing attachment: ' . $path);
        }

        $mime = trim((string)$att['mime_type']) ?: 'application/octet-stream';
        $name = safe_filename((string)$att['original_name']);
        $encodedName = rawurlencode($name);

        $out .= '--' . $mixed . "\r\n";
        $out .= 'Content-Type: ' . $mime . '; name="' . $name . '"' . "\r\n";
        $out .= "Content-Transfer-Encoding: base64\r\n";
        $out .= 'Content-Disposition: attachment; filename="' . $name .
                '"; filename*=UTF-8\'\'' . $encodedName . "\r\n\r\n";
        $out .= base64_file($path) . "\r\n";
    }

    $out .= '--' . $mixed . "--\r\n";

    return $out;
}

function submit_message(string $from, string $to, string $message): array {
    $cmd = ['/usr/sbin/sendmail', '-i', '-f', $from, '--', $to];

    $spec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $proc = proc_open($cmd, $spec, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Could not start Postfix sendmail');
    }

    fwrite($pipes[0], $message);
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $code = proc_close($proc);

    return [$code, trim($stdout . "\n" . $stderr)];
}

while (true) {
    // Re-open SQLite for every polling cycle.
    // This prevents the long-running worker retaining a stale WAL/read snapshot.
    $db = open_db();

    try {
        $db->beginTransaction();

        $row = $db->query(
            "SELECT mr.*
             FROM mailing_recipients mr
             JOIN mailings m ON m.id=mr.mailing_id
             WHERE mr.status='queued'
               AND m.status IN ('queued','submitting')
             ORDER BY m.is_test DESC,m.id,mr.id
             LIMIT 1"
        )->fetch();

        if (!$row) {
            $db->commit();
            $db = null;
            sleep(2);
            continue;
        }

        $rid = (int)$row['id'];
        $mid = (int)$row['mailing_id'];

        $claim = $db->prepare(
            "UPDATE mailing_recipients
             SET status='processing', error=NULL
             WHERE id=? AND status='queued'"
        );
        $claim->execute([$rid]);

        if ($claim->rowCount() !== 1) {
            $db->rollBack();
            usleep(200000);
            continue;
        }

        $db->prepare(
            "UPDATE mailings SET status='submitting'
             WHERE id=? AND status='queued'"
        )->execute([$mid]);

        $db->commit();

        $mailStmt = $db->prepare(
            'SELECT m.*,u.account_type
             FROM mailings m
             JOIN users u ON u.id=m.acting_for_user_id
             WHERE m.id=?'
        );
        $mailStmt->execute([$mid]);
        $mailing = $mailStmt->fetch();

        if (!$mailing) {
            throw new RuntimeException("Mailing $mid not found");
        }

        $from = strtolower(trim((string)$mailing['sender_email']));
        $to   = strtolower(trim((string)$row['email']));

        $message = build_message($db, $mailing, $row);
        [$code, $detail] = submit_message($from, $to, $message);

        if ($code === 0) {
            $db->prepare(
                "UPDATE mailing_recipients
                 SET status='postfix', error=NULL
                 WHERE id=?"
            )->execute([$rid]);

            logmsg("mailing=$mid recipient=$rid to=$to handed_to_postfix");
        } else {
            $db->prepare(
                "UPDATE mailing_recipients
                 SET status='failed', error=?
                 WHERE id=?"
            )->execute([substr($detail, 0, 2000), $rid]);

            logmsg("mailing=$mid recipient=$rid to=$to FAILED code=$code $detail");
        }

        $counts = $db->prepare(
            "SELECT
               SUM(CASE WHEN status IN ('queued','processing') THEN 1 ELSE 0 END) pending,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) failed,
               SUM(CASE WHEN status='postfix' THEN 1 ELSE 0 END) postfix
             FROM mailing_recipients
             WHERE mailing_id=?"
        );
        $counts->execute([$mid]);
        $c = $counts->fetch();

        if ((int)($c['pending'] ?? 0) === 0) {
            $newStatus = (int)($c['failed'] ?? 0) > 0 ? 'partial' : 'submitted';
            $db->prepare('UPDATE mailings SET status=? WHERE id=?')
               ->execute([$newStatus, $mid]);
        }

        $db = null;

    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }

        if (isset($rid) && $rid) {
            try {
                $db->prepare(
                    "UPDATE mailing_recipients
                     SET status='failed', error=?
                     WHERE id=?"
                )->execute([substr($e->getMessage(), 0, 2000), $rid]);
            } catch (Throwable $ignored) {
            }
        }

        logmsg('ERROR ' . $e->getMessage());
        $db = null;
        sleep(2);
    }
}
