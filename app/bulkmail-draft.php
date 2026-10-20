<?php
declare(strict_types=1);

/*
 * The Grange Bulk Mail
 * Persistent compose draft support
 */

function bulkmail_ensure_draft_table(PDO $db): void
{
    $db->exec(
        'CREATE TABLE IF NOT EXISTS compose_drafts (
            user_id INTEGER NOT NULL,
            acting_for_user_id INTEGER NOT NULL,
            sender_identity_id INTEGER,
            custom_from TEXT,
            subject TEXT NOT NULL DEFAULT "",
            body_html TEXT NOT NULL DEFAULT "",
            all_contacts INTEGER NOT NULL DEFAULT 0,
            groups_json TEXT NOT NULL DEFAULT "[]",
            contacts_json TEXT NOT NULL DEFAULT "[]",
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, acting_for_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(acting_for_user_id) REFERENCES users(id) ON DELETE CASCADE
        )'
    );
}

function bulkmail_clear_compose_draft(PDO $db, int $userId, int $actingFor): void
{
    bulkmail_ensure_draft_table($db);
    bulkmail_archive_draft($db,$userId,$actingFor,'Before clearing');

    $s = $db->prepare(
        'DELETE FROM compose_drafts
         WHERE user_id=? AND acting_for_user_id=?'
    );

    $s->execute([$userId, $actingFor]);
}

function bulkmail_handle_draft_api(PDO $db, string $page): void
{
    if ($page !== 'draft_api') {
        return;
    }

    bulkmail_ensure_draft_table($db);

    $userId = (int)$_SESSION['user_id'];
    $actingFor = (int)($_GET['acting_for'] ?? $_POST['acting_for'] ?? $userId);

    if (!is_admin()) {
        $actingFor = $userId;
    }

    allowed_context($db, $actingFor);

    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $s = $db->prepare(
            'SELECT *
             FROM compose_drafts
             WHERE user_id=? AND acting_for_user_id=?'
        );

        $s->execute([$userId, $actingFor]);
        $row = $s->fetch();

        if (!$row) {
            echo json_encode(['ok' => true, 'draft' => null]);
            exit;
        }

        echo json_encode([
            'ok' => true,
            'draft' => [
                'sender_identity_id' => $row['sender_identity_id'],
                'custom_from' => $row['custom_from'],
                'subject' => $row['subject'],
                'body_html' => $row['body_html'],
                'all_contacts' => (bool)$row['all_contacts'],
                'groups' => json_decode($row['groups_json'], true) ?: [],
                'contacts' => json_decode($row['contacts_json'], true) ?: [],
                'updated_at' => $row['updated_at'],
            ],
        ]);

        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['ok' => false]);
        exit;
    }

    check_csrf();
    bm_check_workspace($db,$userId,$actingFor);
    bulkmail_archive_draft($db,$userId,$actingFor,'Before autosave');

    $groups = json_decode((string)($_POST['groups'] ?? '[]'), true);
    $contacts = json_decode((string)($_POST['contacts'] ?? '[]'), true);

    if (!is_array($groups)) {
        $groups = [];
    }

    if (!is_array($contacts)) {
        $contacts = [];
    }

    $groups = array_values(array_unique(array_map('intval', $groups)));
    $contacts = array_values(array_unique(array_map('intval', $contacts)));

    $senderId = (int)($_POST['sender_identity_id'] ?? 0);
    if ($senderId < 1) {
        $senderId = null;
    }

    $s = $db->prepare(
        'INSERT INTO compose_drafts
         (
             user_id,
             acting_for_user_id,
             sender_identity_id,
             custom_from,
             subject,
             body_html,
             all_contacts,
             groups_json,
             contacts_json,
             updated_at
         )
         VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)

         ON CONFLICT(user_id,acting_for_user_id)
         DO UPDATE SET
             sender_identity_id=excluded.sender_identity_id,
             custom_from=excluded.custom_from,
             subject=excluded.subject,
             body_html=excluded.body_html,
             all_contacts=excluded.all_contacts,
             groups_json=excluded.groups_json,
             contacts_json=excluded.contacts_json,
             updated_at=CURRENT_TIMESTAMP'
    );

    $s->execute([
        $userId,
        $actingFor,
        $senderId,
        trim((string)($_POST['custom_from'] ?? '')),
        trim((string)($_POST['subject'] ?? '')),
        sanitize_html((string)($_POST['body_html'] ?? '')),
        !empty($_POST['all_contacts']) ? 1 : 0,
        json_encode($groups),
        json_encode($contacts),
    ]);

    bulkmail_archive_draft($db,$userId,$actingFor,'Autosaved');
    echo json_encode([
        'ok' => true,
        'saved_at' => gmdate('Y-m-d H:i:s'),
    ]);

    exit;
}
