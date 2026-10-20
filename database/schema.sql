-- Schema only; SQLite creates sqlite_sequence automatically.
CREATE TABLE users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL,
 email TEXT,
 organisation TEXT,
 account_type TEXT NOT NULL DEFAULT 'internal' CHECK(account_type IN ('internal','marketing')),
 is_admin INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
, locked_sender_identity_id INTEGER);
CREATE TABLE domains (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
 description TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_domains (
 user_id INTEGER NOT NULL,
 domain_id INTEGER NOT NULL,
 PRIMARY KEY(user_id,domain_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
CREATE TABLE sender_identities (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 domain_id INTEGER,
 label TEXT NOT NULL,
 email TEXT NOT NULL COLLATE NOCASE,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(owner_user_id,email),
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE SET NULL
);
CREATE TABLE contacts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 name TEXT,
 company TEXT,
 email TEXT NOT NULL COLLATE NOCASE,
 telephone TEXT,
 unit_name TEXT,
 unit_number TEXT,
 notes TEXT,
 lawful_basis TEXT,
 source TEXT,
 source_date TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(owner_user_id,email),
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE groups (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 name TEXT NOT NULL COLLATE NOCASE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(owner_user_id,name),
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE group_members (
 group_id INTEGER NOT NULL,
 contact_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,contact_id),
 FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
 FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE TABLE suppressions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 email TEXT NOT NULL COLLATE NOCASE,
 reason TEXT NOT NULL DEFAULT 'unsubscribe',
 source_mailing_id INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 created_by_user_id INTEGER,
 UNIQUE(owner_user_id,email),
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE mailings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 initiated_by_user_id INTEGER NOT NULL,
 acting_for_user_id INTEGER NOT NULL,
 sender_identity_id INTEGER,
 sender_email TEXT NOT NULL,
 subject TEXT NOT NULL,
 body_html TEXT NOT NULL,
 selected_count INTEGER NOT NULL DEFAULT 0,
 unique_count INTEGER NOT NULL DEFAULT 0,
 duplicate_count INTEGER NOT NULL DEFAULT 0,
 suppressed_count INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'queued',
 is_test INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(initiated_by_user_id) REFERENCES users(id),
 FOREIGN KEY(acting_for_user_id) REFERENCES users(id),
 FOREIGN KEY(sender_identity_id) REFERENCES sender_identities(id)
);
CREATE TABLE mailing_recipients (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_id INTEGER NOT NULL,
 contact_id INTEGER,
 email TEXT NOT NULL,
 name TEXT,
 unsubscribe_token TEXT UNIQUE,
 status TEXT NOT NULL DEFAULT 'queued',
 queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 sent_at TEXT,
 error TEXT,
 FOREIGN KEY(mailing_id) REFERENCES mailings(id) ON DELETE CASCADE
);
CREATE TABLE mailing_attachments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_id INTEGER NOT NULL,
 original_name TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 mime_type TEXT,
 file_size INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(mailing_id) REFERENCES mailings(id) ON DELETE CASCADE
);
CREATE TABLE mailing_assets (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_id INTEGER NOT NULL,
 cid TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 mime_type TEXT NOT NULL DEFAULT 'image/jpeg',
 page_number INTEGER,
 UNIQUE(mailing_id,cid),
 FOREIGN KEY(mailing_id) REFERENCES mailings(id) ON DELETE CASCADE
);
CREATE TABLE audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 action TEXT NOT NULL,
 details TEXT,
 ip_address TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE login_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT,
 ip_address TEXT,
 success INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE organisation_settings (
 user_id INTEGER PRIMARY KEY,
 privacy_notice_url TEXT,
 footer_name TEXT,
 footer_address TEXT,
 footer_phone TEXT,
 retention_months INTEGER NOT NULL DEFAULT 36,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_contacts_owner ON contacts(owner_user_id);
CREATE INDEX idx_groups_owner ON groups(owner_user_id);
CREATE INDEX idx_suppressions_owner_email ON suppressions(owner_user_id,email);
CREATE INDEX idx_recipients_mailing ON mailing_recipients(mailing_id);
CREATE INDEX idx_login_attempts_lookup ON login_attempts(username,ip_address,created_at);
CREATE TABLE compose_drafts (
    user_id INTEGER NOT NULL,
    acting_for_user_id INTEGER NOT NULL,
    sender_identity_id INTEGER,
    custom_from TEXT,
    subject TEXT NOT NULL DEFAULT '',
    body_html TEXT NOT NULL DEFAULT '',
    all_contacts INTEGER NOT NULL DEFAULT 0,
    groups_json TEXT NOT NULL DEFAULT '[]',
    contacts_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, acting_for_user_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(acting_for_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE mailing_recipient_attachments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_recipient_id INTEGER NOT NULL,
 original_name TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 mime_type TEXT,
 file_size INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(mailing_recipient_id) REFERENCES mailing_recipients(id) ON DELETE CASCADE
);
CREATE INDEX idx_recipient_attachments_recipient ON mailing_recipient_attachments(mailing_recipient_id);
CREATE TABLE email_templates (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 created_by_user_id INTEGER,
 sender_identity_id INTEGER,
 name TEXT NOT NULL,
 subject TEXT NOT NULL DEFAULT "",
 body_html TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(created_by_user_id) REFERENCES users(id),
 FOREIGN KEY(sender_identity_id) REFERENCES sender_identities(id) ON DELETE SET NULL
);
CREATE INDEX idx_templates_owner ON email_templates(owner_user_id,name);
CREATE TABLE editor_images (
 token TEXT PRIMARY KEY,
 owner_user_id INTEGER NOT NULL,
 uploaded_by_user_id INTEGER NOT NULL,
 original_name TEXT,
 stored_path TEXT NOT NULL,
 mime_type TEXT NOT NULL DEFAULT "image/jpeg",
 file_size INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(uploaded_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_editor_images_owner ON editor_images(owner_user_id);
CREATE TABLE compose_draft_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        acting_for_user_id INTEGER NOT NULL, subject TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX draft_versions_user ON compose_draft_versions(user_id,id);
CREATE TABLE prepared_compose_drafts (
        user_id INTEGER NOT NULL, acting_for_user_id INTEGER NOT NULL,
        token TEXT NOT NULL, draft_json TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id,acting_for_user_id));
CREATE TABLE mailing_send_tokens (user_id INTEGER NOT NULL,draft_token TEXT NOT NULL,mailing_id INTEGER NOT NULL,PRIMARY KEY(user_id,draft_token));
CREATE TABLE compose_file_store (
      token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,
      kind TEXT NOT NULL,contact_id INTEGER NOT NULL DEFAULT 0,original_name TEXT NOT NULL,
      stored_path TEXT NOT NULL,mime_type TEXT NOT NULL,file_size INTEGER NOT NULL,extension TEXT NOT NULL,
      sha256 TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE compose_file_selection (
      user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,token TEXT NOT NULL,
      PRIMARY KEY(user_id,acting_for_user_id,token));
CREATE TABLE mail_saved_drafts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,
      title TEXT NOT NULL,snapshot_json TEXT NOT NULL,files_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE compose_workspaces (
      user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,workspace_token TEXT NOT NULL,
      saved_draft_id INTEGER,PRIMARY KEY(user_id,acting_for_user_id));
CREATE TABLE sent_mailbox_copies (
      mailing_id INTEGER PRIMARY KEY,message_key TEXT NOT NULL,status TEXT NOT NULL DEFAULT "pending",
      attempts INTEGER NOT NULL DEFAULT 0,error TEXT,filed_at TEXT,next_attempt_at TEXT,
      archive_path TEXT,mailbox TEXT NOT NULL DEFAULT "Sent");
