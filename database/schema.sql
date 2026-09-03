-- Brimstone On-Prem BulkMail database schema
-- Generated without live data or SQLite internal objects.

PRAGMA foreign_keys=ON;

-- table: audit_log
CREATE TABLE audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 action TEXT NOT NULL,
 details TEXT,
 ip_address TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- table: compose_drafts
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

-- table: contacts
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

-- table: domains
CREATE TABLE domains (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
 description TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- table: group_members
CREATE TABLE group_members (
 group_id INTEGER NOT NULL,
 contact_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,contact_id),
 FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
 FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- table: groups
CREATE TABLE groups (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 name TEXT NOT NULL COLLATE NOCASE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(owner_user_id,name),
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- table: login_attempts
CREATE TABLE login_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT,
 ip_address TEXT,
 success INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- table: mailing_assets
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

-- table: mailing_attachments
CREATE TABLE mailing_attachments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_id INTEGER NOT NULL,
 original_name TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 mime_type TEXT,
 file_size INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(mailing_id) REFERENCES mailings(id) ON DELETE CASCADE
);

-- table: mailing_recipients
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

-- table: mailings
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

-- table: organisation_settings
CREATE TABLE organisation_settings (
 user_id INTEGER PRIMARY KEY,
 privacy_notice_url TEXT,
 footer_name TEXT,
 footer_address TEXT,
 footer_phone TEXT,
 retention_months INTEGER NOT NULL DEFAULT 36,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- table: sender_identities
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

-- table: suppressions
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

-- table: user_domains
CREATE TABLE user_domains (
 user_id INTEGER NOT NULL,
 domain_id INTEGER NOT NULL,
 PRIMARY KEY(user_id,domain_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

-- table: users
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
);

-- index: idx_contacts_owner
CREATE INDEX idx_contacts_owner ON contacts(owner_user_id);

-- index: idx_groups_owner
CREATE INDEX idx_groups_owner ON groups(owner_user_id);

-- index: idx_login_attempts_lookup
CREATE INDEX idx_login_attempts_lookup ON login_attempts(username,ip_address,created_at);

-- index: idx_recipients_mailing
CREATE INDEX idx_recipients_mailing ON mailing_recipients(mailing_id);

-- index: idx_suppressions_owner_email
CREATE INDEX idx_suppressions_owner_email ON suppressions(owner_user_id,email);
