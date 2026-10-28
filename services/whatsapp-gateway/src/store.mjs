import { DatabaseSync } from 'node:sqlite';
import { chmodSync } from 'node:fs';

const transitions = {
  sending: new Set(['submitted', 'delivered', 'read', 'failed', 'unknown']),
  unknown: new Set(['submitted', 'delivered', 'read', 'failed']),
  submitted: new Set(['delivered', 'read', 'failed']),
  failed: new Set(['delivered', 'read']),
  delivered: new Set(['read']),
  read: new Set()
};

/** One SQLite file stores auth keys and the durable outbound idempotency journal. */
export class Store {
  constructor(filename, { recover = true } = {}) {
    this.db = new DatabaseSync(filename);
    if (filename !== ':memory:') chmodSync(filename, 0o600);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS auth_values (
        category TEXT NOT NULL,
        key_id TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(category, key_id)
      );
      CREATE TABLE IF NOT EXISTS outbound (
        id TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL,
        provider_id TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('sending','submitted','delivered','read','failed','unknown')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        error TEXT,
        message_json TEXT
      );
    `);
    if (recover) {
      this.db.prepare(`UPDATE outbound SET status='unknown',
        error='gateway_restarted_during_send', updated_at=? WHERE status='sending'`)
        .run(new Date().toISOString());
    }
  }

  close() { this.db.close(); }

  transaction(work) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  authGet(category, id) {
    return this.db.prepare('SELECT value FROM auth_values WHERE category=? AND key_id=?')
      .get(category, id)?.value;
  }

  authBatch(entries) {
    const save = this.db.prepare(`INSERT INTO auth_values(category,key_id,value) VALUES(?,?,?)
      ON CONFLICT(category,key_id) DO UPDATE SET value=excluded.value`);
    const remove = this.db.prepare('DELETE FROM auth_values WHERE category=? AND key_id=?');
    this.transaction(() => {
      for (const { category, id, value } of entries) {
        if (value === null) remove.run(category, id);
        else save.run(category, id, value);
      }
    });
  }

  find(id) {
    return this.db.prepare('SELECT * FROM outbound WHERE id=?').get(id) ?? null;
  }

  findByProviderId(providerId) {
    return this.db.prepare('SELECT * FROM outbound WHERE provider_id=?').get(providerId) ?? null;
  }

  reserve(id, contentHash, providerId) {
    const now = new Date().toISOString();
    this.db.prepare(`INSERT INTO outbound
      (id,content_hash,provider_id,status,created_at,updated_at) VALUES(?,?,?,'sending',?,?)`)
      .run(id, contentHash, providerId, now, now);
    return this.find(id);
  }

  transition(providerId, next, error = null) {
    const current = this.findByProviderId(providerId);
    if (!current || !transitions[current.status]?.has(next)) return current;
    this.db.prepare('UPDATE outbound SET status=?,error=?,updated_at=? WHERE provider_id=?')
      .run(next, error, new Date().toISOString(), providerId);
    return this.findByProviderId(providerId);
  }

  saveMessage(providerId, messageJson) {
    this.db.prepare('UPDATE outbound SET message_json=? WHERE provider_id=?').run(messageJson, providerId);
  }

  /** Keep receipt metadata/idempotency forever; remove retry message bodies after seven days. */
  pruneMessageBodies(before = new Date(Date.now() - 7 * 86400000).toISOString()) {
    return this.db.prepare('UPDATE outbound SET message_json=NULL WHERE created_at<? AND message_json IS NOT NULL')
      .run(before).changes;
  }
}

export function publicMessage(row) {
  return {
    id: row.id,
    status: row.status,
    provider_id: row.provider_id,
    error: row.error,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}
