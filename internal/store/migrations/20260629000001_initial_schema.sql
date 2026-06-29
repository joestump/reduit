-- +goose Up
-- Governing: ADR-0006 (SQLite cache), ADR-0012 (single-user, no users table),
--   ADR-0013 (no secret columns), ADR-0014 (stable-hash keying).

-- mailboxes: one row per configured Proton mailbox.
-- Secrets (refresh_token, mailbox_passphrase) live in the OS keychain, NOT here.
CREATE TABLE mailboxes (
    id              TEXT PRIMARY KEY,          -- UUIDv7
    proton_user_id  TEXT UNIQUE,               -- immutable after first auth; UNIQUE prevents duplicate account
    address         TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending_auth',  -- pending_auth | active | needs_reauth
    added_at        DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_sync_at    DATETIME
);

-- messages: decrypted mail cache. Keyed by stable content hash for idempotent sync.
-- id = UUIDv7; hash = stable content fingerprint (Proton message id + content hash).
-- No encrypted columns — cache confidentiality via OS full-disk encryption (ADR-0012).
CREATE TABLE messages (
    id          TEXT PRIMARY KEY,              -- UUIDv7 internal row id
    hash        TEXT NOT NULL UNIQUE,          -- stable content fingerprint (ADR-0014)
    mailbox_id  TEXT NOT NULL REFERENCES mailboxes(id),
    proton_id   TEXT NOT NULL,                 -- Proton's message id
    ts          DATETIME NOT NULL,
    sender      TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL DEFAULT '',
    folder      TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_messages_mailbox_ts ON messages(mailbox_id, ts DESC);
CREATE INDEX idx_messages_proton_id ON messages(proton_id);

-- attachments: per-message attachments.
-- Keyed by (message_hash, proton_attachment_id) for idempotent upsert.
-- extracted_text is populated by the attachment extraction pass (ADR-0016).
CREATE TABLE attachments (
    id              TEXT PRIMARY KEY,          -- UUIDv7
    message_hash    TEXT NOT NULL,             -- FK to messages.hash (no FK constraint — stable-hash keying)
    proton_att_id   TEXT NOT NULL,             -- Proton's attachment id
    filename        TEXT NOT NULL DEFAULT '',
    mime            TEXT NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    extracted_text  TEXT,                      -- populated by embed/extract pass
    UNIQUE(message_hash, proton_att_id)
);
CREATE INDEX idx_attachments_message_hash ON attachments(message_hash);

-- links: URLs extracted from message bodies.
CREATE TABLE links (
    id            TEXT PRIMARY KEY,            -- UUIDv7
    message_hash  TEXT NOT NULL,               -- FK to messages.hash
    url           TEXT NOT NULL,
    anchor_text   TEXT,
    UNIQUE(message_hash, url)
);
CREATE INDEX idx_links_message_hash ON links(message_hash);

-- contacts: correspondent identity — one person spanning several addresses.
CREATE TABLE contacts (
    id            TEXT PRIMARY KEY,            -- UUIDv7
    display_name  TEXT NOT NULL DEFAULT ''
);

-- contact_identifiers: email addresses belonging to a contact.
CREATE TABLE contact_identifiers (
    contact_id  TEXT NOT NULL REFERENCES contacts(id),
    address     TEXT NOT NULL,
    PRIMARY KEY(contact_id, address)
);
CREATE UNIQUE INDEX idx_contact_identifiers_address ON contact_identifiers(address);

-- embeddings: vector embeddings for messages and chunks.
-- Keyed by (hash, model) — stable content hash + model name.
-- No FK to messages: stable-hash keying survives re-sync (ADR-0014, ADR-0015).
CREATE TABLE embeddings (
    hash   TEXT NOT NULL,   -- stable content hash of the message or chunk
    model  TEXT NOT NULL,   -- model name used to generate the embedding
    dim    INTEGER NOT NULL,
    vec    BLOB NOT NULL,   -- raw float32 vector bytes
    PRIMARY KEY(hash, model)
);

-- contact_facts: cited facts about contacts extracted from messages (ADR-0019).
CREATE TABLE contact_facts (
    id                   TEXT PRIMARY KEY,     -- UUIDv7
    contact_id           TEXT NOT NULL REFERENCES contacts(id),
    fact                 TEXT NOT NULL,
    category             TEXT NOT NULL DEFAULT '',
    fact_hash            TEXT NOT NULL,        -- dedup key: hash of (contact_id, fact)
    source_message_hash  TEXT NOT NULL,        -- which message the fact was cited from
    created_at           DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(fact_hash)
);
CREATE INDEX idx_contact_facts_contact_id ON contact_facts(contact_id);

-- fact_state: per-mailbox cursor for incremental fact extraction.
CREATE TABLE fact_state (
    mailbox_id        TEXT PRIMARY KEY REFERENCES mailboxes(id),
    last_processed_ts DATETIME
);

-- sync_state: per-mailbox Proton event cursor.
CREATE TABLE sync_state (
    mailbox_id    TEXT PRIMARY KEY REFERENCES mailboxes(id),
    event_cursor  TEXT,
    last_run_at   DATETIME
);

-- denylist: senders and conversations excluded from LLM processing.
-- mailbox_id NULL means the rule applies across all mailboxes (ADR-0018).
CREATE TABLE denylist (
    id          TEXT PRIMARY KEY,              -- UUIDv7
    mailbox_id  TEXT REFERENCES mailboxes(id), -- NULL = all mailboxes
    kind        TEXT NOT NULL,                 -- 'conversation' | 'sender'
    value       TEXT NOT NULL,
    added_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(mailbox_id, kind, value)
);

-- messages_fts: FTS5 external-content table for full-text search.
-- Kept in sync with messages via triggers below.
-- content='' means we manage content ourselves (the triggers do the job).
CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject, sender, body,
    content='messages',
    content_rowid='rowid'
);

-- Triggers to keep messages_fts in sync with messages.
-- +goose StatementBegin
CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, subject, sender, body)
    VALUES (new.rowid, new.subject, new.sender, new.body);
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, sender, body)
    VALUES ('delete', old.rowid, old.subject, old.sender, old.body);
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, sender, body)
    VALUES ('delete', old.rowid, old.subject, old.sender, old.body);
    INSERT INTO messages_fts(rowid, subject, sender, body)
    VALUES (new.rowid, new.subject, new.sender, new.body);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS messages_au;
DROP TRIGGER IF EXISTS messages_ad;
DROP TRIGGER IF EXISTS messages_ai;
DROP TABLE IF EXISTS messages_fts;
DROP TABLE IF EXISTS denylist;
DROP TABLE IF EXISTS sync_state;
DROP TABLE IF EXISTS fact_state;
DROP TABLE IF EXISTS contact_facts;
DROP TABLE IF EXISTS embeddings;
DROP TABLE IF EXISTS contact_identifiers;
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS links;
DROP TABLE IF EXISTS attachments;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS mailboxes;
