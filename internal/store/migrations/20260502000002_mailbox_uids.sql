-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0003 REQ "UID Stability",
--            SPEC-0003 REQ "Folder Hierarchy and Mapping",
--            SPEC-0003 REQ "Account Isolation in IMAP Operations",
--            SPEC-0001 REQ "Account-Scoped Data".
--
-- Tables that materialise the IMAP-side mailbox state. Three tables
-- so the (mailbox, uid) and (mailbox, message) uniqueness invariants
-- can be enforced at the schema level rather than relying on
-- application-side discipline:
--
--   mailboxes   - one row per (account, IMAP folder name). Holds the
--                 UIDVALIDITY assigned at first sync and the per-mailbox
--                 UIDNEXT counter incremented atomically on every UID
--                 assignment.
--
--   messages    - one row per (account, Proton message ID). Independent
--                 of mailbox membership: the same Proton message can
--                 appear in any number of mailboxes (the Labels/* model
--                 is additive). Soft metadata only — full body/headers
--                 are fetched on demand via the Proton client.
--
--   message_uids - join table mapping (mailbox, message) -> UID. UNIQUE
--                  on (mailbox, uid) gives us "no two messages in this
--                  mailbox ever share a UID, including across expunge +
--                  re-add"; UNIQUE on (mailbox, message) gives us "one
--                  message has at most one UID in any given mailbox".
--                  An expunge deletes the row; a re-add of the same
--                  Proton message inserts a fresh row that consumes a
--                  fresh UID from mailboxes.uid_next, structurally
--                  preventing UID reuse.
--
-- All three tables carry account_id with a foreign key + cascade. Per
-- SPEC-0001 REQ "Account-Scoped Data" every per-account query MUST
-- filter by account_id; the cascade keeps tombstones consistent when an
-- account is hard-deleted by the retention sweep.

CREATE TABLE mailboxes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id       TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name             TEXT    NOT NULL,
    proton_label_id  TEXT    NOT NULL,
    kind             TEXT    NOT NULL CHECK (kind IN ('system', 'user_label')),
    uid_validity     INTEGER NOT NULL,
    uid_next         INTEGER NOT NULL DEFAULT 1,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_mailboxes_account_name
    ON mailboxes(account_id, name);
CREATE UNIQUE INDEX idx_mailboxes_account_proton_label
    ON mailboxes(account_id, proton_label_id);

CREATE TABLE messages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id         TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proton_message_id  TEXT    NOT NULL,
    subject            TEXT    NOT NULL DEFAULT '',
    sender             TEXT    NOT NULL DEFAULT '',
    rfc822_size        INTEGER NOT NULL DEFAULT 0,
    flags              TEXT    NOT NULL DEFAULT '',
    internal_date      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_messages_account_proton_id
    ON messages(account_id, proton_message_id);

CREATE TABLE message_uids (
    account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_id  INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    uid         INTEGER NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mailbox_id, uid)
);

-- Second uniqueness invariant: a given message has at most one UID in
-- any given mailbox. (mailbox_id, message_id) is the natural key for the
-- "is this message currently in this mailbox?" lookup.
CREATE UNIQUE INDEX idx_message_uids_mailbox_message
    ON message_uids(mailbox_id, message_id);

-- Account-scoped reads (LIST + per-account housekeeping) want a
-- single-column index on account_id for the (mailbox, message) join.
CREATE INDEX idx_message_uids_account
    ON message_uids(account_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_message_uids_account;
DROP INDEX IF EXISTS idx_message_uids_mailbox_message;
DROP TABLE IF EXISTS message_uids;
DROP INDEX IF EXISTS idx_messages_account_proton_id;
DROP TABLE IF EXISTS messages;
DROP INDEX IF EXISTS idx_mailboxes_account_proton_label;
DROP INDEX IF EXISTS idx_mailboxes_account_name;
DROP TABLE IF EXISTS mailboxes;

-- +goose StatementEnd
