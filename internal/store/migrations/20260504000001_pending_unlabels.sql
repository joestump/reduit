-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0003 REQ "Moving between system folders changes Proton
--            system flag",
--            SPEC-0003 REQ "Moving between Labels/ folders adjusts labels
--            additively",
--            SPEC-0001 REQ "Account-Scoped Data".
--
-- pending_unlabels records the "this Proton label should have been
-- removed from this message but the UnlabelMessages call failed" intent
-- produced by the IMAP MOVE handler's Phase-3 (source unlabel) failure.
--
-- Without a durable record of this intent the message is stuck: Proton
-- still carries BOTH the source and destination labels, so the next sync
-- event re-materialises the source-mailbox link and the message lives in
-- two IMAP mailboxes forever. The sync-worker reconciliation pass drains
-- this table by retrying UnlabelMessages; a successful retry deletes the
-- row.
--
-- (account_id, proton_message_id, proton_label_id) is the natural key:
-- a given (message, label) unlabel intent is recorded at most once.
-- Re-recording the same intent (e.g. a second failed MOVE of the same
-- message) is an idempotent upsert that refreshes attempt bookkeeping.

CREATE TABLE pending_unlabels (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id         TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proton_message_id  TEXT    NOT NULL,
    proton_label_id    TEXT    NOT NULL,
    attempts           INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The reconciler drains by account (WHERE account_id = ? [AND attempts <
-- ?]); this composite unique index has account_id as its leftmost column,
-- so it already serves the account-scoped scan as a prefix. No separate
-- single-column account_id index is needed.
CREATE UNIQUE INDEX idx_pending_unlabels_natural
    ON pending_unlabels(account_id, proton_message_id, proton_label_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_pending_unlabels_natural;
DROP TABLE IF EXISTS pending_unlabels;

-- +goose StatementEnd
