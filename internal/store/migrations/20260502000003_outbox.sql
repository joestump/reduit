-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation"
--            (timeout-detached submissions persisted for operator audit).
--
-- The `outbox_pending` table stores one row per submission whose
-- synchronous SMTP_SUBMIT_TIMEOUT fired (default 60s). The SMTP server
-- has already returned 451 4.4.7 to the sending MTA at this point;
-- this row exists so the operator can audit "did the message
-- eventually go out, or did it die in retry?" via the admin UI.
--
-- Schema notes:
--   * `id` is UUIDv7 — text storage, lexicographic order matches
--     creation time so an audit query without ORDER BY still hands
--     back rows in roughly chronological order.
--   * `account_id` references the owning account with ON DELETE
--     CASCADE so soft-delete + hard-delete sweep across this table
--     too. SPEC-0001 REQ "Account-Scoped Data".
--   * `recipient_count` and `body_bytes` are PII-free metadata. The
--     SPEC-0004 security checklist forbids body content in logs and
--     this table is part of that surface.
--   * `status` discriminates between "timeout_failed" (background
--     retry exhausted / errored) and "timeout_resolved" (background
--     retry succeeded after the 451). The two outcomes are
--     operationally different — the second tells the operator the
--     mail DID send, but the originating client thinks it didn't.
--   * `failure_reason` is a free-text categorisation captured from
--     the wrapped Reduit error vocabulary (proton_auth, proton_rate,
--     proton_reject, proton_server, key_lookup). Free-text instead of
--     enum because the v0.1 retry policy is best-effort and the set
--     of failure modes is still being characterised.

CREATE TABLE outbox_pending (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mail_from       TEXT NOT NULL,
    recipient_count INTEGER NOT NULL,
    body_bytes      INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('timeout_failed', 'timeout_resolved')),
    failure_reason  TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Per-account index for the admin UI's "show recent timeouts" query.
CREATE INDEX idx_outbox_pending_account_created
    ON outbox_pending(account_id, created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_outbox_pending_account_created;
DROP TABLE IF EXISTS outbox_pending;
-- +goose StatementEnd
