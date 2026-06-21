-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0002 REQ "Panic Isolation"
--                (a crashed worker must surface to an operator, not fail
--                 silently -- the crashed flag set on accounts is a
--                 boolean; this table carries the human-readable "what
--                 happened" the admin UI shows),
--            SPEC-0002 REQ "Backoff on Failure"
--                (the permanent-error auto-revert to pending_proton_setup
--                 likewise emits an admin notification so the operator is
--                 actively told the account needs re-auth),
--            SPEC-0001 REQ "Account-Scoped Data" (account_id FK + cascade).
--
-- admin_notifications is a minimal per-account operator-notification
-- surface. Each row records one event the operator should see: a worker
-- crash, or an automatic state revert. Rows are immutable except for the
-- acknowledged_at column, which the admin UI sets when an operator
-- dismisses the notification.
--
-- account_id cascades on account hard-delete so notifications never
-- outlive the account they describe (SPEC-0001 "Account-Scoped Data").

CREATE TABLE admin_notifications (
    id              TEXT      PRIMARY KEY,
    account_id      TEXT      NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind            TEXT      NOT NULL CHECK (kind IN (
        'worker_crashed',
        'auto_reverted'
    )),
    -- Human-readable summary rendered verbatim in the admin UI.
    message         TEXT      NOT NULL,
    -- Optional structured detail (e.g. the panic value or the upstream
    -- error string). Shown in the expanded notification body.
    detail          TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL until an operator dismisses the notification. The admin UI's
    -- unacknowledged badge counts rows where this is NULL.
    acknowledged_at TIMESTAMP
);

-- The hot query is "unacknowledged notifications, newest first" for the
-- badge + list. A partial index on the unacknowledged set keeps that
-- scan cheap as acknowledged history accumulates.
CREATE INDEX idx_admin_notifications_unack
    ON admin_notifications(created_at DESC)
    WHERE acknowledged_at IS NULL;

CREATE INDEX idx_admin_notifications_account
    ON admin_notifications(account_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE admin_notifications;
-- +goose StatementEnd
