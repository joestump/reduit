-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0004 (OIDC control-plane auth),
--            SPEC-0005 REQ "Authentication Gating",
--            SPEC-0005 REQ "Admin Account Management"
--                ("drop sessions" on suspend/soft-delete).

-- Round-1 hostile review on PR #55 (C4) flagged that the SCS-managed
-- `sessions` schema has no link from a session row to the owning
-- account: an admin who suspends or soft-deletes an account had no
-- index from account_id to that account's live sessions, forcing a
-- cleanup pass to deserialise every `sessions.data` blob to find
-- owners.
--
-- Direct extension of the `sessions` table is unsafe: SCS's
-- sqlite3store implementation issues `REPLACE INTO sessions(token,
-- data, expiry) VALUES (...)` on every commit, which would clear any
-- additional column on every request — there is no public hook in
-- the store interface to preserve extra columns. Sidecar table.
--
-- session_owners.token is the SCS session token verbatim. The FK on
-- account_id cascades on hard-delete; suspend/soft-delete are state
-- transitions that leave the row in place, so RevokeSessionsForAccount
-- below issues an explicit DELETE FROM sessions joined on this index.
CREATE TABLE session_owners (
    token       TEXT    PRIMARY KEY,
    account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    bound_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_owners_account_id ON session_owners(account_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE session_owners;
-- +goose StatementEnd
