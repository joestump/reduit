-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0004 (OIDC control-plane auth),
--            ADR-0010 (multi-Proton-account per user),
--            SPEC-0005 REQ "Authentication Gating",
--            SPEC-0005 REQ "Session admin tag is computed at bind time",
--            SPEC-0005 REQ "Admin Account Management"
--                ("drop sessions" on suspend/soft-delete).

-- Round-1 hostile review on PR #55 (C4) flagged that the SCS-managed
-- `sessions` schema has no link from a session row to the owning
-- principal: an admin who suspends or soft-deletes an account had no
-- index back to that account's live sessions, forcing a cleanup pass
-- to deserialise every `sessions.data` blob to find owners.
--
-- Direct extension of the `sessions` table is unsafe: SCS's
-- sqlite3store implementation issues `REPLACE INTO sessions(token,
-- data, expiry) VALUES (...)` on every commit, which would clear any
-- additional column on every request -- there is no public hook in
-- the store interface to preserve extra columns. Sidecar table.
--
-- ADR-0010 split: a session is bound primarily to a `user_id` (a user
-- can own zero accounts and still have a valid session, e.g. right
-- after first login before the wizard runs). `account_id` is OPTIONAL
-- and only set when handlers scope a request to a specific account
-- (e.g. /accounts/{id}/...).
--
-- We DELIBERATELY do NOT add a FK from session_owners.token to
-- sessions(token). SCS's sqlite3store commits via
-- `REPLACE INTO sessions(token, data, expiry)` on every request,
-- which is DELETE + INSERT under the hood. A cascading FK would
-- therefore drop the matching session_owners row on every commit
-- and the bind would not survive the SCS LoadAndSave middleware's
-- end-of-handler Commit. The cost is that re-login (which renews
-- the SCS token) leaves the prior token's owner row orphaned in
-- session_owners until it is swept on schedule -- a known follow-up.
--
-- users(id) and accounts(id) cascades drive the per-user and
-- per-account revocation paths (RevokeSessionsForUser /
-- RevokeSessionsForAccount), neither of which conflicts with SCS's
-- write pattern.
--
-- session_owners.token is the SCS session token verbatim.
CREATE TABLE session_owners (
    token       TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id  TEXT             REFERENCES accounts(id) ON DELETE CASCADE,
    bound_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_owners_user_id    ON session_owners(user_id);
CREATE INDEX idx_session_owners_account_id ON session_owners(account_id) WHERE account_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE session_owners;
-- +goose StatementEnd
