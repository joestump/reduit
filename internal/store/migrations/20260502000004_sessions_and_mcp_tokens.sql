-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0004 (OIDC control-plane auth),
--            SPEC-0005 REQ "Authentication Gating",
--            SPEC-0005 REQ "OIDC Login Flow",
--            SPEC-0006 REQ "Bearer Authentication Required".

-- alexedwards/scs/sqlite3store backing table. Schema is fixed by the
-- store implementation: token TEXT PK, data BLOB NOT NULL, expiry REAL.
-- The store's background cleanup goroutine sweeps expired rows.
CREATE TABLE sessions (
    token   TEXT    PRIMARY KEY,
    data    BLOB    NOT NULL,
    expiry  REAL    NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions(expiry);

-- Per-user MCP bearer tokens (SPEC-0006). Tokens are stored as the
-- SHA-256 hash of the bearer value — the plaintext is shown to the
-- user exactly once at issuance and never persisted. Lookup at request
-- time is O(1) on the unique index over `token_hash`.
CREATE TABLE mcp_tokens (
    id          TEXT    PRIMARY KEY,
    account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  BLOB    NOT NULL UNIQUE,
    label       TEXT    NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP,
    revoked_at  TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX idx_mcp_tokens_account_id ON mcp_tokens(account_id);
CREATE INDEX idx_mcp_tokens_revoked_at ON mcp_tokens(revoked_at) WHERE revoked_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE mcp_tokens;
DROP TABLE sessions;
-- +goose StatementEnd
