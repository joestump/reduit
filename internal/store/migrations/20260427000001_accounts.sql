-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0010 (multi-Proton-account per user),
--            SPEC-0001 REQ "Account Identity",
--            SPEC-0001 REQ "Per-Account Data Key",
--            SPEC-0001 REQ "Encrypted Secret Storage",
--            SPEC-0001 REQ "Account Lifecycle States",
--            SPEC-0001 REQ "Admin Status" (admin status NOT persisted),
--            SPEC-0001 REQ "Account-Scoped Data" (foreign-key cascade rule).
--
-- ADR-0010 split: each account belongs to a user (one users row may own
-- many accounts). The previous shape carried oidc_subject and is_admin
-- on accounts directly; both fields are now removed -- ownership is the
-- user_id FK, admin status is a session attribute computed from
-- OIDC_ADMIN_SUBS at bind time. The UNIQUE (user_id, proton_user_id)
-- constraint enforces SPEC-0001's "no duplicate Proton account per
-- user" rule (per-user, not global -- two users may relay the same
-- Proton mailbox from different deployments).

CREATE TABLE accounts (
    id                              TEXT    PRIMARY KEY,
    user_id                         TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    proton_user_id                  TEXT,
    email                           TEXT,
    state                           TEXT    NOT NULL CHECK (state IN (
        'pending_proton_setup',
        'active',
        'suspended',
        'soft_deleted'
    )),
    key_envelope                    BLOB    NOT NULL,
    refresh_token_ciphertext        BLOB,
    mailbox_passphrase_ciphertext   BLOB,
    imap_password_ciphertext        BLOB,
    imap_password_hash              TEXT,
    last_event_id                   TEXT,
    crashed                         INTEGER NOT NULL DEFAULT 0,
    created_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at                      TIMESTAMP,
    UNIQUE (user_id, proton_user_id)
);

CREATE INDEX idx_accounts_user_id    ON accounts(user_id);
CREATE INDEX idx_accounts_state      ON accounts(state);
CREATE INDEX idx_accounts_deleted_at ON accounts(deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE accounts;
-- +goose StatementEnd
