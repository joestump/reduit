-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0001 REQ "Account Identity",
--            SPEC-0001 REQ "Per-Account Data Key",
--            SPEC-0001 REQ "Encrypted Secret Storage",
--            SPEC-0001 REQ "Account Lifecycle States",
--            SPEC-0001 REQ "Admin Flag",
--            SPEC-0001 REQ "Account-Scoped Data" (foreign-key cascade rule).

CREATE TABLE accounts (
    id                              TEXT    PRIMARY KEY,
    oidc_subject                    TEXT    NOT NULL UNIQUE,
    proton_user_id                  TEXT,
    email                           TEXT,
    state                           TEXT    NOT NULL CHECK (state IN (
        'pending_proton_setup',
        'active',
        'suspended',
        'soft_deleted'
    )),
    is_admin                        INTEGER NOT NULL DEFAULT 0,
    key_envelope                    BLOB    NOT NULL,
    refresh_token_ciphertext        BLOB,
    mailbox_passphrase_ciphertext   BLOB,
    imap_password_ciphertext        BLOB,
    imap_password_hash              TEXT,
    last_event_id                   TEXT,
    crashed                         INTEGER NOT NULL DEFAULT 0,
    created_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at                      TIMESTAMP
);

CREATE INDEX idx_accounts_state ON accounts(state);
CREATE INDEX idx_accounts_deleted_at ON accounts(deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE accounts;
-- +goose StatementEnd
