-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0010 (multi-Proton-account per user),
--            SPEC-0001 REQ "User Identity",
--            SPEC-0001 REQ "User Lifecycle".
--
-- The users table is sourced from OIDC. Each successful /auth/callback
-- upserts a row keyed by oidc_subject (the OIDC `sub` claim). A user
-- may own zero or more Proton accounts (the accounts.user_id FK in the
-- next migration enforces the relationship). Admin status is NOT
-- persisted here -- it is computed at session-bind time from
-- OIDC_ADMIN_SUBS per SPEC-0001 REQ "Admin Status".

CREATE TABLE users (
    id              TEXT      PRIMARY KEY,
    oidc_subject    TEXT      NOT NULL UNIQUE,
    email           TEXT,
    display_name    TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
-- +goose StatementEnd
