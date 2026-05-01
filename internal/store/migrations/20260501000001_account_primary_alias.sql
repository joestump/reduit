-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity"
--            (per-account primary email alias is the SASL identity).
--
-- Adds the `primary_alias` column used by the IMAP and SMTP servers
-- to resolve a SASL `user@host` identity to an account row. NULL is
-- allowed for now: the column is populated either at account create
-- time (from the OIDC subject's email claim, when Pocket ID provides
-- one) or by the operator via an admin tool. Sync of Proton-side
-- aliases lands in a later story; until then the operator points the
-- mail client at this single canonical address.
--
-- A unique index (case-insensitive via NOCOLLATE on the application
-- side: SQLite has no built-in citext, so the index is exact and the
-- application normalises to lower-case before lookup) prevents two
-- accounts from claiming the same alias. NULLs are NOT considered
-- duplicates by SQLite's UNIQUE semantics, so unprovisioned accounts
-- coexist freely.

ALTER TABLE accounts ADD COLUMN primary_alias TEXT;

CREATE UNIQUE INDEX idx_accounts_primary_alias
    ON accounts(primary_alias)
    WHERE primary_alias IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_accounts_primary_alias;
ALTER TABLE accounts DROP COLUMN primary_alias;

-- +goose StatementEnd
