-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0001 REQ "Ownership is immutable"
--
-- An account's owner (accounts.user_id) is fixed at creation. SPEC-0001
-- forbids any code path from re-binding an account to a different tenant;
-- until now that rule was enforced by application discipline alone (the
-- account repository never SETs user_id -- it appears only in WHERE
-- clauses). This trigger makes the invariant a storage-layer guarantee:
-- any UPDATE that actually changes user_id is aborted at the database,
-- regardless of which code path (or future bug) issued it.
--
-- The guard is scoped with `WHEN OLD.user_id <> NEW.user_id` rather than
-- `BEFORE UPDATE OF user_id` so that the repository's no-op write-lock
-- pattern (`UPDATE accounts SET id = id ...`, and updates that mention
-- user_id only to leave it unchanged) is not falsely rejected. SQLite's
-- `<>` treats two NULLs as not-equal, but user_id is `NOT NULL`, so the
-- comparison is always well-defined here.

CREATE TRIGGER accounts_user_id_immutable
BEFORE UPDATE ON accounts
FOR EACH ROW
WHEN OLD.user_id <> NEW.user_id
BEGIN
    SELECT RAISE(ABORT, 'accounts.user_id is immutable');
END;

-- +goose StatementEnd

-- +goose StatementBegin

-- The BEFORE UPDATE trigger above does not cover REPLACE /
-- INSERT OR REPLACE: SQLite implements those as DELETE-then-INSERT, so
-- BEFORE UPDATE never fires and an upsert can silently re-bind an
-- existing account's owner (and cascade-delete its child rows). This
-- companion BEFORE INSERT trigger closes that bypass: when a row with
-- the same id already exists but with a different user_id, the insert is
-- aborted. Legitimate paths are unaffected -- a brand-new id has no
-- pre-existing row (the WHEN EXISTS is false), and an upsert that keeps
-- the same owner is not rejected (the `user_id <> NEW.user_id` guard is
-- false). Together with the UPDATE trigger, ownership immutability holds
-- regardless of write path.

CREATE TRIGGER accounts_user_id_immutable_replace
BEFORE INSERT ON accounts
WHEN EXISTS (SELECT 1 FROM accounts WHERE id = NEW.id AND user_id <> NEW.user_id)
BEGIN
    SELECT RAISE(ABORT, 'accounts.user_id is immutable');
END;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER accounts_user_id_immutable_replace;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TRIGGER accounts_user_id_immutable;
-- +goose StatementEnd
