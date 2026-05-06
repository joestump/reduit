-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0010 (multi-Proton-account per user),
--            SPEC-0005 REQ "Account Dashboard"
--                ("Last sync" stat on per-account cards),
--            SPEC-0002 REQ "Event Cursor Persistence"
--                (sync worker bumps cursor and last_sync_at together).
--
-- Adds a dedicated `last_sync_at` column to accounts so the dashboard's
-- per-account "Last sync" stat reflects the most recent sync-cursor
-- advance rather than `updated_at`, which is bumped on every state
-- change (suspend, alias change, IMAP-password rotation, ...).
--
-- Nullable: a freshly-created account has never synced, so the column
-- is NULL until the sync worker first commits a cursor for it. The
-- dashboard renders NULL as "Never" -- consistent with how
-- formatLastSync's zero-time branch already behaves.
--
-- The sync worker is not fully wired yet (see #19). This migration
-- adds the column ahead of that work so the dashboard query can rely
-- on it once the worker starts populating it; until then the column
-- stays NULL on every row, which is the correct "never synced" state.

ALTER TABLE accounts ADD COLUMN last_sync_at TIMESTAMP;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite supports DROP COLUMN as of 3.35; modernc.org/sqlite ships a
-- recent enough engine for this to round-trip cleanly in tests.
ALTER TABLE accounts DROP COLUMN last_sync_at;
-- +goose StatementEnd
