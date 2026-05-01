-- +goose Up
-- +goose StatementBegin

-- Governing: SPEC-0002 REQ "Event Cursor Persistence",
--            SPEC-0001 REQ "Account-Scoped Data" (ON DELETE CASCADE
--            per the multi-tenant invariant: when an account is hard-
--            deleted by the retention sweep, every per-account row
--            including its sync cursor MUST go with it).
--
-- The `sync_state` table is the per-account event-cursor + last-poll
-- bookkeeping the sync worker uses to resume from the persisted Proton
-- event ID after restart. One row per account, keyed by account_id;
-- the row is created lazily by the worker on first successful poll
-- (so accounts that have never run a sync worker — e.g. those still
-- in pending_proton_setup — do not occupy a row).
--
-- We store the cursor in its own table (rather than on accounts) so
-- the account row is not dirtied on every event-stream poll: under
-- WAL the page write-amplification of touching accounts every poll
-- interval would needlessly compete with admin-UI reads. The accounts
-- table also already has a `last_event_id` column from the v0.1
-- migration; that column is reserved for v0.2 backfill bookkeeping
-- (per SPEC-0002 "Out of Scope" — first-sync historical backfill is a
-- v0.2 concern) and is left untouched here.
--
-- The `last_synced_at` column is observability only: the admin UI
-- reads it to surface "last sync N seconds ago" without needing to
-- query the worker process. It is not consumed by the worker itself.

CREATE TABLE sync_state (
    account_id      TEXT      PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    last_event_id   TEXT      NOT NULL,
    last_synced_at  TIMESTAMP NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE sync_state;
-- +goose StatementEnd
