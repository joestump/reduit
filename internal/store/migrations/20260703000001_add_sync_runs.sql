-- +goose Up
-- Governing: SPEC-0002 REQ "Bookkeeping And Observability" (per-run summaries
--   MUST be persisted), ADR-0006 (SQLite cache), ADR-0014 (sync-and-cache).
--
-- sync_runs: one row per completed sync run per mailbox — the persisted
-- per-run summary the engine writes at the end of a run. Counts (added /
-- updated / deleted / attachments) and the error count give observability into
-- what each run did; last_error carries the failure cause when a run fails so a
-- mailbox that stalled can be diagnosed without the logs (SPEC-0002 "Per-run
-- summary counts", "Failure in one mailbox does not stall others").
CREATE TABLE sync_runs (
    id           TEXT PRIMARY KEY,              -- UUIDv7
    mailbox_id   TEXT NOT NULL REFERENCES mailboxes(id),
    started_at   DATETIME NOT NULL,
    finished_at  DATETIME NOT NULL,
    added        INTEGER NOT NULL DEFAULT 0,    -- messages inserted
    updated      INTEGER NOT NULL DEFAULT 0,    -- messages converged in place
    deleted      INTEGER NOT NULL DEFAULT 0,    -- messages removed
    attachments  INTEGER NOT NULL DEFAULT 0,    -- attachments processed
    errors       INTEGER NOT NULL DEFAULT 0,    -- per-message failures during the run
    last_error   TEXT                           -- failure cause; NULL on a clean run
);
CREATE INDEX idx_sync_runs_mailbox_started ON sync_runs(mailbox_id, started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS sync_runs;
