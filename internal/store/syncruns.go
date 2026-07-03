// Package store — per-run sync summaries (SPEC-0002 "Bookkeeping And
// Observability"). The sync engine records one row per completed run per mailbox
// so operators can see what each run did (added/updated/deleted/attachments) and
// why a run failed (last_error), without reconstructing it from logs.
//
// Governing: SPEC-0002 REQ "Bookkeeping And Observability", ADR-0006, ADR-0014.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SyncRun is one persisted per-run summary. Counts are what the run applied;
// Errors is the number of per-message failures it absorbed while continuing, and
// LastError carries the failure cause when the run itself failed (nil on a clean
// run). ID/StartedAt/FinishedAt are set by RecordSyncRun when zero.
type SyncRun struct {
	ID          string    `db:"id"`
	MailboxID   string    `db:"mailbox_id"`
	StartedAt   time.Time `db:"started_at"`
	FinishedAt  time.Time `db:"finished_at"`
	Added       int       `db:"added"`
	Updated     int       `db:"updated"`
	Deleted     int       `db:"deleted"`
	Attachments int       `db:"attachments"`
	Errors      int       `db:"errors"`
	LastError   *string   `db:"last_error"`
}

// RecordSyncRun persists a per-run summary on the writer pool (SPEC-0002
// "Per-run summary counts"). MailboxID is required. A zero ID is filled with a
// fresh UUIDv7 and a zero FinishedAt with the current time, so a caller can hand
// over just the counts and the mailbox.
func (s *Store) RecordSyncRun(ctx context.Context, run SyncRun) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	if run.MailboxID == "" {
		return fmt.Errorf("store: record sync run: mailbox_id is required")
	}
	if run.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		run.ID = id
	}
	if run.FinishedAt.IsZero() {
		run.FinishedAt = time.Now().UTC()
	}
	const q = `
        INSERT INTO sync_runs
            (id, mailbox_id, started_at, finished_at, added, updated, deleted, attachments, errors, last_error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.WriterDB().ExecContext(ctx, q,
		run.ID, run.MailboxID, run.StartedAt, run.FinishedAt,
		run.Added, run.Updated, run.Deleted, run.Attachments, run.Errors, run.LastError); err != nil {
		return fmt.Errorf("store: record sync run: %w", err)
	}
	return nil
}

// LatestSyncRun returns the most recent run summary for a mailbox, or
// (SyncRun{}, false, nil) when none has been recorded yet. It reads from the
// multi-conn pool (observability read, not a hot write path).
func (s *Store) LatestSyncRun(ctx context.Context, mailboxID string) (SyncRun, bool, error) {
	if s == nil || s.DB == nil {
		return SyncRun{}, false, errNotOpen
	}
	var run SyncRun
	const q = `
        SELECT id, mailbox_id, started_at, finished_at, added, updated, deleted, attachments, errors, last_error
        FROM sync_runs WHERE mailbox_id = ? ORDER BY started_at DESC, id DESC LIMIT 1`
	if err := s.DB.GetContext(ctx, &run, q, mailboxID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SyncRun{}, false, nil
		}
		return SyncRun{}, false, fmt.Errorf("store: latest sync run: %w", err)
	}
	return run, true, nil
}
