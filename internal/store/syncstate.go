// Governing: ADR-0014 (sync-and-cache — per-mailbox Proton event cursor).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SyncState is a row from the sync_state table.
type SyncState struct {
	MailboxID   string     `db:"mailbox_id"`
	EventCursor *string    `db:"event_cursor"`
	LastRunAt   *time.Time `db:"last_run_at"`
}

// GetSyncState returns the sync cursor for a mailbox. Returns a zero-value
// SyncState (nil cursor) if no row exists yet.
func (s *Store) GetSyncState(ctx context.Context, mailboxID string) (SyncState, error) {
	if s == nil || s.DB == nil {
		return SyncState{}, errNotOpen
	}
	var ss SyncState
	const q = `SELECT mailbox_id, event_cursor, last_run_at FROM sync_state WHERE mailbox_id = ?`
	if err := s.DB.GetContext(ctx, &ss, q, mailboxID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SyncState{MailboxID: mailboxID}, nil
		}
		return SyncState{}, fmt.Errorf("store: get sync state: %w", err)
	}
	return ss, nil
}

// upsertSyncState writes the event cursor and last-run timestamp for a mailbox
// against e, so the cursor advance can run either standalone or inside a caller's
// transaction alongside the delta's cache writes (SPEC-0002 "Cursor advances
// atomically with the delta").
func upsertSyncState(ctx context.Context, e execer, mailboxID, eventCursor string, lastRunAt time.Time) error {
	const q = `
        INSERT INTO sync_state (mailbox_id, event_cursor, last_run_at)
        VALUES (?, ?, ?)
        ON CONFLICT(mailbox_id) DO UPDATE SET event_cursor=excluded.event_cursor, last_run_at=excluded.last_run_at`
	if _, err := e.ExecContext(ctx, q, mailboxID, eventCursor, lastRunAt); err != nil {
		return fmt.Errorf("store: upsert sync state: %w", err)
	}
	return nil
}

// UpsertSyncState writes the event cursor and last-run timestamp for a mailbox
// on the single-conn writer pool — the same pool every other write in this layer
// uses — so a standalone cursor write cannot contend with a concurrent WithTx and
// fall back to the busy_timeout retry.
func (s *Store) UpsertSyncState(ctx context.Context, mailboxID, eventCursor string, lastRunAt time.Time) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	return upsertSyncState(ctx, s.WriterDB(), mailboxID, eventCursor, lastRunAt)
}

// UpsertSyncState advances a mailbox's cursor within the transaction, so the
// engine can commit it together with the delta's cache writes (the seam for
// SPEC-0002 "Cursor advances atomically with the delta").
func (t *Tx) UpsertSyncState(ctx context.Context, mailboxID, eventCursor string, lastRunAt time.Time) error {
	return upsertSyncState(ctx, t.tx, mailboxID, eventCursor, lastRunAt)
}

// ResetSyncCursor clears a mailbox's sync cursor back to unset by deleting its
// sync_state row. The next GetSyncState then reports a nil cursor, so the engine
// re-bootstraps the bounded backfill and re-applies it idempotently — the
// mechanism behind `reduit sync --full` (SPEC-0002 "Full rescan on demand").
// It runs on the writer pool, like every other write in this layer, and is
// idempotent: clearing a mailbox that has no row is a harmless no-op.
func (s *Store) ResetSyncCursor(ctx context.Context, mailboxID string) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	const q = `DELETE FROM sync_state WHERE mailbox_id = ?`
	if _, err := s.WriterDB().ExecContext(ctx, q, mailboxID); err != nil {
		return fmt.Errorf("store: reset sync cursor: %w", err)
	}
	return nil
}
