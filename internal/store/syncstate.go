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

// UpsertSyncState writes the event cursor and last-run timestamp for a mailbox.
func (s *Store) UpsertSyncState(ctx context.Context, mailboxID, eventCursor string, lastRunAt time.Time) error {
	const q = `
        INSERT INTO sync_state (mailbox_id, event_cursor, last_run_at)
        VALUES (?, ?, ?)
        ON CONFLICT(mailbox_id) DO UPDATE SET event_cursor=excluded.event_cursor, last_run_at=excluded.last_run_at`
	if _, err := s.DB.ExecContext(ctx, q, mailboxID, eventCursor, lastRunAt); err != nil {
		return fmt.Errorf("store: upsert sync state: %w", err)
	}
	return nil
}
