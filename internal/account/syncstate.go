// Per-account sync-cursor bookkeeping. The sync worker uses these
// helpers to (a) read the persisted Proton event ID on startup so it
// can resume from where the previous process left off, and (b) write
// the new cursor atomically with any state changes derived from the
// event batch the cursor represents.
//
// The atomic-commit contract is the load-bearing invariant here:
// SetSyncState opens a single sqlx transaction, hands it to the
// caller-supplied txWork callback (typically the future #19 mailbox/
// UID materialisation), and commits the cursor + the callback's
// writes together. If anything in txWork fails the whole transaction
// rolls back including the cursor, so the next worker iteration
// re-fetches the same batch and retries — there is never a window
// where the cursor advanced but the derived state was lost.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence" (atomic commit
// of cursor and derived state), SPEC-0001 REQ "Account-Scoped Data"
// (the sync_state table FK-cascades on account hard-delete).
package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"
)

// ErrNoSyncState is returned by Service.GetSyncState when the account
// has no row in sync_state yet — i.e. no successful event-stream batch
// has ever been committed for this account. The sync worker uses this
// sentinel to decide it should call proton.Client.GetLatestEventID
// instead of resuming from a persisted cursor.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence" — "Resume on
// startup uses persisted cursor" presupposes a cursor exists; the
// first-ever boot has no cursor, and this sentinel is how the worker
// detects that case without conflating it with a real DB error.
var ErrNoSyncState = errors.New("account: no sync state for account")

// SyncState is the in-memory projection of one row of the sync_state
// table. LastEventID is the Proton event cursor the worker should pass
// to the next GetEvent call; LastSyncedAt is bookkeeping the admin UI
// uses to render "last sync N seconds ago" without having to ask the
// worker process directly.
type SyncState struct {
	AccountID    string
	LastEventID  string
	LastSyncedAt time.Time
}

// SyncStateTxWork is the callback signature for the optional unit of
// work SetSyncState commits in the same transaction as the cursor.
// The supplied *sqlx.Tx is owned by SetSyncState — the callback MUST
// NOT call Commit or Rollback on it. Returning a non-nil error rolls
// back the entire transaction (including the cursor write) so the
// caller can safely treat any failure as "neither happened".
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence" — "Cursor
// advances atomically with state changes". For #16's plumbing stage
// txWork is always nil (no derived state yet); #19's mailbox/UID
// materialisation will pass a real callback.
type SyncStateTxWork func(*sqlx.Tx) error

// upsertSyncStateInTx writes (insert-or-replace) the sync_state row
// inside an already-open transaction. Extracted so SetSyncState can
// share the same SQL with any future migration helper that needs to
// seed cursors during a back-fill.
func upsertSyncStateInTx(ctx context.Context, tx *sqlx.Tx, accountID, cursor string, syncedAt time.Time) error {
	const q = `
        INSERT INTO sync_state (account_id, last_event_id, last_synced_at)
        VALUES (?, ?, ?)
        ON CONFLICT(account_id) DO UPDATE SET
            last_event_id  = excluded.last_event_id,
            last_synced_at = excluded.last_synced_at
    `
	if _, err := tx.ExecContext(ctx, q, accountID, cursor, syncedAt); err != nil {
		return fmt.Errorf("account: upsert sync state: %w", err)
	}
	return nil
}

// GetSyncState returns the persisted sync cursor for the account, or
// ErrNoSyncState if no row exists yet. The worker calls this exactly
// once on startup; any non-nil error other than ErrNoSyncState is
// treated as a hard fault (the worker logs and exits — corrupted
// cursor state is not the worker's job to repair).
func (s *service) GetSyncState(ctx context.Context, accountID string) (*SyncState, error) {
	const q = `
        SELECT account_id, last_event_id, last_synced_at
          FROM sync_state
         WHERE account_id = ?
    `
	var row struct {
		AccountID    string    `db:"account_id"`
		LastEventID  string    `db:"last_event_id"`
		LastSyncedAt time.Time `db:"last_synced_at"`
	}
	if err := s.repo.db.GetContext(ctx, &row, q, accountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSyncState
		}
		return nil, fmt.Errorf("account: get sync state: %w", err)
	}
	return &SyncState{
		AccountID:    row.AccountID,
		LastEventID:  row.LastEventID,
		LastSyncedAt: row.LastSyncedAt,
	}, nil
}

// SetSyncState commits the cursor advance AND the caller-supplied
// derived-state writes in one transaction. txWork MAY be nil — in
// that case only the cursor row is written, which is the shape the
// #16 plumbing pass uses (no derived state yet). #19 will pass a real
// callback that writes mailbox/UID rows alongside the cursor.
//
// Atomicity contract (SPEC-0002 REQ "Event Cursor Persistence"):
//
//   - If txWork is nil: the cursor row is upserted under a transaction
//     and the transaction commits. A failure on the upsert returns the
//     wrapped error and the row is unchanged.
//   - If txWork is non-nil: the cursor upsert runs FIRST, then txWork
//     is invoked with the open *sqlx.Tx. If txWork returns an error
//     the whole transaction is rolled back — the cursor stays at its
//     previous value. Only on a successful txWork do we Commit, after
//     which both the cursor and the derived state are durable.
//
// Why upsert-then-txWork (instead of txWork-then-upsert): we want a
// txWork panic to roll back the whole transaction (the deferred
// Rollback below handles that), and a panic AFTER a successful upsert
// is still safe — the row never reaches disk because Commit hasn't
// run. Putting the upsert first means the SQL is straightforward (no
// late "did the caller forget to write the cursor?" inspection); the
// commit-or-nothing invariant is held by Go's defer chain, not by SQL
// ordering.
//
// The optional ...SyncStateTxWork variadic is a deliberate API choice:
// the common #16 call site is `SetSyncState(ctx, id, cursor)` with no
// extra work, and the variadic lets that call site stay readable
// without a sentinel nil. Passing more than one txWork is a programmer
// error — we panic loudly (caller bug, not runtime error) so the
// mistake is caught at first invocation rather than silently dropping
// the second callback.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence",
// SPEC-0002 REQ "Cursor is consistent at shutdown".
func (s *service) SetSyncState(ctx context.Context, accountID, cursor string, txWork ...SyncStateTxWork) error {
	if len(txWork) > 1 {
		panic("account: SetSyncState supports at most one SyncStateTxWork")
	}
	var work SyncStateTxWork
	if len(txWork) == 1 {
		work = txWork[0]
	}

	tx, err := s.repo.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("account: begin sync state tx: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			// Mirror the pattern in repository.transitionState: a failed
			// rollback after a failed (or panicked) txWork is not
			// actionable from the caller's perspective, but we want it
			// in the logs so a wedged SQLite connection can be
			// correlated with downstream errors. sql.ErrTxDone is the
			// benign "tx already finished normally" case and is
			// filtered out so a normally-committed call does not log
			// spurious warnings.
			//
			// We use slog.Default() rather than threading a logger
			// through Service because Service does not currently carry
			// one and adding one solely for this defer would balloon
			// the surface area. Hostile-review fix on PR #41: the
			// previous version's body was empty (comment-only), so a
			// wedged connection during rollback failure was invisible
			// to operators.
			slog.Default().LogAttrs(ctx, slog.LevelWarn,
				"account: SetSyncState rollback failed",
				slog.String("account_id", accountID),
				slog.Any("error", rbErr),
			)
		}
	}()

	if err := upsertSyncStateInTx(ctx, tx, accountID, cursor, s.now().UTC()); err != nil {
		return err
	}
	if work != nil {
		if err := work(tx); err != nil {
			return fmt.Errorf("account: sync state tx work: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("account: commit sync state tx: %w", err)
	}
	committed = true
	return nil
}
