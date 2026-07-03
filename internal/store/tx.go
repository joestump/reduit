// Package store — the sync/cache write seam.
//
// The sync engine (SPEC-0002) must commit a message's cache writes and the
// advanced sync_state cursor in ONE transaction, so a crash never leaves the
// cursor ahead of the data it points past (SPEC-0002 REQ "Crash-Safety And
// Resumability", scenario "Cursor advances atomically with the delta"). This
// file provides that seam.
//
// Every write helper in this package is a free function taking an `execer`,
// the small subset of *sqlx.DB / *sqlx.Tx the writes use. That lets the exact
// same SQL run two ways:
//
//   - Directly on the single-writer pool (Store.UpsertMessage, …) for a
//     one-shot write.
//   - Inside a caller-provided transaction (Tx.UpsertMessage, …) obtained via
//     Store.WithTx, so the engine can batch several message applies plus the
//     cursor advance and commit them together.
//
// Writes go through WriterDB() (MaxOpenConns(1)), so they serialise at the
// database/sql layer rather than racing the SQLite file lock (see store.go).
//
// Governing: SPEC-0002 (Sync & Local Cache), ADR-0006 (SQLite + WAL),
//
//	ADR-0014 (stable-hash keying).
package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// execer is the subset of *sqlx.DB and *sqlx.Tx the write helpers need. Both
// types satisfy it, so a helper written against execer runs unchanged on the
// single-writer pool or inside a caller's transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	GetContext(ctx context.Context, dest any, query string, args ...any) error
}

// Tx is a store-scoped transaction. Its methods run the same write logic as
// the equivalent Store methods but against a single SQLite transaction, so a
// caller can apply several messages and advance the sync cursor atomically.
// Obtain one via Store.WithTx; do not construct it directly.
type Tx struct {
	tx *sqlx.Tx
}

// WithTx runs fn inside a single transaction on the writer connection and
// commits it if fn returns nil, otherwise rolls back. This is the seam the
// sync engine uses to commit a delta's cache writes together with the advanced
// sync_state cursor (SPEC-0002 "Cursor advances atomically with the delta"):
// the engine calls Tx.ApplyMessage for each changed message and Tx.UpsertSyncState
// once, all within the same fn, so a partial commit is never observable.
//
// Inside fn, callers MUST use the Tx.* methods (Tx.ApplyMessage,
// Tx.UpsertMessage, Tx.UpsertSyncState, …) so the writes join this transaction.
// They MUST NOT call the Store.* write methods (s.ApplyMessage, s.UpsertMessage,
// s.RecordSyncRun, …): those acquire the single writer connection themselves,
// but WithTx already holds it for the open transaction, so the nested call would
// block waiting on a connection that cannot be released until fn returns —
// a self-deadlock (WriterDB is MaxOpenConns(1)). The Tx methods reuse the
// transaction's own handle and are the only safe writes here.
//
// A panic inside fn rolls back and re-panics. All writes serialise through the
// single-connection writer pool (store.go).
func (s *Store) WithTx(ctx context.Context, fn func(context.Context, *Tx) error) (err error) {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	tx, err := s.WriterDB().BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
			return
		}
		if cErr := tx.Commit(); cErr != nil {
			err = fmt.Errorf("store: commit tx: %w", cErr)
		}
	}()
	return fn(ctx, &Tx{tx: tx})
}

// newID returns a fresh UUIDv7 string for an internal row id, matching the id
// scheme used across the schema (ADR-0006) and the auth layer.
func newID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("store: generate id: %w", err)
	}
	return id.String(), nil
}
