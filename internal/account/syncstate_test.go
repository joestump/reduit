package account

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
)

// TestGetSyncStateMissingReturnsSentinel pins SPEC-0002 REQ "Event
// Cursor Persistence" — "Resume on startup uses persisted cursor".
// On first boot there is no row, and the worker MUST be able to tell
// "I have no cursor yet" apart from "the DB is broken" so it can
// bootstrap via GetLatestEventID rather than incorrectly retry.
func TestGetSyncStateMissingReturnsSentinel(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-no-cursor"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.GetSyncState(ctx, a.ID); !errors.Is(err, ErrNoSyncState) {
		t.Fatalf("GetSyncState on empty = %v, want ErrNoSyncState", err)
	}
}

// TestSetSyncStateRoundTrip exercises the happy path: write a cursor,
// read it back, overwrite it, read again. Pins both the upsert
// semantics (second write replaces, does not duplicate) and that the
// stored row is what GetSyncState returns.
func TestSetSyncStateRoundTrip(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-cursor"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.SetSyncState(ctx, a.ID, "evt-1"); err != nil {
		t.Fatalf("SetSyncState 1: %v", err)
	}
	got, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if got.LastEventID != "evt-1" {
		t.Errorf("LastEventID = %q, want evt-1", got.LastEventID)
	}
	if got.AccountID != a.ID {
		t.Errorf("AccountID = %q, want %q", got.AccountID, a.ID)
	}
	if got.LastSyncedAt.IsZero() {
		t.Error("LastSyncedAt is zero; should be set to now()")
	}

	// Overwrite — no second row, just an update.
	if err := svc.SetSyncState(ctx, a.ID, "evt-2"); err != nil {
		t.Fatalf("SetSyncState 2: %v", err)
	}
	got, err = svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState 2: %v", err)
	}
	if got.LastEventID != "evt-2" {
		t.Errorf("after overwrite LastEventID = %q, want evt-2", got.LastEventID)
	}
}

// TestSetSyncStateAtomicityRollsBackOnTxWorkFailure is the
// load-bearing test for SPEC-0002 REQ "Event Cursor Persistence" —
// "Cursor advances atomically with state changes". A txWork that
// returns an error MUST leave the cursor untouched so the next
// worker iteration re-fetches the same batch and retries.
func TestSetSyncStateAtomicityRollsBackOnTxWorkFailure(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-tx-rollback"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Seed a baseline cursor so we can prove a failed advance does
	// NOT clobber the prior value.
	if err := svc.SetSyncState(ctx, a.ID, "evt-baseline"); err != nil {
		t.Fatalf("SetSyncState baseline: %v", err)
	}

	wantErr := errors.New("simulated derived-state failure")
	err = svc.SetSyncState(ctx, a.ID, "evt-should-not-stick", func(tx *sqlx.Tx) error {
		// Even after the txWork has done work in the tx, returning an
		// error MUST roll back the cursor upsert that ran before us.
		// We make a dummy write so the rollback covers more than a no-op.
		if _, err := tx.ExecContext(ctx, `UPDATE accounts SET updated_at = updated_at WHERE id = ?`, a.ID); err != nil {
			return fmt.Errorf("dummy write: %w", err)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("SetSyncState txWork-fails error = %v, want wraps %v", err, wantErr)
	}

	// Cursor MUST still be the baseline.
	got, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState after rollback: %v", err)
	}
	if got.LastEventID != "evt-baseline" {
		t.Fatalf("cursor advanced despite txWork failure: got %q, want evt-baseline", got.LastEventID)
	}
}

// TestSetSyncStateCommitsTxWorkAlongsideCursor confirms that on
// success, BOTH the cursor and the txWork's writes land. We use the
// account's `updated_at` column as a proxy for "derived state" since
// #16 doesn't have real derived tables yet — but the atomicity proof
// is the same shape: a single transaction commits both writes.
func TestSetSyncStateCommitsTxWorkAlongsideCursor(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-tx-commit"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Capture pre-write updated_at so we can assert the txWork side
	// effect actually landed.
	var preUpdated time.Time
	if err := svc.(*service).repo.db.GetContext(ctx, &preUpdated, `SELECT updated_at FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read pre updated_at: %v", err)
	}
	// Sleep a millisecond so the new updated_at is observably distinct.
	time.Sleep(2 * time.Millisecond)

	marker := time.Now().UTC().Add(time.Hour) // distinctive value
	err = svc.SetSyncState(ctx, a.ID, "evt-committed", func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET updated_at = ? WHERE id = ?`, marker, a.ID)
		return err
	})
	if err != nil {
		t.Fatalf("SetSyncState happy: %v", err)
	}

	got, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if got.LastEventID != "evt-committed" {
		t.Errorf("cursor = %q, want evt-committed", got.LastEventID)
	}

	var postUpdated time.Time
	if err := svc.(*service).repo.db.GetContext(ctx, &postUpdated, `SELECT updated_at FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read post updated_at: %v", err)
	}
	if !postUpdated.Equal(marker) {
		t.Errorf("txWork's UPDATE did not land: post=%v want=%v", postUpdated, marker)
	}
}

// TestSetSyncStateRejectsMultipleTxWork pins the variadic-cardinality
// guard. Passing >1 callback is a programmer error; we panic loudly
// so the bug surfaces at first invocation rather than silently
// dropping the second callback's work.
func TestSetSyncStateRejectsMultipleTxWork(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-tx-multi"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on multiple txWork args")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "at most one") {
			t.Errorf("panic value = %v, want string containing 'at most one'", r)
		}
	}()

	noop := func(*sqlx.Tx) error { return nil }
	_ = svc.SetSyncState(ctx, a.ID, "evt", noop, noop)
}

// TestSetSyncStateAccountCascade locks in the SPEC-0001 REQ
// "Account-Scoped Data" cascade rule: when an account row is hard-
// deleted, its sync_state row goes with it. Soft-delete is NOT a
// cascade trigger (it only sets deleted_at); only the future
// retention sweep that issues a real DELETE FROM accounts will
// trigger this cascade. We simulate that by issuing the DELETE
// directly so the test does not depend on a future feature.
func TestSetSyncStateAccountCascade(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-cascade"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SetSyncState(ctx, a.ID, "evt-pre-delete"); err != nil {
		t.Fatalf("SetSyncState: %v", err)
	}

	// Hard delete the account row directly (the retention sweep that
	// will eventually do this is not yet implemented).
	if _, err := st.DB.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("hard delete account: %v", err)
	}

	var n int
	if err := st.DB.GetContext(ctx, &n, `SELECT count(*) FROM sync_state WHERE account_id = ?`, a.ID); err != nil {
		t.Fatalf("count sync_state: %v", err)
	}
	if n != 0 {
		t.Fatalf("sync_state row not cascaded: count=%d, want 0", n)
	}
}

// TestSetSyncStateConcurrentWritesPickOne races two writers on the
// same account. We don't care which value wins (Proton's events are
// monotonic, but the worker is single-goroutine, so concurrent
// writes from a misuse of the API would only ever happen in tests
// like this one) — the invariant is that the row's value is one of
// the two we wrote, never a half-written hybrid. Without atomic
// upsert this test would be free to read garbage.
func TestSetSyncStateConcurrentWritesPickOne(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-tx-race"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, cur := range []string{"evt-A", "evt-B"} {
		i, cur := i, cur
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := svc.SetSyncState(ctx, a.ID, cur); err != nil {
				t.Errorf("writer %d (%s): %v", i, cur, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	got, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState after race: %v", err)
	}
	if got.LastEventID != "evt-A" && got.LastEventID != "evt-B" {
		t.Fatalf("post-race cursor = %q, want one of evt-A / evt-B", got.LastEventID)
	}
}
