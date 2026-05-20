// Governing: SPEC-0001 REQ "Account Hard Delete After Retention",
// ADR-0006 (SQLite as persistent store).
package retention

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// migrateMu serializes calls to store.Migrate across parallel tests.
// goose's package-level config (SetBaseFS / SetDialect / SetTableName)
// is global state, so concurrent migrations race on those writes even
// when each test owns its own DB file.
var migrateMu sync.Mutex

// newTestStore opens a fresh on-disk SQLite database under t.TempDir
// and runs the embedded migrations. The store is closed via t.Cleanup.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "retention-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	return st
}

// TestSweepHardDeletesExpiredSoftDeleted is the acceptance test for
// SPEC-0001 REQ "Account Hard Delete After Retention". It inserts a
// soft-deleted row with deleted_at set past the retention window, runs
// the sweep once, and asserts:
//
//   - The accounts row is gone (hard-deleted).
//   - Running the sweep a second time with no new soft-deletes is a
//     no-op (idempotency).
//
// The test also seeds a second soft-deleted account that is NOT past
// the retention window to confirm the sweeper only targets expired rows.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention".
func TestSweepHardDeletesExpiredSoftDeleted(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	// Seed an expired soft-deleted account: state=soft_deleted with
	// deleted_at 31 days ago (past the default 30d retention window).
	expiredAccountID := "acct-expired"
	storetest.SeedUserAccountActive(t, st, expiredAccountID)
	if _, err := st.DB.ExecContext(ctx,
		`UPDATE accounts SET state = 'soft_deleted', deleted_at = datetime('now', '-31 days') WHERE id = ?`,
		expiredAccountID,
	); err != nil {
		t.Fatalf("backdate expired account: %v", err)
	}

	// Seed a fresh soft-deleted account: deleted_at only 1 day ago
	// (within the 30d retention window; must NOT be swept).
	freshAccountID := "acct-fresh-deleted"
	storetest.SeedUserAccountActive(t, st, freshAccountID)
	if _, err := st.DB.ExecContext(ctx,
		`UPDATE accounts SET state = 'soft_deleted', deleted_at = datetime('now', '-1 day') WHERE id = ?`,
		freshAccountID,
	); err != nil {
		t.Fatalf("backdate fresh account: %v", err)
	}

	// Seed an active account (must NOT be swept regardless of age).
	activeAccountID := "acct-active"
	storetest.SeedUserAccountActive(t, st, activeAccountID)

	// Build a sweeper with a 30d retention period. Use time.Now so the
	// cutoff is 30 days ago from now — the expired account at -31d is
	// past the cutoff; the fresh account at -1d is not.
	s := New(Config{
		DB:              st.DB,
		RetentionPeriod: 30 * 24 * time.Hour,
		SweepInterval:   time.Hour, // not used in single-sweep test
	})

	s.sweep(ctx)

	// The expired account must be gone.
	var countExpired int
	if err := st.DB.GetContext(ctx, &countExpired,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, expiredAccountID,
	); err != nil {
		t.Fatalf("count expired: %v", err)
	}
	if countExpired != 0 {
		t.Errorf("expired account still present after sweep; want 0 rows, got %d", countExpired)
	}

	// The fresh soft-deleted account must remain.
	var countFresh int
	if err := st.DB.GetContext(ctx, &countFresh,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, freshAccountID,
	); err != nil {
		t.Fatalf("count fresh: %v", err)
	}
	if countFresh != 1 {
		t.Errorf("fresh soft-deleted account was swept prematurely; want 1 row, got %d", countFresh)
	}

	// The active account must remain.
	var countActive int
	if err := st.DB.GetContext(ctx, &countActive,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, activeAccountID,
	); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if countActive != 1 {
		t.Errorf("active account was swept; want 1 row, got %d", countActive)
	}

	// Idempotency: running sweep again with no new expired rows is a
	// no-op — the sweep must not error and must not remove anything else.
	s.sweep(ctx)

	// All counts must be the same as after the first sweep.
	if err := st.DB.GetContext(ctx, &countExpired,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, expiredAccountID,
	); err != nil {
		t.Fatalf("idempotent count expired: %v", err)
	}
	if countExpired != 0 {
		t.Errorf("idempotent sweep introduced expired account row; want 0, got %d", countExpired)
	}

	if err := st.DB.GetContext(ctx, &countFresh,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, freshAccountID,
	); err != nil {
		t.Fatalf("idempotent count fresh: %v", err)
	}
	if countFresh != 1 {
		t.Errorf("idempotent sweep removed fresh account; want 1, got %d", countFresh)
	}
}

// TestSweepCascadesOnPerAccountTables verifies that ON DELETE CASCADE
// fires on at least one per-account table when the sweep hard-deletes
// an accounts row. We use the sync_state table (added in migration
// 20260502000001) as a representative cascade target.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
// "SHALL cascade to all per-account tables".
func TestSweepCascadesOnPerAccountTables(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	accountID := "acct-cascade"
	storetest.SeedUserAccountActive(t, st, accountID)

	// Seed a sync_state row for this account (cascade target).
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO sync_state (account_id, last_event_id, last_synced_at) VALUES (?, ?, datetime('now'))`,
		accountID, "cursor-abc",
	); err != nil {
		t.Fatalf("insert sync_state: %v", err)
	}

	// Confirm the sync_state row exists.
	var syncCount int
	if err := st.DB.GetContext(ctx, &syncCount,
		`SELECT COUNT(*) FROM sync_state WHERE account_id = ?`, accountID,
	); err != nil {
		t.Fatalf("count sync_state before sweep: %v", err)
	}
	if syncCount != 1 {
		t.Fatalf("sync_state row not seeded; got %d", syncCount)
	}

	// Soft-delete the account with deleted_at 35 days ago.
	if _, err := st.DB.ExecContext(ctx,
		`UPDATE accounts SET state = 'soft_deleted', deleted_at = datetime('now', '-35 days') WHERE id = ?`,
		accountID,
	); err != nil {
		t.Fatalf("soft-delete account: %v", err)
	}

	s := New(Config{
		DB:              st.DB,
		RetentionPeriod: 30 * 24 * time.Hour,
		SweepInterval:   time.Hour,
	})
	s.sweep(ctx)

	// The accounts row must be gone.
	var acctCount int
	if err := st.DB.GetContext(ctx, &acctCount,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, accountID,
	); err != nil {
		t.Fatalf("count accounts after sweep: %v", err)
	}
	if acctCount != 0 {
		t.Errorf("accounts row not removed; want 0, got %d", acctCount)
	}

	// The sync_state row must have cascaded.
	if err := st.DB.GetContext(ctx, &syncCount,
		`SELECT COUNT(*) FROM sync_state WHERE account_id = ?`, accountID,
	); err != nil {
		t.Fatalf("count sync_state after sweep: %v", err)
	}
	if syncCount != 0 {
		t.Errorf("sync_state row not cascaded; want 0, got %d", syncCount)
	}
}

// TestSweepSkipsNonSoftDeleted ensures that accounts in states other
// than soft_deleted are never touched, even if they happen to have
// deleted_at set (which should not occur in practice but guards against
// schema bugs).
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention".
func TestSweepSkipsNonSoftDeleted(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	accountID := "acct-active-with-deletedat"
	storetest.SeedUserAccountActive(t, st, accountID)

	// Manually set deleted_at far in the past on an active row (schema
	// anomaly, but the sweep must not touch it).
	if _, err := st.DB.ExecContext(ctx,
		`UPDATE accounts SET deleted_at = datetime('now', '-60 days') WHERE id = ?`,
		accountID,
	); err != nil {
		t.Fatalf("set deleted_at: %v", err)
	}

	s := New(Config{
		DB:              st.DB,
		RetentionPeriod: 30 * 24 * time.Hour,
		SweepInterval:   time.Hour,
	})
	s.sweep(ctx)

	var count int
	if err := st.DB.GetContext(ctx, &count,
		`SELECT COUNT(*) FROM accounts WHERE id = ?`, accountID,
	); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("active account was swept; want 1 row, got %d", count)
	}
}

// TestNewPanicsOnNilDB confirms that New panics when given a nil DB —
// a missing database is a programming error, not a recoverable runtime
// condition.
func TestNewPanicsOnNilDB(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected New(nil DB) to panic")
		}
	}()
	_ = New(Config{DB: nil})
}
