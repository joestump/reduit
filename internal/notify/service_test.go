package notify

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// migrateMu serializes store.Migrate across parallel tests: goose's
// package-level config is global state. Mirrors the account package's
// test harness.
var migrateMu sync.Mutex

// newTestService spins up a fresh on-disk SQLite (under t.TempDir), runs
// the embedded migrations, and returns a notify.Service plus the store
// so tests can seed the parent account rows the FK requires.
func newTestService(t *testing.T) (Service, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reduit-notify-test.db")
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
	return New(st), st
}

func TestRecordAndListUnacknowledged(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()
	storetest.SeedUserAccountActive(t, st, "acct-1")

	n, err := svc.Record(ctx, "acct-1", KindWorkerCrashed,
		"worker crashed", "panic: boom")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if n.ID == "" {
		t.Fatal("Record returned empty ID")
	}
	if n.CreatedAt.IsZero() {
		t.Fatal("Record returned zero CreatedAt")
	}

	got, err := svc.ListUnacknowledged(ctx, 0)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListUnacknowledged returned %d rows, want 1", len(got))
	}
	if got[0].Kind != KindWorkerCrashed {
		t.Errorf("Kind = %q, want %q", got[0].Kind, KindWorkerCrashed)
	}
	if got[0].Message != "worker crashed" || got[0].Detail != "panic: boom" {
		t.Errorf("message/detail round-trip = %q / %q", got[0].Message, got[0].Detail)
	}
	if got[0].AcknowledgedAt != nil {
		t.Error("fresh notification must have nil AcknowledgedAt")
	}

	count, err := svc.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if count != 1 {
		t.Errorf("CountUnacknowledged = %d, want 1", count)
	}
}

func TestListUnacknowledgedNewestFirst(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()
	storetest.SeedUserAccountActive(t, st, "acct-1")

	// Pin a monotonic clock so the ORDER BY created_at DESC is
	// deterministic regardless of wall-clock resolution.
	s := svc.(*service)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var i int
	s.now = func() time.Time { i++; return base.Add(time.Duration(i) * time.Minute) }

	first, _ := svc.Record(ctx, "acct-1", KindWorkerCrashed, "first", "")
	second, _ := svc.Record(ctx, "acct-1", KindAutoReverted, "second", "")

	got, err := svc.ListUnacknowledged(ctx, 10)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0].ID != second.ID || got[1].ID != first.ID {
		t.Errorf("order = [%s, %s], want newest-first [%s, %s]",
			got[0].ID, got[1].ID, second.ID, first.ID)
	}
}

func TestAcknowledgeRemovesFromUnacknowledged(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()
	storetest.SeedUserAccountActive(t, st, "acct-1")

	n, _ := svc.Record(ctx, "acct-1", KindAutoReverted, "reverted", "401")

	if err := svc.Acknowledge(ctx, n.ID); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	got, err := svc.ListUnacknowledged(ctx, 10)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("acknowledged notification still listed: %d rows", len(got))
	}
	count, _ := svc.CountUnacknowledged(ctx)
	if count != 0 {
		t.Errorf("CountUnacknowledged = %d after ack, want 0", count)
	}

	// Idempotent: re-acknowledging an already-dismissed row is a no-op,
	// NOT an error.
	if err := svc.Acknowledge(ctx, n.ID); err != nil {
		t.Errorf("double Acknowledge returned %v, want nil (idempotent)", err)
	}
}

func TestAcknowledgeUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	if err := svc.Acknowledge(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Acknowledge(unknown) = %v, want ErrNotFound", err)
	}
}

func TestRecordRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()
	storetest.SeedUserAccountActive(t, st, "acct-1")

	if _, err := svc.Record(ctx, "", KindWorkerCrashed, "m", ""); err == nil {
		t.Error("Record with empty accountID must error")
	}
	if _, err := svc.Record(ctx, "acct-1", Kind("bogus"), "m", ""); err == nil {
		t.Error("Record with invalid kind must error")
	}
}

// TestNotificationsCascadeOnAccountDelete pins SPEC-0001 "Account-Scoped
// Data": a notification must not outlive its account. Hard-deleting the
// account row cascades to admin_notifications.
func TestNotificationsCascadeOnAccountDelete(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()
	storetest.SeedUserAccountActive(t, st, "acct-1")

	if _, err := svc.Record(ctx, "acct-1", KindWorkerCrashed, "m", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	count, err := svc.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if count != 0 {
		t.Errorf("notifications survived account delete: count = %d, want 0 (FK cascade)", count)
	}
}
