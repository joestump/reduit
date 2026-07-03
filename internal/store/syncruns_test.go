package store

import (
	"context"
	"testing"
	"time"
)

// TestRecordAndReadSyncRun: a recorded run is read back with its counts and
// failure cause intact (SPEC-0002 REQ "Bookkeeping And Observability").
func TestRecordAndReadSyncRun(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	start := time.Date(2026, 7, 3, 1, 0, 0, 0, time.UTC)
	cause := "decrypt failed for m7"
	run := SyncRun{
		MailboxID:   testMailboxID,
		StartedAt:   start,
		FinishedAt:  start.Add(2 * time.Minute),
		Added:       5,
		Updated:     3,
		Deleted:     1,
		Attachments: 4,
		Errors:      2,
		LastError:   &cause,
	}
	if err := st.RecordSyncRun(ctx, run); err != nil {
		t.Fatalf("RecordSyncRun: %v", err)
	}

	got, ok, err := st.LatestSyncRun(ctx, testMailboxID)
	if err != nil {
		t.Fatalf("LatestSyncRun: %v", err)
	}
	if !ok {
		t.Fatal("LatestSyncRun: ok=false, want a recorded run")
	}
	if got.ID == "" {
		t.Error("recorded run has empty id (should be assigned a UUIDv7)")
	}
	if got.Added != 5 || got.Updated != 3 || got.Deleted != 1 || got.Attachments != 4 || got.Errors != 2 {
		t.Errorf("counts did not persist: %+v", got)
	}
	if !got.StartedAt.Equal(start) {
		t.Errorf("started_at = %v, want %v", got.StartedAt, start)
	}
	if got.LastError == nil || *got.LastError != cause {
		t.Errorf("last_error = %v, want %q", got.LastError, cause)
	}
}

// TestRecordSyncRunDefaults: a zero ID is assigned a UUIDv7 and a zero
// FinishedAt is filled, so a caller can hand over just counts + mailbox. A clean
// run's LastError round-trips as nil.
func TestRecordSyncRunDefaults(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	if err := st.RecordSyncRun(ctx, SyncRun{MailboxID: testMailboxID, Added: 1}); err != nil {
		t.Fatalf("RecordSyncRun: %v", err)
	}
	got, ok, err := st.LatestSyncRun(ctx, testMailboxID)
	if err != nil || !ok {
		t.Fatalf("LatestSyncRun: ok=%v err=%v", ok, err)
	}
	if got.ID == "" {
		t.Error("id not assigned")
	}
	if got.FinishedAt.IsZero() {
		t.Error("finished_at not defaulted")
	}
	if got.LastError != nil {
		t.Errorf("last_error = %v, want nil for a clean run", *got.LastError)
	}
}

// TestRecordSyncRunRequiresMailbox: an empty mailbox id is rejected.
func TestRecordSyncRunRequiresMailbox(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	if err := st.RecordSyncRun(context.Background(), SyncRun{Added: 1}); err == nil {
		t.Fatal("RecordSyncRun with empty mailbox_id: want error, got nil")
	}
}

// TestLatestSyncRunNone: no recorded run reports ok=false, not an error.
func TestLatestSyncRunNone(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")

	_, ok, err := st.LatestSyncRun(context.Background(), testMailboxID)
	if err != nil {
		t.Fatalf("LatestSyncRun: %v", err)
	}
	if ok {
		t.Error("ok=true for a mailbox with no runs")
	}
}

// TestLatestSyncRunReturnsNewest: with several runs recorded, the most recent by
// started_at is returned.
func TestLatestSyncRunReturnsNewest(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	base := time.Date(2026, 7, 3, 1, 0, 0, 0, time.UTC)
	if err := st.RecordSyncRun(ctx, SyncRun{MailboxID: testMailboxID, StartedAt: base, FinishedAt: base, Added: 1}); err != nil {
		t.Fatalf("record older: %v", err)
	}
	newer := base.Add(time.Hour)
	if err := st.RecordSyncRun(ctx, SyncRun{MailboxID: testMailboxID, StartedAt: newer, FinishedAt: newer, Added: 9}); err != nil {
		t.Fatalf("record newer: %v", err)
	}
	got, ok, err := st.LatestSyncRun(ctx, testMailboxID)
	if err != nil || !ok {
		t.Fatalf("LatestSyncRun: ok=%v err=%v", ok, err)
	}
	if got.Added != 9 {
		t.Errorf("returned run Added=%d, want 9 (the newest)", got.Added)
	}
}
