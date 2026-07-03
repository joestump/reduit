package store

import (
	"context"
	"testing"
	"time"
)

// TestResetSyncCursor: a set cursor is cleared back to unset, so GetSyncState
// reports a nil cursor and the engine re-bootstraps (SPEC-0002 "Full rescan on
// demand" — the store seam behind `reduit sync --full`).
func TestResetSyncCursor(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	// Set a cursor, then confirm it round-trips.
	if err := st.UpsertSyncState(ctx, testMailboxID, "ev-42", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertSyncState: %v", err)
	}
	ss, err := st.GetSyncState(ctx, testMailboxID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if ss.EventCursor == nil || *ss.EventCursor != "ev-42" {
		t.Fatalf("cursor before reset = %v, want ev-42", ss.EventCursor)
	}

	// Reset clears it back to unset.
	if err := st.ResetSyncCursor(ctx, testMailboxID); err != nil {
		t.Fatalf("ResetSyncCursor: %v", err)
	}
	ss, err = st.GetSyncState(ctx, testMailboxID)
	if err != nil {
		t.Fatalf("GetSyncState after reset: %v", err)
	}
	if ss.EventCursor != nil {
		t.Errorf("cursor after reset = %v, want nil", ss.EventCursor)
	}

	// Idempotent: resetting a mailbox that already has no row is a no-op.
	if err := st.ResetSyncCursor(ctx, testMailboxID); err != nil {
		t.Errorf("ResetSyncCursor (idempotent): %v", err)
	}
}
