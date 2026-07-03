package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestWithTxAtomicMessageAndCursor: a message apply and the cursor advance
// committed in one WithTx both land (SPEC-0002 "Cursor advances atomically with
// the delta"). This is the seam the sync engine relies on.
func TestWithTxAtomicMessageAndCursor(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	w := MessageWrite{
		Message:     sampleMessage(testMailboxID, "m1"),
		Contacts:    []ContactInput{{Address: "alice@example.com", DisplayName: "Alice"}},
		Links:       []LinkInput{{URL: "https://example.com/a", AnchorText: "a"}},
		Attachments: []AttachmentInput{{ProtonAttID: "att1", Filename: "f.pdf", MIME: "application/pdf", SizeBytes: 10}},
	}
	runAt := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	err := st.WithTx(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ApplyMessage(ctx, w); err != nil {
			return err
		}
		return tx.UpsertSyncState(ctx, testMailboxID, "cursor-42", runAt)
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	// Message + derived rows landed.
	if got := countRows(t, st, "messages"); got != 1 {
		t.Errorf("messages=%d, want 1", got)
	}
	if got := countRows(t, st, "links"); got != 1 {
		t.Errorf("links=%d, want 1", got)
	}
	if got := countRows(t, st, "attachments"); got != 1 {
		t.Errorf("attachments=%d, want 1", got)
	}
	if got := countRows(t, st, "contacts"); got != 1 {
		t.Errorf("contacts=%d, want 1", got)
	}
	// Cursor advanced in the same commit.
	ss, err := st.GetSyncState(ctx, testMailboxID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if ss.EventCursor == nil || *ss.EventCursor != "cursor-42" {
		t.Errorf("cursor not advanced: %v", ss.EventCursor)
	}
}

// TestWithTxRollsBackOnError: an error returned inside WithTx rolls back every
// write in the transaction — neither the message nor the cursor is observable
// (SPEC-0002 "a partial commit SHALL NOT be observable").
func TestWithTxRollsBackOnError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	sentinel := errors.New("boom")
	err := st.WithTx(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ApplyMessage(ctx, MessageWrite{Message: sampleMessage(testMailboxID, "m1")}); err != nil {
			return err
		}
		if err := tx.UpsertSyncState(ctx, testMailboxID, "cursor-99", time.Now()); err != nil {
			return err
		}
		return sentinel // abort — everything above must roll back
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx returned %v, want sentinel", err)
	}

	if got := countRows(t, st, "messages"); got != 0 {
		t.Errorf("message survived rollback: %d", got)
	}
	ss, err := st.GetSyncState(ctx, testMailboxID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if ss.EventCursor != nil {
		t.Errorf("cursor survived rollback: %v", *ss.EventCursor)
	}
}

// TestWithTxOverlappingWindowsNoDuplicate: applying the same message across two
// separate transactions (as a backfill window then a tail would) converges to
// one row (SPEC-0002 "Overlapping windows do not duplicate").
func TestWithTxOverlappingWindowsNoDuplicate(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	apply := func(cursor string) {
		err := st.WithTx(ctx, func(ctx context.Context, tx *Tx) error {
			if _, err := tx.ApplyMessage(ctx, MessageWrite{Message: sampleMessage(testMailboxID, "m1")}); err != nil {
				return err
			}
			return tx.UpsertSyncState(ctx, testMailboxID, cursor, time.Now())
		})
		if err != nil {
			t.Fatalf("apply %s: %v", cursor, err)
		}
	}
	apply("backfill")
	apply("tail")

	if got := countRows(t, st, "messages"); got != 1 {
		t.Errorf("overlapping windows duplicated: messages=%d, want 1", got)
	}
}
