package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMailboxLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	ctx := context.Background()

	// Insert a new mailbox.
	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000001", "joe@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}

	// Fetch it back.
	m, err := st.GetMailbox(ctx, "01234567-test-uuid-v7-000000000001")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	if m.State != MailboxStatePendingAuth {
		t.Errorf("initial state = %q, want pending_auth", m.State)
	}
	if m.ProtonUserID != nil {
		t.Error("ProtonUserID should be nil before first auth")
	}

	// Set proton_user_id on first auth — transitions to active.
	if err := st.SetProtonUserID(ctx, m.ID, "proton-user-123"); err != nil {
		t.Fatalf("SetProtonUserID: %v", err)
	}
	m2, _ := st.GetMailbox(ctx, m.ID)
	if m2.State != MailboxStateActive {
		t.Errorf("state after SetProtonUserID = %q, want active", m2.State)
	}

	// Attempt to overwrite with a different proton_user_id — must fail.
	if err := st.SetProtonUserID(ctx, m.ID, "proton-user-OTHER"); err == nil {
		t.Error("expected ErrProtonUserIDConflict when overwriting proton_user_id")
	}

	// List returns the mailbox.
	list, err := st.ListMailboxes(ctx)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListMailboxes returned %d, want 1", len(list))
	}

	// Delete removes it.
	if err := st.DeleteMailbox(ctx, m.ID); err != nil {
		t.Fatalf("DeleteMailbox: %v", err)
	}
	if _, err := st.GetMailbox(ctx, m.ID); err == nil {
		t.Error("GetMailbox after DeleteMailbox: expected not found error")
	}
}

func TestMailboxMultiMailbox(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()

	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000001", "alice@pm.me"); err != nil {
		t.Fatalf("InsertMailbox alice: %v", err)
	}
	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000002", "bob@pm.me"); err != nil {
		t.Fatalf("InsertMailbox bob: %v", err)
	}
	list, err := st.ListMailboxes(ctx)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("ListMailboxes = %d, want 2", len(list))
	}
}

func TestMailboxDuplicateProtonUserID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()

	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000001", "alice@pm.me"); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000002", "alice2@pm.me"); err != nil {
		t.Fatal(err)
	}
	// Assign same proton_user_id to both — second should fail via UNIQUE constraint.
	if err := st.SetProtonUserID(ctx, "01234567-test-uuid-v7-000000000001", "proton-user-123"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProtonUserID(ctx, "01234567-test-uuid-v7-000000000002", "proton-user-123"); err == nil {
		t.Error("expected UNIQUE constraint error for duplicate proton_user_id")
	}
}
