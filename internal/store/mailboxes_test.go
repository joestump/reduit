package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
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

func TestMailboxSessionUID(t *testing.T) {
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

	if err := st.InsertMailbox(ctx, "01234567-test-uuid-v7-000000000001", "joe@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	// A fresh row (like a pre-migration one) has no session UID.
	m, _ := st.GetMailbox(ctx, "01234567-test-uuid-v7-000000000001")
	if m.SessionUID != nil {
		t.Errorf("SessionUID should be nil before it is set, got %v", *m.SessionUID)
	}

	// Set, then read back through every accessor.
	if err := st.SetSessionUID(ctx, m.ID, "session-uid-abc"); err != nil {
		t.Fatalf("SetSessionUID: %v", err)
	}
	got, _ := st.GetMailbox(ctx, m.ID)
	if got.SessionUID == nil || *got.SessionUID != "session-uid-abc" {
		t.Errorf("GetMailbox SessionUID = %v, want session-uid-abc", got.SessionUID)
	}
	byAddr, _ := st.GetMailboxByAddress(ctx, "joe@example.com")
	if byAddr.SessionUID == nil || *byAddr.SessionUID != "session-uid-abc" {
		t.Errorf("GetMailboxByAddress SessionUID = %v, want session-uid-abc", byAddr.SessionUID)
	}
	list, _ := st.ListMailboxes(ctx)
	if len(list) != 1 || list[0].SessionUID == nil || *list[0].SessionUID != "session-uid-abc" {
		t.Errorf("ListMailboxes SessionUID = %v, want session-uid-abc", list)
	}

	// Rotation: a later resume overwrites it.
	if err := st.SetSessionUID(ctx, m.ID, "session-uid-rotated"); err != nil {
		t.Fatalf("SetSessionUID rotate: %v", err)
	}
	rot, _ := st.GetMailbox(ctx, m.ID)
	if rot.SessionUID == nil || *rot.SessionUID != "session-uid-rotated" {
		t.Errorf("rotated SessionUID = %v, want session-uid-rotated", rot.SessionUID)
	}

	// Unknown id is a clear not-found, not a silent no-op.
	if err := st.SetSessionUID(ctx, "no-such-id", "x"); !errors.Is(err, ErrMailboxNotFound) {
		t.Errorf("SetSessionUID on unknown id = %v, want ErrMailboxNotFound", err)
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

// TestDeleteMailbox_CascadesAllDependents reproduces the live `auth remove`
// failure: a mailbox with a recorded sync_run (FK to mailboxes) made
// DeleteMailbox trip "FOREIGN KEY constraint failed". The delete must remove
// EVERY dependent row — messages (+ hash-keyed links/attachments/embeddings),
// sync_runs, sync_state, fact_state, mailbox-scoped denylist — atomically,
// while retaining shared contacts.
func TestDeleteMailbox_CascadesAllDependents(t *testing.T) {
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

	const mb = "01234567-test-uuid-v7-00000000del1"
	if err := st.InsertMailbox(ctx, mb, "del@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}

	// A cached message with every hash-keyed child + a contact.
	res, err := st.ApplyMessage(ctx, MessageWrite{
		Message: MessageRow{MailboxID: mb, ProtonID: "pm-1", Timestamp: time.Now().UTC(),
			Sender: "a@example.com", Subject: "hi", Body: "see https://example.com"},
		Contacts:    []ContactInput{{Address: "a@example.com", DisplayName: "A"}},
		Links:       []LinkInput{{URL: "https://example.com"}},
		Attachments: []AttachmentInput{{ProtonAttID: "att-1", Filename: "f.pdf", MIME: "application/pdf", SizeBytes: 1}},
	})
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	if _, err := st.WriterDB().ExecContext(ctx,
		`INSERT INTO embeddings (hash, model, dim, vec) VALUES (?, 'm', 1, x'00')`, res.Hash); err != nil {
		t.Fatalf("seed embedding: %v", err)
	}
	// The exact live trigger: a recorded sync_run referencing the mailbox.
	if err := st.RecordSyncRun(ctx, SyncRun{MailboxID: mb,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("RecordSyncRun: %v", err)
	}
	if err := st.UpsertSyncState(ctx, mb, "ev-1", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertSyncState: %v", err)
	}
	if _, err := st.WriterDB().ExecContext(ctx,
		`INSERT INTO denylist (id, mailbox_id, kind, value) VALUES ('dl-1', ?, 'sender', 'x@y.z')`, mb); err != nil {
		t.Fatalf("seed denylist: %v", err)
	}

	if err := st.DeleteMailbox(ctx, mb); err != nil {
		t.Fatalf("DeleteMailbox with dependents: %v", err)
	}

	for _, q := range []struct{ name, sql string }{
		{"mailboxes", `SELECT COUNT(*) FROM mailboxes WHERE id = '` + mb + `'`},
		{"messages", `SELECT COUNT(*) FROM messages WHERE mailbox_id = '` + mb + `'`},
		{"links", `SELECT COUNT(*) FROM links WHERE message_hash = '` + res.Hash + `'`},
		{"attachments", `SELECT COUNT(*) FROM attachments WHERE message_hash = '` + res.Hash + `'`},
		{"embeddings", `SELECT COUNT(*) FROM embeddings WHERE hash = '` + res.Hash + `'`},
		{"sync_runs", `SELECT COUNT(*) FROM sync_runs WHERE mailbox_id = '` + mb + `'`},
		{"sync_state", `SELECT COUNT(*) FROM sync_state WHERE mailbox_id = '` + mb + `'`},
		{"denylist", `SELECT COUNT(*) FROM denylist WHERE mailbox_id = '` + mb + `'`},
	} {
		var n int
		if err := st.DB.GetContext(ctx, &n, q.sql); err != nil {
			t.Fatalf("count %s: %v", q.name, err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows survive DeleteMailbox, want 0", q.name, n)
		}
	}
	// Shared contacts are retained.
	var contacts int
	if err := st.DB.GetContext(ctx, &contacts, `SELECT COUNT(*) FROM contact_identifiers WHERE address = 'a@example.com'`); err != nil {
		t.Fatalf("count contacts: %v", err)
	}
	if contacts != 1 {
		t.Errorf("contact_identifiers = %d, want 1 (contacts are shared, retained)", contacts)
	}
	// Idempotent on a now-missing mailbox.
	if err := st.DeleteMailbox(ctx, mb); err != nil {
		t.Fatalf("DeleteMailbox second call: %v", err)
	}
}
