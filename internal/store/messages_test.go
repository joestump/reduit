package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore opens a fresh migrated store in a temp dir, matching the setup
// the other store tests use.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// seedMailbox inserts a mailbox so message rows satisfy any downstream
// expectations; messages.mailbox_id references mailboxes(id).
func seedMailbox(t *testing.T, st *Store, id, address string) {
	t.Helper()
	if err := st.InsertMailbox(context.Background(), id, address); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
}

func countRows(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.DB.GetContext(context.Background(), &n, "SELECT COUNT(*) FROM "+table); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

const testMailboxID = "01234567-test-uuid-v7-000000000001"

func sampleMessage(mailboxID, protonID string) MessageRow {
	return MessageRow{
		MailboxID: mailboxID,
		ProtonID:  protonID,
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Sender:    "alice@example.com",
		Subject:   "Hello",
		Body:      "See https://example.com/a for details.",
		Folder:    "Inbox",
	}
}

// TestMessageHashStable confirms the hash depends only on (mailbox_id, proton_id)
// and not on any mutable content — the property that makes re-sync converge and
// keeps derived data attached.
func TestMessageHashStable(t *testing.T) {
	t.Parallel()
	base := MessageHash("mb1", "msg1")
	if base == "" || len(base) != 64 {
		t.Fatalf("hash not a sha256 hex string: %q", base)
	}
	// Same identity inputs → same hash.
	if got := MessageHash("mb1", "msg1"); got != base {
		t.Errorf("hash not stable: %q != %q", got, base)
	}
	// Different mailbox or proton id → different hash.
	if MessageHash("mb2", "msg1") == base {
		t.Error("hash collided across mailboxes")
	}
	if MessageHash("mb1", "msg2") == base {
		t.Error("hash collided across proton ids")
	}
	// The NUL separator must be unambiguous: ("a","bc") != ("ab","c").
	if MessageHash("a", "bc") == MessageHash("ab", "c") {
		t.Error("hash separator is ambiguous")
	}
}

// TestUpsertMessageConverges: upserting the same message twice yields exactly
// one row (SPEC-0002 "Re-importing a message converges").
func TestUpsertMessageConverges(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	h1, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	h2, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash changed across upserts: %q != %q", h1, h2)
	}
	if n := countRows(t, st, "messages"); n != 1 {
		t.Errorf("message count grew: got %d, want 1", n)
	}
}

// TestUpsertMessageUpdatesMutableColumnsKeepsID: a re-sync with changed content
// updates the mutable columns in place and preserves the internal id and
// created_at (no churn).
func TestUpsertMessageUpdatesMutableColumnsKeepsID(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	if _, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	type row struct {
		ID        string    `db:"id"`
		Subject   string    `db:"subject"`
		Body      string    `db:"body"`
		Folder    string    `db:"folder"`
		CreatedAt time.Time `db:"created_at"`
	}
	var before row
	if err := st.DB.GetContext(ctx, &before, `SELECT id, subject, body, folder, created_at FROM messages WHERE proton_id = 'm1'`); err != nil {
		t.Fatalf("read before: %v", err)
	}

	changed := sampleMessage(testMailboxID, "m1")
	changed.Subject = "Re: Hello"
	changed.Body = "updated body"
	changed.Folder = "Archive"
	if _, err := st.UpsertMessage(ctx, changed); err != nil {
		t.Fatalf("update: %v", err)
	}

	var after row
	if err := st.DB.GetContext(ctx, &after, `SELECT id, subject, body, folder, created_at FROM messages WHERE proton_id = 'm1'`); err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after.ID != before.ID {
		t.Errorf("internal id churned: %q -> %q", before.ID, after.ID)
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("created_at churned: %v -> %v", before.CreatedAt, after.CreatedAt)
	}
	if after.Subject != "Re: Hello" || after.Body != "updated body" || after.Folder != "Archive" {
		t.Errorf("mutable columns not updated: %+v", after)
	}
}

// TestDerivedDataSurvivesReSync: seeding an embedding row and an attachment with
// extracted_text, then re-syncing the message, leaves the derived data intact
// (SPEC-0002 "Derived data survives re-sync").
func TestDerivedDataSurvivesReSync(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	hash, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}
	// Seed derived data keyed by the stable hash.
	if _, err := st.WriterDB().ExecContext(ctx,
		`INSERT INTO embeddings (hash, model, dim, vec) VALUES (?, 'test-model', 1, ?)`,
		hash, []byte{0x00, 0x00, 0x00, 0x00}); err != nil {
		t.Fatalf("seed embedding: %v", err)
	}
	if err := st.UpsertAttachment(ctx, hash, "att1", "file.pdf", "application/pdf", 100); err != nil {
		t.Fatalf("seed attachment: %v", err)
	}
	if _, err := st.WriterDB().ExecContext(ctx,
		`UPDATE attachments SET extracted_text = 'extracted body' WHERE message_hash = ? AND proton_att_id = 'att1'`, hash); err != nil {
		t.Fatalf("seed extracted_text: %v", err)
	}

	// Re-sync the message with a changed body — hash unchanged.
	changed := sampleMessage(testMailboxID, "m1")
	changed.Body = "different body"
	if _, err := st.UpsertMessage(ctx, changed); err != nil {
		t.Fatalf("re-sync message: %v", err)
	}
	// Re-sync the attachment metadata too (as the engine would).
	if err := st.UpsertAttachment(ctx, hash, "att1", "file.pdf", "application/pdf", 100); err != nil {
		t.Fatalf("re-sync attachment: %v", err)
	}

	if n := countRows(t, st, "embeddings"); n != 1 {
		t.Errorf("embedding orphaned/wiped: got %d, want 1", n)
	}
	var text *string
	if err := st.DB.GetContext(ctx, &text,
		`SELECT extracted_text FROM attachments WHERE message_hash = ? AND proton_att_id = 'att1'`, hash); err != nil {
		t.Fatalf("read extracted_text: %v", err)
	}
	if text == nil || *text != "extracted body" {
		t.Errorf("extracted_text clobbered: %v", text)
	}
}

// TestFTSFindsMessage: after UpsertMessage the messages_fts index (maintained by
// triggers) matches the message (SPEC-0002 "New message becomes searchable").
func TestFTSFindsMessage(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	if _, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var n int
	if err := st.DB.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'Hello'`); err != nil {
		t.Fatalf("fts match: %v", err)
	}
	if n != 1 {
		t.Errorf("FTS did not find message: got %d, want 1", n)
	}

	// After an update the FTS row reflects new content.
	changed := sampleMessage(testMailboxID, "m1")
	changed.Subject = "Zebra"
	if _, err := st.UpsertMessage(ctx, changed); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := st.DB.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'Zebra'`); err != nil {
		t.Fatalf("fts match after update: %v", err)
	}
	if n != 1 {
		t.Errorf("FTS not updated: got %d, want 1", n)
	}
	// The pre-update term must be GONE — an external-content FTS index that
	// double-indexed (insert-new without delete-old) would still match 'Hello'.
	if err := st.DB.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'Hello'`); err != nil {
		t.Fatalf("fts match stale term after update: %v", err)
	}
	if n != 0 {
		t.Errorf("stale FTS term 'Hello' still indexed after update: got %d, want 0 (index corruption)", n)
	}
}

// TestDeleteMessage removes the message and its links/attachments, keeps
// contacts, and is idempotent (SPEC-0002 deletes + "Contact Materialization").
func TestDeleteMessage(t *testing.T) {
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
	if err := st.ApplyMessage(ctx, w); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countRows(t, st, "messages"); got != 1 {
		t.Fatalf("precondition messages=%d", got)
	}

	if err := st.DeleteMessageByProtonID(ctx, testMailboxID, "m1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := countRows(t, st, "messages"); got != 0 {
		t.Errorf("message not deleted: %d", got)
	}
	if got := countRows(t, st, "links"); got != 0 {
		t.Errorf("links not deleted: %d", got)
	}
	if got := countRows(t, st, "attachments"); got != 0 {
		t.Errorf("attachments not deleted: %d", got)
	}
	if got := countRows(t, st, "contacts"); got != 1 {
		t.Errorf("contacts wrongly deleted: %d", got)
	}
	// FTS entry gone too.
	var n int
	if err := st.DB.GetContext(ctx, &n, `SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'Hello'`); err != nil {
		t.Fatalf("fts count: %v", err)
	}
	if n != 0 {
		t.Errorf("FTS entry not removed: %d", n)
	}

	// Idempotent: deleting again is a no-op, no error.
	if err := st.DeleteMessageByProtonID(ctx, testMailboxID, "m1"); err != nil {
		t.Errorf("second delete errored: %v", err)
	}
}
