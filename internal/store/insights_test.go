package store

import (
	"context"
	"testing"
)

// insightsSeed inserts a mailbox, a message, an attachment on it, and a contact
// with one fact, returning the message hash and attachment/contact ids so tests
// can assert the read joins.
func insightsSeed(t *testing.T, st *Store) (attID, contactID string) {
	t.Helper()
	ctx := context.Background()
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	res, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("UpsertMessage: %v", err)
	}
	if err := st.UpsertAttachment(ctx, res.Hash, "att-1", "invoice.pdf", "application/pdf", 20480); err != nil {
		t.Fatalf("UpsertAttachment: %v", err)
	}
	// Resolve the attachment id.
	if err := st.DB.GetContext(ctx, &attID, "SELECT id FROM attachments WHERE proton_att_id = ?", "att-1"); err != nil {
		t.Fatalf("resolve attachment id: %v", err)
	}
	// Seed a contact + identifier + fact directly (no public writer yet).
	contactID = "01234567-test-uuid-v7-00000000c001"
	mustExec(t, st, `INSERT INTO contacts (id, display_name) VALUES (?, ?)`, contactID, "Alice Example")
	mustExec(t, st, `INSERT INTO contact_identifiers (contact_id, address) VALUES (?, ?)`, contactID, "alice@example.com")
	mustExec(t, st, `INSERT INTO contact_facts (id, contact_id, fact, category, fact_hash, source_message_hash)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"01234567-test-uuid-v7-00000000f001", contactID, "prefers email over calls", "preference", "fh1", res.Hash)
	return attID, contactID
}

func mustExec(t *testing.T, st *Store, q string, args ...any) {
	t.Helper()
	if _, err := st.DB.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func TestListAttachments(t *testing.T) {
	st := newTestStore(t)
	insightsSeed(t, st)
	rows, err := st.ListAttachments(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListAttachments: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d attachments, want 1", len(rows))
	}
	a := rows[0]
	if a.Filename != "invoice.pdf" || a.MIME != "application/pdf" || a.SizeBytes != 20480 {
		t.Errorf("attachment metadata wrong: %+v", a)
	}
	if a.MessageSubj != "Hello" || a.MessageSender != "alice@example.com" {
		t.Errorf("owning-message join wrong: subj=%q sender=%q", a.MessageSubj, a.MessageSender)
	}
	if a.HasText {
		t.Error("HasText should be false before an extraction pass")
	}
}

func TestAttachmentText(t *testing.T) {
	st := newTestStore(t)
	attID, _ := insightsSeed(t, st)
	// Before extraction: found, empty.
	txt, found, err := st.AttachmentText(context.Background(), attID)
	if err != nil || !found || txt != "" {
		t.Fatalf("pre-extract: txt=%q found=%v err=%v", txt, found, err)
	}
	// After an extraction writes text.
	mustExec(t, st, `UPDATE attachments SET extracted_text = ? WHERE id = ?`, "Invoice total: $42", attID)
	txt, found, err = st.AttachmentText(context.Background(), attID)
	if err != nil || !found || txt != "Invoice total: $42" {
		t.Fatalf("post-extract: txt=%q found=%v err=%v", txt, found, err)
	}
	// Unknown id: not found, no error.
	_, found, err = st.AttachmentText(context.Background(), "nope")
	if err != nil || found {
		t.Errorf("unknown id: found=%v err=%v, want found=false nil", found, err)
	}
}

func TestListContactsAndFacts(t *testing.T) {
	st := newTestStore(t)
	_, contactID := insightsSeed(t, st)
	contacts, err := st.ListContacts(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 1 {
		t.Fatalf("got %d contacts, want 1", len(contacts))
	}
	c := contacts[0]
	if c.DisplayName != "Alice Example" || c.Address != "alice@example.com" || c.FactCount != 1 {
		t.Errorf("contact row wrong: %+v", c)
	}
	facts, err := st.ContactFacts(context.Background(), contactID)
	if err != nil {
		t.Fatalf("ContactFacts: %v", err)
	}
	if len(facts) != 1 || facts[0].Fact != "prefers email over calls" || facts[0].Category != "preference" {
		t.Fatalf("facts wrong: %+v", facts)
	}
	if facts[0].SourceMessageHash == "" {
		t.Error("fact must carry its source_message_hash citation")
	}
}

func TestInsightsReadsOnEmptyCache(t *testing.T) {
	// Cold cache: every read returns empty, never errors (TUI empty-state).
	st := newTestStore(t)
	ctx := context.Background()
	if rows, err := st.ListAttachments(ctx, 0); err != nil || len(rows) != 0 {
		t.Errorf("ListAttachments cold: rows=%d err=%v", len(rows), err)
	}
	if rows, err := st.ListContacts(ctx, 0); err != nil || len(rows) != 0 {
		t.Errorf("ListContacts cold: rows=%d err=%v", len(rows), err)
	}
	if rows, err := st.ContactFacts(ctx, "whatever"); err != nil || len(rows) != 0 {
		t.Errorf("ContactFacts cold: rows=%d err=%v", len(rows), err)
	}
}
