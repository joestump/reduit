package store

import (
	"context"
	"testing"
)

// TestLinksConverge: re-upserting the same (message_hash, url) does not grow the
// link set; anchor text converges (SPEC-0002 "Re-sync converges links").
func TestLinksConverge(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	hash, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	if err := st.UpsertLink(ctx, hash, "https://example.com/a", "first"); err != nil {
		t.Fatalf("link 1: %v", err)
	}
	if err := st.UpsertLink(ctx, hash, "https://example.com/a", "second"); err != nil {
		t.Fatalf("link 2: %v", err)
	}
	if got := countRows(t, st, "links"); got != 1 {
		t.Errorf("link set grew: %d, want 1", got)
	}
	var anchor string
	if err := st.DB.GetContext(ctx, &anchor,
		`SELECT anchor_text FROM links WHERE message_hash = ? AND url = 'https://example.com/a'`, hash); err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if anchor != "second" {
		t.Errorf("anchor not converged: %q", anchor)
	}

	// A second distinct URL is a separate row.
	if err := st.UpsertLink(ctx, hash, "https://example.com/b", ""); err != nil {
		t.Fatalf("link 3: %v", err)
	}
	if got := countRows(t, st, "links"); got != 2 {
		t.Errorf("links=%d, want 2", got)
	}
}

// TestLinkEmptyURLNoOp: an empty URL writes nothing and does not error.
func TestLinkEmptyURLNoOp(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	hash, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	if err := st.UpsertLink(ctx, hash, "   ", "x"); err != nil {
		t.Fatalf("empty url errored: %v", err)
	}
	if got := countRows(t, st, "links"); got != 0 {
		t.Errorf("links written for empty url: %d", got)
	}
}

// TestMessageWithNoLinks: applying a message that carries no links writes no
// link rows (SPEC-0002 "A message with no URLs yields no links").
func TestMessageWithNoLinks(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	w := MessageWrite{Message: sampleMessage(testMailboxID, "m1")}
	if err := st.ApplyMessage(ctx, w); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countRows(t, st, "links"); got != 0 {
		t.Errorf("links written for link-less message: %d", got)
	}
	if got := countRows(t, st, "messages"); got != 1 {
		t.Errorf("message not written: %d", got)
	}
}

// TestAttachmentsConvergeKeepExtractedText: re-upserting an attachment updates
// metadata but never clobbers extracted_text (SPEC-0002 "Derived data survives
// re-sync").
func TestAttachmentsConvergeKeepExtractedText(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	hash, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	if err := st.UpsertAttachment(ctx, hash, "att1", "old.pdf", "application/pdf", 10); err != nil {
		t.Fatalf("attachment 1: %v", err)
	}
	if _, err := st.WriterDB().ExecContext(ctx,
		`UPDATE attachments SET extracted_text = 'body text' WHERE message_hash = ? AND proton_att_id = 'att1'`, hash); err != nil {
		t.Fatalf("seed extracted_text: %v", err)
	}
	// Re-upsert with changed metadata.
	if err := st.UpsertAttachment(ctx, hash, "att1", "new.pdf", "application/pdf", 20); err != nil {
		t.Fatalf("attachment 2: %v", err)
	}
	if got := countRows(t, st, "attachments"); got != 1 {
		t.Errorf("attachments grew: %d, want 1", got)
	}
	type row struct {
		Filename  string  `db:"filename"`
		Size      int64   `db:"size_bytes"`
		Extracted *string `db:"extracted_text"`
	}
	var r row
	if err := st.DB.GetContext(ctx, &r,
		`SELECT filename, size_bytes, extracted_text FROM attachments WHERE message_hash = ? AND proton_att_id = 'att1'`, hash); err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.Filename != "new.pdf" || r.Size != 20 {
		t.Errorf("metadata not updated: %+v", r)
	}
	if r.Extracted == nil || *r.Extracted != "body text" {
		t.Errorf("extracted_text clobbered: %v", r.Extracted)
	}
}

// TestAttachmentEmptyIDNoOp: an empty proton_att_id writes nothing.
func TestAttachmentEmptyIDNoOp(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	seedMailbox(t, st, testMailboxID, "joe@example.com")
	ctx := context.Background()

	hash, err := st.UpsertMessage(ctx, sampleMessage(testMailboxID, "m1"))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	if err := st.UpsertAttachment(ctx, hash, "  ", "f.pdf", "application/pdf", 1); err != nil {
		t.Fatalf("empty att id errored: %v", err)
	}
	if got := countRows(t, st, "attachments"); got != 0 {
		t.Errorf("attachment written for empty id: %d", got)
	}
}
