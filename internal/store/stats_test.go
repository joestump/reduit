package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// openMigrated opens a fresh store in a temp dir and applies the embedded
// migrations, failing the test on any error.
func openMigrated(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// seedMessages inserts nMsgs messages for mailboxID, embedding the first
// nEmbedded of them. Messages and embeddings are written directly (no public
// store writer exists yet — those land in the sync/embed stories) so the
// stats aggregates have something to count.
func seedMessages(t *testing.T, st *Store, mailboxID string, nMsgs, nEmbedded int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < nMsgs; i++ {
		hash := fmt.Sprintf("%s-hash-%03d", mailboxID, i)
		_, err := st.DB.ExecContext(ctx,
			`INSERT INTO messages (id, hash, mailbox_id, proton_id, ts, sender)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("%s-msg-%03d", mailboxID, i), hash, mailboxID,
			fmt.Sprintf("pid-%03d", i), "2026-01-01T00:00:00Z", "sender@example.com")
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
		if i < nEmbedded {
			_, err := st.DB.ExecContext(ctx,
				`INSERT INTO embeddings (hash, model, dim, vec) VALUES (?, ?, ?, ?)`,
				hash, "test-embed", 2, []byte{0, 0, 0, 0})
			if err != nil {
				t.Fatalf("insert embedding: %v", err)
			}
		}
	}
}

func TestStatsEmptyCache(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)
	ctx := context.Background()

	got, err := st.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	want := Stats{Mailboxes: 0, Messages: 0, Attachments: 0, Embedded: 0}
	if got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

func TestStatsCountsEmbedded(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)
	ctx := context.Background()

	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-0000000000aa", "a@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	// 3 messages, 2 of them embedded.
	seedMessages(t, st, "01999999-0000-7000-8000-0000000000aa", 3, 2)

	got, err := st.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.Messages != 3 {
		t.Errorf("Stats().Messages = %d, want 3", got.Messages)
	}
	if got.Embedded != 2 {
		t.Errorf("Stats().Embedded = %d, want 2", got.Embedded)
	}
}

func TestMailboxStatsEmpty(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)
	got, err := st.MailboxStats(context.Background())
	if err != nil {
		t.Fatalf("MailboxStats: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("MailboxStats() = %d rows, want 0", len(got))
	}
}

func TestMailboxStatsCoverage(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)
	ctx := context.Background()

	// Mailbox b: 4 messages, 0 embedded → coverage 0.0.
	// Mailbox a: 2 messages, 1 embedded → coverage 0.5.
	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-0000000000b0", "b@example.com"); err != nil {
		t.Fatalf("InsertMailbox b: %v", err)
	}
	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-0000000000a0", "a@example.com"); err != nil {
		t.Fatalf("InsertMailbox a: %v", err)
	}
	seedMessages(t, st, "01999999-0000-7000-8000-0000000000b0", 4, 0)
	seedMessages(t, st, "01999999-0000-7000-8000-0000000000a0", 2, 1)

	got, err := st.MailboxStats(ctx)
	if err != nil {
		t.Fatalf("MailboxStats: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("MailboxStats() = %d rows, want 2", len(got))
	}
	// Ordered by address ascending: a@ then b@.
	if got[0].Address != "a@example.com" {
		t.Errorf("row[0].Address = %q, want a@example.com (ordered by address)", got[0].Address)
	}
	if got[0].Messages != 2 || got[0].Embedded != 1 {
		t.Errorf("a@: messages/embedded = %d/%d, want 2/1", got[0].Messages, got[0].Embedded)
	}
	if got[1].Address != "b@example.com" {
		t.Errorf("row[1].Address = %q, want b@example.com", got[1].Address)
	}
	if got[1].Messages != 4 || got[1].Embedded != 0 {
		t.Errorf("b@: messages/embedded = %d/%d, want 4/0", got[1].Messages, got[1].Embedded)
	}
	if got[1].LastSyncAt != nil {
		t.Errorf("b@: LastSyncAt = %v, want nil (never synced)", got[1].LastSyncAt)
	}
}

func TestStatsCountsMailboxes(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)
	ctx := context.Background()

	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-000000000001", "a@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-000000000002", "b@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}

	got, err := st.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.Mailboxes != 2 {
		t.Errorf("Stats().Mailboxes = %d, want 2", got.Mailboxes)
	}
}

func TestSchemaVersionReportsHead(t *testing.T) {
	t.Parallel()
	st := openMigrated(t)

	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	// After Migrate the current version must equal the newest migration on disk,
	// which is the session_uid column add (20260702000001).
	if want := int64(20260702000001); v != want {
		t.Errorf("SchemaVersion() = %d, want %d", v, want)
	}
}

// TestSchemaVersionUnmigrated confirms SchemaVersion reports 0 (not an error)
// when the goose version-tracking table does not yet exist — the signal the
// `status` tool uses to flag an un-migrated, unhealthy cache.
func TestSchemaVersionUnmigrated(t *testing.T) {
	t.Parallel()
	st, err := Open(filepath.Join(t.TempDir(), "unmigrated.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion on un-migrated db: %v", err)
	}
	if v != 0 {
		t.Errorf("SchemaVersion() on un-migrated db = %d, want 0", v)
	}
}
