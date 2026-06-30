package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/joestump/reduit/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect builds a server over st and returns a connected MCP client session
// driven through the SDK's in-memory transport — no spawned process or socket.
//
// Governing: SPEC-0006 REQ "In-Memory Round-Trip Testability".
func connect(t *testing.T, st *store.Store) *mcpsdk.ClientSession {
	t.Helper()
	srv := NewServer(st, Options{
		Version: "test",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx := context.Background()
	t1, t2 := mcpsdk.NewInMemoryTransports()
	if _, err := srv.srv.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// openMigratedStore opens a fresh migrated store in a temp dir.
func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// seedMessages inserts nMsgs messages for mailboxID, embedding the first
// nEmbedded of them, writing directly (no public store writer exists until the
// sync/embed stories) so the status aggregates have something to count.
func seedMessages(t *testing.T, st *store.Store, mailboxID string, nMsgs, nEmbedded int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < nMsgs; i++ {
		hash := fmt.Sprintf("%s-hash-%03d", mailboxID, i)
		if _, err := st.DB.ExecContext(ctx,
			`INSERT INTO messages (id, hash, mailbox_id, proton_id, ts, sender)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("%s-msg-%03d", mailboxID, i), hash, mailboxID,
			fmt.Sprintf("pid-%03d", i), "2026-01-01T00:00:00Z", "sender@example.com"); err != nil {
			t.Fatalf("insert message: %v", err)
		}
		if i < nEmbedded {
			if _, err := st.DB.ExecContext(ctx,
				`INSERT INTO embeddings (hash, model, dim, vec) VALUES (?, ?, ?, ?)`,
				hash, "test-embed", 2, []byte{0, 0, 0, 0}); err != nil {
				t.Fatalf("insert embedding: %v", err)
			}
		}
	}
}

// rawOutput returns the tool's structured output as JSON bytes, failing the
// test on a tool error.
func rawOutput(t *testing.T, cs *mcpsdk.ClientSession, name string, args map[string]any) []byte {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("tool %s returned error: %+v", name, res.Content)
	}
	if sc, ok := res.StructuredContent.(json.RawMessage); ok {
		return sc
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s output: %v", name, err)
	}
	return b
}

// callStatus invokes the status tool and decodes into the registered typed
// output schema (statusOut), so the test asserts the real wire contract.
func callStatus(t *testing.T, cs *mcpsdk.ClientSession) statusOut {
	t.Helper()
	var out statusOut
	if err := json.Unmarshal(rawOutput(t, cs, "status", nil), &out); err != nil {
		t.Fatalf("decode status output: %v", err)
	}
	return out
}

// callTool invokes a tool and decodes its structured output into a map.
func callTool(t *testing.T, cs *mcpsdk.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(rawOutput(t, cs, name, args), &out); err != nil {
		t.Fatalf("decode %s output: %v", name, err)
	}
	return out
}

func TestStatusToolEmptyCache(t *testing.T) {
	st := openMigratedStore(t)
	cs := connect(t, st)

	out := callStatus(t, cs)

	if !out.Healthy {
		t.Errorf("healthy = %v, want true on a migrated cache", out.Healthy)
	}
	// schema_version is the initial migration's timestamped id.
	if out.SchemaVersion != 20260629000001 {
		t.Errorf("schema_version = %d, want 20260629000001", out.SchemaVersion)
	}
	if out.Totals != (statusTotals{}) {
		t.Errorf("totals = %+v, want all zero", out.Totals)
	}
	if out.DBPath == "" {
		t.Error("db_path is empty")
	}
	if out.Mailboxes == nil {
		t.Error("mailboxes is null, want []")
	}
	if len(out.Mailboxes) != 0 {
		t.Errorf("mailboxes = %d, want 0", len(out.Mailboxes))
	}
}

// TestStatusToolFreshnessAndCoverage seeds a mailbox with messages and partial
// embeddings and asserts the per-mailbox row + embed_coverage the LLM uses to
// self-assess cache completeness.
func TestStatusToolFreshnessAndCoverage(t *testing.T) {
	st := openMigratedStore(t)
	ctx := context.Background()
	const mbox = "01999999-0000-7000-8000-00000000000a"
	if err := st.InsertMailbox(ctx, mbox, "joe@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	// 4 messages, 3 embedded → coverage 0.75.
	seedMessages(t, st, mbox, 4, 3)
	cs := connect(t, st)

	out := callStatus(t, cs)

	if !out.Healthy {
		t.Fatalf("healthy = false, want true")
	}
	wantTotals := statusTotals{Mailboxes: 1, Messages: 4, Attachments: 0, Embedded: 3}
	if out.Totals != wantTotals {
		t.Errorf("totals = %+v, want %+v", out.Totals, wantTotals)
	}
	if len(out.Mailboxes) != 1 {
		t.Fatalf("mailboxes = %d, want 1", len(out.Mailboxes))
	}
	mb := out.Mailboxes[0]
	if mb.Address != "joe@example.com" {
		t.Errorf("address = %q, want joe@example.com", mb.Address)
	}
	if mb.State != string(store.MailboxStatePendingAuth) {
		t.Errorf("state = %q, want pending_auth", mb.State)
	}
	if mb.Messages != 4 || mb.Embedded != 3 {
		t.Errorf("messages/embedded = %d/%d, want 4/3", mb.Messages, mb.Embedded)
	}
	if mb.EmbedCoverage != 0.75 {
		t.Errorf("embed_coverage = %v, want 0.75", mb.EmbedCoverage)
	}
	if mb.LastSyncAt != nil {
		t.Errorf("last_sync_at = %v, want null (never synced)", *mb.LastSyncAt)
	}
}

// TestStatusToolUnmigrated confirms `status` does not error on a cache whose
// migrations have not run: it reports healthy=false, schema_version=0.
func TestStatusToolUnmigrated(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "unmigrated.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cs := connect(t, st)

	out := callStatus(t, cs)
	if out.Healthy {
		t.Errorf("healthy = %v, want false on an un-migrated cache", out.Healthy)
	}
	if out.SchemaVersion != 0 {
		t.Errorf("schema_version = %d, want 0", out.SchemaVersion)
	}
}

func TestListMailboxesTool(t *testing.T) {
	st := openMigratedStore(t)
	ctx := context.Background()
	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-00000000000b", "a@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	if err := st.InsertMailbox(ctx, "01999999-0000-7000-8000-00000000000c", "b@example.com"); err != nil {
		t.Fatalf("InsertMailbox: %v", err)
	}
	cs := connect(t, st)

	out := callTool(t, cs, "list_mailboxes", nil)
	boxes, _ := out["mailboxes"].([]any)
	if len(boxes) != 2 {
		t.Fatalf("mailboxes = %d, want 2: %v", len(boxes), out)
	}
	first, _ := boxes[0].(map[string]any)
	if first["address"] != "a@example.com" {
		t.Errorf("first mailbox address = %v, want a@example.com", first["address"])
	}
	if first["state"] != string(store.MailboxStatePendingAuth) {
		t.Errorf("first mailbox state = %v, want pending_auth", first["state"])
	}
}
