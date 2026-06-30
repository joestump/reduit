// Package mcp — tool registration and handlers.
//
// Every handler here is a thin adapter over internal/store: it shapes a typed
// input into a store call and a store result into a typed, JSON-serialisable
// output. No handler queries the database directly (SPEC-0006 REQ "Thin
// Adapter Over the Store").
//
// Governing: ADR-0017 (stdio MCP), ADR-0012 (single-user local-first),
//
//	SPEC-0006 (MCP Tool Surface).
package mcp

import (
	"context"
	"math"
	"time"

	"github.com/joestump/reduit/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTools adds every Reduit tool to the underlying MCP server.
//
// S7.1 scope: the read-only `status` (cache health) and `list_mailboxes`
// tools. The hybrid `search_messages`, message/transcript/context retrieval,
// attachment-text, contact-facts, and the single mutating `send` tool are
// deferred to #100/#101.
func (s *Server) registerTools() {
	mcpsdk.AddTool(s.srv, &mcpsdk.Tool{
		Name: "status",
		Description: "Report local cache health and freshness: current schema (migration) " +
			"version, an overall healthy flag, the database path, corpus totals (mailboxes, " +
			"messages, attachments, embedded messages), and a per-mailbox breakdown with " +
			"last sync time and embedding coverage (embedded/messages). Read-only; call this " +
			"to verify the cache is reachable, migrated, fresh, and fully indexed before " +
			"relying on semantic search.",
	}, s.status)

	mcpsdk.AddTool(s.srv, &mcpsdk.Tool{
		Name: "list_mailboxes",
		Description: "List every configured Proton mailbox with its address, lifecycle " +
			"state, and last successful sync time. Read-only.",
	}, s.listMailboxes)
}

// --- status ---

// statusIn takes no arguments: the tool reports the whole cache.
type statusIn struct{}

// statusTotals carries the corpus-wide counts.
type statusTotals struct {
	Mailboxes   int64 `json:"mailboxes"`
	Messages    int64 `json:"messages"`
	Attachments int64 `json:"attachments"`
	// Embedded is the number of messages carrying at least one embedding.
	Embedded int64 `json:"embedded"`
}

// mailboxStatus is the per-mailbox freshness/coverage projection. It carries
// no secrets (ADR-0013). LastSyncAt is a pointer so it serialises as JSON null
// (never synced) rather than an empty string.
type mailboxStatus struct {
	Address    string  `json:"address"`
	State      string  `json:"state"`
	LastSyncAt *string `json:"last_sync_at"`
	Messages   int64   `json:"messages"`
	Embedded   int64   `json:"embedded"`
	// EmbedCoverage is embedded/messages in [0.0, 1.0]; 0.0 when messages==0.
	EmbedCoverage float64 `json:"embed_coverage"`
}

// statusOut is the typed result an MCP client receives from `status`.
//
// Governing: SPEC-0006 REQ "Thin Adapter Over the Store" (sourced via
//
//	store.Stats / store.MailboxStats / store.SchemaVersion, the same methods
//	the UI uses).
type statusOut struct {
	// SchemaVersion is the current goose migration version (0 = un-migrated).
	SchemaVersion int64 `json:"schema_version"`
	// Healthy is true when the cache is open, migrated (schema_version > 0),
	// and the counts were read without error.
	Healthy bool `json:"healthy"`
	// DBPath is the absolute path of the SQLite cache file.
	DBPath string `json:"db_path"`
	// Totals are the corpus-wide counts.
	Totals statusTotals `json:"totals"`
	// Mailboxes is the per-mailbox freshness/coverage breakdown, ordered by
	// address. Empty (never nil) so the field serialises as [] not null.
	Mailboxes []mailboxStatus `json:"mailboxes"`
}

// status returns a snapshot of cache health and freshness. It is read-only and
// never errors on an empty or un-migrated cache: an un-migrated cache simply
// reports healthy=false with schema_version=0, which is the actionable signal
// (run `reduit migrate`) rather than a tool failure.
func (s *Server) status(ctx context.Context, _ *mcpsdk.CallToolRequest, _ statusIn) (*mcpsdk.CallToolResult, statusOut, error) {
	version, err := s.store.SchemaVersion(ctx)
	if err != nil {
		return nil, statusOut{}, err
	}

	out := statusOut{
		SchemaVersion: version,
		DBPath:        s.store.Path(),
		Mailboxes:     []mailboxStatus{},
	}

	// Counts require the content tables to exist; on an un-migrated cache
	// (version 0) they would error on a missing table, so skip them and
	// report unhealthy rather than failing the call.
	if version > 0 {
		stats, statErr := s.store.Stats(ctx)
		if statErr != nil {
			s.log.Warn("status: stats read failed", "error", statErr)
			return nil, out, nil // healthy stays false
		}
		mboxes, mErr := s.store.MailboxStats(ctx)
		if mErr != nil {
			s.log.Warn("status: mailbox stats read failed", "error", mErr)
			return nil, out, nil // healthy stays false
		}
		out.Totals = statusTotals{
			Mailboxes:   stats.Mailboxes,
			Messages:    stats.Messages,
			Attachments: stats.Attachments,
			Embedded:    stats.Embedded,
		}
		out.Mailboxes = make([]mailboxStatus, 0, len(mboxes))
		for _, m := range mboxes {
			out.Mailboxes = append(out.Mailboxes, mailboxStatusFrom(m))
		}
		out.Healthy = true
	}

	return nil, out, nil
}

// mailboxStatusFrom projects a store.MailboxStat into the wire shape:
// RFC3339-formats LastSyncAt (null when never synced) and computes
// embed_coverage as embedded/messages, 0.0 when there are no messages.
func mailboxStatusFrom(m store.MailboxStat) mailboxStatus {
	ms := mailboxStatus{
		Address:  m.Address,
		State:    m.State,
		Messages: m.Messages,
		Embedded: m.Embedded,
	}
	if m.LastSyncAt != nil {
		ts := m.LastSyncAt.UTC().Format(time.RFC3339)
		ms.LastSyncAt = &ts
	}
	if m.Messages > 0 {
		ms.EmbedCoverage = round4(float64(m.Embedded) / float64(m.Messages))
	}
	return ms
}

// round4 rounds to four decimal places so embed_coverage is a clean,
// reproducible fraction rather than a long binary-float tail.
func round4(f float64) float64 {
	return math.Round(f*10000) / 10000
}

// --- list_mailboxes ---

type listMailboxesIn struct{}

// mailboxInfo is the per-mailbox projection returned to the client. It carries
// no secrets (refresh tokens/passphrases live in the OS keychain, ADR-0013).
type mailboxInfo struct {
	ID         string `json:"id"`
	Address    string `json:"address"`
	State      string `json:"state"`
	AddedAt    string `json:"added_at"`
	LastSyncAt string `json:"last_sync_at,omitempty"`
}

type listMailboxesOut struct {
	Mailboxes []mailboxInfo `json:"mailboxes"`
}

func (s *Server) listMailboxes(ctx context.Context, _ *mcpsdk.CallToolRequest, _ listMailboxesIn) (*mcpsdk.CallToolResult, listMailboxesOut, error) {
	rows, err := s.store.ListMailboxes(ctx)
	if err != nil {
		return nil, listMailboxesOut{}, err
	}
	out := listMailboxesOut{Mailboxes: make([]mailboxInfo, 0, len(rows))}
	for _, m := range rows {
		out.Mailboxes = append(out.Mailboxes, mailboxInfoFrom(m))
	}
	return nil, out, nil
}

// mailboxInfoFrom projects a store.Mailbox into the wire shape, formatting
// timestamps as RFC3339 and leaving last_sync_at empty when never synced.
func mailboxInfoFrom(m store.Mailbox) mailboxInfo {
	const layout = "2006-01-02T15:04:05Z07:00"
	info := mailboxInfo{
		ID:      m.ID,
		Address: m.Address,
		State:   string(m.State),
		AddedAt: m.AddedAt.UTC().Format(layout),
	}
	if m.LastSyncAt != nil {
		info.LastSyncAt = m.LastSyncAt.UTC().Format(layout)
	}
	return info
}
