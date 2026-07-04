// Package tuistore is the TUI's read-only view onto the shared SQLite cache.
//
// Every TUI view reads through this facade, which exposes ONLY read methods of
// the underlying *store.Store — the same methods the MCP tools call (ADR-0017
// no-drift). Because the Reader interface has no write, sync, or Proton
// methods, a view holding a Reader cannot mutate the store or reach the network
// even by accident: a write call simply does not compile. That is the
// enforcement mechanism for SPEC-0005 REQ "Read-Only Shared-Store Access",
// stronger than a convention.
//
// The DTOs (Stats, MailboxStat, Mailbox, SyncRun) are type aliases of the
// store package's types, so views import only this package while reusing the
// exact shapes the store returns — no copying, no drift.
//
// Governing: ADR-0025 (Bubble Tea TUI), ADR-0017 (shared store, MCP primary —
// same store methods, no second query path), SPEC-0005 REQ "Read-Only
// Shared-Store Access".
package tuistore

import (
	"context"

	"github.com/joestump/reduit/internal/store"
)

// Read DTOs — aliases so callers depend on one package but reuse store's types.
type (
	Stats          = store.Stats
	MailboxStat    = store.MailboxStat
	Mailbox        = store.Mailbox
	SyncRun        = store.SyncRun
	AttachmentRow  = store.AttachmentRow
	ContactRow     = store.ContactRow
	ContactFactRow = store.ContactFactRow
	SearchHit      = store.SearchHit
	MessageDetail  = store.MessageDetail
)

// Reader is the read-only surface the TUI views depend on. It is deliberately
// an interface (not a concrete type) so views are unit-testable against an
// in-memory fake with no SQLite, and so the compiler guarantees no view can
// call a write path. As real read methods land in internal/store (FTS search
// for #169, attachment/facts listings for #170), they are added here and to
// Facade; nothing else about the boundary changes.
type Reader interface {
	// Stats returns corpus-wide counts (mailboxes, messages, attachments,
	// embedded) for the stats view.
	Stats(ctx context.Context) (Stats, error)
	// MailboxStats returns per-mailbox coverage for the metadata view.
	MailboxStats(ctx context.Context) ([]MailboxStat, error)
	// ListMailboxes returns the configured mailboxes.
	ListMailboxes(ctx context.Context) ([]Mailbox, error)
	// LatestSyncRun returns the most recent sync run for a mailbox, if any.
	LatestSyncRun(ctx context.Context, mailboxID string) (SyncRun, bool, error)
	// SchemaVersion returns the current goose migration version (0 = un-migrated).
	SchemaVersion(ctx context.Context) (int64, error)
	// DBPath returns the absolute path of the open database, for the stats view's
	// on-disk-size readout.
	DBPath() string

	// ListAttachments returns the attachment index (metadata + owning-message
	// subject) for the attachments view.
	ListAttachments(ctx context.Context, limit int) ([]AttachmentRow, error)
	// AttachmentText returns an attachment's extracted text (found=false if the
	// id is unknown) for the attachments detail pager.
	AttachmentText(ctx context.Context, id string) (string, bool, error)
	// ListContacts returns the contacts index (name, address, fact count) for
	// the contact-facts view.
	ListContacts(ctx context.Context, limit int) ([]ContactRow, error)
	// ContactFacts returns a contact's extracted facts with citations for the
	// contact-facts detail pager.
	ContactFacts(ctx context.Context, contactID string) ([]ContactFactRow, error)

	// SearchMessages runs a bm25-ranked FTS keyword search for the search view.
	SearchMessages(ctx context.Context, query string, limit int) ([]SearchHit, error)
	// GetMessage returns one cached message by hash for the search pager.
	GetMessage(ctx context.Context, hash string) (MessageDetail, bool, error)
}

// Facade is the concrete Reader backed by a live *store.Store. It embeds no
// write access: it forwards only the read calls above. Construct one with New
// and hand it to the TUI; the TUI never sees the raw *store.Store.
type Facade struct {
	st *store.Store
}

// compile-time assurance that Facade satisfies the read-only Reader.
var _ Reader = (*Facade)(nil)

// New wraps a *store.Store in the read-only facade.
func New(st *store.Store) *Facade { return &Facade{st: st} }

// Stats forwards to store.Stats (read-only).
func (f *Facade) Stats(ctx context.Context) (Stats, error) { return f.st.Stats(ctx) }

// MailboxStats forwards to store.MailboxStats (read-only).
func (f *Facade) MailboxStats(ctx context.Context) ([]MailboxStat, error) {
	return f.st.MailboxStats(ctx)
}

// ListMailboxes forwards to store.ListMailboxes (read-only).
func (f *Facade) ListMailboxes(ctx context.Context) ([]Mailbox, error) {
	return f.st.ListMailboxes(ctx)
}

// LatestSyncRun forwards to store.LatestSyncRun (read-only).
func (f *Facade) LatestSyncRun(ctx context.Context, mailboxID string) (SyncRun, bool, error) {
	return f.st.LatestSyncRun(ctx, mailboxID)
}

// SchemaVersion forwards to store.SchemaVersion (read-only).
func (f *Facade) SchemaVersion(ctx context.Context) (int64, error) {
	return f.st.SchemaVersion(ctx)
}

// DBPath forwards to store.Path (read-only).
func (f *Facade) DBPath() string { return f.st.Path() }

// ListAttachments forwards to store.ListAttachments (read-only).
func (f *Facade) ListAttachments(ctx context.Context, limit int) ([]AttachmentRow, error) {
	return f.st.ListAttachments(ctx, limit)
}

// AttachmentText forwards to store.AttachmentText (read-only).
func (f *Facade) AttachmentText(ctx context.Context, id string) (string, bool, error) {
	return f.st.AttachmentText(ctx, id)
}

// ListContacts forwards to store.ListContacts (read-only).
func (f *Facade) ListContacts(ctx context.Context, limit int) ([]ContactRow, error) {
	return f.st.ListContacts(ctx, limit)
}

// ContactFacts forwards to store.ContactFacts (read-only).
func (f *Facade) ContactFacts(ctx context.Context, contactID string) ([]ContactFactRow, error) {
	return f.st.ContactFacts(ctx, contactID)
}

// SearchMessages forwards to store.SearchMessages (read-only).
func (f *Facade) SearchMessages(ctx context.Context, query string, limit int) ([]SearchHit, error) {
	return f.st.SearchMessages(ctx, query, limit)
}

// GetMessage forwards to store.GetMessage (read-only).
func (f *Facade) GetMessage(ctx context.Context, hash string) (MessageDetail, bool, error) {
	return f.st.GetMessage(ctx, hash)
}
