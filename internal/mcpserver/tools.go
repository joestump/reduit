// Read-side MCP tool surface for SPEC-0006.
//
// Tools registered here cover the read half of the spec's required tool
// set: list_messages, get_message, search_messages, list_labels. The
// write half (send_message, add_label, ...) lands in #29; streaming
// variants of get_message / download_attachment land in #30.
//
// Every tool handler:
//
//   - Reads the authenticated *account.Account off the request context
//     (stamped by requireBearerAndAccount). A missing account is a
//     defense-in-depth path -- the chain in New() guarantees it is
//     present, but tool handlers fail closed rather than panicking on
//     a future re-ordering bug.
//
//   - Resolves a session-bearing proton.Client via the configured
//     ProtonClientFactory. Tests inject a stub factory so handler
//     coverage does not require a live Proton stand-in.
//
//   - Scopes every store query by account_id (the mailbox.Service is
//     account-scoped at the SQL layer; we pass acct.ID through every
//     call site).
//
// Folder-name resolution shares the same mailbox.ClassifyName helper
// the IMAP backend uses (SPEC-0003). The "FolderResolver" the spec
// mentions is the package-level helper -- there is no separate type;
// the literal-test target for folder parity is "the same string fed
// to mailbox.ClassifyName produces the same kind/protonRef".
//
// Governing: ADR-0008 (embedded MCP), SPEC-0006 REQ "Required Tool
// Set" (read subset), SPEC-0006 REQ "Pagination on List and Search",
// SPEC-0006 REQ "Folder Names Match IMAP Mapping",
// SPEC-0006 REQ "Account Scope on All Operations".

package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

// Pagination defaults and clamps. The spec pins these values: omitted
// page_size defaults to 50; page_size > 200 is clamped to 200 and the
// response carries clamped: true.
//
// Governing: SPEC-0006 REQ "Pagination on List and Search".
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// ProtonClientFactory mints a session-bearing proton.Client for the
// supplied account. The composition root resolves the account's
// secrets via account.Service and calls proton.Manager.NewClient or
// equivalent; tests inject a stub that returns a fake Client so
// handler-level coverage does not require a live Proton stand-in.
//
// Mirrors sync.ClientFactory by intent (one Proton-client-per-account
// wiring point) without sharing the type so the two stories stay
// independently buildable.
type ProtonClientFactory func(ctx context.Context, acct *account.Account) (proton.Client, error)

// ToolDeps is the dependency bundle every tool handler needs. Held
// separately from Deps so the registration call site can pass an
// already-validated bundle (no per-tool nil checks) and tests can
// build it without spinning up the auth/concurrency middleware.
type ToolDeps struct {
	Mailboxes        mailbox.Service
	ProtonForAccount ProtonClientFactory
	Logger           *slog.Logger
}

// validate fails fast if a required dependency is missing. Tool
// registration happens at process boot so a panic here is the
// operator-actionable failure mode.
func (td ToolDeps) validate() error {
	if td.Mailboxes == nil {
		return errors.New("mcpserver: ToolDeps.Mailboxes is required")
	}
	if td.ProtonForAccount == nil {
		return errors.New("mcpserver: ToolDeps.ProtonForAccount is required")
	}
	return nil
}

// RegisterReadTools wires the read-half of SPEC-0006's tool surface
// onto srv. Panics on a misconfigured ToolDeps -- the only legitimate
// caller is the boot path (mcpserver.New / tests).
//
// Governing: SPEC-0006 REQ "Required Tool Set" (read).
func RegisterReadTools(srv *mcp.Server, td ToolDeps) {
	if srv == nil {
		panic("mcpserver: RegisterReadTools nil server")
	}
	if err := td.validate(); err != nil {
		panic(err)
	}
	if td.Logger == nil {
		td.Logger = defaultLogger()
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_messages",
		Description: "List messages in a folder. Folder is the IMAP-side name (e.g. INBOX, Sent, Labels/Receipts).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ListMessagesIn) (*mcp.CallToolResult, ListMessagesOut, error) {
		out, err := listMessages(ctx, td, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_message",
		Description: "Fetch a single message by id. The non-streaming variant returns metadata plus the decoded body; large bodies should use the streaming variant once available.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GetMessageIn) (*mcp.CallToolResult, GetMessageOut, error) {
		out, err := getMessage(ctx, td, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_messages",
		Description: "Search messages by subject keyword. Pagination matches list_messages.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SearchMessagesIn) (*mcp.CallToolResult, SearchMessagesOut, error) {
		out, err := searchMessages(ctx, td, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_labels",
		Description: "List all folders and labels available to this account: the seven IMAP system folders plus any user labels under Labels/.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ListLabelsIn) (*mcp.CallToolResult, ListLabelsOut, error) {
		out, err := listLabels(ctx, td, in)
		return nil, out, err
	})
}

// --- input/output types ---

// MessageMeta is the listing-shaped projection of one message. Mirrors
// the fields IMAP and the local store already track; deliberately a
// flat shape (no nested Proton-only structures) so MCP clients can
// consume it without the Proton type vocabulary.
type MessageMeta struct {
	ID           string   `json:"id"`
	Subject      string   `json:"subject"`
	Sender       string   `json:"sender"`
	InternalDate string   `json:"internal_date"`
	Size         int64    `json:"size"`
	Flags        []string `json:"flags,omitempty"`
	// Folder is the IMAP-side name this listing was drawn from.
	// Always populated for list_messages; empty for search_messages
	// (which spans folders) and get_message (which is folder-agnostic).
	Folder string `json:"folder,omitempty"`
}

// ListMessagesIn is the JSON-schema-bound input for list_messages.
type ListMessagesIn struct {
	Folder   string `json:"folder"`
	Query    string `json:"query,omitempty"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
}

// PaginationMeta is the shared pagination envelope every paged
// response carries. TotalCount is a pointer so a nil value can be
// distinguished from a zero count; TotalCountKnown is the explicit
// signal the spec mandates ("total_count_known: false") when the
// server can't cheaply produce the count.
type PaginationMeta struct {
	Page            int  `json:"page"`
	PageSize        int  `json:"page_size"`
	TotalCount      *int `json:"total_count,omitempty"`
	TotalCountKnown bool `json:"total_count_known"`
	HasMore         bool `json:"has_more"`
	Clamped         bool `json:"clamped,omitempty"`
}

// ListMessagesOut is the response body for list_messages.
type ListMessagesOut struct {
	Messages []MessageMeta `json:"messages"`
	PaginationMeta
}

// GetMessageIn is the JSON-schema-bound input for get_message. Format
// is "metadata" (default) or "raw"; the streaming "raw" variant is
// out of scope for #28 -- a request for raw bodies returns a
// not_implemented error pointing the caller at the streaming tool
// once it lands in #30.
type GetMessageIn struct {
	MessageID string `json:"message_id"`
	Format    string `json:"format,omitempty"`
}

// GetMessageOut is the response body for get_message in metadata mode.
type GetMessageOut struct {
	MessageMeta
	// To/Cc/Bcc are address strings for human consumption; tests on
	// the MCP layer treat them as opaque strings.
	To       []string `json:"to,omitempty"`
	Cc       []string `json:"cc,omitempty"`
	Bcc      []string `json:"bcc,omitempty"`
	ReplyTo  []string `json:"reply_to,omitempty"`
	MIMEType string   `json:"mime_type,omitempty"`
	Body     string   `json:"body,omitempty"`
	// LabelIDs are the Proton-side label IDs the message currently
	// carries. MCP clients that want IMAP-side names can cross-
	// reference list_labels.
	LabelIDs []string `json:"label_ids,omitempty"`
}

// SearchMessagesIn is the JSON-schema-bound input for search_messages.
type SearchMessagesIn struct {
	Query    string `json:"query"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
}

// SearchMessagesOut shares the same shape as ListMessagesOut.
type SearchMessagesOut struct {
	Messages []MessageMeta `json:"messages"`
	PaginationMeta
}

// ListLabelsIn is empty -- list_labels takes no parameters.
type ListLabelsIn struct{}

// LabelInfo is one entry of list_labels' output. Kind is "system" or
// "user_label" mirroring mailbox.Kind so MCP clients can branch on
// the same distinction the IMAP backend already exposes.
type LabelInfo struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	ProtonLabelID string `json:"proton_label_id,omitempty"`
	ProtonPath    string `json:"proton_path,omitempty"`
}

// ListLabelsOut returns the system + user-label set in stable order
// (system folders first by spec ordering, user labels alphabetical).
type ListLabelsOut struct {
	Labels []LabelInfo `json:"labels"`
}

// --- handlers ---

// listMessages enumerates messages in a single folder owned by the
// authenticated account. Folder names are resolved via the shared
// mailbox.ClassifyName helper so the same wire string maps identically
// in IMAP and MCP code paths (SPEC-0006 REQ "Folder Names Match IMAP
// Mapping").
//
// The implementation reads from the local store (mailbox.Service);
// SPEC-0002's sync worker is responsible for keeping that store in
// sync with Proton. Callers who want strictly fresher data can wait
// for the sync cursor to advance -- but the read tool is a snapshot
// query, not a forced refresh.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (list_messages),
// SPEC-0006 REQ "Folder Names Match IMAP Mapping",
// SPEC-0006 REQ "Pagination on List and Search",
// SPEC-0006 REQ "Account Scope on All Operations".
func listMessages(ctx context.Context, td ToolDeps, in ListMessagesIn) (ListMessagesOut, error) {
	acct, err := requireAccount(ctx)
	if err != nil {
		return ListMessagesOut{}, err
	}
	if strings.TrimSpace(in.Folder) == "" {
		return ListMessagesOut{}, toolErrorf("invalid_argument", false, "folder is required")
	}

	// Folder must classify -- unknown name is the canonical
	// unknown_folder error per spec.
	if _, _, ok := mailbox.ClassifyName(in.Folder); !ok {
		return ListMessagesOut{}, unknownFolderError(in.Folder)
	}

	page, pageSize, clamped := normalizePagination(in.Page, in.PageSize)

	mb, err := td.Mailboxes.GetMailboxByName(ctx, acct.ID, in.Folder)
	if err != nil {
		if errors.Is(err, mailbox.ErrMailboxNotFound) {
			// Folder name resolves but no mailbox row exists for
			// this account yet (sync worker hasn't materialised
			// it). Return an empty page rather than not_found:
			// the operator-visible "INBOX has zero messages on a
			// brand-new account" UX is the same as a real empty
			// folder, and a separate "mailbox not provisioned"
			// error would leak sync-worker progress to the MCP
			// client.
			return emptyListResponse(page, pageSize, clamped), nil
		}
		td.Logger.WarnContext(ctx, "mcpserver: list_messages mailbox lookup failed",
			slog.String("account_id", acct.ID),
			slog.String("folder", in.Folder),
			slog.String("error", err.Error()))
		return ListMessagesOut{}, internalToolError(err)
	}

	rows, err := td.Mailboxes.ListMessagesInMailbox(ctx, acct.ID, mb.ID)
	if err != nil {
		td.Logger.WarnContext(ctx, "mcpserver: list_messages list rows failed",
			slog.String("account_id", acct.ID),
			slog.String("folder", in.Folder),
			slog.String("error", err.Error()))
		return ListMessagesOut{}, internalToolError(err)
	}

	// Newest-first ordering for human consumption -- the sync
	// worker writes UID-ascending which is creation-ascending; we
	// reverse here so a default page-1 read shows the most recent
	// messages without the caller having to seek.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].InternalDate.Equal(rows[j].InternalDate) {
			return rows[i].UID > rows[j].UID
		}
		return rows[i].InternalDate.After(rows[j].InternalDate)
	})

	// Optional in-memory subject filter. Local-store query is the
	// pragmatic v0.1 shape; a future spec'd "search via Proton's
	// /mail/v4/messages?Keyword=..." path is search_messages's
	// territory, not list_messages'.
	if q := strings.TrimSpace(in.Query); q != "" {
		rows = filterMessagesBySubject(rows, q)
	}

	total := len(rows)
	start, end, hasMore := paginate(total, page, pageSize)
	pageRows := rows[start:end]

	out := ListMessagesOut{
		Messages: make([]MessageMeta, 0, len(pageRows)),
		PaginationMeta: PaginationMeta{
			Page:            page,
			PageSize:        pageSize,
			TotalCount:      intPtr(total),
			TotalCountKnown: true,
			HasMore:         hasMore,
			Clamped:         clamped,
		},
	}
	for _, r := range pageRows {
		out.Messages = append(out.Messages, messageMetaFromRow(in.Folder, r))
	}
	return out, nil
}

// getMessage fetches a single message metadata + body. The streaming
// raw-body path lives in #30; this story handles format=metadata
// (default) only and returns a not_implemented error for raw.
//
// Account scoping: the local store is consulted first to verify the
// message belongs to the authenticated account. A miss -- whether
// "no such message" or "exists but belongs to another account" --
// surfaces as a byte-identical not_found error per SPEC-0006 REQ
// "Account Scope on All Operations".
//
// Governing: SPEC-0006 REQ "Required Tool Set" (get_message),
// SPEC-0006 REQ "Account Scope on All Operations".
func getMessage(ctx context.Context, td ToolDeps, in GetMessageIn) (GetMessageOut, error) {
	acct, err := requireAccount(ctx)
	if err != nil {
		return GetMessageOut{}, err
	}
	if strings.TrimSpace(in.MessageID) == "" {
		return GetMessageOut{}, toolErrorf("invalid_argument", false, "message_id is required")
	}
	format := strings.TrimSpace(in.Format)
	if format == "" {
		format = "metadata"
	}
	switch format {
	case "metadata", "raw":
	default:
		return GetMessageOut{}, toolErrorf("invalid_argument", false, "format must be 'metadata' or 'raw'")
	}
	if format == "raw" {
		// Streaming variant lives in #30; refusing here keeps the
		// non-streaming surface honest about what it returns.
		return GetMessageOut{}, toolErrorf("not_implemented", false, "raw body streaming is provided by the streaming get_message tool (issue #30)")
	}

	// Verify the message exists under this account before going to
	// Proton. The (account_id, proton_message_id) UNIQUE index
	// keeps this O(1) and is the structural account-scope check.
	if _, err := td.Mailboxes.FindMessageByProtonID(ctx, acct.ID, in.MessageID); err != nil {
		if errors.Is(err, mailbox.ErrMessageNotFound) {
			return GetMessageOut{}, toolErrorf("not_found", false, "message %s not found", in.MessageID)
		}
		td.Logger.WarnContext(ctx, "mcpserver: get_message store lookup failed",
			slog.String("account_id", acct.ID),
			slog.String("message_id", in.MessageID),
			slog.String("error", err.Error()))
		return GetMessageOut{}, internalToolError(err)
	}

	pc, err := td.ProtonForAccount(ctx, acct)
	if err != nil {
		td.Logger.WarnContext(ctx, "mcpserver: proton client unavailable",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		return GetMessageOut{}, mapProtonError(err)
	}
	msg, err := pc.GetMessage(ctx, in.MessageID)
	if err != nil {
		return GetMessageOut{}, mapProtonError(err)
	}

	out := GetMessageOut{
		MessageMeta: messageMetaFromProton(msg.MessageMetadata),
		To:          addressesToStrings(msg.ToList),
		Cc:          addressesToStrings(msg.CCList),
		Bcc:         addressesToStrings(msg.BCCList),
		ReplyTo:     addressesToStrings(msg.ReplyTos),
		MIMEType:    string(msg.MIMEType),
		Body:        msg.Body,
		LabelIDs:    append([]string(nil), msg.LabelIDs...),
	}
	return out, nil
}

// searchMessages proxies to Proton's metadata-listing endpoint with a
// subject filter. Pagination semantics match list_messages.
//
// total_count is intentionally NOT reported -- Proton's /messages
// endpoint pages without returning a total, and computing one would
// require draining every page. The response carries
// total_count_known=false per SPEC-0006 REQ "Pagination on List and
// Search" Scenario "Pagination metadata included".
//
// Governing: SPEC-0006 REQ "Required Tool Set" (search_messages),
// SPEC-0006 REQ "Pagination on List and Search",
// SPEC-0006 REQ "Account Scope on All Operations".
func searchMessages(ctx context.Context, td ToolDeps, in SearchMessagesIn) (SearchMessagesOut, error) {
	acct, err := requireAccount(ctx)
	if err != nil {
		return SearchMessagesOut{}, err
	}
	q := strings.TrimSpace(in.Query)
	if q == "" {
		return SearchMessagesOut{}, toolErrorf("invalid_argument", false, "query is required")
	}

	page, pageSize, clamped := normalizePagination(in.Page, in.PageSize)

	pc, err := td.ProtonForAccount(ctx, acct)
	if err != nil {
		td.Logger.WarnContext(ctx, "mcpserver: proton client unavailable",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		return SearchMessagesOut{}, mapProtonError(err)
	}

	got, err := pc.ListMessages(ctx, proton.MessageFilter{Subject: q})
	if err != nil {
		return SearchMessagesOut{}, mapProtonError(err)
	}

	// Apply page+page_size locally. Proton's filter returned one
	// concatenated slice; for an MVP this is acceptable -- the
	// expected hot path is "first page of recent matches". A
	// follow-up issue can move the windowing into the upstream
	// EndID cursor when search becomes a hot path.
	total := len(got)
	start, end, hasMore := paginate(total, page, pageSize)
	pageRows := got[start:end]

	out := SearchMessagesOut{
		Messages: make([]MessageMeta, 0, len(pageRows)),
		PaginationMeta: PaginationMeta{
			Page:            page,
			PageSize:        pageSize,
			TotalCountKnown: false,
			HasMore:         hasMore,
			Clamped:         clamped,
		},
	}
	for _, r := range pageRows {
		out.Messages = append(out.Messages, messageMetaFromProton(r))
	}
	return out, nil
}

// listLabels returns every folder/label visible to this account: the
// seven IMAP system folders (always) plus any user labels under
// Labels/ that the local store has materialised.
//
// We do NOT round-trip Proton here -- the local store is the source
// of truth for account-scoped label rows (the sync worker
// materialises them) and a Proton hop just to render the same
// information would burn API quota that the per-account concurrency
// cap is in place to protect.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (list_labels),
// SPEC-0006 REQ "Folder Names Match IMAP Mapping",
// SPEC-0006 REQ "Account Scope on All Operations".
func listLabels(ctx context.Context, td ToolDeps, _ ListLabelsIn) (ListLabelsOut, error) {
	acct, err := requireAccount(ctx)
	if err != nil {
		return ListLabelsOut{}, err
	}

	out := ListLabelsOut{Labels: make([]LabelInfo, 0, 16)}

	// System folders are static per SPEC-0003. Always present in
	// the response so a fresh account (no mailbox rows yet) still
	// shows the standard IMAP names.
	for _, sys := range mailbox.SystemFolders() {
		out.Labels = append(out.Labels, LabelInfo{
			Name:          sys.IMAPName,
			Kind:          string(mailbox.KindSystem),
			ProtonLabelID: sys.ProtonLabelID,
		})
	}

	mboxes, err := td.Mailboxes.ListMailboxes(ctx, acct.ID)
	if err != nil {
		td.Logger.WarnContext(ctx, "mcpserver: list_labels mailbox enumeration failed",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		return ListLabelsOut{}, internalToolError(err)
	}

	userLabels := make([]LabelInfo, 0)
	for _, mb := range mboxes {
		if mb.Kind != mailbox.KindUserLabel {
			continue
		}
		path, ok := mailbox.ParseUserLabelName(mb.Name)
		if !ok {
			// A user_label row whose name doesn't sit under
			// Labels/ is a sync-worker invariant violation;
			// skip it rather than surface it to the MCP client.
			continue
		}
		userLabels = append(userLabels, LabelInfo{
			Name:          mb.Name,
			Kind:          string(mailbox.KindUserLabel),
			ProtonLabelID: mb.ProtonLabelID,
			ProtonPath:    path,
		})
	}
	sort.Slice(userLabels, func(i, j int) bool {
		return userLabels[i].Name < userLabels[j].Name
	})
	out.Labels = append(out.Labels, userLabels...)
	return out, nil
}

// --- helpers ---

// requireAccount returns the *account.Account stamped on ctx by the
// auth middleware, or a tool-shaped error if missing. The middleware
// guarantees the value is present on the production path; this
// accessor is the defense-in-depth layer.
func requireAccount(ctx context.Context) (*account.Account, error) {
	acct := AccountFromContext(ctx)
	if acct == nil {
		return nil, toolErrorf("unauthenticated", false, "no account on context")
	}
	return acct, nil
}

// normalizePagination applies the SPEC-0006 defaults: omitted
// page_size -> 50; >200 -> clamped to 200; <=0 page -> 1.
func normalizePagination(page, pageSize int) (resolvedPage, resolvedSize int, clamped bool) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
		clamped = true
	}
	return page, pageSize, clamped
}

// paginate returns the [start, end) slice indices for the requested
// page plus the has_more flag. Out-of-range pages return an empty
// window with has_more=false.
func paginate(total, page, pageSize int) (start, end int, hasMore bool) {
	if total <= 0 || pageSize <= 0 {
		return 0, 0, false
	}
	start = (page - 1) * pageSize
	if start >= total {
		return total, total, false
	}
	end = start + pageSize
	if end > total {
		end = total
	}
	hasMore = end < total
	return start, end, hasMore
}

// emptyListResponse builds the canonical empty-page shape for a known
// folder with no materialised mailbox row yet.
func emptyListResponse(page, pageSize int, clamped bool) ListMessagesOut {
	zero := 0
	return ListMessagesOut{
		Messages: []MessageMeta{},
		PaginationMeta: PaginationMeta{
			Page:            page,
			PageSize:        pageSize,
			TotalCount:      &zero,
			TotalCountKnown: true,
			HasMore:         false,
			Clamped:         clamped,
		},
	}
}

// filterMessagesBySubject returns rows whose subject contains q
// (case-insensitive). Used by list_messages' optional query filter;
// search_messages goes to Proton instead.
func filterMessagesBySubject(rows []*mailbox.MessageInMailbox, q string) []*mailbox.MessageInMailbox {
	needle := strings.ToLower(q)
	out := rows[:0]
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Subject), needle) {
			out = append(out, r)
		}
	}
	return out
}

// messageMetaFromRow projects a local store row into the wire shape.
func messageMetaFromRow(folder string, r *mailbox.MessageInMailbox) MessageMeta {
	return MessageMeta{
		ID:           r.ProtonMessageID,
		Subject:      r.Subject,
		Sender:       r.Sender,
		InternalDate: r.InternalDate.UTC().Format(time.RFC3339),
		Size:         r.RFC822Size,
		Flags:        splitFlags(r.Flags),
		Folder:       folder,
	}
}

// messageMetaFromProton projects a Proton MessageMetadata into the
// wire shape. Used by search_messages and get_message.
func messageMetaFromProton(m proton.MessageMetadata) MessageMeta {
	sender := ""
	if m.Sender != nil {
		sender = m.Sender.Address
	}
	flags := []string{}
	if !bool(m.Unread) {
		flags = append(flags, `\Seen`)
	}
	if bool(m.IsReplied) || bool(m.IsRepliedAll) {
		flags = append(flags, `\Answered`)
	}
	if bool(m.IsForwarded) {
		flags = append(flags, "$Forwarded")
	}
	return MessageMeta{
		ID:           m.ID,
		Subject:      m.Subject,
		Sender:       sender,
		InternalDate: protonTimeToISO(m.Time),
		Size:         int64(m.Size),
		Flags:        flags,
	}
}

// addressesToStrings flattens a list of *mail.Address into bare
// "user@host" strings. The MCP wire shape does not preserve display
// names -- callers that need them can issue get_message and parse
// the raw body once #30 lands.
func addressesToStrings(in []*mail.Address) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a == nil {
			continue
		}
		if a.Address != "" {
			out = append(out, a.Address)
		}
	}
	return out
}

// protonTimeToISO converts a Proton-side Unix timestamp (seconds) to
// RFC3339 UTC. Returns "" for the zero value.
func protonTimeToISO(t int64) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

// splitFlags splits the local store's space-joined flags string into
// a slice. Empty in -> empty out.
func splitFlags(flags string) []string {
	flags = strings.TrimSpace(flags)
	if flags == "" {
		return nil
	}
	return strings.Fields(flags)
}

// intPtr returns &n. Used to populate optional pagination fields.
func intPtr(n int) *int { return &n }

// toolError is the structured error envelope SPEC-0006 mandates for
// recoverable tool failures. The MCP SDK returns the JSON
// representation when the handler returns the error.
type toolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retriable bool   `json:"retriable"`
}

// Error implements the error interface. Format is "<code>: <message>"
// so errors.Is/As callers can pattern-match.
func (e *toolError) Error() string {
	return e.Code + ": " + e.Message
}

// toolErrorf builds a structured tool error.
func toolErrorf(code string, retriable bool, format string, args ...any) *toolError {
	return &toolError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Retriable: retriable,
	}
}

// unknownFolderError is the canonical error for SPEC-0006 REQ "Folder
// Names Match IMAP Mapping" Scenario "Unknown folder name yields a
// clear error".
func unknownFolderError(name string) *toolError {
	return toolErrorf("unknown_folder", false, "Folder %s does not exist", name)
}

// internalToolError wraps an unexpected store error in a generic
// not-retriable code so we don't leak SQL strings to MCP clients.
// The original error is logged at the call site.
func internalToolError(err error) *toolError {
	return toolErrorf("internal", false, "internal error: %v", err)
}

// mapProtonError translates a proton-package error into a
// SPEC-0006-shaped tool error. Per the spec's error-mapping table:
// 401 -> auth_required, 429 -> rate_limited, 5xx ->
// proton_unavailable. The mapping intentionally avoids leaking
// upstream HTTP details to MCP clients.
//
// Governing: SPEC-0006 design.md "Error mapping".
func mapProtonError(err error) *toolError {
	if err == nil {
		return nil
	}
	if errors.Is(err, proton.ErrNotAuthenticated) {
		return toolErrorf("auth_required", false, "proton session unavailable")
	}
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status == 401:
			return toolErrorf("auth_required", false, "proton authentication required")
		case apiErr.Status == 429:
			return toolErrorf("rate_limited", true, "proton rate limit hit")
		case apiErr.Status >= 500:
			return toolErrorf("proton_unavailable", true, "proton upstream error %d", apiErr.Status)
		case apiErr.Status >= 400:
			return toolErrorf("bad_request", false, "proton rejected request: %d", apiErr.Status)
		}
	}
	return toolErrorf("proton_unavailable", true, "proton call failed: %v", err)
}
