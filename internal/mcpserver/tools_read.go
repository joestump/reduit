// Read tools: list_messages, get_message, search_messages, list_labels.
//
// Folder names accepted and returned here match the IMAP backend's
// SPEC-0003 mapping exactly -- the same internal/mailbox resolver the
// IMAP MOVE/COPY handlers use. Pagination follows SPEC-0006: default
// page_size 50, max 200 (values above are clamped and flagged), with
// page/page_size/total_count/has_more metadata on every list/search.
//
// Governing: SPEC-0006 REQ "Required Tool Set", SPEC-0006 REQ
// "Pagination on List and Search", SPEC-0006 REQ "Folder Names Match
// IMAP Mapping".
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

// Pagination constants per SPEC-0006 REQ "Pagination on List and Search"
// Scenario "Default and max page_size".
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// MessageMeta is the listing-friendly projection of a Proton message
// returned by list_messages / search_messages. Folders is the set of
// IMAP-mapped folder/label names the message currently carries (system
// folders by their IMAP name, user labels under Labels/<path>), so the
// agent sees the same names move_to_folder accepts.
//
// Governing: SPEC-0006 REQ "Folder Names Match IMAP Mapping".
type MessageMeta struct {
	MessageID      string   `json:"message_id" jsonschema:"Proton message ID; stable handle for get_message and the mutation tools"`
	Subject        string   `json:"subject"`
	From           string   `json:"from,omitempty"`
	To             []string `json:"to,omitempty"`
	CC             []string `json:"cc,omitempty"`
	Date           int64    `json:"date" jsonschema:"Unix timestamp (seconds) the message was received"`
	Size           int      `json:"size" jsonschema:"RFC822 size in bytes"`
	Unread         bool     `json:"unread"`
	NumAttachments int      `json:"num_attachments"`
	Folders        []string `json:"folders" jsonschema:"IMAP-mapped folders/labels the message carries (e.g. INBOX, Labels/Receipts)"`
	LabelIDs       []string `json:"label_ids" jsonschema:"Raw Proton label IDs the message carries"`
}

// pageMeta is the shared pagination block embedded in list/search
// responses per SPEC-0006 REQ "Pagination on List and Search" Scenario
// "Pagination metadata included".
type pageMeta struct {
	Page            int  `json:"page"`
	PageSize        int  `json:"page_size"`
	TotalCount      *int `json:"total_count,omitempty"`
	TotalCountKnown bool `json:"total_count_known"`
	HasMore         bool `json:"has_more"`
	// Clamped is true when the caller's page_size exceeded maxPageSize
	// and was reduced to 200. Per the "Default and max page_size"
	// scenario.
	Clamped bool `json:"clamped,omitempty"`
}

// ----- list_messages -----

// ListMessagesIn is the input schema for list_messages.
type ListMessagesIn struct {
	Folder   string `json:"folder" jsonschema:"IMAP folder name (INBOX, Sent, Drafts, Trash, Spam, Archive, All Mail, or Labels/<name>)"`
	Query    string `json:"query,omitempty" jsonschema:"Optional case-insensitive substring filter on the subject"`
	Page     int    `json:"page,omitempty" jsonschema:"1-based page number; defaults to 1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"Page size; default 50, max 200"`
}

// ListMessagesOut is the output schema for list_messages.
type ListMessagesOut struct {
	Messages []MessageMeta `json:"messages"`
	pageMeta
	Error *ToolError `json:"error,omitempty"`
}

func (r *toolRegistry) registerRead(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_messages",
		Description: "List messages in a folder (system folder name or Labels/<name>), paginated. Optional subject substring filter via query.",
	}, r.listMessages)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_message",
		Description: "Fetch one message by Proton message ID. format=metadata (default) returns headers + parsed fields; format=raw streams the full RFC822 source as ordered content chunks, capped at 16 MiB (a larger source is truncated and raw_stream.truncated is set true).",
	}, r.getMessage)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_messages",
		Description: "Search messages by subject substring across all mail, paginated.",
	}, r.searchMessages)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_labels",
		Description: "List the account's user labels and folders with their Proton label IDs (the IDs add_label / remove_label accept).",
	}, r.listLabels)
}

// listMessages implements the list_messages tool.
func (r *toolRegistry) listMessages(ctx context.Context, _ *mcp.CallToolRequest, in ListMessagesIn) (*mcp.CallToolResult, ListMessagesOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, ListMessagesOut{}, err
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, ListMessagesOut{Error: terr}, nil
	}

	// Resolve the folder name to a Proton label ID using the SAME
	// mapping the IMAP backend uses. System folders resolve directly;
	// user labels (Labels/<path>) require a path->ID lookup against the
	// account's labels.
	labelID, terr := r.resolveFolderToLabelID(ctx, cl, in.Folder)
	if terr != nil {
		return nil, ListMessagesOut{Error: terr}, nil
	}

	page, pageSize, clamped := normalisePagination(in.Page, in.PageSize)

	filter := proton.MessageFilter{LabelID: labelID}
	subjectQuery := strings.TrimSpace(in.Query)

	out := ListMessagesOut{}
	out.Page = page
	out.PageSize = pageSize
	out.Clamped = clamped

	// total_count is cheaply available for a plain folder listing via the
	// per-label grouped count. A subject query has no cheap server-side
	// count, so we report total_count_known=false in that case.
	if subjectQuery == "" {
		if total, ok := r.folderTotal(ctx, cl, labelID); ok {
			out.TotalCount = &total
			out.TotalCountKnown = true
		}
	}

	metas, rawLen, terr := r.fetchPage(ctx, cl, filter, subjectQuery, page, pageSize)
	if terr != nil {
		return nil, ListMessagesOut{Error: terr}, nil
	}
	out.Messages = metas
	// has_more is computed from the RAW upstream page length, not the
	// post-subject-filter count, so a filter that matches few rows on a
	// full page does not truncate later pages.
	out.HasMore = computeHasMore(out.TotalCount, page, pageSize, rawLen)
	return nil, out, nil
}

// ----- search_messages -----

// SearchMessagesIn is the input schema for search_messages.
type SearchMessagesIn struct {
	Query    string `json:"query" jsonschema:"Case-insensitive subject substring to match across all mail"`
	Page     int    `json:"page,omitempty" jsonschema:"1-based page number; defaults to 1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"Page size; default 50, max 200"`
}

// SearchMessagesOut is the output schema for search_messages.
type SearchMessagesOut struct {
	Messages []MessageMeta `json:"messages"`
	pageMeta
	Error *ToolError `json:"error,omitempty"`
}

// searchMessages implements the search_messages tool. v0.1 scopes the
// search to a subject substring across All Mail; Proton's full-text
// search surface is deferred to a follow-up.
func (r *toolRegistry) searchMessages(ctx context.Context, _ *mcp.CallToolRequest, in SearchMessagesIn) (*mcp.CallToolResult, SearchMessagesOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, SearchMessagesOut{}, err
	}
	query := strings.TrimSpace(in.Query)
	if query == "" {
		return nil, SearchMessagesOut{Error: &ToolError{
			Code:      codeInvalidArgument,
			Message:   "query is required and must be non-empty",
			Retriable: false,
		}}, nil
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, SearchMessagesOut{Error: terr}, nil
	}

	page, pageSize, clamped := normalisePagination(in.Page, in.PageSize)

	// Search spans All Mail; Proton's Subject filter is a server-side
	// substring match. We additionally re-filter client-side so casing
	// and trimming match the documented semantics deterministically.
	filter := proton.MessageFilter{
		LabelID: mailbox.ProtonAllMailLabelID,
		Subject: query,
	}

	metas, rawLen, terr := r.fetchPage(ctx, cl, filter, query, page, pageSize)
	if terr != nil {
		return nil, SearchMessagesOut{Error: terr}, nil
	}

	out := SearchMessagesOut{Messages: metas}
	out.Page = page
	out.PageSize = pageSize
	out.Clamped = clamped
	out.TotalCountKnown = false // no cheap server-side count for a search
	// has_more from the RAW page length so the subject filter does not
	// truncate later matching pages.
	out.HasMore = computeHasMore(nil, page, pageSize, rawLen)
	return nil, out, nil
}

// ----- get_message -----

// GetMessageIn is the input schema for get_message.
type GetMessageIn struct {
	MessageID string `json:"message_id" jsonschema:"Proton message ID"`
	Format    string `json:"format,omitempty" jsonschema:"metadata (default) or raw (full RFC822 source)"`
}

// GetMessageOut is the output schema for get_message.
type GetMessageOut struct {
	Message *FullMessage `json:"message,omitempty"`
	// RawStream carries the chunk accounting for a format=raw response.
	// The raw bytes themselves ride in CallToolResult.Content (one text
	// content block per chunk); this struct is the streaming envelope.
	// Nil for format=metadata.
	//
	// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments".
	RawStream *rawStreamMeta `json:"raw_stream,omitempty"`
	Error     *ToolError     `json:"error,omitempty"`
}

// FullMessage is the get_message projection. Body is populated for
// format=metadata (decrypted text/HTML); Raw is populated for
// format=raw. Folders mirror the IMAP mapping.
type FullMessage struct {
	MessageID string   `json:"message_id"`
	Subject   string   `json:"subject"`
	From      string   `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	CC        []string `json:"cc,omitempty"`
	BCC       []string `json:"bcc,omitempty"`
	Date      int64    `json:"date"`
	Unread    bool     `json:"unread"`
	MIMEType  string   `json:"mime_type,omitempty"`
	Body      string   `json:"body,omitempty"`
	Raw       string   `json:"raw,omitempty"`
	Folders   []string `json:"folders"`
	LabelIDs  []string `json:"label_ids"`
	// Attachments lists the message's attachments (id/name/size/mime) so
	// an agent can pick one to pass to download_attachment.
	//
	// Governing: SPEC-0006 REQ "Required Tool Set" (download_attachment).
	Attachments []AttachmentMeta `json:"attachments,omitempty"`
}

// AttachmentMeta is the listing-friendly projection of one Proton
// attachment, surfaced on a get_message response so the agent has the
// attachment_id download_attachment accepts plus the name/size/MIME to
// decide whether to fetch it.
type AttachmentMeta struct {
	AttachmentID string `json:"attachment_id"`
	Name         string `json:"name,omitempty"`
	MIMEType     string `json:"mime_type,omitempty"`
	Size         int64  `json:"size"`
}

// getMessage implements the get_message tool. format=metadata returns
// the decrypted body inline; format=raw streams the RFC822 source as
// ordered MCP content chunks bounded by the 16 MiB cap (per issue #19 /
// SPEC-0006 REQ "Streaming Bodies and Attachments") so a large message
// never buffers in full beyond the cap.
//
// Governing: SPEC-0006 REQ "Required Tool Set", REQ "Streaming Bodies and
// Attachments".
func (r *toolRegistry) getMessage(ctx context.Context, _ *mcp.CallToolRequest, in GetMessageIn) (*mcp.CallToolResult, GetMessageOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, GetMessageOut{}, err
	}
	if strings.TrimSpace(in.MessageID) == "" {
		return nil, GetMessageOut{Error: &ToolError{
			Code:      codeInvalidArgument,
			Message:   "message_id is required",
			Retriable: false,
		}}, nil
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, GetMessageOut{Error: terr}, nil
	}

	msg, mErr := cl.GetMessage(ctx, in.MessageID)
	if mErr != nil {
		return nil, GetMessageOut{Error: mapMessageLookupError(mErr)}, nil
	}

	full := &FullMessage{
		MessageID:   msg.ID,
		Subject:     msg.Subject,
		From:        addrString(msg.Sender),
		To:          addrStrings(msg.ToList),
		CC:          addrStrings(msg.CCList),
		BCC:         addrStrings(msg.BCCList),
		Date:        msg.Time,
		Unread:      bool(msg.Unread),
		MIMEType:    string(msg.MIMEType),
		Folders:     foldersForLabelIDs(msg.LabelIDs),
		LabelIDs:    msg.LabelIDs,
		Attachments: attachmentMetas(msg),
	}

	switch strings.ToLower(strings.TrimSpace(in.Format)) {
	case "", "metadata":
		full.Body = msg.Body
		return nil, GetMessageOut{Message: full}, nil
	case "raw":
		// The decrypted RFC822 source: reconstruct from the stored
		// header block + decrypted body. go-proton-api exposes Header
		// (raw) and Body (decrypted); concatenated they form the RFC822
		// representation an agent expects from format=raw.
		//
		// Stream the source as ordered content chunks bounded by the
		// 16 MiB cap rather than packing the whole body into the Raw
		// struct field. We do NOT also set full.Raw -- that would double
		// the in-process copy and defeat the cap -- so a raw response's
		// bytes live ONLY in the content chunks. The structured envelope
		// (full + RawStream) tells the agent how many chunks to expect.
		//
		// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments"
		// (Scenario "Large message body streamed").
		contents, meta := streamRawBody(rawSource(msg))
		return &mcp.CallToolResult{Content: contents},
			GetMessageOut{Message: full, RawStream: &meta}, nil
	default:
		return nil, GetMessageOut{Error: &ToolError{
			Code:      codeInvalidArgument,
			Message:   fmt.Sprintf("unknown format %q; expected metadata or raw", in.Format),
			Retriable: false,
		}}, nil
	}
}

// attachmentMetas projects a message's attachments into the
// listing-friendly AttachmentMeta slice. Returns nil (omitempty) when
// the message carries no attachments.
func attachmentMetas(msg proton.Message) []AttachmentMeta {
	if len(msg.Attachments) == 0 {
		return nil
	}
	out := make([]AttachmentMeta, 0, len(msg.Attachments))
	for _, a := range msg.Attachments {
		out = append(out, AttachmentMeta{
			AttachmentID: a.ID,
			Name:         a.Name,
			MIMEType:     string(a.MIMEType),
			Size:         a.Size,
		})
	}
	return out
}

// ----- list_labels -----

// ListLabelsIn is the (empty) input schema for list_labels.
type ListLabelsIn struct{}

// LabelInfo is one label in the list_labels response. FolderName is the
// IMAP-mapped name (Labels/<path>) so the agent can pass it to
// move_to_folder; ID is the raw Proton label ID add_label / remove_label
// accept.
type LabelInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	FolderName string `json:"folder_name" jsonschema:"IMAP-mapped name usable with move_to_folder (Labels/<path>)"`
	Type       string `json:"type" jsonschema:"label or folder"`
	Color      string `json:"color,omitempty"`
}

// ListLabelsOut is the output schema for list_labels.
type ListLabelsOut struct {
	Labels []LabelInfo `json:"labels"`
	Error  *ToolError  `json:"error,omitempty"`
}

// listLabels implements the list_labels tool. It surfaces user-created
// labels and folders; system folders are reached via their fixed IMAP
// names (INBOX, Sent, ...) and so are intentionally not duplicated here.
func (r *toolRegistry) listLabels(ctx context.Context, _ *mcp.CallToolRequest, _ ListLabelsIn) (*mcp.CallToolResult, ListLabelsOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, ListLabelsOut{}, err
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, ListLabelsOut{Error: terr}, nil
	}

	labels, lErr := cl.GetLabels(ctx, proton.LabelTypeLabel, proton.LabelTypeFolder)
	if lErr != nil {
		return nil, ListLabelsOut{Error: mapProtonError(lErr)}, nil
	}

	out := ListLabelsOut{Labels: make([]LabelInfo, 0, len(labels))}
	for _, l := range labels {
		typeName := "label"
		if l.Type == proton.LabelTypeFolder {
			typeName = "folder"
		}
		out.Labels = append(out.Labels, LabelInfo{
			ID:         l.ID,
			Name:       l.Name,
			FolderName: mailbox.FormatUserLabelName(labelPath(l)),
			Type:       typeName,
			Color:      l.Color,
		})
	}
	return nil, out, nil
}

// ----- shared helpers -----

// fetchPage fetches one page of message metadata and projects it into
// MessageMeta, optionally re-filtering by a case-insensitive subject
// substring. Pagination is server-side via ListMessagesPage so a single
// page never buffers the whole mailbox.
// It returns the projected (possibly subject-filtered) metas AND the RAW
// pre-filter page length. The raw length is what has_more must be based
// on: a client-side subject filter can shrink the returned slice well
// below pageSize even when the upstream page was full and more matching
// pages exist downstream. Using the filtered count would falsely report
// has_more=false and silently truncate the result set (the bug the
// hostile review of PR #31 caught).
//
// Governing: SPEC-0006 REQ "Pagination on List and Search".
func (r *toolRegistry) fetchPage(ctx context.Context, cl proton.Client, filter proton.MessageFilter, subjectQuery string, page, pageSize int) (metas []MessageMeta, rawLen int, terr *ToolError) {
	// go-proton-api pages are 0-based; the tool surface is 1-based.
	raw, err := cl.ListMessagesPage(ctx, page-1, pageSize, filter)
	if err != nil {
		return nil, 0, mapProtonError(err)
	}
	metas = make([]MessageMeta, 0, len(raw))
	q := strings.ToLower(subjectQuery)
	for _, m := range raw {
		if q != "" && !strings.Contains(strings.ToLower(m.Subject), q) {
			continue
		}
		metas = append(metas, MessageMeta{
			MessageID:      m.ID,
			Subject:        m.Subject,
			From:           addrString(m.Sender),
			To:             addrStrings(m.ToList),
			CC:             addrStrings(m.CCList),
			Date:           m.Time,
			Size:           m.Size,
			Unread:         bool(m.Unread),
			NumAttachments: m.NumAttachments,
			Folders:        foldersForLabelIDs(m.LabelIDs),
			LabelIDs:       m.LabelIDs,
		})
	}
	return metas, len(raw), nil
}

// folderTotal returns the total message count for a Proton label ID via
// the cheap grouped-count endpoint. ok=false when the count is
// unavailable (the caller then reports total_count_known=false).
func (r *toolRegistry) folderTotal(ctx context.Context, cl proton.Client, labelID string) (int, bool) {
	counts, err := cl.GroupedMessageCount(ctx)
	if err != nil {
		return 0, false
	}
	for _, c := range counts {
		if c.LabelID == labelID {
			return c.Total, true
		}
	}
	// A label with zero messages is absent from the grouped count; treat
	// "label resolved but not present" as a genuine zero so an empty
	// folder still reports total_count=0 rather than unknown.
	return 0, true
}

// resolveFolderToLabelID maps an IMAP folder name to its Proton label ID
// using the shared internal/mailbox resolver. System folders resolve
// from the static table; user labels (Labels/<path>) require a path->ID
// lookup against the account's labels. Unknown names yield the
// SPEC-0006 unknown_folder structured error.
//
// Governing: SPEC-0006 REQ "Folder Names Match IMAP Mapping".
func (r *toolRegistry) resolveFolderToLabelID(ctx context.Context, cl proton.Client, folder string) (string, *ToolError) {
	id, _, terr := r.resolveFolderForMove(ctx, cl, folder)
	return id, terr
}

// resolveFolderForMove is resolveFolderToLabelID plus the destination
// KIND (isSystem). The move handler needs the kind to decide whether the
// operation is a relocation (system destination -> strip source location)
// or additive label application (user-label destination -> no strip).
//
// Governing: SPEC-0006 REQ "Folder Names Match IMAP Mapping".
func (r *toolRegistry) resolveFolderForMove(ctx context.Context, cl proton.Client, folder string) (labelID string, isSystem bool, terr *ToolError) {
	folder = strings.TrimSpace(folder)
	kind, ref, ok := mailbox.ClassifyName(folder)
	if !ok {
		return "", false, unknownFolderError(folder)
	}
	if kind == mailbox.KindSystem {
		// ref is already the Proton system label ID.
		return ref, true, nil
	}
	// User label: ref is the label PATH. Resolve to the Proton label ID
	// by matching against the account's labels + folders.
	labels, err := cl.GetLabels(ctx, proton.LabelTypeLabel, proton.LabelTypeFolder)
	if err != nil {
		return "", false, mapProtonError(err)
	}
	for _, l := range labels {
		if labelPath(l) == ref {
			return l.ID, false, nil
		}
	}
	return "", false, unknownFolderError(folder)
}

// unknownFolderError builds the SPEC-0006 unknown_folder structured
// error. Message format matches the spec scenario verbatim.
func unknownFolderError(folder string) *ToolError {
	return &ToolError{
		Code:      codeUnknownFolder,
		Message:   fmt.Sprintf("Folder %s does not exist", folder),
		Retriable: false,
	}
}

// normalisePagination applies the SPEC-0006 defaults and clamp: page
// defaults to 1; page_size defaults to 50 and is clamped to 200.
func normalisePagination(page, pageSize int) (normPage, normSize int, clamped bool) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
		clamped = true
	}
	return page, pageSize, clamped
}

// computeHasMore decides whether more pages exist. When total_count is
// known it is authoritative; otherwise we fall back to "the upstream
// page came back full" as the has-more heuristic. rawReturned MUST be
// the pre-filter (raw) upstream page length -- never a post-subject-
// filter count -- or a filter that matches fewer than a full page would
// falsely report no more pages.
func computeHasMore(total *int, page, pageSize, rawReturned int) bool {
	if total != nil {
		return page*pageSize < *total
	}
	return rawReturned == pageSize
}

// foldersForLabelIDs maps a message's Proton label IDs to their IMAP
// folder names where a system mapping exists. User-label IDs (numeric or
// not) that aren't system folders are returned as raw IDs prefixed so the
// agent can still correlate them; the authoritative human name comes from
// list_labels. We only translate system IDs here to avoid an N+1 label
// lookup per message.
func foldersForLabelIDs(labelIDs []string) []string {
	out := make([]string, 0, len(labelIDs))
	for _, id := range labelIDs {
		if name := mailbox.ResolveSystemFolderName(id); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// labelPath joins a Proton label's Path segments into the hierarchical
// path string the IMAP namespace uses. Falls back to Name when Path is
// empty (a flat, non-nested label).
func labelPath(l proton.Label) string {
	if len(l.Path) > 0 {
		return strings.Join(l.Path, "/")
	}
	return l.Name
}

// rawSource reconstructs an RFC822-shaped source from a decrypted Proton
// message: the stored raw header block, a blank line, then the decrypted
// body. This is the inline (non-streaming) form; streaming for large
// payloads is issue #19.
func rawSource(msg proton.Message) string {
	header := strings.TrimRight(msg.Header, "\r\n")
	if header == "" {
		return msg.Body
	}
	return header + "\r\n\r\n" + msg.Body
}
