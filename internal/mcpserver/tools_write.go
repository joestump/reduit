// Write tools: add_label, remove_label, move_to_folder, mark_read,
// mark_unread.
//
// Every mutation is idempotent per SPEC-0006 REQ "Idempotent Mutations":
// the handler reads the message's current label set first, computes the
// no-op-or-mutate decision locally, and only calls Proton when the
// target state differs. A message ID belonging to another account
// surfaces as a `not_found` error identical to a genuine miss.
//
// Governing: SPEC-0006 REQ "Required Tool Set", SPEC-0006 REQ
// "Idempotent Mutations", SPEC-0006 REQ "Folder Names Match IMAP
// Mapping", SPEC-0006 REQ "Account Scope on All Operations".
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

func (r *toolRegistry) registerWrite(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "add_label",
		Description: "Apply a Proton label to a message. Idempotent: a no-op when the label is already present.",
	}, r.addLabel)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "remove_label",
		Description: "Remove a Proton label from a message. Idempotent: a no-op when the label is not present.",
	}, r.removeLabel)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "move_to_folder",
		Description: "Move a message to a folder (system folder name or Labels/<name>). Idempotent: a no-op when already in the target folder.",
	}, r.moveToFolder)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mark_read",
		Description: "Mark one or more messages read. Idempotent.",
	}, r.markRead)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mark_unread",
		Description: "Mark one or more messages unread. Idempotent.",
	}, r.markUnread)
}

// ----- add_label / remove_label -----

// LabelMutationIn is the shared input for add_label and remove_label.
type LabelMutationIn struct {
	MessageID string `json:"message_id" jsonschema:"Proton message ID"`
	LabelID   string `json:"label_id" jsonschema:"Proton label ID (from list_labels)"`
}

// AddLabelOut is the add_label result. Mirrors the SPEC-0006 idempotency
// scenario shape exactly: {applied, already_present}.
type AddLabelOut struct {
	Applied        bool       `json:"applied"`
	AlreadyPresent bool       `json:"already_present"`
	Error          *ToolError `json:"error,omitempty"`
}

// RemoveLabelOut is the remove_label result: {removed, not_present}.
type RemoveLabelOut struct {
	Removed    bool       `json:"removed"`
	NotPresent bool       `json:"not_present"`
	Error      *ToolError `json:"error,omitempty"`
}

// addLabel implements the add_label tool.
//
// Governing: SPEC-0006 REQ "Idempotent Mutations" (Scenario "Adding an
// already-applied label").
func (r *toolRegistry) addLabel(ctx context.Context, _ *mcp.CallToolRequest, in LabelMutationIn) (*mcp.CallToolResult, AddLabelOut, error) {
	cl, msg, terr, err := r.loadMessageForMutation(ctx, in.MessageID)
	if err != nil {
		return nil, AddLabelOut{}, err
	}
	if terr != nil {
		return nil, AddLabelOut{Error: terr}, nil
	}
	if strings.TrimSpace(in.LabelID) == "" {
		return nil, AddLabelOut{Error: &ToolError{Code: codeInvalidArgument, Message: "label_id is required", Retriable: false}}, nil
	}

	if hasLabel(msg.LabelIDs, in.LabelID) {
		// Already present -- no Proton mutation. Per the idempotency
		// scenario the response is {applied:false, already_present:true}.
		return nil, AddLabelOut{Applied: false, AlreadyPresent: true}, nil
	}
	if mErr := cl.LabelMessages(ctx, []string{in.MessageID}, in.LabelID); mErr != nil {
		return nil, AddLabelOut{Error: mapProtonError(mErr)}, nil
	}
	return nil, AddLabelOut{Applied: true, AlreadyPresent: false}, nil
}

// removeLabel implements the remove_label tool.
//
// Governing: SPEC-0006 REQ "Idempotent Mutations" (Scenario "Removing a
// non-applied label").
func (r *toolRegistry) removeLabel(ctx context.Context, _ *mcp.CallToolRequest, in LabelMutationIn) (*mcp.CallToolResult, RemoveLabelOut, error) {
	cl, msg, terr, err := r.loadMessageForMutation(ctx, in.MessageID)
	if err != nil {
		return nil, RemoveLabelOut{}, err
	}
	if terr != nil {
		return nil, RemoveLabelOut{Error: terr}, nil
	}
	if strings.TrimSpace(in.LabelID) == "" {
		return nil, RemoveLabelOut{Error: &ToolError{Code: codeInvalidArgument, Message: "label_id is required", Retriable: false}}, nil
	}

	if !hasLabel(msg.LabelIDs, in.LabelID) {
		return nil, RemoveLabelOut{Removed: false, NotPresent: true}, nil
	}
	if mErr := cl.UnlabelMessages(ctx, []string{in.MessageID}, in.LabelID); mErr != nil {
		return nil, RemoveLabelOut{Error: mapProtonError(mErr)}, nil
	}
	return nil, RemoveLabelOut{Removed: true, NotPresent: false}, nil
}

// ----- move_to_folder -----

// MoveToFolderIn is the input for move_to_folder.
type MoveToFolderIn struct {
	MessageID string `json:"message_id" jsonschema:"Proton message ID"`
	Folder    string `json:"folder" jsonschema:"Destination IMAP folder name (INBOX, Sent, ... or Labels/<name>)"`
}

// MoveToFolderOut is the move_to_folder result: {moved, already_in_folder}.
type MoveToFolderOut struct {
	Moved           bool       `json:"moved"`
	AlreadyInFolder bool       `json:"already_in_folder"`
	Error           *ToolError `json:"error,omitempty"`
}

// moveToFolder implements the move_to_folder tool. Proton's model is
// additive labels, so the semantics differ by destination KIND, exactly
// mirroring the IMAP layer (SPEC-0003):
//
//   - System-folder destination (INBOX, Archive, Trash, ...): this is a
//     relocation. Add the destination location label, then remove the
//     SOURCE exclusive location label(s) the message currently carries.
//     All Mail ("5") is NEVER removed (it is a permanent virtual
//     aggregate, not a location), and user labels are left intact.
//
//   - User-label destination (Labels/<name>): this is label APPLICATION,
//     not relocation. Add the label and change nothing else -- the
//     message stays in its current folder (INBOX/All Mail/etc.). This
//     matches the IMAP layer's treatment of Labels/* as additive.
//
// The bug the hostile review of PR #31 caught was stripping EVERY
// non-destination system folder (including All Mail) on every move, and
// running that strip for user-label destinations too. Both are fixed
// here: All Mail is excluded from the strip set, and the strip only runs
// for system-folder destinations.
//
// Governing: SPEC-0006 REQ "Idempotent Mutations" (Scenario "Moving to
// current folder"), SPEC-0006 REQ "Folder Names Match IMAP Mapping",
// SPEC-0003 REQ "Moving between system folders changes Proton system
// flag", SPEC-0003 REQ "Moving between Labels/ folders adjusts labels
// additively".
func (r *toolRegistry) moveToFolder(ctx context.Context, _ *mcp.CallToolRequest, in MoveToFolderIn) (*mcp.CallToolResult, MoveToFolderOut, error) {
	cl, msg, terr, err := r.loadMessageForMutation(ctx, in.MessageID)
	if err != nil {
		return nil, MoveToFolderOut{}, err
	}
	if terr != nil {
		return nil, MoveToFolderOut{Error: terr}, nil
	}

	// Classify the destination so we can branch on system vs user label.
	// resolveFolderToLabelID still performs the Labels/<name> -> Proton
	// label-ID lookup; we additionally need the KIND here.
	destLabelID, destIsSystem, terr := r.resolveFolderForMove(ctx, cl, in.Folder)
	if terr != nil {
		return nil, MoveToFolderOut{Error: terr}, nil
	}

	if destIsSystem {
		// Relocation. No-op iff already in dest AND not carrying any other
		// EXCLUSIVE location folder (All Mail does not count).
		if hasLabel(msg.LabelIDs, destLabelID) && !carriesOtherExclusiveSystemFolder(msg.LabelIDs, destLabelID) {
			return nil, MoveToFolderOut{Moved: false, AlreadyInFolder: true}, nil
		}

		// Add-new before remove-old (mirrors IMAP performMove Phase 2->3)
		// so a failure leaves the message reachable.
		if !hasLabel(msg.LabelIDs, destLabelID) {
			if mErr := cl.LabelMessages(ctx, []string{in.MessageID}, destLabelID); mErr != nil {
				return nil, MoveToFolderOut{Error: mapProtonError(mErr)}, nil
			}
		}
		// Strip ONLY the source exclusive location folders -- never All
		// Mail, never user labels.
		for _, id := range exclusiveSystemFolderLabelIDs(msg.LabelIDs) {
			if id == destLabelID {
				continue
			}
			if mErr := cl.UnlabelMessages(ctx, []string{in.MessageID}, id); mErr != nil {
				return nil, MoveToFolderOut{Error: mapProtonError(mErr)}, nil
			}
		}
		return nil, MoveToFolderOut{Moved: true, AlreadyInFolder: false}, nil
	}

	// User-label destination: additive label application, no strip.
	if hasLabel(msg.LabelIDs, destLabelID) {
		return nil, MoveToFolderOut{Moved: false, AlreadyInFolder: true}, nil
	}
	if mErr := cl.LabelMessages(ctx, []string{in.MessageID}, destLabelID); mErr != nil {
		return nil, MoveToFolderOut{Error: mapProtonError(mErr)}, nil
	}
	return nil, MoveToFolderOut{Moved: true, AlreadyInFolder: false}, nil
}

// ----- mark_read / mark_unread -----

// maxMarkBatch caps the number of message IDs a single mark_read /
// mark_unread call may carry. Each ID costs one GetMessage round-trip
// plus a conditional mark round-trip, all sequential, so an unbounded
// list could pin a per-account concurrency slot for a long time and
// exhaust the account's Proton quota. 100 is generous for interactive
// agent use; larger batches should be chunked by the caller.
const maxMarkBatch = 100

// MarkReadIn is the input for mark_read / mark_unread. message_ids is a
// list per SPEC-0006 REQ "Required Tool Set" (mark_read(message_ids)).
type MarkReadIn struct {
	MessageIDs []string `json:"message_ids" jsonschema:"Proton message IDs to mark (max 100)"`
}

// MarkReadOut reports how many messages changed vs were already in the
// target read-state (idempotency surface).
type MarkReadOut struct {
	Changed        []string   `json:"changed"`
	AlreadyInState []string   `json:"already_in_state"`
	Error          *ToolError `json:"error,omitempty"`
}

// markRead implements mark_read: applies the read state to each message,
// no-op for messages already read.
func (r *toolRegistry) markRead(ctx context.Context, _ *mcp.CallToolRequest, in MarkReadIn) (*mcp.CallToolResult, MarkReadOut, error) {
	return r.setReadState(ctx, in.MessageIDs, true)
}

// markUnread implements mark_unread.
func (r *toolRegistry) markUnread(ctx context.Context, _ *mcp.CallToolRequest, in MarkReadIn) (*mcp.CallToolResult, MarkReadOut, error) {
	return r.setReadState(ctx, in.MessageIDs, false)
}

// setReadState is the shared mark_read / mark_unread body. It reads each
// message's current Unread flag and only calls Proton for messages whose
// state differs, so a repeat call is a no-op.
func (r *toolRegistry) setReadState(ctx context.Context, messageIDs []string, read bool) (*mcp.CallToolResult, MarkReadOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, MarkReadOut{}, err
	}
	if len(messageIDs) == 0 {
		return nil, MarkReadOut{Error: &ToolError{Code: codeInvalidArgument, Message: "message_ids is required and must be non-empty", Retriable: false}}, nil
	}
	if len(messageIDs) > maxMarkBatch {
		return nil, MarkReadOut{Error: &ToolError{
			Code:      codeInvalidArgument,
			Message:   fmt.Sprintf("message_ids exceeds the maximum batch size of %d", maxMarkBatch),
			Retriable: false,
		}}, nil
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, MarkReadOut{Error: terr}, nil
	}

	out := MarkReadOut{}
	for _, id := range messageIDs {
		msg, mErr := cl.GetMessage(ctx, id)
		if mErr != nil {
			// Return the partial progress accumulated so far alongside the
			// error so the agent knows exactly which messages changed
			// before the failure and can retry only the remainder.
			out.Error = mapMessageLookupError(mErr)
			return nil, out, nil
		}
		currentlyUnread := bool(msg.Unread)
		// read==true means we want Unread=false. No-op when already in
		// the target state.
		if read && !currentlyUnread {
			out.AlreadyInState = append(out.AlreadyInState, id)
			continue
		}
		if !read && currentlyUnread {
			out.AlreadyInState = append(out.AlreadyInState, id)
			continue
		}
		var sErr error
		if read {
			sErr = cl.MarkMessagesRead(ctx, id)
		} else {
			sErr = cl.MarkMessagesUnread(ctx, id)
		}
		if sErr != nil {
			out.Error = mapProtonError(sErr)
			return nil, out, nil
		}
		out.Changed = append(out.Changed, id)
	}
	return nil, out, nil
}

// ----- helpers -----

// loadMessageForMutation resolves the bound account, the per-account
// Proton client, and the message metadata in one shared step. The
// returned *ToolError is a structured (agent-facing) failure; the
// returned error is an internal (protocol-level) failure. Exactly one of
// the two is non-nil on a non-success path.
func (r *toolRegistry) loadMessageForMutation(ctx context.Context, messageID string) (proton.Client, *proton.Message, *ToolError, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if strings.TrimSpace(messageID) == "" {
		return nil, nil, &ToolError{Code: codeInvalidArgument, Message: "message_id is required", Retriable: false}, nil
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, nil, terr, nil
	}
	msg, mErr := cl.GetMessage(ctx, messageID)
	if mErr != nil {
		return nil, nil, mapMessageLookupError(mErr), nil
	}
	return cl, &msg, nil, nil
}

// hasLabel reports whether labelID is present in the message's label set.
func hasLabel(labelIDs []string, labelID string) bool {
	for _, id := range labelIDs {
		if id == labelID {
			return true
		}
	}
	return false
}

// isExclusiveSystemFolderID reports whether a Proton label ID is an
// EXCLUSIVE IMAP "location" system folder -- one of the mutually-
// exclusive places a message lives (INBOX, Archive, Trash, Spam, Sent,
// Drafts). It deliberately EXCLUDES All Mail (ProtonAllMailLabelID,
// "5"), which every Proton message carries permanently as a virtual
// aggregate, not a location. Removing All Mail orphans the message from
// the All-Mail view and desyncs Reduit's mailbox state -- the bug the
// hostile review of PR #31 caught. A move must never touch it.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag" (mirrors internal/imapserver performMove, which removes
// only the SOURCE location label, never All Mail).
func isExclusiveSystemFolderID(labelID string) bool {
	if labelID == mailbox.ProtonAllMailLabelID {
		// All Mail is non-exclusive: never a move source or strip target.
		return false
	}
	return mailbox.ResolveSystemFolderName(labelID) != ""
}

// exclusiveSystemFolderLabelIDs filters a message's label set down to the
// exclusive location system folders it currently carries (per
// isExclusiveSystemFolderID -- All Mail excluded). The move handler
// strips exactly these (minus the destination) so a message lands in a
// single location folder without losing its All Mail membership or any
// user labels.
func exclusiveSystemFolderLabelIDs(labelIDs []string) []string {
	out := make([]string, 0, len(labelIDs))
	for _, id := range labelIDs {
		if isExclusiveSystemFolderID(id) {
			out = append(out, id)
		}
	}
	return out
}

// carriesOtherExclusiveSystemFolder reports whether the message carries
// an exclusive location system folder OTHER than destLabelID -- i.e. a
// move to a system destination is still needed even though the message
// already has the destination label. All Mail is ignored (it is always
// present and is never a move source).
func carriesOtherExclusiveSystemFolder(labelIDs []string, destLabelID string) bool {
	for _, id := range exclusiveSystemFolderLabelIDs(labelIDs) {
		if id != destLabelID {
			return true
		}
	}
	return false
}
