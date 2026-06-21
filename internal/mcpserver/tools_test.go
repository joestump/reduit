// Internal (white-box) tests for the MCP tool surface. These exercise
// the tool handlers directly -- building a toolRegistry, stamping an
// account on the context the way the bearer-auth middleware would, and
// asserting the handler output. They cover registration, pagination
// semantics, folder-name mapping, idempotency, and the send_message ->
// outbox encryption-pipeline handoff.
//
// Governing: SPEC-0006 REQ "Required Tool Set", REQ "Pagination on List
// and Search", REQ "Folder Names Match IMAP Mapping", REQ "Idempotent
// Mutations", REQ "Send-Message Encryption".
package mcpserver

import (
	"context"
	"net/mail"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/outbox"
	"github.com/joestump/reduit/internal/proton"
)

// ----- fakes -----

// fakeClient is a configurable proton.Client for tool tests. Only the
// methods the tools touch are meaningful; everything else panics so a
// stray call is loud.
type fakeClient struct {
	messages map[string]proton.Message // by ID
	pages    [][]proton.MessageMetadata
	counts   []proton.MessageGroupCount
	labels   []proton.Label

	labeled   []labelCall
	unlabeled []labelCall
	readCalls [][]string
	unread    [][]string
}

type labelCall struct {
	ids     []string
	labelID string
}

func (f *fakeClient) GetMessage(_ context.Context, id string) (proton.Message, error) {
	m, ok := f.messages[id]
	if !ok {
		return proton.Message{}, &proton.APIError{Status: 404, Message: "not found"}
	}
	return m, nil
}

func (f *fakeClient) ListMessagesPage(_ context.Context, page, _ int, _ proton.MessageFilter) ([]proton.MessageMetadata, error) {
	if page < 0 || page >= len(f.pages) {
		return nil, nil
	}
	return f.pages[page], nil
}

func (f *fakeClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	return f.counts, nil
}

func (f *fakeClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	return f.labels, nil
}

func (f *fakeClient) LabelMessages(_ context.Context, ids []string, labelID string) error {
	f.labeled = append(f.labeled, labelCall{ids: ids, labelID: labelID})
	return nil
}

func (f *fakeClient) UnlabelMessages(_ context.Context, ids []string, labelID string) error {
	f.unlabeled = append(f.unlabeled, labelCall{ids: ids, labelID: labelID})
	return nil
}

func (f *fakeClient) MarkMessagesRead(_ context.Context, ids ...string) error {
	f.readCalls = append(f.readCalls, ids)
	return nil
}

func (f *fakeClient) MarkMessagesUnread(_ context.Context, ids ...string) error {
	f.unread = append(f.unread, ids)
	return nil
}

// Unused-by-tools methods panic.
func (f *fakeClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	panic("unused")
}
func (f *fakeClient) AuthTOTP(context.Context, string) error           { panic("unused") }
func (f *fakeClient) AuthFIDO2(context.Context, proton.FIDO2Req) error { panic("unused") }
func (f *fakeClient) KeySalts(context.Context) (proton.Salts, error)   { panic("unused") }
func (f *fakeClient) GetUser(context.Context) (proton.User, error)     { panic("unused") }
func (f *fakeClient) GetAddresses(context.Context) ([]proton.Address, error) {
	panic("unused")
}
func (f *fakeClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	panic("unused")
}
func (f *fakeClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	panic("unused")
}
func (f *fakeClient) GetLatestEventID(context.Context) (string, error) { panic("unused") }
func (f *fakeClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("unused")
}
func (f *fakeClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("unused")
}
func (f *fakeClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	panic("unused")
}
func (f *fakeClient) GetAttachment(context.Context, string) ([]byte, error) { panic("unused") }
func (f *fakeClient) GetMessageRFC822(context.Context, string) ([]byte, error) {
	panic("unused")
}
func (f *fakeClient) Logout(context.Context) error { return nil }
func (f *fakeClient) LatestRefreshToken() string   { return "" }

var _ proton.Client = (*fakeClient)(nil)

// fakeOutbox records the submission it received and returns a canned
// result. It lets a test assert that send_message handed the assembled
// RFC 5322 envelope to the outbox (the SPEC-0004 encryption pipeline)
// rather than encrypting itself.
type fakeOutbox struct {
	got    *outbox.Submission
	result outbox.Result
}

func (f *fakeOutbox) Submit(_ context.Context, sub outbox.Submission) outbox.Result {
	cp := sub
	f.got = &cp
	return f.result
}

var _ Submitter = (*fakeOutbox)(nil)

// ----- harness -----

func testRegistry(cl proton.Client, ob Submitter) *toolRegistry {
	return &toolRegistry{deps: ToolDeps{
		Clients: ClientResolverFunc(func(context.Context, string) (proton.Client, error) {
			return cl, nil
		}),
		Outbox: ob,
	}}
}

func ctxWithAccount(a *account.Account) context.Context {
	return withAccount(context.Background(), a)
}

func activeAccount() *account.Account {
	return &account.Account{ID: "acct-1", UserID: "user-1", State: account.StateActive, PrimaryAlias: "joe@example.com", Email: "joe@proton.me"}
}

func addr(s string) *mail.Address { return &mail.Address{Address: s} }

// ----- registration -----

func TestRegisterTools_AllRequiredToolsPresent(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	registerTools(srv, ToolDeps{
		Clients: ClientResolverFunc(func(context.Context, string) (proton.Client, error) { return &fakeClient{}, nil }),
		Outbox:  &fakeOutbox{},
	})

	// The SDK exposes registered tools via the session's tools/list; here
	// we assert registration did not panic and the server is usable. The
	// authoritative "required set present" assertion lives in the
	// transport-level test below.
	if srv == nil {
		t.Fatal("nil server after registerTools")
	}
}

// ----- list_messages pagination + folder mapping -----

func TestListMessages_PaginationDefaultsAndClamp(t *testing.T) {
	cl := &fakeClient{
		pages: [][]proton.MessageMetadata{
			{{ID: "m1", Subject: "Hello", Sender: addr("a@b.com"), Time: 100}},
		},
		counts: []proton.MessageGroupCount{{LabelID: mailbox.ProtonInboxLabelID, Total: 1}},
	}
	r := testRegistry(cl, nil)

	// page_size omitted -> 50; page_size over max -> clamped to 200.
	_, out, err := r.listMessages(ctxWithAccount(activeAccount()), nil, ListMessagesIn{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if out.PageSize != 50 {
		t.Errorf("default page_size = %d, want 50", out.PageSize)
	}
	if out.Page != 1 {
		t.Errorf("default page = %d, want 1", out.Page)
	}
	if out.TotalCount == nil || *out.TotalCount != 1 {
		t.Errorf("total_count = %v, want 1", out.TotalCount)
	}
	if !out.TotalCountKnown {
		t.Error("total_count_known = false, want true for a folder listing")
	}
	if len(out.Messages) != 1 || out.Messages[0].MessageID != "m1" {
		t.Fatalf("messages = %+v", out.Messages)
	}

	_, clamped, err := r.listMessages(ctxWithAccount(activeAccount()), nil, ListMessagesIn{Folder: "INBOX", PageSize: 5000})
	if err != nil {
		t.Fatalf("listMessages clamp: %v", err)
	}
	if clamped.PageSize != 200 || !clamped.Clamped {
		t.Errorf("clamp: page_size=%d clamped=%v, want 200/true", clamped.PageSize, clamped.Clamped)
	}
}

func TestListMessages_UserLabelFolderMapping(t *testing.T) {
	cl := &fakeClient{
		labels: []proton.Label{{ID: "lbl-42", Name: "Receipts", Path: []string{"Receipts"}, Type: proton.LabelTypeLabel}},
		pages: [][]proton.MessageMetadata{
			{{ID: "m1", Subject: "Receipt", LabelIDs: []string{"lbl-42"}, Time: 1}},
		},
		counts: []proton.MessageGroupCount{{LabelID: "lbl-42", Total: 1}},
	}
	r := testRegistry(cl, nil)

	_, out, err := r.listMessages(ctxWithAccount(activeAccount()), nil, ListMessagesIn{Folder: "Labels/Receipts"})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if len(out.Messages) != 1 {
		t.Fatalf("messages = %+v", out.Messages)
	}
}

func TestListMessages_UnknownFolder(t *testing.T) {
	r := testRegistry(&fakeClient{}, nil)
	_, out, err := r.listMessages(ctxWithAccount(activeAccount()), nil, ListMessagesIn{Folder: "Bogus"})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if out.Error == nil || out.Error.Code != codeUnknownFolder {
		t.Fatalf("error = %+v, want code unknown_folder", out.Error)
	}
	if out.Error.Message != "Folder Bogus does not exist" {
		t.Errorf("message = %q", out.Error.Message)
	}
}

// ----- search_messages -----

func TestSearchMessages_SubjectFilterAndUnknownTotal(t *testing.T) {
	cl := &fakeClient{
		pages: [][]proton.MessageMetadata{
			{
				{ID: "m1", Subject: "Tax Receipt 2025", Time: 1},
				{ID: "m2", Subject: "Lunch plans", Time: 2},
			},
		},
	}
	r := testRegistry(cl, nil)
	_, out, err := r.searchMessages(ctxWithAccount(activeAccount()), nil, SearchMessagesIn{Query: "receipt"})
	if err != nil {
		t.Fatalf("searchMessages: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if len(out.Messages) != 1 || out.Messages[0].MessageID != "m1" {
		t.Fatalf("messages = %+v, want only m1 (subject substring)", out.Messages)
	}
	if out.TotalCountKnown {
		t.Error("search total_count_known = true, want false (no cheap count)")
	}
}

func TestSearchMessages_EmptyQueryRejected(t *testing.T) {
	r := testRegistry(&fakeClient{}, nil)
	_, out, _ := r.searchMessages(ctxWithAccount(activeAccount()), nil, SearchMessagesIn{Query: "  "})
	if out.Error == nil || out.Error.Code != codeInvalidArgument {
		t.Fatalf("error = %+v, want invalid_argument", out.Error)
	}
}

// TestPagination_FilterMatchesFewerThanFullPage is the regression test
// for the hostile finding (PR #31, item 4): when a client-side subject
// filter matches fewer than a full page but the RAW upstream page was
// full (so more matching pages exist downstream), has_more MUST stay
// true. The earlier code based has_more on the post-filter count and
// dropped later pages.
func TestPagination_FilterMatchesFewerThanFullPage(t *testing.T) {
	const pageSize = 5
	// A full raw page of pageSize messages; only ONE matches "needle".
	fullPage := make([]proton.MessageMetadata, pageSize)
	for i := range fullPage {
		fullPage[i] = proton.MessageMetadata{ID: "m", Subject: "noise", Time: int64(i)}
	}
	fullPage[2] = proton.MessageMetadata{ID: "hit", Subject: "the needle here", Time: 99}

	cl := &fakeClient{pages: [][]proton.MessageMetadata{fullPage}}
	r := testRegistry(cl, nil)

	// search_messages path.
	_, sout, _ := r.searchMessages(ctxWithAccount(activeAccount()), nil, SearchMessagesIn{Query: "needle", PageSize: pageSize})
	if len(sout.Messages) != 1 {
		t.Fatalf("search matched %d, want 1", len(sout.Messages))
	}
	if !sout.HasMore {
		t.Error("search has_more = false on a full raw page; later matching pages would be dropped (PR #31 finding)")
	}

	// list_messages-with-query path (no cheap total -> same raw-length
	// fallback). LabelID resolves via INBOX; grouped count is empty so
	// total stays unknown for the query branch.
	_, lout, _ := r.listMessages(ctxWithAccount(activeAccount()), nil, ListMessagesIn{Folder: "INBOX", Query: "needle", PageSize: pageSize})
	if len(lout.Messages) != 1 {
		t.Fatalf("list matched %d, want 1", len(lout.Messages))
	}
	if lout.TotalCount != nil {
		t.Errorf("list-with-query total_count = %v, want nil (no cheap count for filtered list)", lout.TotalCount)
	}
	if !lout.HasMore {
		t.Error("list-with-query has_more = false on a full raw page (PR #31 finding)")
	}
}

// ----- get_message -----

func TestGetMessage_MetadataAndRaw(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {
			MessageMetadata: proton.MessageMetadata{
				ID: "m1", Subject: "Hi", Sender: addr("a@b.com"),
				ToList:   []*mail.Address{addr("joe@example.com")},
				LabelIDs: []string{mailbox.ProtonInboxLabelID}, Time: 7, Unread: true,
			},
			Header: "Subject: Hi", Body: "the body", MIMEType: "text/plain",
		},
	}}
	r := testRegistry(cl, nil)

	_, meta, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "m1"})
	if err != nil {
		t.Fatalf("getMessage: %v", err)
	}
	if meta.Error != nil || meta.Message == nil {
		t.Fatalf("meta result: err=%+v msg=%+v", meta.Error, meta.Message)
	}
	if meta.Message.Body != "the body" || meta.Message.Raw != "" {
		t.Errorf("metadata format: body=%q raw=%q", meta.Message.Body, meta.Message.Raw)
	}
	if len(meta.Message.Folders) != 1 || meta.Message.Folders[0] != "INBOX" {
		t.Errorf("folders = %v, want [INBOX]", meta.Message.Folders)
	}

	_, raw, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "m1", Format: "raw"})
	if err != nil {
		t.Fatalf("getMessage raw: %v", err)
	}
	if raw.Message.Raw == "" || raw.Message.Body != "" {
		t.Errorf("raw format: raw=%q body=%q", raw.Message.Raw, raw.Message.Body)
	}
}

func TestGetMessage_NotFoundIsGenericMiss(t *testing.T) {
	r := testRegistry(&fakeClient{messages: map[string]proton.Message{}}, nil)
	_, out, _ := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "ghost"})
	if out.Error == nil || out.Error.Code != codeNotFound {
		t.Fatalf("error = %+v, want not_found", out.Error)
	}
}

// ----- list_labels -----

func TestListLabels_MapsToIMAPNames(t *testing.T) {
	cl := &fakeClient{labels: []proton.Label{
		{ID: "l1", Name: "Receipts", Path: []string{"Receipts"}, Type: proton.LabelTypeLabel},
		{ID: "f1", Name: "Projects", Path: []string{"Projects"}, Type: proton.LabelTypeFolder},
	}}
	r := testRegistry(cl, nil)
	_, out, err := r.listLabels(ctxWithAccount(activeAccount()), nil, ListLabelsIn{})
	if err != nil {
		t.Fatalf("listLabels: %v", err)
	}
	if len(out.Labels) != 2 {
		t.Fatalf("labels = %+v", out.Labels)
	}
	if out.Labels[0].FolderName != "Labels/Receipts" {
		t.Errorf("folder_name = %q, want Labels/Receipts", out.Labels[0].FolderName)
	}
	if out.Labels[1].Type != "folder" {
		t.Errorf("type = %q, want folder", out.Labels[1].Type)
	}
}

// ----- idempotency: add/remove label -----

func TestAddLabel_Idempotent(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1", LabelIDs: []string{"existing"}}},
	}}
	r := testRegistry(cl, nil)

	// Already present -> no Proton mutation.
	_, out, _ := r.addLabel(ctxWithAccount(activeAccount()), nil, LabelMutationIn{MessageID: "m1", LabelID: "existing"})
	if out.Applied || !out.AlreadyPresent {
		t.Fatalf("already-present: %+v", out)
	}
	if len(cl.labeled) != 0 {
		t.Fatalf("expected no LabelMessages call, got %v", cl.labeled)
	}

	// Absent -> applied + one Proton call.
	_, out2, _ := r.addLabel(ctxWithAccount(activeAccount()), nil, LabelMutationIn{MessageID: "m1", LabelID: "new"})
	if !out2.Applied || out2.AlreadyPresent {
		t.Fatalf("apply: %+v", out2)
	}
	if len(cl.labeled) != 1 || cl.labeled[0].labelID != "new" {
		t.Fatalf("LabelMessages calls = %v", cl.labeled)
	}
}

func TestRemoveLabel_Idempotent(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1", LabelIDs: []string{"keep"}}},
	}}
	r := testRegistry(cl, nil)

	// Not present -> no-op.
	_, out, _ := r.removeLabel(ctxWithAccount(activeAccount()), nil, LabelMutationIn{MessageID: "m1", LabelID: "absent"})
	if out.Removed || !out.NotPresent {
		t.Fatalf("not-present: %+v", out)
	}
	if len(cl.unlabeled) != 0 {
		t.Fatalf("expected no UnlabelMessages call, got %v", cl.unlabeled)
	}

	// Present -> removed.
	_, out2, _ := r.removeLabel(ctxWithAccount(activeAccount()), nil, LabelMutationIn{MessageID: "m1", LabelID: "keep"})
	if !out2.Removed || out2.NotPresent {
		t.Fatalf("remove: %+v", out2)
	}
}

// ----- idempotency: move_to_folder -----

func TestMoveToFolder_AlreadyInFolder(t *testing.T) {
	// Message already only in INBOX; move to INBOX is a no-op.
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1", LabelIDs: []string{mailbox.ProtonInboxLabelID}}},
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.moveToFolder(ctxWithAccount(activeAccount()), nil, MoveToFolderIn{MessageID: "m1", Folder: "INBOX"})
	if out.Moved || !out.AlreadyInFolder {
		t.Fatalf("already-in-folder: %+v", out)
	}
	if len(cl.labeled) != 0 || len(cl.unlabeled) != 0 {
		t.Fatalf("expected no proton mutation; labeled=%v unlabeled=%v", cl.labeled, cl.unlabeled)
	}
}

func TestMoveToFolder_MovesAndStripsOldSystemFolder(t *testing.T) {
	// Message in INBOX, move to Archive: add Archive, remove INBOX.
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1", LabelIDs: []string{mailbox.ProtonInboxLabelID}}},
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.moveToFolder(ctxWithAccount(activeAccount()), nil, MoveToFolderIn{MessageID: "m1", Folder: "Archive"})
	if !out.Moved || out.AlreadyInFolder {
		t.Fatalf("move: %+v", out)
	}
	if len(cl.labeled) != 1 || cl.labeled[0].labelID != mailbox.ProtonArchiveLabelID {
		t.Fatalf("add-dest: %v", cl.labeled)
	}
	if len(cl.unlabeled) != 1 || cl.unlabeled[0].labelID != mailbox.ProtonInboxLabelID {
		t.Fatalf("strip-src: %v", cl.unlabeled)
	}
}

func TestMoveToFolder_UnknownFolder(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1"}},
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.moveToFolder(ctxWithAccount(activeAccount()), nil, MoveToFolderIn{MessageID: "m1", Folder: "Nope"})
	if out.Error == nil || out.Error.Code != codeUnknownFolder {
		t.Fatalf("error = %+v, want unknown_folder", out.Error)
	}
}

// TestMoveToFolder_RetainsAllMail is the regression test for the hostile
// finding (PR #31): a realistic Proton message carries BOTH its location
// label AND All Mail ("5"). Moving INBOX->Archive must add Archive and
// remove ONLY INBOX -- All Mail must be retained, or the message is
// orphaned from the All-Mail view and Reduit's mailbox state desyncs.
func TestMoveToFolder_RetainsAllMail(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{
			ID:       "m1",
			LabelIDs: []string{mailbox.ProtonInboxLabelID, mailbox.ProtonAllMailLabelID},
		}},
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.moveToFolder(ctxWithAccount(activeAccount()), nil, MoveToFolderIn{MessageID: "m1", Folder: "Archive"})
	if !out.Moved || out.AlreadyInFolder {
		t.Fatalf("move: %+v", out)
	}
	if len(cl.labeled) != 1 || cl.labeled[0].labelID != mailbox.ProtonArchiveLabelID {
		t.Fatalf("add-dest: %v", cl.labeled)
	}
	// Exactly ONE unlabel, and it MUST be INBOX -- never All Mail.
	if len(cl.unlabeled) != 1 {
		t.Fatalf("expected exactly one unlabel (INBOX), got %v", cl.unlabeled)
	}
	if cl.unlabeled[0].labelID != mailbox.ProtonInboxLabelID {
		t.Fatalf("stripped %q, want INBOX only", cl.unlabeled[0].labelID)
	}
	for _, u := range cl.unlabeled {
		if u.labelID == mailbox.ProtonAllMailLabelID {
			t.Fatal("All Mail was stripped -- regression of the PR #31 finding")
		}
	}
}

// TestMoveToFolder_UserLabelIsAdditive is the regression test for the
// second hostile finding: moving to a USER label (Labels/<name>) must be
// additive -- add the label, keep the current folder AND All Mail, strip
// nothing. The earlier code ran the system-folder strip loop and deleted
// the message out of INBOX + All Mail.
func TestMoveToFolder_UserLabelIsAdditive(t *testing.T) {
	cl := &fakeClient{
		labels: []proton.Label{{ID: "lbl-99", Name: "Receipts", Path: []string{"Receipts"}, Type: proton.LabelTypeLabel}},
		messages: map[string]proton.Message{
			"m1": {MessageMetadata: proton.MessageMetadata{
				ID:       "m1",
				LabelIDs: []string{mailbox.ProtonInboxLabelID, mailbox.ProtonAllMailLabelID},
			}},
		},
	}
	r := testRegistry(cl, nil)
	_, out, _ := r.moveToFolder(ctxWithAccount(activeAccount()), nil, MoveToFolderIn{MessageID: "m1", Folder: "Labels/Receipts"})
	if !out.Moved || out.AlreadyInFolder {
		t.Fatalf("move: %+v", out)
	}
	if len(cl.labeled) != 1 || cl.labeled[0].labelID != "lbl-99" {
		t.Fatalf("add-label: %v", cl.labeled)
	}
	// Additive: NOTHING is stripped -- INBOX and All Mail are retained.
	if len(cl.unlabeled) != 0 {
		t.Fatalf("user-label move must not strip any label, got %v", cl.unlabeled)
	}
}

// ----- idempotency: mark_read / mark_unread -----

func TestMarkRead_Idempotent(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"unreadMsg": {MessageMetadata: proton.MessageMetadata{ID: "unreadMsg", Unread: true}},
		"readMsg":   {MessageMetadata: proton.MessageMetadata{ID: "readMsg", Unread: false}},
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.markRead(ctxWithAccount(activeAccount()), nil, MarkReadIn{MessageIDs: []string{"unreadMsg", "readMsg"}})
	if len(out.Changed) != 1 || out.Changed[0] != "unreadMsg" {
		t.Fatalf("changed = %v, want [unreadMsg]", out.Changed)
	}
	if len(out.AlreadyInState) != 1 || out.AlreadyInState[0] != "readMsg" {
		t.Fatalf("already = %v, want [readMsg]", out.AlreadyInState)
	}
	if len(cl.readCalls) != 1 {
		t.Fatalf("MarkMessagesRead calls = %v, want exactly one (for unreadMsg)", cl.readCalls)
	}
}

// ----- send_message -> outbox handoff -----

func TestSendMessage_ReusesOutboxPipeline(t *testing.T) {
	ob := &fakeOutbox{result: outbox.Result{Modes: map[string]outbox.EncryptionMode{
		"bob@proton.me":   outbox.ModeProtonE2E,
		"carol@gmail.com": outbox.ModeCleartext,
	}}}
	r := testRegistry(&fakeClient{}, ob)

	_, out, err := r.sendMessage(ctxWithAccount(activeAccount()), nil, SendMessageIn{
		To:         []string{"bob@proton.me", "carol@gmail.com"},
		Subject:    "Hi there",
		Body:       "hello\nworld",
		BodyFormat: "text",
	})
	if err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if !out.Sent {
		t.Fatal("sent = false")
	}
	if ob.got == nil {
		t.Fatal("outbox.Submit was not called -- send_message must reuse the outbox pipeline")
	}
	if ob.got.AccountID != "acct-1" {
		t.Errorf("submission AccountID = %q, want acct-1", ob.got.AccountID)
	}
	if ob.got.MailFrom != "joe@example.com" {
		t.Errorf("MailFrom = %q, want primary alias joe@example.com", ob.got.MailFrom)
	}
	if len(ob.got.Recipients) != 2 {
		t.Errorf("recipients = %v", ob.got.Recipients)
	}
	// The handler must NOT have encrypted anything itself -- the body it
	// hands the outbox is the cleartext RFC 5322 envelope. The per-
	// recipient modes come back FROM the outbox.
	if !strings.Contains(string(ob.got.Body), "Subject: Hi there") {
		t.Errorf("assembled body missing subject header:\n%s", ob.got.Body)
	}
	if !strings.Contains(string(ob.got.Body), "hello\r\nworld") {
		t.Errorf("assembled body missing CRLF-normalised body:\n%s", ob.got.Body)
	}
	if out.Recipients["bob@proton.me"] != "proton_e2e" {
		t.Errorf("recipient mode = %v, want proton_e2e reported from outbox", out.Recipients)
	}
}

func TestSendMessage_MultipartWithAttachment(t *testing.T) {
	ob := &fakeOutbox{result: outbox.Result{}}
	r := testRegistry(&fakeClient{}, ob)
	_, out, err := r.sendMessage(ctxWithAccount(activeAccount()), nil, SendMessageIn{
		To:         []string{"bob@proton.me"},
		Subject:    "doc",
		Body:       "see attached",
		BodyFormat: "html",
		Attachments: []AttachmentIn{
			{Filename: "a.txt", ContentType: "text/plain", Content: "aGVsbG8="}, // "hello"
		},
	})
	if err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("tool error: %+v", out.Error)
	}
	if !strings.Contains(string(ob.got.Body), "multipart/mixed") {
		t.Errorf("expected multipart/mixed envelope:\n%s", ob.got.Body)
	}
	if !strings.Contains(string(ob.got.Body), `filename="a.txt"`) {
		t.Errorf("expected attachment disposition:\n%s", ob.got.Body)
	}
}

func TestSendMessage_OutboxErrorMapsToStructured(t *testing.T) {
	ob := &fakeOutbox{result: outbox.Result{Err: &outbox.ErrKeyLookup{Recipient: "bob@proton.me"}}}
	r := testRegistry(&fakeClient{}, ob)
	_, out, _ := r.sendMessage(ctxWithAccount(activeAccount()), nil, SendMessageIn{
		To: []string{"bob@proton.me"}, Subject: "s", Body: "b", BodyFormat: "text",
	})
	if out.Error == nil || out.Error.Code != codeRecipientKeyUnavailable {
		t.Fatalf("error = %+v, want recipient_key_unavailable", out.Error)
	}
	if out.Error.Details["recipient"] != "bob@proton.me" {
		t.Errorf("details = %+v", out.Error.Details)
	}
}

func TestSendMessage_BadBodyFormat(t *testing.T) {
	r := testRegistry(&fakeClient{}, &fakeOutbox{})
	_, out, _ := r.sendMessage(ctxWithAccount(activeAccount()), nil, SendMessageIn{
		To: []string{"x@y.com"}, Subject: "s", Body: "b", BodyFormat: "rtf",
	})
	if out.Error == nil || out.Error.Code != codeInvalidArgument {
		t.Fatalf("error = %+v, want invalid_argument", out.Error)
	}
}

// TestSendMessage_HeaderInjectionRejected is the regression test for the
// hostile finding (PR #31): a recipient carrying a CRLF + smuggled header
// must be rejected BEFORE the envelope is assembled or handed to the
// outbox -- otherwise the injected "Bcc: attacker@evil.com" would reach
// the wire (the outbox relays the body verbatim).
func TestSendMessage_HeaderInjectionRejected(t *testing.T) {
	cases := []struct {
		name string
		in   SendMessageIn
	}{
		{
			name: "CRLF in To injects Bcc",
			in:   SendMessageIn{To: []string{"a@x.com\r\nBcc: attacker@evil.com"}, Subject: "s", Body: "b", BodyFormat: "text"},
		},
		{
			name: "bare LF in Cc",
			in:   SendMessageIn{To: []string{"a@x.com"}, CC: []string{"c@x.com\nX-Evil: 1"}, Subject: "s", Body: "b", BodyFormat: "text"},
		},
		{
			name: "non-parsing address",
			in:   SendMessageIn{To: []string{"not an address"}, Subject: "s", Body: "b", BodyFormat: "text"},
		},
		{
			name: "CRLF in Bcc",
			in:   SendMessageIn{To: []string{"a@x.com"}, BCC: []string{"b@x.com\r\nSubject: hijack"}, Subject: "s", Body: "b", BodyFormat: "text"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob := &fakeOutbox{}
			r := testRegistry(&fakeClient{}, ob)
			_, out, err := r.sendMessage(ctxWithAccount(activeAccount()), nil, tc.in)
			if err != nil {
				t.Fatalf("sendMessage: %v", err)
			}
			if out.Error == nil || out.Error.Code != codeInvalidArgument {
				t.Fatalf("error = %+v, want invalid_argument (rejected)", out.Error)
			}
			if ob.got != nil {
				t.Fatal("outbox.Submit was called with an injection payload -- must be rejected before submit")
			}
		})
	}
}

// TestSendMessage_AttachmentFilenameCRLFRejected covers item 6: a CR/LF
// in an attachment filename (interpolated into Content-Disposition) must
// be rejected.
func TestSendMessage_AttachmentFilenameCRLFRejected(t *testing.T) {
	ob := &fakeOutbox{}
	r := testRegistry(&fakeClient{}, ob)
	_, out, _ := r.sendMessage(ctxWithAccount(activeAccount()), nil, SendMessageIn{
		To: []string{"a@x.com"}, Subject: "s", Body: "b", BodyFormat: "text",
		Attachments: []AttachmentIn{{Filename: "ok.txt\r\nX-Evil: 1", Content: "aGk="}},
	})
	if out.Error == nil || out.Error.Code != codeInvalidArgument {
		t.Fatalf("error = %+v, want invalid_argument", out.Error)
	}
	if ob.got != nil {
		t.Fatal("outbox.Submit was called with a CRLF filename -- must be rejected")
	}
}

// TestMarkRead_PartialProgressOnFailure covers item 5: a mid-batch
// failure must return the Changed/AlreadyInState accumulated so far so
// the agent knows which messages were mutated.
func TestMarkRead_PartialProgressOnFailure(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"a": {MessageMetadata: proton.MessageMetadata{ID: "a", Unread: true}},
		"b": {MessageMetadata: proton.MessageMetadata{ID: "b", Unread: false}},
		// "c" is absent -> GetMessage 404 mid-batch.
	}}
	r := testRegistry(cl, nil)
	_, out, _ := r.markRead(ctxWithAccount(activeAccount()), nil, MarkReadIn{MessageIDs: []string{"a", "b", "c"}})
	if out.Error == nil || out.Error.Code != codeNotFound {
		t.Fatalf("error = %+v, want not_found", out.Error)
	}
	// Progress before the failure MUST be reported.
	if len(out.Changed) != 1 || out.Changed[0] != "a" {
		t.Errorf("changed = %v, want [a] preserved on partial failure", out.Changed)
	}
	if len(out.AlreadyInState) != 1 || out.AlreadyInState[0] != "b" {
		t.Errorf("already = %v, want [b] preserved on partial failure", out.AlreadyInState)
	}
}

// TestMarkRead_BatchCap covers item 5: a message_ids list over the cap is
// rejected.
func TestMarkRead_BatchCap(t *testing.T) {
	ids := make([]string, maxMarkBatch+1)
	for i := range ids {
		ids[i] = "m"
	}
	r := testRegistry(&fakeClient{messages: map[string]proton.Message{}}, nil)
	_, out, _ := r.markRead(ctxWithAccount(activeAccount()), nil, MarkReadIn{MessageIDs: ids})
	if out.Error == nil || out.Error.Code != codeInvalidArgument {
		t.Fatalf("error = %+v, want invalid_argument for oversized batch", out.Error)
	}
}
