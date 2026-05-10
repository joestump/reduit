package mcpserver_test

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/mcpserver"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// migrateMu serializes calls to store.Migrate across parallel tests in
// this package -- goose's package-level config is global state, same
// reason internal/mailbox tests serialize.
var migrateMu sync.Mutex

// newToolsFixture spins up a fresh SQLite store, runs migrations, seeds
// one account, and returns a ToolDeps wired to a stub Proton client.
// Tests then drive each tool handler via the package-internal entry
// points (exposed by export_test.go) with a context that carries the
// seeded account.
func newToolsFixture(t *testing.T) (*toolsFixture, mcpserver.ToolDeps) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reduit-mcp-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const acctID = "acct-mcp-tools"
	storetest.SeedUserAccountActive(t, st, acctID)

	svc := mailbox.New(st)
	stub := &stubProtonClient{}

	td := mcpserver.ToolDeps{
		Mailboxes: svc,
		ProtonForAccount: func(_ context.Context, _ *account.Account) (proton.Client, error) {
			return stub, nil
		},
	}
	f := &toolsFixture{
		st:     st,
		svc:    svc,
		acctID: acctID,
		stub:   stub,
	}
	return f, td
}

type toolsFixture struct {
	st     *store.Store
	svc    mailbox.Service
	acctID string
	stub   *stubProtonClient
}

// ctx returns a background context with the fixture's seeded account
// stamped in the position the auth middleware would have stamped it.
func (f *toolsFixture) ctx() context.Context {
	return mcpserver.WithAccount(context.Background(),
		&account.Account{ID: f.acctID, State: account.StateActive})
}

// seedMailbox provisions a mailbox row for (folder) and returns it.
func (f *toolsFixture) seedMailbox(t *testing.T, folder, protonLabelID string, kind mailbox.Kind) *mailbox.Mailbox {
	t.Helper()
	mb, err := f.svc.EnsureMailbox(context.Background(), f.acctID, folder, protonLabelID, kind)
	if err != nil {
		t.Fatalf("EnsureMailbox(%q): %v", folder, err)
	}
	return mb
}

// seedMessages inserts n messages into the supplied mailbox with
// monotonically increasing UIDs. Subjects are formatted "msg-%d" so
// tests can assert on ordering.
func (f *toolsFixture) seedMessages(t *testing.T, mb *mailbox.Mailbox, n int) []int64 {
	t.Helper()
	out := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		mid, err := f.svc.UpsertMessage(context.Background(), &mailbox.Message{
			AccountID:       f.acctID,
			ProtonMessageID: fmt.Sprintf("proton-%s-%03d", mb.Name, i),
			Subject:         fmt.Sprintf("msg-%03d", i),
			Sender:          "alice@example.com",
			RFC822Size:      int64(1024 + i),
			InternalDate:    time.Now().UTC().Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("UpsertMessage(%d): %v", i, err)
		}
		if _, err := f.svc.AssignUID(context.Background(), f.acctID, mb.ID, mid); err != nil {
			t.Fatalf("AssignUID(%d): %v", i, err)
		}
		out = append(out, mid)
	}
	return out
}

// stubProtonClient implements just enough of proton.Client for the
// read-tools tests. Each method routes through a configurable hook so
// tests can pin the per-call shape.
type stubProtonClient struct {
	getMessageFn  func(ctx context.Context, id string) (proton.Message, error)
	listMessageFn func(ctx context.Context, f proton.MessageFilter) ([]proton.MessageMetadata, error)
}

func (s *stubProtonClient) GetMessage(ctx context.Context, id string) (proton.Message, error) {
	if s.getMessageFn != nil {
		return s.getMessageFn(ctx, id)
	}
	return proton.Message{}, errors.New("stubProtonClient: GetMessage not configured")
}

func (s *stubProtonClient) ListMessages(ctx context.Context, f proton.MessageFilter) ([]proton.MessageMetadata, error) {
	if s.listMessageFn != nil {
		return s.listMessageFn(ctx, f)
	}
	return nil, errors.New("stubProtonClient: ListMessages not configured")
}

// Methods we don't exercise in this test file panic so a future test
// reaching for one fails loudly.
func (s *stubProtonClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	panic("stubProtonClient.AuthInfo: unused")
}
func (s *stubProtonClient) AuthTOTP(context.Context, string) error {
	panic("stubProtonClient.AuthTOTP: unused")
}
func (s *stubProtonClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	panic("stubProtonClient.AuthFIDO2: unused")
}
func (s *stubProtonClient) KeySalts(context.Context) (proton.Salts, error) {
	panic("stubProtonClient.KeySalts: unused")
}
func (s *stubProtonClient) GetUser(context.Context) (proton.User, error) {
	panic("stubProtonClient.GetUser: unused")
}
func (s *stubProtonClient) GetAddresses(context.Context) ([]proton.Address, error) {
	panic("stubProtonClient.GetAddresses: unused")
}
func (s *stubProtonClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	panic("stubProtonClient.Unlock: unused")
}
func (s *stubProtonClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	panic("stubProtonClient.GetEvent: unused")
}
func (s *stubProtonClient) GetLatestEventID(context.Context) (string, error) {
	panic("stubProtonClient.GetLatestEventID: unused")
}
func (s *stubProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("stubProtonClient.SendDraft: unused")
}
func (s *stubProtonClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	panic("stubProtonClient.GetPublicKeys: unused")
}
func (s *stubProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("stubProtonClient.GetAttachment: unused")
}
func (s *stubProtonClient) LabelMessages(context.Context, []string, string) error {
	panic("stubProtonClient.LabelMessages: unused")
}
func (s *stubProtonClient) UnlabelMessages(context.Context, []string, string) error {
	panic("stubProtonClient.UnlabelMessages: unused")
}
func (s *stubProtonClient) Logout(context.Context) error {
	panic("stubProtonClient.Logout: unused")
}
func (s *stubProtonClient) LatestRefreshToken() string {
	panic("stubProtonClient.LatestRefreshToken: unused")
}

// --- list_messages tests ---

// TestListMessages_HappyPath confirms a list call returns the seeded
// messages with pagination metadata defaulting to page=1, page_size=50.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (list_messages).
func TestListMessages_HappyPath(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 3)

	out, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if got := len(out.Messages); got != 3 {
		t.Errorf("len(messages) = %d, want 3", got)
	}
	if out.Page != 1 {
		t.Errorf("Page = %d, want 1", out.Page)
	}
	if out.PageSize != mcpserver.DefaultPageSize {
		t.Errorf("PageSize = %d, want default %d", out.PageSize, mcpserver.DefaultPageSize)
	}
	if out.HasMore {
		t.Errorf("HasMore = true, want false (3 rows < page_size)")
	}
	if out.TotalCount == nil || *out.TotalCount != 3 {
		t.Errorf("TotalCount = %v, want 3", out.TotalCount)
	}
	if !out.TotalCountKnown {
		t.Errorf("TotalCountKnown = false, want true")
	}
}

// TestListMessages_PageSizeDefault covers SPEC-0006 REQ "Pagination on
// List and Search" Scenario "Default and max page_size": omitted
// page_size MUST default to 50.
func TestListMessages_PageSizeDefault(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 60)

	out, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if out.PageSize != 50 {
		t.Errorf("PageSize = %d, want 50 (default)", out.PageSize)
	}
	if got := len(out.Messages); got != 50 {
		t.Errorf("len(messages) = %d, want 50", got)
	}
	if !out.HasMore {
		t.Errorf("HasMore = false, want true (60 > 50)")
	}
	if out.Clamped {
		t.Errorf("Clamped = true, want false (no clamp at default)")
	}
}

// TestListMessages_PageSizeClamp covers SPEC-0006 REQ "Pagination on
// List and Search" Scenario "Default and max page_size":
// page_size > 200 MUST be clamped to 200 with clamped: true in metadata.
func TestListMessages_PageSizeClamp(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 5)

	out, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{
		Folder:   "INBOX",
		PageSize: 9999,
	})
	if err != nil {
		t.Fatalf("listMessages: %v", err)
	}
	if out.PageSize != mcpserver.MaxPageSize {
		t.Errorf("PageSize = %d, want %d (clamp)", out.PageSize, mcpserver.MaxPageSize)
	}
	if !out.Clamped {
		t.Errorf("Clamped = false, want true")
	}
}

// TestListMessages_HasMore covers SPEC-0006 REQ "Pagination on List
// and Search" Scenario "Pagination metadata included": has_more is
// true when more pages exist, false on the last page.
func TestListMessages_HasMore(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 5)

	// Page 1 of 2 (page_size=2 -> rows 0..1, 4 more).
	page1, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{
		Folder:   "INBOX",
		Page:     1,
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if !page1.HasMore {
		t.Errorf("page 1 HasMore = false, want true")
	}
	if got := len(page1.Messages); got != 2 {
		t.Errorf("page 1 len = %d, want 2", got)
	}

	// Page 3: rows 4..4 (one row), no more.
	page3, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{
		Folder:   "INBOX",
		Page:     3,
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if page3.HasMore {
		t.Errorf("page 3 HasMore = true, want false")
	}
	if got := len(page3.Messages); got != 1 {
		t.Errorf("page 3 len = %d, want 1", got)
	}
}

// TestListMessages_UnknownFolder covers SPEC-0006 REQ "Folder Names
// Match IMAP Mapping" Scenario "Unknown folder name yields a clear
// error".
func TestListMessages_UnknownFolder(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	_, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: "NotARealFolder"})
	if err == nil {
		t.Fatalf("listMessages(unknown folder): want error, got nil")
	}
	if msg := err.Error(); msg != "unknown_folder: Folder NotARealFolder does not exist" {
		t.Errorf("error = %q, want unknown_folder", msg)
	}
}

// TestListMessages_LabelsFolder covers SPEC-0006 REQ "Folder Names
// Match IMAP Mapping" Scenario "Symbolic folder names are accepted":
// `Labels/Receipts` resolves through the shared FolderResolver
// (mailbox.ClassifyName).
func TestListMessages_LabelsFolder(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "Labels/Receipts", "user-receipts", mailbox.KindUserLabel)
	f.seedMessages(t, mb, 2)

	out, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: "Labels/Receipts"})
	if err != nil {
		t.Fatalf("listMessages(Labels/Receipts): %v", err)
	}
	if got := len(out.Messages); got != 2 {
		t.Errorf("len = %d, want 2", got)
	}
}

// TestListMessages_EmptyFolder covers the "valid folder, no messages
// yet" path: should return an empty page with total_count=0, not an
// unknown_folder error.
func TestListMessages_EmptyFolder(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	// No seeding -- INBOX classifies but has no mailbox row.

	out, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("listMessages(empty): %v", err)
	}
	if got := len(out.Messages); got != 0 {
		t.Errorf("len = %d, want 0", got)
	}
	if out.TotalCount == nil || *out.TotalCount != 0 {
		t.Errorf("TotalCount = %v, want 0", out.TotalCount)
	}
}

// TestListMessages_FolderResolverParity is the literal "same string
// resolves identically in IMAP and MCP code paths" test. We pin the
// shared mailbox.ClassifyName helper as the single resolver used by
// both surfaces; the IMAP backend's mailbox.go and this MCP file both
// call it, so a parity test means asserting that the same input
// produces the same kind+ref triple regardless of which surface
// invokes it.
//
// Governing: SPEC-0006 REQ "Folder Names Match IMAP Mapping",
// SPEC-0003 REQ "Folder Hierarchy and Mapping".
func TestListMessages_FolderResolverParity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		folder    string
		wantKind  mailbox.Kind
		wantRef   string
		wantMatch bool
	}{
		{"inbox", "INBOX", mailbox.KindSystem, mailbox.ProtonInboxLabelID, true},
		{"sent", "Sent", mailbox.KindSystem, mailbox.ProtonSentLabelID, true},
		{"trash", "Trash", mailbox.KindSystem, mailbox.ProtonTrashLabelID, true},
		{"all_mail", "All Mail", mailbox.KindSystem, mailbox.ProtonAllMailLabelID, true},
		{"user_label", "Labels/Receipts", mailbox.KindUserLabel, "Receipts", true},
		{"nested_user_label", "Labels/Family/Tax", mailbox.KindUserLabel, "Family/Tax", true},
		{"unknown", "NotAFolder", "", "", false},
		{"labels_root", "Labels/", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// IMAP and MCP both call mailbox.ClassifyName; the test
			// pins this shared resolver as the single source of
			// truth. The IMAP backend also consumes ClassifyName
			// (see internal/imapserver/session.go's Move handler);
			// keeping the call sites converged on one helper is
			// the parity guarantee.
			kind, ref, ok := mailbox.ClassifyName(tc.folder)
			if ok != tc.wantMatch {
				t.Errorf("ClassifyName(%q) ok=%v, want %v", tc.folder, ok, tc.wantMatch)
			}
			if !ok {
				return
			}
			if kind != tc.wantKind {
				t.Errorf("ClassifyName(%q) kind=%q, want %q", tc.folder, kind, tc.wantKind)
			}
			if ref != tc.wantRef {
				t.Errorf("ClassifyName(%q) ref=%q, want %q", tc.folder, ref, tc.wantRef)
			}
		})
	}
}

// TestListMessages_MissingFolderArg covers the input-validation path:
// an empty folder string MUST be rejected with invalid_argument.
func TestListMessages_MissingFolderArg(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	_, err := mcpserver.CallListMessages(f.ctx(), td, mcpserver.ListMessagesIn{Folder: ""})
	if err == nil || err.Error() != "invalid_argument: folder is required" {
		t.Errorf("err = %v, want invalid_argument", err)
	}
}

// TestListMessages_NoAccount is the defense-in-depth test: a context
// without an account stamped MUST surface unauthenticated, not panic.
func TestListMessages_NoAccount(t *testing.T) {
	t.Parallel()
	_, td := newToolsFixture(t)

	_, err := mcpserver.CallListMessages(context.Background(), td, mcpserver.ListMessagesIn{Folder: "INBOX"})
	if err == nil {
		t.Fatalf("expected unauthenticated error, got nil")
	}
	if err.Error() != "unauthenticated: no account on context" {
		t.Errorf("err = %v, want unauthenticated", err)
	}
}

// --- get_message tests ---

// TestGetMessage_HappyPath covers the metadata-format path: a seeded
// message resolves through the local store first (account scope),
// then through the proton.Client.
func TestGetMessage_HappyPath(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 1)
	mid := "proton-INBOX-000"

	f.stub.getMessageFn = func(_ context.Context, id string) (proton.Message, error) {
		if id != mid {
			t.Errorf("GetMessage id = %q, want %q", id, mid)
		}
		return proton.Message{
			MessageMetadata: proton.MessageMetadata{
				ID:      mid,
				Subject: "hello",
				Sender:  &mail.Address{Address: "alice@example.com"},
				ToList:  []*mail.Address{{Address: "bob@example.com"}},
				Time:    time.Now().Unix(),
				Size:    1234,
			},
			Body:     "body bytes",
			MIMEType: "text/plain",
		}, nil
	}

	out, err := mcpserver.CallGetMessage(f.ctx(), td, mcpserver.GetMessageIn{MessageID: mid})
	if err != nil {
		t.Fatalf("getMessage: %v", err)
	}
	if out.ID != mid {
		t.Errorf("ID = %q, want %q", out.ID, mid)
	}
	if out.Body != "body bytes" {
		t.Errorf("Body = %q, want body bytes", out.Body)
	}
	if len(out.To) != 1 || out.To[0] != "bob@example.com" {
		t.Errorf("To = %v, want [bob@example.com]", out.To)
	}
	if out.MIMEType != "text/plain" {
		t.Errorf("MIMEType = %q, want text/plain", out.MIMEType)
	}
}

// TestGetMessage_NotFound covers SPEC-0006 REQ "Account Scope on All
// Operations" Scenario "Message lookup filters by account_id": a
// message ID belonging to another account (or no account) surfaces as
// not_found, identical to a genuine miss.
func TestGetMessage_NotFound(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	_, err := mcpserver.CallGetMessage(f.ctx(), td, mcpserver.GetMessageIn{MessageID: "no-such-id"})
	if err == nil {
		t.Fatalf("expected not_found, got nil")
	}
	if err.Error() != "not_found: message no-such-id not found" {
		t.Errorf("err = %v, want not_found", err)
	}
}

// TestGetMessage_RawNotImplemented covers the streaming-deferral
// contract: format=raw MUST surface a not_implemented error pointing
// callers at the streaming tool (issue #30) until that lands.
func TestGetMessage_RawNotImplemented(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	mb := f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	f.seedMessages(t, mb, 1)

	_, err := mcpserver.CallGetMessage(f.ctx(), td, mcpserver.GetMessageIn{
		MessageID: "proton-INBOX-000",
		Format:    "raw",
	})
	if err == nil {
		t.Fatalf("expected not_implemented, got nil")
	}
	if err.Error() != "not_implemented: raw body streaming is provided by the streaming get_message tool (issue #30)" {
		t.Errorf("err = %v, want not_implemented", err)
	}
}

// TestGetMessage_InvalidFormat covers the input-validation path on the
// format field.
func TestGetMessage_InvalidFormat(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	_, err := mcpserver.CallGetMessage(f.ctx(), td, mcpserver.GetMessageIn{
		MessageID: "anything",
		Format:    "fancy",
	})
	if err == nil || err.Error() != "invalid_argument: format must be 'metadata' or 'raw'" {
		t.Errorf("err = %v, want invalid_argument", err)
	}
}

// --- search_messages tests ---

// TestSearchMessages_HappyPath confirms that search_messages proxies
// through to the proton.Client and applies pagination locally.
func TestSearchMessages_HappyPath(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	f.stub.listMessageFn = func(_ context.Context, _ proton.MessageFilter) ([]proton.MessageMetadata, error) {
		out := make([]proton.MessageMetadata, 0, 5)
		for i := 0; i < 5; i++ {
			out = append(out, proton.MessageMetadata{
				ID:      fmt.Sprintf("hit-%d", i),
				Subject: fmt.Sprintf("found-%d", i),
				Sender:  &mail.Address{Address: "alice@example.com"},
				Time:    time.Now().Unix(),
				Size:    1024,
			})
		}
		return out, nil
	}

	out, err := mcpserver.CallSearchMessages(f.ctx(), td, mcpserver.SearchMessagesIn{Query: "found"})
	if err != nil {
		t.Fatalf("searchMessages: %v", err)
	}
	if got := len(out.Messages); got != 5 {
		t.Errorf("len = %d, want 5", got)
	}
	if out.TotalCountKnown {
		t.Errorf("TotalCountKnown = true, want false (proton search has no cheap total)")
	}
	if out.TotalCount != nil {
		t.Errorf("TotalCount = %v, want nil (unknown)", out.TotalCount)
	}
	if out.PageSize != mcpserver.DefaultPageSize {
		t.Errorf("PageSize = %d, want default %d", out.PageSize, mcpserver.DefaultPageSize)
	}
}

// TestSearchMessages_PageSizeClamp pins the same SPEC-0006 clamp
// behaviour as list_messages.
func TestSearchMessages_PageSizeClamp(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	f.stub.listMessageFn = func(_ context.Context, _ proton.MessageFilter) ([]proton.MessageMetadata, error) {
		return nil, nil
	}

	out, err := mcpserver.CallSearchMessages(f.ctx(), td, mcpserver.SearchMessagesIn{
		Query:    "anything",
		PageSize: 9999,
	})
	if err != nil {
		t.Fatalf("searchMessages: %v", err)
	}
	if out.PageSize != mcpserver.MaxPageSize {
		t.Errorf("PageSize = %d, want %d (clamp)", out.PageSize, mcpserver.MaxPageSize)
	}
	if !out.Clamped {
		t.Errorf("Clamped = false, want true")
	}
}

// TestSearchMessages_EmptyQuery covers the input-validation path.
func TestSearchMessages_EmptyQuery(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)

	_, err := mcpserver.CallSearchMessages(f.ctx(), td, mcpserver.SearchMessagesIn{Query: "  "})
	if err == nil || err.Error() != "invalid_argument: query is required" {
		t.Errorf("err = %v, want invalid_argument", err)
	}
}

// TestSearchMessages_HasMore confirms that pagination across two pages
// behaves correctly.
func TestSearchMessages_HasMore(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	f.stub.listMessageFn = func(_ context.Context, _ proton.MessageFilter) ([]proton.MessageMetadata, error) {
		out := make([]proton.MessageMetadata, 0, 5)
		for i := 0; i < 5; i++ {
			out = append(out, proton.MessageMetadata{
				ID:      fmt.Sprintf("hit-%d", i),
				Subject: fmt.Sprintf("found-%d", i),
				Sender:  &mail.Address{Address: "alice@example.com"},
				Time:    time.Now().Unix(),
			})
		}
		return out, nil
	}

	out, err := mcpserver.CallSearchMessages(f.ctx(), td, mcpserver.SearchMessagesIn{
		Query:    "found",
		Page:     1,
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("searchMessages: %v", err)
	}
	if !out.HasMore {
		t.Errorf("HasMore = false, want true")
	}
	if got := len(out.Messages); got != 2 {
		t.Errorf("len = %d, want 2", got)
	}
}

// --- list_labels tests ---

// TestListLabels_HappyPath confirms the system folders are always
// returned, plus any user labels the local store has materialised.
func TestListLabels_HappyPath(t *testing.T) {
	t.Parallel()
	f, td := newToolsFixture(t)
	// Seed two user labels and one system folder. The system
	// folder set is constant; the user labels surface only after
	// the sync worker has materialised them locally.
	f.seedMailbox(t, "Labels/Receipts", "user-receipts", mailbox.KindUserLabel)
	f.seedMailbox(t, "Labels/Family/Tax", "user-family-tax", mailbox.KindUserLabel)
	f.seedMailbox(t, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)

	out, err := mcpserver.CallListLabels(f.ctx(), td, mcpserver.ListLabelsIn{})
	if err != nil {
		t.Fatalf("listLabels: %v", err)
	}

	systemNames := map[string]bool{}
	userNames := map[string]bool{}
	for _, l := range out.Labels {
		switch l.Kind {
		case string(mailbox.KindSystem):
			systemNames[l.Name] = true
		case string(mailbox.KindUserLabel):
			userNames[l.Name] = true
		}
	}
	// All seven system folders MUST be present.
	for _, want := range []string{"INBOX", "Sent", "Drafts", "Trash", "Spam", "Archive", "All Mail"} {
		if !systemNames[want] {
			t.Errorf("system folder %q missing from list_labels output", want)
		}
	}
	// User labels in alphabetical order.
	if !userNames["Labels/Family/Tax"] || !userNames["Labels/Receipts"] {
		t.Errorf("user labels missing: got %v", userNames)
	}
}

// TestListLabels_NoAccount confirms the defense-in-depth path.
func TestListLabels_NoAccount(t *testing.T) {
	t.Parallel()
	_, td := newToolsFixture(t)

	_, err := mcpserver.CallListLabels(context.Background(), td, mcpserver.ListLabelsIn{})
	if err == nil || err.Error() != "unauthenticated: no account on context" {
		t.Errorf("err = %v, want unauthenticated", err)
	}
}

// TestRegisterReadTools_PanicsOnNilDeps covers the boot-path safety net.
func TestRegisterReadTools_PanicsOnNilDeps(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil ToolDeps.Mailboxes, got none")
		}
	}()
	// nil ProtonForAccount triggers validate(); panic is the
	// expected operator-actionable failure mode.
	mcpserver.RegisterReadTools(nil, mcpserver.ToolDeps{})
}

// TestRegisterReadTools_ToolsListReflectsRequiredSet covers SPEC-0006
// REQ "Required Tool Set" Scenario "Tool listing reflects the
// required set": an MCP `tools/list` MUST include the four read-side
// tools by name with their JSON schemas.
//
// Drives the real MCP SDK over an in-memory transport pair so the
// registration call site, schema inference, and `tools/list`
// dispatch are all exercised end-to-end.
func TestRegisterReadTools_ToolsListReflectsRequiredSet(t *testing.T) {
	t.Parallel()
	_, td := newToolsFixture(t)

	srv := mcp.NewServer(&mcp.Implementation{Name: "reduit-test", Version: "v0.0.0"}, nil)
	mcpserver.RegisterReadTools(srv, td)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()
	cl := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.0"}, nil)
	cs, err := cl.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tt := range res.Tools {
		got[tt.Name] = true
		if tt.InputSchema == nil {
			t.Errorf("tool %q has nil InputSchema; spec requires JSON schema for inputs", tt.Name)
		}
	}
	for _, want := range []string{"list_messages", "get_message", "search_messages", "list_labels"} {
		if !got[want] {
			t.Errorf("tools/list missing %q; got %v", want, got)
		}
	}
}
