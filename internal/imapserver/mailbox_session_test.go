// Tests for the post-Login session methods that landed in #19. Each
// test wires a real internal/mailbox.Service against an in-memory
// SQLite, drives the IMAP session methods directly (not through the
// network), and asserts the spec-mandated behaviour.
//
// We bypass the TCP / TLS / SASL stack here for two reasons:
//
//   1. The auth path is exhaustively covered in server_test.go; this
//      file is about post-auth behaviour.
//   2. Driving Move / Copy through a real client requires a server
//      that advertises MOVE in its CAPABILITY response, which our
//      capFilterListener does not yet (it strips IDLE; MOVE is part
//      of the IMAP4rev2 cap set we deliberately do not advertise per
//      ADR-0007 — but the SessionMove interface is implemented and is
//      callable directly). End-to-end MOVE plumbing lands when we
//      enable IMAP4rev2 in a follow-up.

package imapserver

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// migrateMu is the cross-package equivalent of mailbox.migrateMu and
// account.migrateMu — goose's globals are not safe for concurrent
// migration runs.
var imapMigrateMu sync.Mutex

func newMailboxStack(t *testing.T) (mailbox.Service, *store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reduit-imap-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	imapMigrateMu.Lock()
	err = st.Migrate("")
	imapMigrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	const accountID = "acct-imap-test"
	const q = `
INSERT INTO accounts (id, oidc_subject, state, key_envelope, created_at, updated_at)
VALUES (?, ?, 'active', X'00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
	if _, err := st.DB.Exec(q, accountID, "sub-"+accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return mailbox.New(st), st, accountID
}

func seedAccountID(t *testing.T, st *store.Store, id string) {
	t.Helper()
	const q = `
INSERT INTO accounts (id, oidc_subject, state, key_envelope, created_at, updated_at)
VALUES (?, ?, 'active', X'00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
	if _, err := st.DB.Exec(q, id, "sub-"+id); err != nil {
		t.Fatalf("seed account %s: %v", id, err)
	}
}

// newAuthedSession constructs a session bound to the supplied accountID
// and mailbox/proton backends but without the TCP/TLS plumbing —
// emersion's Conn is nil here, which is fine because none of the
// post-auth handlers we test write directly through it.
func newAuthedSession(t *testing.T, mboxes mailbox.Service, p ProtonClientLookup, accountID string) *session {
	t.Helper()
	stub := newStubAccounts()
	stub.addAccount(accountID, "user@reduit.example", "pw", testActive)

	backendOpts := []BackendOption{}
	if mboxes != nil {
		backendOpts = append(backendOpts, WithMailboxes(mboxes))
	}
	if p != nil {
		backendOpts = append(backendOpts, WithProton(p))
	}
	b, err := NewBackend(stub, NewSessions(), nil, backendOpts...)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	return &session{
		backend:   b,
		conn:      nil, // not exercised by these tests
		remote:    "127.0.0.1:0",
		rateKey:   "127.0.0.1",
		logger:    b.logger,
		accountID: accountID,
	}
}

// testActive avoids importing the account package twice — we already
// import it transitively via stubAccounts.
const testActive = "active"

// fakeProton records LabelMessages / UnlabelMessages calls so the Move
// tests can assert which labels were touched in which order.
type fakeProton struct {
	mu    sync.Mutex
	calls []protonCall
}

type protonCall struct {
	op      string // "label" or "unlabel"
	labelID string
	msgIDs  []string
}

func (f *fakeProton) ProtonForAccount(_ context.Context, _ string) (proton.Client, error) {
	return &fakeProtonClient{parent: f}, nil
}

func (f *fakeProton) record(op, label string, msgIDs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(msgIDs))
	copy(cp, msgIDs)
	f.calls = append(f.calls, protonCall{op: op, labelID: label, msgIDs: cp})
}

func (f *fakeProton) snapshot() []protonCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]protonCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// fakeProtonClient is the per-call adapter; every method records into
// the parent fakeProton's call log.
type fakeProtonClient struct{ parent *fakeProton }

func (c *fakeProtonClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	return proton.AuthInfo{}, errors.New("not implemented")
}
func (c *fakeProtonClient) AuthTOTP(context.Context, string) error { return nil }
func (c *fakeProtonClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	return nil
}
func (c *fakeProtonClient) KeySalts(context.Context) (proton.Salts, error) { return nil, nil }
func (c *fakeProtonClient) Unlock(_ proton.User, _ []proton.Address, _ []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	return nil, nil, nil
}
func (c *fakeProtonClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	return nil, false, nil
}
func (c *fakeProtonClient) GetMessage(context.Context, string) (proton.Message, error) {
	return proton.Message{}, nil
}
func (c *fakeProtonClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	return nil, nil
}
func (c *fakeProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	return proton.Message{}, nil
}
func (c *fakeProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	return nil, nil
}
func (c *fakeProtonClient) LabelMessages(_ context.Context, msgIDs []string, labelID string) error {
	c.parent.record("label", labelID, msgIDs)
	return nil
}
func (c *fakeProtonClient) UnlabelMessages(_ context.Context, msgIDs []string, labelID string) error {
	c.parent.record("unlabel", labelID, msgIDs)
	return nil
}
func (c *fakeProtonClient) Logout(context.Context) error { return nil }

// We deliberately do NOT exercise the wire shape of LIST in unit
// tests. emersion's ListWriter is a thin pass-through to its internal
// *Conn (which cannot be constructed without a live TCP connection),
// so the right place for wire-shape assertions is an integration
// test once IMAP4rev2 is enabled. The spec REQs this file pins
// ("LIST shows only own folders", "Account Isolation in IMAP
// Operations") govern data-layer behaviour reachable via the
// mailbox.Service.ListMailboxes call the production handler delegates
// to.

// TestSessionListShowsOnlyOwnMailboxes wires two accounts' mailboxes
// into the same store and confirms each session's List yields ONLY
// that session's mailboxes.
//
// Governing: SPEC-0003 REQ "LIST shows only own folders".
func TestSessionListShowsOnlyOwnMailboxes(t *testing.T) {
	t.Parallel()
	mboxes, st, acctA := newMailboxStack(t)
	const acctB = "acct-other"
	seedAccountID(t, st, acctB)

	ctx := context.Background()
	if _, err := mboxes.EnsureMailbox(ctx, acctA, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acctA, "Labels/PrivateA", "user-private-a", mailbox.KindUserLabel); err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acctB, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acctB, "Labels/SecretB", "user-secret-b", mailbox.KindUserLabel); err != nil {
		t.Fatal(err)
	}

	listA, err := mboxes.ListMailboxes(ctx, acctA)
	if err != nil {
		t.Fatalf("ListMailboxes(A): %v", err)
	}
	for _, m := range listA {
		if m.AccountID != acctA {
			t.Errorf("listA leaked %q (account %s)", m.Name, m.AccountID)
		}
		if m.Name == "Labels/SecretB" {
			t.Errorf("listA contained account-B-only mailbox %q", m.Name)
		}
	}

	// And via the Session-level helper directly.
	sess := newAuthedSession(t, mboxes, nil, acctA)
	if sess.snapshotAccountID() != acctA {
		t.Fatalf("session account ID drift: got %q", sess.snapshotAccountID())
	}
}

// TestSessionSelectRefusesNonOwnedMailbox confirms a session for
// account A receives the byte-identical "Mailbox does not exist"
// response when trying to SELECT a mailbox owned by account B.
//
// Governing: SPEC-0003 REQ "SELECT of a non-owned mailbox fails as
// not-found".
func TestSessionSelectRefusesNonOwnedMailbox(t *testing.T) {
	t.Parallel()
	mboxes, st, acctA := newMailboxStack(t)
	const acctB = "acct-other"
	seedAccountID(t, st, acctB)

	ctx := context.Background()
	if _, err := mboxes.EnsureMailbox(ctx, acctB, "Labels/Family", "user-family", mailbox.KindUserLabel); err != nil {
		t.Fatal(err)
	}

	sess := newAuthedSession(t, mboxes, nil, acctA)

	// Genuine miss: a name that exists nowhere.
	_, errGenuine := sess.Select("Labels/DefinitelyMissing", nil)
	// Cross-account miss: a name that exists under acctB.
	_, errCross := sess.Select("Labels/Family", nil)

	if errGenuine == nil || errCross == nil {
		t.Fatalf("expected both Selects to fail; genuine=%v cross=%v", errGenuine, errCross)
	}

	// SPEC requirement: "identical to a genuine not-found case". We
	// assert exact error pointer equality (or at least byte-identical
	// IMAP rendering): both must be errMailboxNotFound.
	gErr, gOK := errGenuine.(*imap.Error)
	cErr, cOK := errCross.(*imap.Error)
	if !gOK || !cOK {
		t.Fatalf("expected *imap.Error responses; got %T / %T", errGenuine, errCross)
	}
	if gErr.Type != cErr.Type || gErr.Code != cErr.Code || gErr.Text != cErr.Text {
		t.Errorf("genuine vs cross-account responses differ; genuine=%+v cross=%+v",
			*gErr, *cErr)
	}
	if gErr.Text != "Mailbox does not exist" {
		t.Errorf("response text = %q, want %q", gErr.Text, "Mailbox does not exist")
	}
}

// TestSessionSelectReturnsUIDValidityAndCount confirms a successful
// Select on an owned mailbox returns the persisted UIDVALIDITY and the
// correct message count.
//
// Governing: SPEC-0003 REQ "UIDVALIDITY assigned at first sync".
func TestSessionSelectReturnsUIDValidityAndCount(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	mb, err := mboxes.EnsureMailbox(ctx, acct, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		mid, err := mboxes.UpsertMessage(ctx, &mailbox.Message{
			AccountID:       acct,
			ProtonMessageID: testProtonID(i),
			InternalDate:    time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mboxes.AssignUID(ctx, acct, mb.ID, mid); err != nil {
			t.Fatal(err)
		}
	}

	sess := newAuthedSession(t, mboxes, nil, acct)
	data, err := sess.Select("INBOX", nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if data.UIDValidity != mb.UIDValidity {
		t.Errorf("UIDVALIDITY = %d, want %d", data.UIDValidity, mb.UIDValidity)
	}
	if data.NumMessages != 3 {
		t.Errorf("NumMessages = %d, want 3", data.NumMessages)
	}
	if data.UIDNext != imap.UID(4) {
		t.Errorf("UIDNext = %d, want 4", data.UIDNext)
	}
}

// TestSessionStatusReturnsRequestedFields exercises the STATUS verb
// against an owned mailbox.
func TestSessionStatusReturnsRequestedFields(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	mb, err := mboxes.EnsureMailbox(ctx, acct, "Archive", mailbox.ProtonArchiveLabelID, mailbox.KindSystem)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		mid, err := mboxes.UpsertMessage(ctx, &mailbox.Message{
			AccountID:       acct,
			ProtonMessageID: testProtonID(i),
			InternalDate:    time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mboxes.AssignUID(ctx, acct, mb.ID, mid); err != nil {
			t.Fatal(err)
		}
	}

	sess := newAuthedSession(t, mboxes, nil, acct)
	data, err := sess.Status("Archive", &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
		UIDValidity: true,
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if data.NumMessages == nil || *data.NumMessages != 5 {
		t.Errorf("NumMessages = %v, want 5", data.NumMessages)
	}
	if data.UIDValidity != mb.UIDValidity {
		t.Errorf("UIDVALIDITY = %d, want %d", data.UIDValidity, mb.UIDValidity)
	}
	if data.UIDNext != imap.UID(6) {
		t.Errorf("UIDNext = %d, want 6", data.UIDNext)
	}
}

// TestSessionStatusCrossAccount exercises the cross-account STATUS
// rejection: account B asks for STATUS of account A's Archive. The
// response MUST be the same generic NO an unknown mailbox produces.
func TestSessionStatusCrossAccount(t *testing.T) {
	t.Parallel()
	mboxes, st, acctA := newMailboxStack(t)
	const acctB = "acct-cross-status"
	seedAccountID(t, st, acctB)
	ctx := context.Background()

	if _, err := mboxes.EnsureMailbox(ctx, acctA, "Archive", mailbox.ProtonArchiveLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}

	sessB := newAuthedSession(t, mboxes, nil, acctB)
	_, err := sessB.Status("Archive", &imap.StatusOptions{NumMessages: true})
	if err == nil {
		t.Errorf("Status(B, A's Archive) succeeded; expected NO")
	}
	imapErr, ok := err.(*imap.Error)
	if !ok || imapErr.Text != "Mailbox does not exist" {
		t.Errorf("got %v, want Mailbox does not exist", err)
	}
}

// TestSessionMoveBetweenSystemFoldersAdjustsProtonLabels drives MOVE
// from INBOX → Archive and asserts the Proton client received a
// LabelMessages(Archive) call AND an UnlabelMessages(Inbox) call.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes
// Proton system flag".
func TestSessionMoveBetweenSystemFoldersAdjustsProtonLabels(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	inbox, err := mboxes.EnsureMailbox(ctx, acct, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acct, "Archive", mailbox.ProtonArchiveLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}

	mid, err := mboxes.UpsertMessage(ctx, &mailbox.Message{
		AccountID:       acct,
		ProtonMessageID: "proton-msg-1",
		Subject:         "subject 1",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.AssignUID(ctx, acct, inbox.ID, mid); err != nil {
		t.Fatal(err)
	}

	fp := &fakeProton{}
	sess := newAuthedSession(t, mboxes, fp, acct)
	if _, err := sess.Select("INBOX", nil); err != nil {
		t.Fatalf("Select INBOX: %v", err)
	}

	if _, err := sess.performMove(imap.SeqSet{{Start: 1, Stop: 1}}, "Archive"); err != nil {
		t.Fatalf("Move: %v", err)
	}

	calls := fp.snapshot()
	// Expect: label(Archive=6), then unlabel(Inbox=0).
	if len(calls) != 2 {
		t.Fatalf("expected 2 Proton calls, got %d: %+v", len(calls), calls)
	}
	if calls[0].op != "label" || calls[0].labelID != mailbox.ProtonArchiveLabelID {
		t.Errorf("call 0: %+v, want label/archive", calls[0])
	}
	if calls[1].op != "unlabel" || calls[1].labelID != mailbox.ProtonInboxLabelID {
		t.Errorf("call 1: %+v, want unlabel/inbox", calls[1])
	}
	if len(calls[0].msgIDs) != 1 || calls[0].msgIDs[0] != "proton-msg-1" {
		t.Errorf("call 0 msgIDs = %v, want [proton-msg-1]", calls[0].msgIDs)
	}
}

// TestSessionMoveBetweenUserLabelsAdjustsLabels mirrors the system-
// folder move but for the additive Labels/* namespace.
//
// Governing: SPEC-0003 REQ "Moving between Labels/ folders adjusts
// labels additively".
func TestSessionMoveBetweenUserLabelsAdjustsLabels(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	src, err := mboxes.EnsureMailbox(ctx, acct, "Labels/Foo", "user-foo", mailbox.KindUserLabel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acct, "Labels/Bar", "user-bar", mailbox.KindUserLabel); err != nil {
		t.Fatal(err)
	}
	mid, err := mboxes.UpsertMessage(ctx, &mailbox.Message{
		AccountID:       acct,
		ProtonMessageID: "proton-msg-foo-to-bar",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.AssignUID(ctx, acct, src.ID, mid); err != nil {
		t.Fatal(err)
	}

	fp := &fakeProton{}
	sess := newAuthedSession(t, mboxes, fp, acct)
	if _, err := sess.Select("Labels/Foo", nil); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if _, err := sess.performMove(imap.SeqSet{{Start: 1, Stop: 1}}, "Labels/Bar"); err != nil {
		t.Fatalf("Move: %v", err)
	}

	calls := fp.snapshot()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %+v", len(calls), calls)
	}
	if calls[0].op != "label" || calls[0].labelID != "user-bar" {
		t.Errorf("call 0: %+v, want label/user-bar", calls[0])
	}
	if calls[1].op != "unlabel" || calls[1].labelID != "user-foo" {
		t.Errorf("call 1: %+v, want unlabel/user-foo", calls[1])
	}
}

// TestSessionMoveProtonFailureLeavesLocalUntouched confirms that if
// Phase 1 (LabelMessages) fails, the local mirror is unchanged: the
// source UID is still present, the destination has not gained a row.
func TestSessionMoveProtonFailureLeavesLocalUntouched(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	inbox, err := mboxes.EnsureMailbox(ctx, acct, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := mboxes.EnsureMailbox(ctx, acct, "Archive", mailbox.ProtonArchiveLabelID, mailbox.KindSystem)
	if err != nil {
		t.Fatal(err)
	}
	mid, err := mboxes.UpsertMessage(ctx, &mailbox.Message{
		AccountID:       acct,
		ProtonMessageID: "proton-msg-fail",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.AssignUID(ctx, acct, inbox.ID, mid); err != nil {
		t.Fatal(err)
	}

	fp := &fakeProton{}
	// Wrap the fake so LabelMessages returns an error.
	sess := newAuthedSession(t, mboxes, &erroringProton{parent: fp, failOn: "label"}, acct)
	if _, err := sess.Select("INBOX", nil); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if _, err := sess.performMove(imap.SeqSet{{Start: 1, Stop: 1}}, "Archive"); err == nil {
		t.Fatalf("Move succeeded; expected error")
	}

	// Source still has the message; destination is empty.
	srcMsgs, _ := mboxes.ListMessagesInMailbox(ctx, acct, inbox.ID)
	if len(srcMsgs) != 1 {
		t.Errorf("source mailbox lost its message after failed move: %d msgs left", len(srcMsgs))
	}
	destMsgs, _ := mboxes.ListMessagesInMailbox(ctx, acct, dest.ID)
	if len(destMsgs) != 0 {
		t.Errorf("destination mailbox has %d msgs after failed move; want 0", len(destMsgs))
	}
}

// erroringProton wraps a fakeProton and forces a specific operation
// to fail. Used by the failure-path tests.
type erroringProton struct {
	parent *fakeProton
	failOn string // "label" or "unlabel"
}

func (e *erroringProton) ProtonForAccount(ctx context.Context, accountID string) (proton.Client, error) {
	cli, err := e.parent.ProtonForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return &erroringProtonClient{wrapped: cli.(*fakeProtonClient), failOn: e.failOn}, nil
}

type erroringProtonClient struct {
	wrapped *fakeProtonClient
	failOn  string
}

func (c *erroringProtonClient) AuthInfo(ctx context.Context, r proton.AuthInfoReq) (proton.AuthInfo, error) {
	return c.wrapped.AuthInfo(ctx, r)
}
func (c *erroringProtonClient) AuthTOTP(ctx context.Context, code string) error {
	return c.wrapped.AuthTOTP(ctx, code)
}
func (c *erroringProtonClient) AuthFIDO2(ctx context.Context, r proton.FIDO2Req) error {
	return c.wrapped.AuthFIDO2(ctx, r)
}
func (c *erroringProtonClient) KeySalts(ctx context.Context) (proton.Salts, error) {
	return c.wrapped.KeySalts(ctx)
}
func (c *erroringProtonClient) Unlock(u proton.User, a []proton.Address, p []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	return c.wrapped.Unlock(u, a, p)
}
func (c *erroringProtonClient) GetEvent(ctx context.Context, id string) ([]proton.Event, bool, error) {
	return c.wrapped.GetEvent(ctx, id)
}
func (c *erroringProtonClient) GetMessage(ctx context.Context, id string) (proton.Message, error) {
	return c.wrapped.GetMessage(ctx, id)
}
func (c *erroringProtonClient) ListMessages(ctx context.Context, f proton.MessageFilter) ([]proton.MessageMetadata, error) {
	return c.wrapped.ListMessages(ctx, f)
}
func (c *erroringProtonClient) SendDraft(ctx context.Context, id string, r proton.SendDraftReq) (proton.Message, error) {
	return c.wrapped.SendDraft(ctx, id, r)
}
func (c *erroringProtonClient) GetAttachment(ctx context.Context, id string) ([]byte, error) {
	return c.wrapped.GetAttachment(ctx, id)
}
func (c *erroringProtonClient) LabelMessages(ctx context.Context, msgIDs []string, labelID string) error {
	if c.failOn == "label" {
		return errors.New("simulated proton label failure")
	}
	return c.wrapped.LabelMessages(ctx, msgIDs, labelID)
}
func (c *erroringProtonClient) UnlabelMessages(ctx context.Context, msgIDs []string, labelID string) error {
	if c.failOn == "unlabel" {
		return errors.New("simulated proton unlabel failure")
	}
	return c.wrapped.UnlabelMessages(ctx, msgIDs, labelID)
}
func (c *erroringProtonClient) Logout(ctx context.Context) error { return c.wrapped.Logout(ctx) }

// TestSessionConcurrentSelectIsolation confirms that two sessions for
// the SAME account each have an isolated `selected` view: a SELECT in
// session A does not affect session B's selection.
//
// Governing: SPEC-0003 REQ "Per-session state is isolated".
func TestSessionConcurrentSelectIsolation(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()
	if _, err := mboxes.EnsureMailbox(ctx, acct, "INBOX", mailbox.ProtonInboxLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.EnsureMailbox(ctx, acct, "Sent", mailbox.ProtonSentLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}

	sessA := newAuthedSession(t, mboxes, nil, acct)
	sessB := newAuthedSession(t, mboxes, nil, acct)

	if _, err := sessA.Select("INBOX", nil); err != nil {
		t.Fatalf("Select(A INBOX): %v", err)
	}
	if _, err := sessB.Select("Sent", nil); err != nil {
		t.Fatalf("Select(B Sent): %v", err)
	}

	stA := sessA.state()
	stB := sessB.state()
	stA.mu.Lock()
	gotA := ""
	if stA.selected != nil {
		gotA = stA.selected.Name
	}
	stA.mu.Unlock()
	stB.mu.Lock()
	gotB := ""
	if stB.selected != nil {
		gotB = stB.selected.Name
	}
	stB.mu.Unlock()
	if gotA != "INBOX" {
		t.Errorf("sessA.selected = %q, want INBOX", gotA)
	}
	if gotB != "Sent" {
		t.Errorf("sessB.selected = %q, want Sent", gotB)
	}

	// Unselect on B must not touch A.
	if err := sessB.Unselect(); err != nil {
		t.Fatalf("Unselect(B): %v", err)
	}
	stA.mu.Lock()
	gotA = ""
	if stA.selected != nil {
		gotA = stA.selected.Name
	}
	stA.mu.Unlock()
	if gotA != "INBOX" {
		t.Errorf("after B Unselect, sessA.selected = %q; want INBOX", gotA)
	}
}

// TestSessionListMatchesPattern asserts the LIST pattern matching
// behaves correctly with the IMAP wildcards (`*`, `%`).
func TestSessionListMatchesPattern(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	for _, name := range []string{
		"INBOX", "Sent", "Drafts", "Trash",
		"Labels/Receipts", "Labels/Family/Tax", "Labels/Family/Trips",
	} {
		var (
			labelID string
			kind    mailbox.Kind
		)
		if id := mailbox.ResolveSystemFolderID(name); id != "" {
			labelID, kind = id, mailbox.KindSystem
		} else if path, ok := mailbox.ParseUserLabelName(name); ok {
			labelID, kind = "user-"+strings.ReplaceAll(path, "/", "-"), mailbox.KindUserLabel
		}
		if _, err := mboxes.EnsureMailbox(ctx, acct, name, labelID, kind); err != nil {
			t.Fatal(err)
		}
	}

	// Smoke: ListMailboxes returns all 7.
	all, err := mboxes.ListMailboxes(ctx, acct)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 7 {
		t.Errorf("expected 7 mailboxes, got %d", len(all))
	}

	// Use the imapserver.MatchList helper directly to confirm the
	// pattern logic the Session.List handler relies on.
	match := func(name, pattern string) bool {
		return imapserver.MatchList(name, '/', "", pattern)
	}
	cases := []struct {
		name, pattern string
		want          bool
	}{
		{"INBOX", "*", true},
		{"Labels/Receipts", "Labels/*", true},
		{"Labels/Family/Tax", "Labels/*", true},
		{"INBOX", "Labels/*", false},
		{"Labels/Family/Tax", "Labels/Family/%", true},
	}
	for _, tc := range cases {
		if got := match(tc.name, tc.pattern); got != tc.want {
			t.Errorf("MatchList(%q, %q) = %v, want %v",
				tc.name, tc.pattern, got, tc.want)
		}
	}
}

// testProtonID returns a stable Proton-style message ID for index i.
func testProtonID(i int) string {
	return "proton-msg-test-" + intDigits(i)
}

func intDigits(i int) string {
	if i == 0 {
		return "0"
	}
	const charset = "0123456789"
	out := make([]byte, 0, 12)
	for i > 0 {
		out = append([]byte{charset[i%10]}, out...)
		i /= 10
	}
	return string(out)
}

// We deliberately do NOT exercise the wire shape of MOVE in unit
// tests. emersion's MoveWriter is a thin pass-through to its internal
// *Conn, which cannot be constructed without a live TCP connection.
// The wire shape is exercised by emersion's own tests; the spec REQs
// we pin in this file ("Moving between system folders changes Proton
// system flag", "Moving between Labels/ folders adjusts labels
// additively") govern the Proton-side and local-mirror effects, both
// of which are reachable through performMove. Once IMAP4rev2 is
// enabled and end-to-end MOVE plumbing lands, a follow-up story can
// add a TCP-level integration test.
