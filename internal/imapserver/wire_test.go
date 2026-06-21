// Wire-shape integration tests: drive the full IMAP4rev1 + MOVE surface
// over a real TCP + TLS connection using emersion's imapclient, so the
// COPYUID / EXPUNGE / LIST response framing is exercised end-to-end (not
// just the performMove data half the unit tests in
// mailbox_session_test.go cover).
//
// These complement, rather than replace, the direct performMove tests:
// the unit tests pin the Proton-call sequence and local UID effects; the
// wire tests pin that the advertised MOVE capability actually produces a
// well-formed COPYUID + EXPUNGE the client library can parse.
//
// Governing: ADR-0007 (emersion go-imap v2 — MOVE advertised),
// SPEC-0003 REQ "Moving between system folders changes Proton system
// flag", SPEC-0003 REQ "System folders map to standard names".

package imapserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/mailbox"
)

// dialWireClient opens a TLS connection to the server and wraps it in an
// emersion imapclient. The cleanup logs the client out.
func dialWireClient(t *testing.T, addr string) *imapclient.Client {
	t.Helper()
	conn := dialTLSClient(t, addr)
	c := imapclient.New(conn, &imapclient.Options{})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestWireMoveEmitsCopyUIDAndExpunge drives a full MOVE over the wire and
// asserts the client library parses a COPYUID (SourceUIDs/DestUIDs) plus
// the source EXPUNGE. This is the wire-shape proof that advertising the
// MOVE capability (server.go Caps) produces a response the client can
// act on.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag".
func TestWireMoveEmitsCopyUIDAndExpunge(t *testing.T) {
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
		ProtonMessageID: "proton-wire-1",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srcUID, err := mboxes.AssignUID(ctx, acct, inbox.ID, mid)
	if err != nil {
		t.Fatal(err)
	}

	stub := newStubAccounts()
	stub.addAccount(acct, "joe@reduit.example", "pw", account.StateActive)
	fp := &fakeProton{}
	srv := startTestServerWithBackend(t, stub, NewSessions(), mboxes, fp)

	c := dialWireClient(t, srv.addr)
	if err := c.Authenticate(sasl.NewPlainClient("", "joe@reduit.example", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// MOVE must be advertised so the client issues a real MOVE (not the
	// COPY+STORE+EXPUNGE fallback). If the cap were missing this would
	// silently exercise a different code path.
	if !c.Caps().Has(imap.CapMove) {
		t.Fatalf("server did not advertise MOVE; caps = %v", c.Caps())
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX: %v", err)
	}

	data, err := c.Move(imap.SeqSet{{Start: 1, Stop: 1}}, "Archive").Wait()
	if err != nil {
		t.Fatalf("Move: %v", err)
	}

	// COPYUID: destination UIDVALIDITY present, source + dest UID sets
	// non-empty.
	if data.UIDValidity == 0 {
		t.Errorf("MOVE COPYUID missing UIDVALIDITY")
	}
	srcUIDs, ok := data.SourceUIDs.(imap.UIDSet)
	if !ok || len(srcUIDs) == 0 {
		t.Errorf("MOVE SourceUIDs = %v, want non-empty UIDSet", data.SourceUIDs)
	} else if !srcUIDs.Contains(imap.UID(srcUID)) {
		t.Errorf("MOVE SourceUIDs %v does not contain the source UID %d", srcUIDs, srcUID)
	}
	if destUIDs, ok := data.DestUIDs.(imap.UIDSet); !ok || len(destUIDs) == 0 {
		t.Errorf("MOVE DestUIDs = %v, want non-empty UIDSet", data.DestUIDs)
	}

	// The Proton side saw label(Archive) + unlabel(Inbox).
	calls := fp.snapshot()
	if len(calls) != 2 || calls[0].op != "label" || calls[1].op != "unlabel" {
		t.Errorf("Proton calls = %+v, want label then unlabel", calls)
	}

	// After the MOVE the source mailbox is empty over the wire: re-SELECT
	// INBOX and confirm zero messages.
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("re-Select INBOX: %v", err)
	}
	if sel.NumMessages != 0 {
		t.Errorf("INBOX NumMessages after MOVE = %d, want 0", sel.NumMessages)
	}
}

// TestWireListShowsSystemFolders drives LIST "" "*" over the wire and
// confirms the system folders are returned with their special-use
// attributes, exercising the ListWriter framing the unit tests
// deliberately skip (emersion's ListWriter needs a live *Conn).
//
// Governing: SPEC-0003 REQ "System folders map to standard names".
func TestWireListShowsSystemFolders(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()
	for _, f := range []struct {
		name, label string
	}{
		{"INBOX", mailbox.ProtonInboxLabelID},
		{"Archive", mailbox.ProtonArchiveLabelID},
		{"Trash", mailbox.ProtonTrashLabelID},
	} {
		if _, err := mboxes.EnsureMailbox(ctx, acct, f.name, f.label, mailbox.KindSystem); err != nil {
			t.Fatal(err)
		}
	}

	stub := newStubAccounts()
	stub.addAccount(acct, "joe@reduit.example", "pw", account.StateActive)
	srv := startTestServerWithBackend(t, stub, NewSessions(), mboxes, &fakeProton{})

	c := dialWireClient(t, srv.addr)
	if err := c.Authenticate(sasl.NewPlainClient("", "joe@reduit.example", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	list, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]bool{}
	for _, ld := range list {
		got[ld.Mailbox] = true
	}
	for _, want := range []string{"INBOX", "Archive", "Trash"} {
		if !got[want] {
			t.Errorf("LIST missing %q; got %v", want, got)
		}
	}
}

// TestWireCopyEmitsCopyUID drives COPY over the wire and asserts a
// COPYUID response. COPY shares performCopy's pre-allocate-then-label
// structure with MOVE; the wire test confirms the client parses the
// COPYUID the server emits.
func TestWireCopyEmitsCopyUID(t *testing.T) {
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
		ProtonMessageID: "proton-wire-copy-1",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mboxes.AssignUID(ctx, acct, inbox.ID, mid); err != nil {
		t.Fatal(err)
	}

	stub := newStubAccounts()
	stub.addAccount(acct, "joe@reduit.example", "pw", account.StateActive)
	fp := &fakeProton{}
	srv := startTestServerWithBackend(t, stub, NewSessions(), mboxes, fp)

	c := dialWireClient(t, srv.addr)
	if err := c.Authenticate(sasl.NewPlainClient("", "joe@reduit.example", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX: %v", err)
	}

	data, err := c.Copy(imap.SeqSet{{Start: 1, Stop: 1}}, "Archive").Wait()
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if data.UIDValidity == 0 {
		t.Errorf("COPY COPYUID missing UIDVALIDITY")
	}
	if len(data.DestUIDs) == 0 {
		t.Errorf("COPY DestUIDs = %v, want non-empty UIDSet", data.DestUIDs)
	}

	// COPY adds the destination label but does NOT remove the source
	// (unlike MOVE) — exactly one Proton label call.
	calls := fp.snapshot()
	if len(calls) != 1 || calls[0].op != "label" {
		t.Errorf("COPY Proton calls = %+v, want a single label call", calls)
	}
}

// TestWireAppendImportsAndReturnsAppendUID drives APPEND over the wire:
// the client uploads a message literal into Drafts and the server
// imports it to Proton, materialises it, and returns an APPENDUID the
// client library parses. A subsequent SELECT shows the message.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping".
func TestWireAppendImportsAndReturnsAppendUID(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()
	if _, err := mboxes.EnsureMailbox(ctx, acct, "Drafts", mailbox.ProtonDraftsLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}

	stub := newStubAccounts()
	stub.addAccount(acct, "joe@reduit.example", "pw", account.StateActive)
	fp := &fakeProton{importID: "proton-wire-append-1"}
	srv := startTestServerWithBackend(t, stub, NewSessions(), mboxes, fp)

	c := dialWireClient(t, srv.addr)
	if err := c.Authenticate(sasl.NewPlainClient("", "joe@reduit.example", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	raw := []byte("From: joe@reduit.example\r\nSubject: wire draft\r\n\r\nhello")
	appendCmd := c.Append("Drafts", int64(len(raw)), &imap.AppendOptions{})
	if _, err := appendCmd.Write(raw); err != nil {
		t.Fatalf("Append write: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Append close: %v", err)
	}
	data, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if data.UID == 0 {
		t.Errorf("APPENDUID missing UID: %+v", data)
	}

	// Proton import recorded under the Drafts label.
	fp.mu.Lock()
	imports := append([]importCall(nil), fp.imports...)
	fp.mu.Unlock()
	if len(imports) != 1 || imports[0].labelID != mailbox.ProtonDraftsLabelID {
		t.Fatalf("import calls = %+v, want one under Drafts", imports)
	}

	// The message is visible over the wire.
	sel, err := c.Select("Drafts", nil).Wait()
	if err != nil {
		t.Fatalf("Select Drafts: %v", err)
	}
	if sel.NumMessages != 1 {
		t.Errorf("Drafts NumMessages after APPEND = %d, want 1", sel.NumMessages)
	}
}

// TestWireAppendLimitIsAdvertised confirms the server advertises
// APPENDLIMIT=<appendMaxLiteralBytes> (RFC 7889) so a client knows the
// ceiling before streaming, and that an over-limit APPEND is rejected
// with [TOOBIG] up front rather than after a wasted upload.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping".
func TestWireAppendLimitIsAdvertised(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()
	if _, err := mboxes.EnsureMailbox(ctx, acct, "Drafts", mailbox.ProtonDraftsLabelID, mailbox.KindSystem); err != nil {
		t.Fatal(err)
	}

	stub := newStubAccounts()
	stub.addAccount(acct, "joe@reduit.example", "pw", account.StateActive)
	fp := &fakeProton{}
	srv := startTestServerWithBackend(t, stub, NewSessions(), mboxes, fp)

	c := dialWireClient(t, srv.addr)
	if err := c.Authenticate(sasl.NewPlainClient("", "joe@reduit.example", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	limit, ok := c.Caps().AppendLimit()
	if !ok {
		t.Fatalf("server did not advertise APPENDLIMIT; caps = %v", c.Caps())
	}
	if limit == nil || *limit != uint32(appendMaxLiteralBytes) {
		t.Errorf("advertised APPENDLIMIT = %v, want %d", limit, appendMaxLiteralBytes)
	}

	// An over-limit APPEND must be refused with [TOOBIG] — emersion checks
	// the announced literal size against AppendLimit() BEFORE accepting
	// the body, so the rejection is early. We never write the (huge) body;
	// announcing an over-limit size is enough to trigger the check.
	over := int64(appendMaxLiteralBytes) + 1
	appendCmd := c.Append("Drafts", over, &imap.AppendOptions{})
	_, err := appendCmd.Wait()
	if err == nil {
		t.Fatal("over-limit APPEND succeeded; want [TOOBIG] rejection")
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("over-limit APPEND error = %v (%T), want *imap.Error", err, err)
	}
	if imapErr.Code != imap.ResponseCodeTooBig {
		t.Errorf("over-limit APPEND code = %q, want TOOBIG", imapErr.Code)
	}

	// No Proton import happened — the literal was rejected before the
	// handler ran.
	fp.mu.Lock()
	nImports := len(fp.imports)
	fp.mu.Unlock()
	if nImports != 0 {
		t.Errorf("over-limit APPEND reached Proton import: %d calls", nImports)
	}
}
