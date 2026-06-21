package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// TestCleartextConnectionClosesWithoutGreeting confirms that a
// non-TLS TCP client sees the listener slam the door without ever
// emitting the SMTP `220 ...` greeting. With tls.Listen, the
// cleartext payload triggers a TLS handshake error and the connection
// is closed before any SMTP bytes flow.
//
// Governing: SPEC-0004 REQ "TLS Required, SMTPS Only" — scenario
// "Cleartext connections are refused".
func TestCleartextConnectionClosesWithoutGreeting(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t, newStubAccounts(), NewSessions())

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send an SMTP command in cleartext. tls.Listen will interpret
	// the bytes as a malformed ClientHello and abort the handshake.
	if _, err := conn.Write([]byte("EHLO localhost\r\n")); err != nil {
		t.Logf("write returned %v (continuing to read)", err)
	}

	buf := make([]byte, 256)
	n, readErr := conn.Read(buf)
	got := string(buf[:n])
	if n > 0 && strings.Contains(got, "220 ") {
		t.Fatalf("got SMTP greeting on cleartext conn: %q", got)
	}
	if readErr == nil && n == 0 {
		return
	}
	t.Logf("read returned err=%v n=%d data=%q", readErr, n, got)
}

// TestEHLOAdvertisesAuthAndSize confirms the EHLO response includes
// AUTH PLAIN and SIZE 26214400 (25 MiB), and excludes STARTTLS and
// every non-PLAIN SASL mechanism.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP",
// SPEC-0004 REQ "Recipient and Message Size Limits".
func TestEHLOAdvertisesAuthAndSize(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t, newStubAccounts(), NewSessions())

	conn := dialTLSClient(t, srv.addr)
	r := bufio.NewReader(conn)
	lines := ehlo(t, conn, r)

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "AUTH PLAIN") {
		t.Errorf("EHLO missing AUTH PLAIN: %v", lines)
	}
	wantSize := fmt.Sprintf("SIZE %d", DefaultMaxMessageBytes)
	if !strings.Contains(joined, wantSize) {
		t.Errorf("EHLO missing %q: %v", wantSize, lines)
	}
	for _, banned := range []string{
		"STARTTLS",
		"AUTH LOGIN", "AUTH CRAM-MD5", "AUTH DIGEST-MD5",
		"AUTH GSSAPI", "AUTH SCRAM",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("EHLO must not advertise %q; got %v", banned, lines)
		}
	}
}

// TestSASLPlainHappyPath drives the standard AUTH PLAIN flow against
// a known-good account and asserts the server completes the SASL
// exchange with `235 ...`.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP".
func TestSASLPlainHappyPath(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "correct-horse-battery-staple", account.StateActive)
	srv := startTestServer(t, stub, NewSessions())

	resp := authPlain(t, srv.addr, "joe@reduit.example", "correct-horse-battery-staple")
	if !strings.HasPrefix(resp, "235 ") {
		t.Fatalf("expected `235 ...`, got %q", resp)
	}
}

// TestSASLPlainAuthFailuresAreIdentical drives every failure mode and
// asserts byte-identical 535 responses across the board. This is the
// "no detail leak" guarantee SPEC-0004 inherits from SPEC-0003.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP"
// (the "no detail leak" guarantee SPEC-0004 inherits from SPEC-0003's
// "Authentication failure returns NO with no detail").
func TestSASLPlainAuthFailuresAreIdentical(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-active", "alice@reduit.example", "alice-password", account.StateActive)
	stub.addAccount("acct-suspended", "bob@reduit.example", "bob-password", account.StateSuspended)
	stub.addAccount("acct-deleted", "carol@reduit.example", "carol-password", account.StateSoftDeleted)
	stub.addAccount("acct-pending", "dave@reduit.example", "dave-password", account.StatePendingProtonSetup)
	srv := startTestServer(t, stub, NewSessions())
	srv.disableRateLimit()

	cases := []struct {
		name     string
		username string
		password string
	}{
		{"wrong-password", "alice@reduit.example", "definitely-wrong"},
		{"unknown-user", "ghost@reduit.example", "any-password"},
		{"suspended-correct-pass", "bob@reduit.example", "bob-password"},
		{"soft-deleted-correct-pass", "carol@reduit.example", "carol-password"},
		{"pending-proton-setup", "dave@reduit.example", "dave-password"},
		{"malformed-no-at", "joeexample.com", "any-password"},
		{"malformed-non-ascii", "jo\xc3\xa9@example.com", "any-password"},
	}

	var responses [][]byte
	for _, tc := range cases {
		resp := authPlain(t, srv.addr, tc.username, tc.password)
		t.Logf("%s -> %s", tc.name, resp)
		responses = append(responses, []byte(resp))
	}

	first := responses[0]
	for i, r := range responses {
		if !bytes.Equal(r, first) {
			t.Errorf("response %d (%s) differs from baseline:\n  baseline: %q\n  got:      %q",
				i, cases[i].name, first, r)
		}
	}
	if !bytes.HasPrefix(first, []byte("535 ")) {
		t.Errorf("baseline response not `535 ...`: %q", first)
	}
}

// TestNonPlainSASLRecordsRateLimitFailure ensures an AUTH GSSAPI /
// CRAM-MD5 attempt records a per-IP failure for rate-limiting.
// Credential stuffing is not picky about mechanism names.
func TestNonPlainSASLRecordsRateLimitFailure(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	backend, err := NewBackend(stub, NewSessions(), &stubOutbox{}, nil)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	sess := &session{
		backend: backend,
		remote:  "192.0.2.1:1234",
		rateKey: "192.0.2.1",
		logger:  backend.logger,
	}

	if got := backend.rateLimit.entries[sess.rateKey]; got != nil {
		t.Fatalf("limiter pre-state: entry exists, want none")
	}

	srv, err := sess.Auth("GSSAPI")
	if srv != nil || err != ErrAuthFailed {
		t.Errorf("Auth(GSSAPI) = (%v, %v), want (nil, ErrAuthFailed)", srv, err)
	}
	entry := backend.rateLimit.entries[sess.rateKey]
	if entry == nil {
		t.Fatalf("limiter post-state: no entry for %q — RecordFailure was not called", sess.rateKey)
	}
	if entry.failures != 1 {
		t.Errorf("limiter failures = %d, want 1", entry.failures)
	}

	_, _ = sess.Auth("CRAM-MD5")
	if got := backend.rateLimit.entries[sess.rateKey].failures; got != 2 {
		t.Errorf("limiter failures after second attempt = %d, want 2", got)
	}
}

// TestBackendErrorHidesDetail confirms a transient backend error
// (e.g., DB unreachable) still surfaces as the byte-identical 535
// rather than leaking the underlying error.
func TestBackendErrorHidesDetail(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t, errorAccounts{}, NewSessions())
	resp := authPlain(t, srv.addr, "joe@reduit.example", "anything")
	if !strings.HasPrefix(resp, "535 ") {
		t.Errorf("expected `535 ...`, got %q", resp)
	}
	if strings.Contains(resp, "boom") {
		t.Errorf("response leaked underlying error text: %q", resp)
	}
}

type errorAccounts struct{}

func (errorAccounts) GetByPrimaryAlias(_ context.Context, _ string) (*account.Account, error) {
	return nil, errors.New("boom")
}

func (errorAccounts) VerifyIMAPPassword(_ context.Context, _ string, _ []byte) error {
	return errors.New("boom")
}

// TestMailFromAuthorization covers SPEC-0004's "Submission
// Authorization" requirement. Happy path: MAIL FROM matches the
// primary alias → 250 OK. Sad path: MAIL FROM is some other address
// → 553 5.7.1 with the exact text from the spec.
//
// Governing: SPEC-0004 REQ "Submission Authorization".
func TestMailFromAuthorization(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "pw", account.StateActive)
	srv := startTestServer(t, stub, NewSessions())

	t.Run("matches-primary-alias", func(t *testing.T) {
		conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
		defer conn.Close()
		writeSMTPCmd(t, conn, "MAIL FROM:<joe@reduit.example>")
		resp := readSMTPLine(t, r)
		if !strings.HasPrefix(resp, "250 ") {
			t.Errorf("expected 250 OK, got %q", resp)
		}
	})

	t.Run("matches-primary-alias-case-insensitive", func(t *testing.T) {
		conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
		defer conn.Close()
		writeSMTPCmd(t, conn, "MAIL FROM:<JOE@REDUIT.EXAMPLE>")
		resp := readSMTPLine(t, r)
		if !strings.HasPrefix(resp, "250 ") {
			t.Errorf("expected 250 OK on case-insensitive match, got %q", resp)
		}
	})

	t.Run("rejects-foreign-address", func(t *testing.T) {
		conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
		defer conn.Close()
		writeSMTPCmd(t, conn, "MAIL FROM:<not-mine@example.com>")
		resp := readSMTPLine(t, r)
		// SPEC-0004 mandates the EXACT text. Verify code, enhanced
		// status, and the canonical message.
		if !strings.HasPrefix(resp, "553 5.7.1 Sender address rejected: not authorized for this account") {
			t.Errorf("expected SPEC-0004 553 5.7.1 text, got %q", resp)
		}
	})
}

// TestRecipientLimitEnforced confirms the 101st RCPT TO returns
// `452 4.5.3 Too many recipients`.
//
// Governing: SPEC-0004 REQ "Recipient and Message Size Limits".
func TestRecipientLimitEnforced(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "pw", account.StateActive)
	// Shrink the recipient cap to 3 to keep the test fast — the
	// boundary behaviour is identical at any cap.
	srv := startTestServer(t, stub, NewSessions(), func(c *Config) {
		c.MaxRecipients = 3
	})

	conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
	defer conn.Close()

	writeSMTPCmd(t, conn, "MAIL FROM:<joe@reduit.example>")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("MAIL FROM: %q", resp)
	}

	for i := 0; i < 3; i++ {
		writeSMTPCmd(t, conn, fmt.Sprintf("RCPT TO:<rcpt%d@example.com>", i))
		resp := readSMTPLine(t, r)
		if !strings.HasPrefix(resp, "250 ") {
			t.Fatalf("RCPT %d: expected 250, got %q", i, resp)
		}
	}

	// 4th RCPT (the one past the cap) must be rejected with 452 4.5.3.
	writeSMTPCmd(t, conn, "RCPT TO:<rcpt-overflow@example.com>")
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "452 4.5.3") {
		t.Errorf("expected `452 4.5.3 ...` on overflow RCPT, got %q", resp)
	}
}

// TestMessageSizeLimitDuringStreaming confirms the size cap is
// enforced WHILE the body is being streamed, not at end-of-DATA.
// We send a payload bigger than the cap; the server returns
// `552 5.3.4 ...` without buffering the whole payload.
//
// Governing: SPEC-0004 REQ "Recipient and Message Size Limits"
// (scenario "Message size limit" — enforced mid-stream, not after
// buffering the whole body).
func TestMessageSizeLimitDuringStreaming(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "pw", account.StateActive)
	// Tiny cap so the test is fast: 1 KiB.
	const cap = 1024
	srv := startTestServer(t, stub, NewSessions(), func(c *Config) {
		c.MaxMessageBytes = cap
	})

	conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
	defer conn.Close()

	writeSMTPCmd(t, conn, "MAIL FROM:<joe@reduit.example>")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("MAIL FROM: %q", resp)
	}
	writeSMTPCmd(t, conn, "RCPT TO:<bob@example.com>")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("RCPT TO: %q", resp)
	}
	writeSMTPCmd(t, conn, "DATA")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "354 ") {
		t.Fatalf("DATA: expected 354, got %q", resp)
	}

	// Send 18 KiB of body — well past the 1 KiB cap. The server's
	// dataReader returns ErrDataTooLarge as soon as it reads past the
	// cap, so the response arrives before we finish writing.
	body := bytes.Repeat([]byte("Subject: Spam\r\n"), 1200)
	body = append(body, []byte("\r\n.\r\n")...)
	if _, err := conn.Write(body); err != nil {
		t.Logf("write body returned %v (expected if server closed early)", err)
	}

	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "552 5.3.4") {
		t.Errorf("expected `552 5.3.4 ...`, got %q", resp)
	}
}

// TestDATAStubReturns250 confirms a small in-cap DATA payload reaches
// the stub and returns the queued-OK response. The actual outbox
// handoff is deferred to #22.
func TestDATAStubReturns250(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "pw", account.StateActive)
	srv := startTestServer(t, stub, NewSessions())

	conn, r := loginPlain(t, srv.addr, "joe@reduit.example", "pw")
	defer conn.Close()

	writeSMTPCmd(t, conn, "MAIL FROM:<joe@reduit.example>")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("MAIL FROM: %q", resp)
	}
	writeSMTPCmd(t, conn, "RCPT TO:<bob@example.com>")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("RCPT TO: %q", resp)
	}
	writeSMTPCmd(t, conn, "DATA")
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "354 ") {
		t.Fatalf("DATA: %q", resp)
	}

	body := "From: <joe@reduit.example>\r\n" +
		"To: <bob@example.com>\r\n" +
		"Subject: Hello\r\n\r\n" +
		"hello\r\n.\r\n"
	if _, err := io.WriteString(conn, body); err != nil {
		t.Fatalf("write body: %v", err)
	}

	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "250 ") {
		t.Errorf("expected 250 from DATA stub, got %q", resp)
	}
}

// TestSessionsDropForAccountClosesLiveSessions covers SPEC-0004's
// "Per-Session Authentication Lifetime" requirement. Two clients log
// in for the same account, the suspension code path calls
// `Sessions.DropForAccount`, and both clients observe a `421 4.7.1`
// followed by EOF within 1 second.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".
func TestSessionsDropForAccountClosesLiveSessions(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-multi", "user@reduit.example", "pw", account.StateActive)
	registry := NewSessions()
	srv := startTestServer(t, stub, registry)

	conn1, r1 := loginPlain(t, srv.addr, "user@reduit.example", "pw")
	conn2, r2 := loginPlain(t, srv.addr, "user@reduit.example", "pw")

	deadline := time.Now().Add(1 * time.Second)
	for registry.CountForAccount("acct-multi") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("expected 2 registered sessions, got %d",
				registry.CountForAccount("acct-multi"))
		}
		time.Sleep(5 * time.Millisecond)
	}

	dropStart := time.Now()
	dropped := registry.DropForAccount("acct-multi", "Account suspended")
	if dropped != 2 {
		t.Errorf("DropForAccount returned %d, want 2", dropped)
	}

	for i, pair := range []struct {
		conn net.Conn
		r    *bufio.Reader
	}{{conn1, r1}, {conn2, r2}} {
		i := i
		_ = pair.conn.SetDeadline(time.Now().Add(1 * time.Second))
		line, err := pair.r.ReadString('\n')
		if err != nil {
			t.Errorf("conn %d: read 421: %v", i, err)
			continue
		}
		if !strings.HasPrefix(line, "421 4.7.1 Account suspended") {
			t.Errorf("conn %d: expected `421 4.7.1 Account suspended`, got %q", i, line)
		}
		_, err = pair.r.ReadByte()
		if err == nil {
			t.Errorf("conn %d: expected EOF after 421, got more bytes", i)
		}
	}

	if elapsed := time.Since(dropStart); elapsed > 1*time.Second {
		t.Errorf("DropForAccount took %v, want < 1s", elapsed)
	}
	if got := registry.CountForAccount("acct-multi"); got != 0 {
		t.Errorf("registry should be empty after drop, got %d", got)
	}
}

// TestSessionsRegistryUnregisterOnLogout confirms a normal client
// QUIT removes the entry from the registry.
func TestSessionsRegistryUnregisterOnLogout(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-clean", "clean@reduit.example", "pw", account.StateActive)
	registry := NewSessions()
	srv := startTestServer(t, stub, registry)

	conn, r := loginPlain(t, srv.addr, "clean@reduit.example", "pw")
	if registry.CountForAccount("acct-clean") != 1 {
		t.Fatalf("post-login count = %d, want 1", registry.CountForAccount("acct-clean"))
	}

	writeSMTPCmd(t, conn, "QUIT")
	for {
		_, err := r.ReadString('\n')
		if err != nil {
			break
		}
	}
	_ = conn.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for registry.CountForAccount("acct-clean") != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("registry not cleared after QUIT; count = %d",
				registry.CountForAccount("acct-clean"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSessionsRegistryDirect exercises the registry methods without
// the network. Mirrors the IMAP test of the same name.
func TestSessionsRegistryDirect(t *testing.T) {
	t.Parallel()
	r := NewSessions()

	dropCount := int32(0)
	d := func() sessionDropper {
		return &testDropper{onDrop: func(string) { atomic.AddInt32(&dropCount, 1) }}
	}

	d1 := d()
	d2 := d()
	r.register("acct", d1)
	r.register("acct", d2)
	if got := r.CountForAccount("acct"); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	dropped := r.DropForAccount("acct", "test")
	if dropped != 2 {
		t.Errorf("DropForAccount returned %d, want 2", dropped)
	}
	if got := atomic.LoadInt32(&dropCount); got != 2 {
		t.Errorf("dropper called %d times, want 2", got)
	}
	if got := r.CountForAccount("acct"); got != 0 {
		t.Errorf("count after drop = %d, want 0", got)
	}

	r.unregister("missing-acct", d1)
	r.register("", d1)
	r.register("acct", nil)
	r.unregister("", d1)
}

type testDropper struct {
	onDrop  func(string)
	onClose func()
}

func (t *testDropper) dropWith421(reason string) {
	if t.onDrop != nil {
		t.onDrop(reason)
	}
}

func (t *testDropper) forceClose() {
	if t.onClose != nil {
		t.onClose()
	}
}
