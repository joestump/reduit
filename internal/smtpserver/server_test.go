package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
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
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP",
// SPEC-0004 Security checklist (uniform-time auth).
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
	backend, err := NewBackend(stub, NewSessions(), nil)
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
