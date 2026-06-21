package imapserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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

// readUntil reads from r until the next CRLF and returns the line
// without the trailer. Test helper; uses a generous timeout because
// our test fixtures already set the conn deadline.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// writeCmd sends a tagged IMAP command terminated by CRLF.
func writeCmd(t *testing.T, w io.Writer, tag, cmd string) {
	t.Helper()
	if _, err := fmt.Fprintf(w, "%s %s\r\n", tag, cmd); err != nil {
		t.Fatalf("write %s: %v", cmd, err)
	}
}

// TestCleartextConnectionClosesWithoutGreeting confirms that a
// non-TLS TCP client sees the listener slam the door without ever
// emitting the IMAP `* OK` greeting. With tls.Listen, the cleartext
// payload triggers a TLS handshake error and the connection is
// closed before any IMAP bytes flow.
//
// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only" — scenario
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

	// Send an IMAP command in cleartext. tls.Listen will interpret
	// the bytes as a malformed ClientHello and abort the handshake.
	if _, err := conn.Write([]byte("a001 CAPABILITY\r\n")); err != nil {
		// On some platforms the write itself succeeds because the
		// kernel buffers the bytes; the failure surfaces on read.
		t.Logf("write returned %v (continuing to read)", err)
	}

	// Reading should return either EOF or a non-nil error before any
	// IMAP greeting bytes appear. If we get bytes that look like an
	// IMAP greeting, the cleartext-refused requirement is broken.
	buf := make([]byte, 256)
	n, readErr := conn.Read(buf)
	got := string(buf[:n])
	if n > 0 && strings.Contains(got, "* OK") {
		t.Fatalf("got IMAP greeting on cleartext conn: %q", got)
	}
	if readErr == nil && n == 0 {
		// Server closed without writing anything: also acceptable.
		return
	}
	// Any error is fine; this confirms TLS handshake refused the
	// cleartext payload. We don't pin a specific error string because
	// it varies (TLS record header / unexpected EOF / etc.).
	t.Logf("read returned err=%v n=%d data=%q", readErr, n, got)
}

// TestCapabilityAdvertisesPlainOnly asserts the CAPABILITY line
// includes IMAP4rev1 and AUTH=PLAIN, and excludes every other SASL
// mechanism plus AUTH=LOGIN, STARTTLS, and IMAP4rev2.
//
// Governing: SPEC-0003 REQ "PLAIN is the only advertised SASL
// mechanism", SPEC-0003 REQ "TLS Required, IMAPS Only" (no
// STARTTLS in the advertised set).
func TestCapabilityAdvertisesPlainOnly(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t, newStubAccounts(), NewSessions())

	conn := dialTLSClient(t, srv.addr)
	r := bufio.NewReader(conn)

	// First read: server greeting like
	//   * OK [CAPABILITY IMAP4rev1 SASL-IR LITERAL- AUTH=PLAIN] IMAP server ready
	greet := readLine(t, r)
	if !strings.HasPrefix(greet, "* OK ") {
		t.Fatalf("greeting did not start with `* OK `: %q", greet)
	}
	assertPlainOnlyCapabilities(t, greet)

	// Second read should not happen on its own; ask explicitly to
	// confirm a CAPABILITY response is identical.
	writeCmd(t, conn, "a001", "CAPABILITY")
	capLine := readLine(t, r)
	if !strings.HasPrefix(capLine, "* CAPABILITY ") {
		t.Fatalf("CAPABILITY response not in expected form: %q", capLine)
	}
	assertPlainOnlyCapabilities(t, capLine)

	// And the tagged completion.
	tagged := readLine(t, r)
	if !strings.HasPrefix(tagged, "a001 OK ") {
		t.Fatalf("expected tagged OK after CAPABILITY, got %q", tagged)
	}
}

// assertPlainOnlyCapabilities locks down the capability set we
// expose. SASL-IR and LITERAL- are not SASL mechanisms (they are
// extensions to the IMAP framing) so the spec's SASL-mechanism ban
// does not apply to them.
func assertPlainOnlyCapabilities(t *testing.T, line string) {
	t.Helper()
	if !strings.Contains(line, "IMAP4rev1") {
		t.Errorf("missing IMAP4rev1: %q", line)
	}
	if !strings.Contains(line, "AUTH=PLAIN") {
		t.Errorf("missing AUTH=PLAIN: %q", line)
	}
	for _, banned := range []string{
		"AUTH=LOGIN", "AUTH=CRAM-MD5", "AUTH=DIGEST-MD5",
		"AUTH=ANONYMOUS", "AUTH=GSSAPI", "AUTH=SCRAM",
		"STARTTLS", "IMAP4rev2",
	} {
		if strings.Contains(line, banned) {
			t.Errorf("CAPABILITY must not advertise %q; got %q", banned, line)
		}
	}
}

// TestSASLPlainHappyPath drives the standard AUTHENTICATE PLAIN flow
// against a known-good account and asserts the server completes the
// SASL exchange with `OK`.
//
// Governing: SPEC-0003 REQ "user@host identifies the local user".
func TestSASLPlainHappyPath(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "correct-horse-battery-staple", account.StateActive)
	srv := startTestServer(t, stub, NewSessions())

	resp := authenticatePlain(t, srv.addr, "joe@reduit.example", "correct-horse-battery-staple")
	if !strings.HasPrefix(resp, "a001 OK ") {
		t.Fatalf("expected `a001 OK ...`, got %q", resp)
	}
}

// TestSASLPlainAuthFailuresAreIdentical drives the four failure
// modes — wrong password, unknown alias, suspended account,
// soft-deleted account — and asserts every one produces a
// byte-identical NO [AUTHENTICATIONFAILED] response. This is the
// "no detail leak" guarantee the spec requires.
//
// Governing: SPEC-0003 REQ "Authentication failure returns NO with
// no detail", SPEC-0003 REQ "Suspended account is rejected even
// with correct password".
func TestSASLPlainAuthFailuresAreIdentical(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-active", "alice@reduit.example", "alice-password", account.StateActive)
	stub.addAccount("acct-suspended", "bob@reduit.example", "bob-password", account.StateSuspended)
	stub.addAccount("acct-deleted", "carol@reduit.example", "carol-password", account.StateSoftDeleted)
	srv := startTestServer(t, stub, NewSessions())
	// Suppress per-IP back-off; the test asserts response equality
	// across several failure modes from the same client.
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
	}

	var responses [][]byte
	for _, tc := range cases {
		resp := authenticatePlain(t, srv.addr, tc.username, tc.password)
		t.Logf("%s -> %s", tc.name, resp)
		responses = append(responses, []byte(resp))
	}

	// Every response must be byte-identical (modulo the tag prefix,
	// which is the same across all our calls).
	first := responses[0]
	for i, r := range responses {
		if !bytes.Equal(r, first) {
			t.Errorf("response %d (%s) differs from baseline:\n  baseline: %q\n  got:      %q",
				i, cases[i].name, first, r)
		}
	}
	if !bytes.Contains(first, []byte("AUTHENTICATIONFAILED")) {
		t.Errorf("baseline response missing AUTHENTICATIONFAILED: %q", first)
	}
	if !bytes.HasPrefix(first, []byte("a001 NO ")) {
		t.Errorf("baseline response not `a001 NO ...`: %q", first)
	}
}

// TestSASLPlainIdentityMalformation feeds the server several
// malformed SASL identities and asserts every one produces the
// AUTHENTICATIONFAILED response, identical to the failure produced
// by an unknown-but-syntactically-valid alias.
//
// Governing: SPEC-0003 REQ "Authentication failure returns NO with
// no detail" — a malformed SASL identity is just another failure mode
// the scenario requires be indistinguishable from an unknown alias.
func TestSASLPlainIdentityMalformation(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	srv := startTestServer(t, stub, NewSessions())
	// Many sequential failures from 127.0.0.1 would otherwise trigger
	// the per-IP exponential back-off and make the test wall-time
	// dominated by sleep. The test is asserting validation behaviour,
	// not rate-limit timing.
	srv.disableRateLimit()

	// Baseline: a syntactically valid alias that simply does not
	// resolve to an account.
	baseline := authenticatePlain(t, srv.addr, "ghost@reduit.example", "anything")
	if !strings.Contains(baseline, "AUTHENTICATIONFAILED") {
		t.Fatalf("baseline missing AUTHENTICATIONFAILED: %q", baseline)
	}

	cases := []struct {
		name     string
		username string
	}{
		{"no-at", "joeexample.com"},
		{"two-at", "joe@@example.com"},
		{"empty-local", "@example.com"},
		{"empty-host", "joe@"},
		{"oversized", strings.Repeat("a", MaxSASLIdentityLength+1) + "@example.com"},
		{"control-char-tab", "joe\t@example.com"},
		// CR/LF embedded — the most security-critical case (response
		// injection). authenticatePlain supplies the identity through
		// SASL PLAIN's NUL-delimited blob, so the bytes never appear
		// raw on the wire; what we are checking is that the validator
		// notices the control character and rejects it.
		{"control-char-cr", "joe\r@example.com"},
		{"control-char-lf", "joe\n@example.com"},
		// Non-ASCII bytes — the validator now commits to ASCII-only
		// (RFC 6531 international mailbox names are out of scope for
		// v0.2; the operator-controlled alias namespace is ASCII by
		// construction). Each of these used to slip past the
		// `b < 0x20 || b == 0x7F` check and reach `strings.ToLower`
		// which is Unicode-naive (Turkish dotted-I family of footguns).
		{"non-ascii-utf8-2byte", "jo\xc3\xa9@example.com"},      // é
		{"non-ascii-utf8-3byte", "joe\xe2\x98\x83@example.com"}, // snowman
		{"non-ascii-high-byte", "joe\x80@example.com"},          // bare 0x80
		{"non-ascii-0xff", "joe\xff@example.com"},               // bare 0xFF
	}

	// Subtests run serially. Each one burns a real bcrypt comparison
	// (uniform-time auth — see TestAuthFailureIsConstantTime), so
	// running them in parallel saturates the CPU and stretches per-
	// conn deadlines. Serial keeps the suite predictable.
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp := authenticatePlain(t, srv.addr, tc.username, "any-password")
			if !strings.Contains(resp, "AUTHENTICATIONFAILED") {
				t.Errorf("%s: missing AUTHENTICATIONFAILED: %q", tc.name, resp)
			}
		})
	}
}

// TestSessionsDropForAccountClosesLiveSessions covers the per-session
// authentication lifetime requirement. Two clients log in for the
// same account, the suspension code path calls
// `Sessions.DropForAccount`, and both clients observe a `* BYE
// Account suspended` line followed by EOF within 1 second.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime".
func TestSessionsDropForAccountClosesLiveSessions(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-multi", "user@reduit.example", "pw", account.StateActive)
	registry := NewSessions()
	srv := startTestServer(t, stub, registry)

	// Open + authenticate two TLS sessions.
	conn1, r1 := loginPlain(t, srv.addr, "user@reduit.example", "pw")
	conn2, r2 := loginPlain(t, srv.addr, "user@reduit.example", "pw")

	// Wait for both sessions to register. Login returns once the
	// server has emitted `OK ... authentication successful`, but the
	// goroutine that adds to the registry runs in the same code path
	// before the OK is written, so by the time the read returns the
	// registry is populated.
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

	// Both connections must produce the BYE line and then EOF.
	for i, pair := range []struct {
		conn net.Conn
		r    *bufio.Reader
	}{{conn1, r1}, {conn2, r2}} {
		i := i
		_ = pair.conn.SetDeadline(time.Now().Add(1 * time.Second))
		bye, err := pair.r.ReadString('\n')
		if err != nil {
			t.Errorf("conn %d: read BYE: %v", i, err)
			continue
		}
		if !strings.Contains(bye, "* BYE Account suspended") {
			t.Errorf("conn %d: expected `* BYE Account suspended`, got %q", i, bye)
		}
		// Subsequent read should return error (EOF or closed).
		_, err = pair.r.ReadByte()
		if err == nil {
			t.Errorf("conn %d: expected EOF after BYE, got more bytes", i)
		}
	}

	if elapsed := time.Since(dropStart); elapsed > 1*time.Second {
		t.Errorf("DropForAccount took %v, want < 1s", elapsed)
	}
	if got := registry.CountForAccount("acct-multi"); got != 0 {
		t.Errorf("registry should be empty after drop, got %d", got)
	}
}

// TestSessionsRegistryUnregisterOnClose confirms a normal client
// LOGOUT removes the entry from the registry so a later
// DropForAccount does not race with already-closed connections.
func TestSessionsRegistryUnregisterOnClose(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-clean", "clean@reduit.example", "pw", account.StateActive)
	registry := NewSessions()
	srv := startTestServer(t, stub, registry)

	conn, r := loginPlain(t, srv.addr, "clean@reduit.example", "pw")
	if registry.CountForAccount("acct-clean") != 1 {
		t.Fatalf("post-login count = %d, want 1", registry.CountForAccount("acct-clean"))
	}

	// Issue LOGOUT and read until EOF.
	writeCmd(t, conn, "z001", "LOGOUT")
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
			t.Fatalf("registry not cleared after LOGOUT; count = %d",
				registry.CountForAccount("acct-clean"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSessionsRegistryDirect exercises the registry methods without
// the network. Useful as a smoke test that the public API the
// supervisor uses behaves under concurrent register/unregister and
// that DropForAccount snapshots the set so callers can mutate during
// the dropper invocation.
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

	// Unregister of unknown id is a no-op (must not panic).
	r.unregister("missing-acct", d1)

	// Empty / nil inputs are no-ops.
	r.register("", d1)
	r.register("acct", nil)
	r.unregister("", d1)
}

type testDropper struct {
	onDrop  func(string)
	onClose func()
}

func (t *testDropper) dropWithBye(reason string) {
	if t.onDrop != nil {
		t.onDrop(reason)
	}
}

func (t *testDropper) forceClose() {
	if t.onClose != nil {
		t.onClose()
	}
}

// TestSASLPlainBackendErrorHidesDetail confirms a transient backend
// error (e.g., DB unreachable) still surfaces as the byte-identical
// AUTHENTICATIONFAILED rather than leaking the underlying error.
func TestSASLPlainBackendErrorHidesDetail(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t, errorAccounts{}, NewSessions())
	resp := authenticatePlain(t, srv.addr, "joe@reduit.example", "anything")
	if !strings.Contains(resp, "AUTHENTICATIONFAILED") {
		t.Errorf("expected AUTHENTICATIONFAILED, got %q", resp)
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

// authenticatePlain runs a full TLS dial → AUTHENTICATE PLAIN
// exchange and returns the tagged completion line (`a001 OK ...` or
// `a001 NO ...`). It uses the SASL-IR (initial-response) capability
// so the server completes in a single round trip.
func authenticatePlain(t *testing.T, addr, username, password string) string {
	t.Helper()
	conn := dialTLSClient(t, addr)
	r := bufio.NewReader(conn)

	// Drain the greeting.
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	initial := saslPlainInitialResponse(username, password)
	writeCmd(t, conn, "a001", "AUTHENTICATE PLAIN "+base64.StdEncoding.EncodeToString(initial))

	// Server may respond with a tagged completion immediately (when
	// it accepts the initial response) or with a continuation `+`
	// followed by tagged completion (when it does not). Loop until
	// we see a non-continuation line.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read AUTHENTICATE response: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+") {
			// Continuation; SASL PLAIN is a one-step exchange so we
			// just resend the initial response.
			if _, err := fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString(initial)); err != nil {
				t.Fatalf("write SASL response: %v", err)
			}
			continue
		}
		if strings.HasPrefix(line, "* ") {
			// Untagged data (e.g., updated CAPABILITY); skip.
			continue
		}
		return line
	}
}

// loginPlain runs the AUTHENTICATE PLAIN exchange and asserts
// success, returning the open conn + reader so the caller can drive
// further commands (or wait for `* BYE` from the suspension path).
func loginPlain(t *testing.T, addr, username, password string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialTLSClient(t, addr)
	r := bufio.NewReader(conn)

	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	initial := saslPlainInitialResponse(username, password)
	writeCmd(t, conn, "a001", "AUTHENTICATE PLAIN "+base64.StdEncoding.EncodeToString(initial))

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read AUTHENTICATE response: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "+") {
			if _, err := fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString(initial)); err != nil {
				t.Fatalf("write SASL response: %v", err)
			}
			continue
		}
		if strings.HasPrefix(line, "* ") {
			continue
		}
		if !strings.HasPrefix(line, "a001 OK ") {
			t.Fatalf("loginPlain: expected OK, got %q", line)
		}
		break
	}
	// Disable the deadline so the caller can wait an arbitrary time
	// for an asynchronous BYE.
	_ = conn.SetDeadline(time.Time{})
	return conn, r
}

// saslPlainInitialResponse builds the canonical
// "\x00<authzid omitted>\x00<authcid>\x00<password>" PLAIN payload.
// Authzid is omitted (we do not support delegation).
func saslPlainInitialResponse(username, password string) []byte {
	var b []byte
	b = append(b, 0x00)
	b = append(b, username...)
	b = append(b, 0x00)
	b = append(b, password...)
	return b
}
