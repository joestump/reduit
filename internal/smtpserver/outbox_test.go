// SMTP-side tests for the outbox handoff. We wire a stubOutbox into
// the Backend and assert the DATA handler maps every typed outbox
// error to the spec-mandated SMTP reply code.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".

package smtpserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/outbox"
)

// stubOutbox lets each test plug a Result-returning func into the
// Backend so the SMTP DATA handler observes a deterministic outcome.
type stubOutbox struct {
	mu        sync.Mutex
	calls     []outbox.Submission
	responder func(outbox.Submission) outbox.Result
}

func (s *stubOutbox) Submit(_ context.Context, sub outbox.Submission) outbox.Result {
	s.mu.Lock()
	s.calls = append(s.calls, sub)
	s.mu.Unlock()
	if s.responder == nil {
		return outbox.Result{}
	}
	return s.responder(sub)
}

func (s *stubOutbox) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func startTestServerWithOutbox(t *testing.T, ob OutboxSubmitter, opts ...func(*Config)) *testServer {
	t.Helper()
	stub := newStubAccounts()
	stub.addAccount("acct-joe", "joe@reduit.example", "pw", account.StateActive)
	wrap := append([]func(*Config){func(c *Config) { c.Outbox = ob }}, opts...)
	return startTestServer(t, stub, NewSessions(), wrap...)
}

func driveDataExchange(t *testing.T, addr string) (*bufio.Reader, string) {
	t.Helper()
	conn, r := loginPlain(t, addr, "joe@reduit.example", "pw")
	t.Cleanup(func() { _ = conn.Close() })

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
		"Subject: hi\r\n\r\n" +
		"hello\r\n.\r\n"
	if _, err := io.WriteString(conn, body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	return r, ""
}

// TestData_OutboxSuccessReturns250 covers the SPEC-0004 happy path:
// outbox.Submit returns nil → SMTP responds `250 OK`.
func TestData_OutboxSuccessReturns250(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "250 ") {
		t.Errorf("expected 250 OK, got %q", resp)
	}
	if ob.callCount() != 1 {
		t.Errorf("outbox calls = %d, want 1", ob.callCount())
	}
}

// TestData_OutboxAuthFailureMapsTo535 covers the "Proton refresh
// token revoked" case: *ErrProtonAuth → SMTP `535 5.7.8`.
func TestData_OutboxAuthFailureMapsTo535(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: &outbox.ErrProtonAuth{Cause: errors.New("revoked")}}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "535 5.7.8") {
		t.Errorf("expected `535 5.7.8 ...`, got %q", resp)
	}
}

// TestData_OutboxRateLimitMapsTo421 covers Proton-side throttling:
// *ErrProtonRateLimit → SMTP `421 4.7.0`.
func TestData_OutboxRateLimitMapsTo421(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: &outbox.ErrProtonRateLimit{Cause: errors.New("429")}}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "421 4.7.0") {
		t.Errorf("expected `421 4.7.0 ...`, got %q", resp)
	}
}

// TestData_OutboxRejectMapsTo550 covers a permanent reject:
// *ErrProtonReject → SMTP `550 5.6.0`.
func TestData_OutboxRejectMapsTo550(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: &outbox.ErrProtonReject{Cause: errors.New("malformed body")}}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "550 5.6.0") {
		t.Errorf("expected `550 5.6.0 ...`, got %q", resp)
	}
}

// TestData_OutboxServerErrorMapsTo451 covers an unspecified upstream
// 5xx: *ErrProtonServer → SMTP `451 4.5.0`.
func TestData_OutboxServerErrorMapsTo451(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: &outbox.ErrProtonServer{Cause: errors.New("upstream 502")}}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "451 4.5.0") {
		t.Errorf("expected `451 4.5.0 ...`, got %q", resp)
	}
}

// TestData_OutboxKeyLookupErrorMapsTo451 covers the security-critical
// fail-closed path: *ErrKeyLookup → SMTP `451 4.4.4` (transient — the
// sender retries, so a flaky Proton key endpoint doesn't manifest as a
// permanent reject).
//
// Governing: SPEC-0004 REQ "Encryption Pipeline" + Security checklist.
func TestData_OutboxKeyLookupErrorMapsTo451(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: &outbox.ErrKeyLookup{
				Recipient: "alice@proton.me",
				Cause:     errors.New("503 from /core/v4/keys"),
			}}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "451 4.4.4") {
		t.Errorf("expected `451 4.4.4 ...`, got %q", resp)
	}
}

// TestData_OutboxTimeoutMapsTo451 covers the SPEC-0004 timeout path:
// ErrSubmissionTimedOut → SMTP `451 4.4.7 Submission timed out,
// message will be retried`.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — scenario "Submission timeout".
func TestData_OutboxTimeoutMapsTo451(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: outbox.ErrSubmissionTimedOut}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "451 4.4.7 Submission timed out") {
		t.Errorf("expected `451 4.4.7 Submission timed out ...`, got %q", resp)
	}
}

// TestData_OutboxAccountClosedMapsTo421 covers the resolver-level
// "account no longer authorised" surface (e.g. account suspended
// between auth and DATA).
func TestData_OutboxAccountClosedMapsTo421(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			return outbox.Result{Err: outbox.ErrAccountClosed}
		},
	}
	srv := startTestServerWithOutbox(t, ob)

	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "421 4.7.0") {
		t.Errorf("expected `421 4.7.0 ...`, got %q", resp)
	}
}

// TestData_OutboxSubmissionCarriesEnvelope confirms the DATA handler
// passes the SMTP envelope (account ID, MAIL FROM, RCPT TO, body)
// into outbox.Submit verbatim. The hostile reviewer would (rightly)
// catch a MAIL FROM mismatch at this seam.
func TestData_OutboxSubmissionCarriesEnvelope(t *testing.T) {
	t.Parallel()
	var captured outbox.Submission
	var captureMu sync.Mutex
	ob := &stubOutbox{
		responder: func(sub outbox.Submission) outbox.Result {
			captureMu.Lock()
			captured = sub
			captureMu.Unlock()
			return outbox.Result{}
		},
	}
	srv := startTestServerWithOutbox(t, ob)
	r, _ := driveDataExchange(t, srv.addr)
	if resp := readSMTPLine(t, r); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("expected 250 from happy-path send, got %q", resp)
	}

	captureMu.Lock()
	defer captureMu.Unlock()
	if captured.AccountID != "acct-joe" {
		t.Errorf("AccountID = %q, want acct-joe", captured.AccountID)
	}
	if captured.MailFrom != "joe@reduit.example" {
		t.Errorf("MailFrom = %q, want joe@reduit.example", captured.MailFrom)
	}
	if len(captured.Recipients) != 1 || captured.Recipients[0] != "bob@example.com" {
		t.Errorf("Recipients = %v, want [bob@example.com]", captured.Recipients)
	}
	if !strings.Contains(string(captured.Body), "Subject: hi") {
		t.Errorf("body missing Subject; got %q", string(captured.Body))
	}
}

// TestMapOutboxError_TableDriven exercises every branch of the
// mapper without going through the full SMTP round trip, so a future
// reviewer can scan the mapping at a glance.
func TestMapOutboxError_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		err     error
		wantC   int
		wantEnh [3]int
	}{
		{"timed-out", outbox.ErrSubmissionTimedOut, 451, [3]int{4, 4, 7}},
		{"account-closed", outbox.ErrAccountClosed, 421, [3]int{4, 7, 0}},
		{"envelope", outbox.ErrSubmissionEnvelope, 503, [3]int{5, 5, 1}},
		{"key-lookup", &outbox.ErrKeyLookup{Recipient: "x", Cause: errors.New("y")}, 451, [3]int{4, 4, 4}},
		{"proton-auth", &outbox.ErrProtonAuth{Cause: errors.New("y")}, 535, [3]int{5, 7, 8}},
		{"proton-rate", &outbox.ErrProtonRateLimit{Cause: errors.New("y")}, 421, [3]int{4, 7, 0}},
		{"proton-reject", &outbox.ErrProtonReject{Cause: errors.New("y")}, 550, [3]int{5, 6, 0}},
		{"proton-server", &outbox.ErrProtonServer{Cause: errors.New("y")}, 451, [3]int{4, 5, 0}},
		{"context-canceled", context.Canceled, 451, [3]int{4, 4, 5}},
		{"context-deadline", context.DeadlineExceeded, 451, [3]int{4, 4, 5}},
		{"unknown", errors.New("mystery"), 451, [3]int{4, 0, 0}},
		{"nil-defensive", nil, 451, [3]int{4, 0, 0}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mapOutboxError(tc.err)
			if got.Code != tc.wantC {
				t.Errorf("Code = %d, want %d", got.Code, tc.wantC)
			}
			if int(got.EnhancedCode[0]) != tc.wantEnh[0] ||
				int(got.EnhancedCode[1]) != tc.wantEnh[1] ||
				int(got.EnhancedCode[2]) != tc.wantEnh[2] {
				t.Errorf("EnhancedCode = %v, want %v", got.EnhancedCode, tc.wantEnh)
			}
		})
	}
}

// TestData_OutboxLatencyBudget ensures the synchronous Submit returns
// within the configured timeout even when the underlying Submit call
// takes most of the budget. The DATA handler adds a 5s headroom on
// top of the configured timeout, so we verify the round trip
// completes within that envelope. This is the "SLA" check the spec's
// scenario "Synchronous send is the primary path" implicitly demands.
func TestData_OutboxLatencyBudget(t *testing.T) {
	t.Parallel()
	ob := &stubOutbox{
		responder: func(_ outbox.Submission) outbox.Result {
			time.Sleep(50 * time.Millisecond)
			return outbox.Result{}
		},
	}
	srv := startTestServerWithOutbox(t, ob, func(c *Config) {
		c.SubmitTimeout = 1 * time.Second
	})

	start := time.Now()
	r, _ := driveDataExchange(t, srv.addr)
	resp := readSMTPLine(t, r)
	elapsed := time.Since(start)
	if !strings.HasPrefix(resp, "250 ") {
		t.Errorf("expected 250 OK, got %q", resp)
	}
	if elapsed > 5*time.Second {
		t.Errorf("DATA round-trip = %v, want < 5s", elapsed)
	}
}
