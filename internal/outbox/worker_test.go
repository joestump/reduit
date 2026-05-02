// Worker / Manager / Submit lifecycle tests. Cover the SPEC-0004
// scenarios: synchronous happy path, Proton failure mapping, timeout
// + clean goroutine unwind, per-account concurrency cap, cross-account
// independence.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation",
// SPEC-0004 REQ "Per-Account Outbox Concurrency Limit".

package outbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// stubResolver returns a single fixed proton.Client for every account.
// Tests that need per-account behaviour swap in a custom resolver.
type stubResolver struct {
	client proton.Client
	err    error
}

func (s stubResolver) ResolveClient(_ string) (proton.Client, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.client, nil
}

// recordingBuilder remembers every call so tests can assert on the
// per-recipient mode map and the order of submissions.
type recordingBuilder struct {
	mu    sync.Mutex
	calls []recordedCall

	// hold blocks Build until the supplied channel closes. Used by
	// concurrency / timeout tests.
	hold <-chan struct{}

	// sendErr is returned by the builder if non-nil (simulates a
	// downstream SendDraft failure surfaced through Build).
	sendErr error
}

type recordedCall struct {
	accountID string
	modes     map[string]EncryptionMode
}

func (b *recordingBuilder) Build(_ context.Context, sub Submission, modes map[string]EncryptionMode, _ proton.Client) (BuildResult, error) {
	if b.hold != nil {
		<-b.hold
	}
	b.mu.Lock()
	b.calls = append(b.calls, recordedCall{accountID: sub.AccountID, modes: modes})
	b.mu.Unlock()
	if b.sendErr != nil {
		return BuildResult{}, b.sendErr
	}
	// Test-only Skip: do not round-trip to a real Proton SendDraft.
	// A production Builder must return a real DraftID with Skip=false
	// so the worker calls SendDraft.
	return BuildResult{Skip: true}, nil
}

func (b *recordingBuilder) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

// alwaysInternalClient resolves every recipient as a Proton-internal
// recipient with one active key. Lets the worker tests exercise the
// happy-path SelectMode -> Build chain without requiring tests to
// configure per-recipient keys.
type alwaysInternalClient struct{ fakeProtonClient }

func (alwaysInternalClient) GetPublicKeys(_ context.Context, _ string) (proton.PublicKeys, proton.RecipientType, error) {
	return proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP"}}, proton.RecipientTypeInternal, nil
}

// rejectingClient returns a Proton-style 401 on every key lookup, used
// to drive the auth-failure-mapping test through the real classifier.
type rejectingClient struct {
	fakeProtonClient
	err error
}

func (r rejectingClient) GetPublicKeys(_ context.Context, _ string) (proton.PublicKeys, proton.RecipientType, error) {
	return nil, proton.RecipientTypeExternal, r.err
}

// silentLogger discards all logs so test output isn't littered.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	if cfg.Resolver == nil {
		cfg.Resolver = stubResolver{client: &alwaysInternalClient{}}
	}
	if cfg.Builder == nil {
		cfg.Builder = noopBuilder
	}
	if cfg.PendingStore == nil {
		cfg.PendingStore = DiscardPendingStore
	}
	if cfg.Logger == nil {
		cfg.Logger = silentLogger()
	}
	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("outbox.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = mgr.Shutdown(ctx)
	})
	return mgr
}

func happyPathSubmission() Submission {
	return Submission{
		AccountID:  "acct-1",
		MailFrom:   "joe@reduit.example",
		Recipients: []string{"alice@proton.me"},
		Body:       []byte("From: joe@reduit.example\r\nTo: alice@proton.me\r\nSubject: hi\r\n\r\nhello\r\n"),
	}
}

// TestSubmit_HappyPath: synchronous Submit returns success within the
// latency budget when the resolver hands back a healthy client and
// SelectMode resolves all recipients.
func TestSubmit_HappyPath(t *testing.T) {
	t.Parallel()
	builder := &recordingBuilder{}
	mgr := newTestManager(t, Config{
		Builder: builder,
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if res.Err != nil {
		t.Fatalf("Submit returned err: %v", res.Err)
	}
	if got, want := res.Modes["alice@proton.me"], ModeProtonE2E; got != want {
		t.Errorf("alice mode = %v, want ModeProtonE2E", got)
	}
	if builder.callCount() != 1 {
		t.Errorf("builder calls = %d, want 1", builder.callCount())
	}
}

// TestSubmit_ProtonKeyLookupErrorPropagates: Proton returns 401 from
// /core/v4/keys (simulating revoked refresh token). The selector
// fails closed with *ErrKeyLookup, but its CAUSE is a *proton.APIError
// whose Status=401. The session-side mapper handles auth-vs-key
// distinction; here we only verify the outbox surfaces the underlying
// *proton.APIError.
//
// The rejecting client wraps a *proton.APIError via fmt.Errorf("%w")
// — exactly the way upstream go-proton-api wraps. The errors.As target
// is *proton.APIError (pointer); see B1 in the hostile review.
func TestSubmit_ProtonKeyLookupErrorPropagates(t *testing.T) {
	t.Parallel()
	upstreamErr := fmt.Errorf("upstream: %w", &proton.APIError{Status: 401, Message: "Refresh token revoked"})
	mgr := newTestManager(t, Config{
		Resolver: stubResolver{client: &rejectingClient{err: upstreamErr}},
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if res.Err == nil {
		t.Fatal("Submit succeeded with rejecting client; expected err")
	}
	var keyErr *ErrKeyLookup
	if !errors.As(res.Err, &keyErr) {
		t.Fatalf("expected *ErrKeyLookup, got %T: %v", res.Err, res.Err)
	}
	var apiErr *proton.APIError
	if !errors.As(res.Err, &apiErr) || apiErr == nil {
		t.Fatalf("expected *proton.APIError in chain, got %v", res.Err)
	}
	if apiErr.Status != 401 {
		t.Errorf("APIError.Status = %d, want 401", apiErr.Status)
	}
}

// TestClassifySendDraftError_WrappedPointerAPIError covers the B1
// regression: go-proton-api returns *APIError (pointer) wrapped via
// fmt.Errorf("%w"), so classifySendDraftError MUST target *APIError —
// not APIError value — or every documented status falls through to
// *ErrProtonServer (451) and the SMTP code mapping the PR body
// advertises is silently broken on the wire.
//
// Each case wraps a *proton.APIError exactly the way the upstream
// library does and asserts the typed Reduit error (and therefore the
// SMTP code mapping at the session layer) is correct.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — error code mapping must reflect Proton's wire status,
// not collapse to a generic 451.
func TestClassifySendDraftError_WrappedPointerAPIError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		status      int
		message     string
		wantTyped   func(error) bool
		wantSMTPHi  int // hundreds digit of the SMTP code (5/4)
		wantSMTPLow int // last two digits (35/21/50/51 etc.)
	}{
		{
			name:    "401-revoked-token-535",
			status:  401,
			message: "Refresh token revoked",
			wantTyped: func(err error) bool {
				var auth *ErrProtonAuth
				return errors.As(err, &auth)
			},
			wantSMTPHi:  535,
			wantSMTPLow: 0,
		},
		{
			name:    "403-forbidden-535",
			status:  403,
			message: "Forbidden",
			wantTyped: func(err error) bool {
				var auth *ErrProtonAuth
				return errors.As(err, &auth)
			},
			wantSMTPHi:  535,
			wantSMTPLow: 0,
		},
		{
			name:    "429-rate-limit-421",
			status:  429,
			message: "Too many requests",
			wantTyped: func(err error) bool {
				var rate *ErrProtonRateLimit
				return errors.As(err, &rate)
			},
			wantSMTPHi:  421,
			wantSMTPLow: 0,
		},
		{
			name:    "422-permanent-reject-550",
			status:  422,
			message: "Recipient invalid",
			wantTyped: func(err error) bool {
				var rej *ErrProtonReject
				return errors.As(err, &rej)
			},
			wantSMTPHi:  550,
			wantSMTPLow: 0,
		},
		{
			name:    "502-server-error-451",
			status:  502,
			message: "Bad gateway",
			wantTyped: func(err error) bool {
				var srv *ErrProtonServer
				return errors.As(err, &srv)
			},
			wantSMTPHi:  451,
			wantSMTPLow: 0,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Wrap exactly as go-proton-api does: a *APIError pointer
			// inside a fmt.Errorf("%w") chain (see upstream
			// response.go around line 110). A value-typed errors.As
			// target on this chain silently misses, falling through
			// to *ErrProtonServer.
			upstream := fmt.Errorf("upstream: %w", &proton.APIError{Status: tc.status, Message: tc.message})
			classified := classifySendDraftError(upstream)
			if !tc.wantTyped(classified) {
				t.Fatalf("classifySendDraftError(%d) = %T %v; expected typed match", tc.status, classified, classified)
			}
		})
	}
}

// TestSubmit_BuilderFailureMapsToReject: a Builder that returns an
// error surfaces as *ErrProtonReject. The session-side mapper then
// turns that into a 550.
func TestSubmit_BuilderFailureMapsToReject(t *testing.T) {
	t.Parallel()
	builder := &recordingBuilder{sendErr: errors.New("malformed MIME")}
	mgr := newTestManager(t, Config{
		Builder: builder,
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if res.Err == nil {
		t.Fatal("Submit succeeded with failing builder; expected err")
	}
	var reject *ErrProtonReject
	if !errors.As(res.Err, &reject) {
		t.Fatalf("expected *ErrProtonReject, got %T: %v", res.Err, res.Err)
	}
}

// TestSubmit_ResolverAuthFailureMapsToProtonAuth: a resolver that
// returns proton.ErrNotAuthenticated surfaces as *ErrProtonAuth so the
// session layer maps it to 535.
func TestSubmit_ResolverAuthFailureMapsToProtonAuth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t, Config{
		Resolver: stubResolver{err: proton.ErrNotAuthenticated},
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if res.Err == nil {
		t.Fatal("Submit succeeded with auth-failing resolver; expected err")
	}
	var authErr *ErrProtonAuth
	if !errors.As(res.Err, &authErr) {
		t.Fatalf("expected *ErrProtonAuth, got %T: %v", res.Err, res.Err)
	}
}

// TestSubmit_ResolverAccountClosedPropagates verifies a resolver-level
// ErrAccountClosed is returned as-is so the session-side mapper picks
// the 421 (drop-the-channel) reply.
func TestSubmit_ResolverAccountClosedPropagates(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t, Config{
		Resolver: stubResolver{err: ErrAccountClosed},
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if !errors.Is(res.Err, ErrAccountClosed) {
		t.Errorf("err = %v, want ErrAccountClosed", res.Err)
	}
}

// TestSubmit_TimeoutDoesNotLeakGoroutine: a hanging upstream call must
// fire the configured timeout, surface ErrSubmissionTimedOut to the
// caller, write an audit row to PendingStore (status=timeout_failed),
// and let the in-flight child goroutine unwind cleanly when its hold
// releases. There is NO Reduit-side retry — the sender's MTA retries
// the SMTP submission per RFC 5321.
//
// Companion goleak coverage in TestMain catches a leaked child
// goroutine that fails to observe the cancelled subCtx and never exits.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — synchronous-first, no Reduit-side retry.
func TestSubmit_TimeoutDoesNotLeakGoroutine(t *testing.T) {
	t.Parallel()
	releaseHold := make(chan struct{})
	pending := &recordingPendingStore{}
	mgr := newTestManager(t, Config{
		Resolver:      stubResolver{client: &alwaysInternalClient{}},
		Builder:       &recordingBuilder{hold: releaseHold},
		PendingStore:  pending,
		SubmitTimeout: 50 * time.Millisecond,
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if !errors.Is(res.Err, ErrSubmissionTimedOut) {
		t.Fatalf("expected ErrSubmissionTimedOut, got %v", res.Err)
	}

	// Audit row is written best-effort, off the synchronous path. Wait
	// briefly for it to land so the assertion is deterministic.
	deadline := time.Now().Add(2 * time.Second)
	for pending.failedCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("PendingStore.failed never recorded after timeout; resolved=%d",
				pending.resolvedCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Release the hold so the child goroutine can finish and the
	// per-account semaphore slot is released. Without this the worker
	// shutdown in t.Cleanup would block, and goleak (TestMain) would
	// flag the surviving goroutine.
	close(releaseHold)
}

// TestSubmit_PerAccountConcurrencyCap: with cap=2, four concurrent
// submissions for one account should result in at most 2 in-flight
// builder calls at any moment. The 3rd and 4th wait for an in-flight
// call to drain.
func TestSubmit_PerAccountConcurrencyCap(t *testing.T) {
	t.Parallel()
	releaseHold := make(chan struct{})
	builder := &concurrencyBuilder{hold: releaseHold}
	mgr := newTestManager(t, Config{
		Resolver:      stubResolver{client: &alwaysInternalClient{}},
		Builder:       builder,
		PerAccountCap: 2,
		SubmitTimeout: 5 * time.Second,
	})

	const submissions = 4
	resCh := make(chan Result, submissions)
	for i := 0; i < submissions; i++ {
		go func() {
			resCh <- mgr.Submit(context.Background(), happyPathSubmission())
		}()
	}

	// Wait for the cap to saturate.
	deadline := time.Now().Add(2 * time.Second)
	for builder.inflightPeak() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("builder peak inflight = %d, want >= 2", builder.inflightPeak())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Confirm we never exceeded the cap.
	if peak := builder.inflightPeak(); peak > 2 {
		t.Errorf("inflight peak = %d, exceeds cap=2", peak)
	}
	if peak := builder.inflightCurrent(); peak > 2 {
		t.Errorf("current inflight = %d, exceeds cap=2", peak)
	}

	// Release everyone and reap.
	close(releaseHold)
	for i := 0; i < submissions; i++ {
		select {
		case r := <-resCh:
			if r.Err != nil {
				t.Errorf("submission %d failed: %v", i, r.Err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("submission %d did not complete", i)
		}
	}

	if peak := builder.inflightPeak(); peak > 2 {
		t.Errorf("final peak = %d, exceeds cap=2", peak)
	}
}

// TestSubmit_CrossAccountIsolation: cap=2 per account, but five
// accounts each sending one submission run in parallel — the cap is
// per-account, not global, so all five proceed concurrently.
func TestSubmit_CrossAccountIsolation(t *testing.T) {
	t.Parallel()
	releaseHold := make(chan struct{})
	builder := &concurrencyBuilder{hold: releaseHold}
	mgr := newTestManager(t, Config{
		Resolver:      stubResolver{client: &alwaysInternalClient{}},
		Builder:       builder,
		PerAccountCap: 2,
		SubmitTimeout: 5 * time.Second,
	})

	const accounts = 5
	resCh := make(chan Result, accounts)
	for i := 0; i < accounts; i++ {
		i := i
		go func() {
			sub := happyPathSubmission()
			sub.AccountID = "acct-" + string(rune('a'+i))
			resCh <- mgr.Submit(context.Background(), sub)
		}()
	}

	// Wait for all five to be in flight (proves no cross-account cap).
	deadline := time.Now().Add(2 * time.Second)
	for builder.inflightCurrent() < accounts {
		if time.Now().After(deadline) {
			t.Fatalf("inflight = %d, want %d", builder.inflightCurrent(), accounts)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := mgr.activeWorkerCount(); got != accounts {
		t.Errorf("activeWorkerCount = %d, want %d", got, accounts)
	}

	close(releaseHold)
	for i := 0; i < accounts; i++ {
		select {
		case r := <-resCh:
			if r.Err != nil {
				t.Errorf("account %d failed: %v", i, r.Err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("account %d did not complete", i)
		}
	}
}

// TestSubmit_EnvelopeValidation rejects malformed submissions with
// ErrSubmissionEnvelope before any upstream call.
func TestSubmit_EnvelopeValidation(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t, Config{})

	cases := []struct {
		name string
		sub  Submission
	}{
		{"missing-account-id", Submission{MailFrom: "x", Recipients: []string{"y"}, Body: []byte("z")}},
		{"missing-mail-from", Submission{AccountID: "a", Recipients: []string{"y"}, Body: []byte("z")}},
		{"empty-recipients", Submission{AccountID: "a", MailFrom: "x", Body: []byte("z")}},
		{"empty-body", Submission{AccountID: "a", MailFrom: "x", Recipients: []string{"y"}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := mgr.Submit(context.Background(), tc.sub)
			if !errors.Is(res.Err, ErrSubmissionEnvelope) {
				t.Errorf("err = %v, want ErrSubmissionEnvelope", res.Err)
			}
		})
	}
}

// TestNewRejectsNilBuilder confirms outbox.New refuses to construct a
// Manager without a Builder. The previous "nil Builder OR NoopBuilder
// = silent 250 OK" path was the worst failure mode the hostile review
// flagged; the constructor's fail-loud guard is the structural fix.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — silent-success guard.
func TestNewRejectsNilBuilder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil-resolver", Config{
			Builder:      noopBuilder,
			PendingStore: DiscardPendingStore,
		}},
		{"nil-builder", Config{
			Resolver:     stubResolver{client: &alwaysInternalClient{}},
			PendingStore: DiscardPendingStore,
		}},
		{"nil-pending-store", Config{
			Resolver: stubResolver{client: &alwaysInternalClient{}},
			Builder:  noopBuilder,
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mgr, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New accepted nil-required field; mgr=%v", mgr)
			}
		})
	}
}

// TestWorker_BuilderEmptyDraftIDFailsLoud covers the silent-success
// guard inside the worker: a Builder that returns BuildResult{}
// (DraftID="" and Skip=false) is a programming error and MUST surface
// as a hard error rather than short-circuit to a fake 250 OK.
// Implemented as a panic-and-recover so the worker goroutine cannot
// crash the process; the recovered panic is mapped to *ErrProtonReject
// (SMTP 550) so the sender does not retry the misconfigured wiring.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — fail loud at the worker boundary.
func TestWorker_BuilderEmptyDraftIDFailsLoud(t *testing.T) {
	t.Parallel()
	badBuilder := BuilderFunc(func(_ context.Context, _ Submission, _ map[string]EncryptionMode, _ proton.Client) (BuildResult, error) {
		return BuildResult{}, nil // empty DraftID, Skip=false → footgun
	})
	mgr := newTestManager(t, Config{
		Resolver: stubResolver{client: &alwaysInternalClient{}},
		Builder:  badBuilder,
	})

	res := mgr.Submit(context.Background(), happyPathSubmission())
	if res.Err == nil {
		t.Fatal("Submit returned nil error for empty-DraftID Builder; expected fail-loud")
	}
	var reject *ErrProtonReject
	if !errors.As(res.Err, &reject) {
		t.Fatalf("expected *ErrProtonReject, got %T: %v", res.Err, res.Err)
	}
}

// TestManagerShutdown blocks Submit calls after Shutdown.
func TestManagerShutdown(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	res := mgr.Submit(context.Background(), happyPathSubmission())
	if !errors.Is(res.Err, ErrAccountClosed) {
		t.Errorf("post-shutdown Submit err = %v, want ErrAccountClosed", res.Err)
	}
}

// TestSubmit_ContextHangIsBoundedByTimeout: an upstream call that
// hangs through the deadline MUST cause Submit to return within a
// strict multiple of SubmitTimeout, not block forever. Bounded means:
// elapsed < 4×SubmitTimeout (generous slack for scheduling on a busy
// CI runner; the median is ~1×).
//
// The error MUST be ErrSubmissionTimedOut specifically: the SMTP
// mapping for 451 4.4.7 (timeout) is different from 451 4.4.4
// (key-lookup), and a sender's MTA may track these distinctly. Per
// the hostile reviewer (concern 10), the "fail-closed in time" SLA
// dictates the kind of failure as well as the latency.
//
// We hang the Builder (not the key lookup) so the run goroutine is
// blocked past key-lookup when subCtx fires; that way the parent
// select on subCtx.Done() deterministically wins the race against
// resultCh and produces ErrSubmissionTimedOut, not *ErrKeyLookup.
func TestSubmit_ContextHangIsBoundedByTimeout(t *testing.T) {
	t.Parallel()
	const timeout = 100 * time.Millisecond
	releaseHold := make(chan struct{})
	mgr := newTestManager(t, Config{
		Resolver:      stubResolver{client: &alwaysInternalClient{}},
		Builder:       &recordingBuilder{hold: releaseHold},
		SubmitTimeout: timeout,
	})
	t.Cleanup(func() { close(releaseHold) })

	start := time.Now()
	res := mgr.Submit(context.Background(), happyPathSubmission())
	elapsed := time.Since(start)

	// Quantitative bound: 4× the configured SubmitTimeout. The
	// synchronous path returns at ~1× timeout; the 4× margin tolerates
	// scheduler jitter on a -race runner.
	if max := 4 * timeout; elapsed > max {
		t.Errorf("Submit took %v, want < %v (timeout=%v)", elapsed, max, timeout)
	}
	// Tighter than "any of two errors": the 451 4.4.7 mapping requires
	// the ErrSubmissionTimedOut sentinel specifically. *ErrKeyLookup
	// from a SelectMode-side ctx-cancel would map to 451 4.4.4 and
	// mislead the sender.
	if !errors.Is(res.Err, ErrSubmissionTimedOut) {
		t.Errorf("err = %v, want ErrSubmissionTimedOut", res.Err)
	}
}

// recordingPendingStore counts RecordTimeout calls so the timeout test
// can wait for the audit row to land. The `resolved` counter is kept
// (always zero now) so a future regression that resurrects the
// background-retry path would surface as a non-zero resolved count.
type recordingPendingStore struct {
	mu       sync.Mutex
	failed   int
	resolved int
}

func (r *recordingPendingStore) RecordTimeout(_ context.Context, _ Submission, _ error) error {
	r.mu.Lock()
	r.failed++
	r.mu.Unlock()
	return nil
}

func (r *recordingPendingStore) failedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

func (r *recordingPendingStore) resolvedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolved
}

// concurrencyBuilder counts in-flight Build calls so the
// concurrency-cap test can assert the cap is enforced. Calls block
// until the supplied hold channel closes.
type concurrencyBuilder struct {
	hold     <-chan struct{}
	inflight atomic.Int32
	peak     atomic.Int32
}

func (b *concurrencyBuilder) Build(_ context.Context, _ Submission, _ map[string]EncryptionMode, _ proton.Client) (BuildResult, error) {
	now := b.inflight.Add(1)
	defer b.inflight.Add(-1)
	for {
		peak := b.peak.Load()
		if now <= peak {
			break
		}
		if b.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	<-b.hold
	return BuildResult{Skip: true}, nil
}

func (b *concurrencyBuilder) inflightPeak() int {
	return int(b.peak.Load())
}

func (b *concurrencyBuilder) inflightCurrent() int {
	return int(b.inflight.Load())
}
