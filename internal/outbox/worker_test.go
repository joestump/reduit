// Worker / Manager / Submit lifecycle tests. Cover the SPEC-0004
// scenarios: synchronous happy path, Proton failure mapping, timeout
// + background retry, per-account concurrency cap, cross-account
// independence.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation",
// SPEC-0004 REQ "Per-Account Outbox Concurrency Limit".

package outbox

import (
	"context"
	"errors"
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
	return BuildResult{}, nil
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
	return proton.PublicKeys{{Flags: proton.KeyStateActive, PublicKey: "PGP"}}, proton.RecipientTypeInternal, nil
}

// hangingClient blocks GetPublicKeys until ctx is cancelled. Used by
// the timeout test.
type hangingClient struct{ fakeProtonClient }

func (hangingClient) GetPublicKeys(ctx context.Context, _ string) (proton.PublicKeys, proton.RecipientType, error) {
	<-ctx.Done()
	return nil, proton.RecipientTypeExternal, ctx.Err()
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
		cfg.Builder = NoopBuilder
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

// TestSubmit_ProtonAuthFailureMapsTo535: Proton returns 401 from
// /core/v4/keys (simulating revoked refresh token). The selector
// fails closed with *ErrKeyLookup, but its CAUSE is a *proton.APIError
// whose Status=401. The session-side mapper handles auth-vs-key
// distinction; here we only verify the outbox surfaces the underlying
// *proton.APIError.
func TestSubmit_ProtonKeyLookupErrorPropagates(t *testing.T) {
	t.Parallel()
	upstreamErr := proton.APIError{Status: 401, Message: "Refresh token revoked"}
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
	var apiErr proton.APIError
	if !errors.As(res.Err, &apiErr) {
		t.Fatalf("expected proton.APIError in chain, got %v", res.Err)
	}
	if apiErr.Status != 401 {
		t.Errorf("APIError.Status = %d, want 401", apiErr.Status)
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

// TestSubmit_TimeoutReturns451AndDetachesBackgroundRetry: a hanging
// upstream call must fire the configured timeout, surface
// ErrSubmissionTimedOut to the caller, and continue the upstream call
// in the background. The PendingStore should observe a recorded
// timeout when the background call eventually completes.
func TestSubmit_TimeoutReturns451AndDetachesBackgroundRetry(t *testing.T) {
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

	// Background goroutine is still running. Releasing the hold
	// causes Build to return success → PendingStore observes a
	// resolved-after-timeout record.
	close(releaseHold)
	deadline := time.Now().Add(2 * time.Second)
	for pending.resolvedCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("PendingStore.resolved never recorded; failed=%d", pending.failedCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
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

// TestSubmit_ContextHangIsBoundedByTimeout: a hangingClient (which
// blocks GetPublicKeys until its ctx is cancelled) MUST cause Submit
// to return within ~SubmitTimeout, not block forever. This is the
// "submission timed out" SLA.
func TestSubmit_ContextHangIsBoundedByTimeout(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t, Config{
		Resolver:      stubResolver{client: &hangingClient{}},
		SubmitTimeout: 100 * time.Millisecond,
	})

	start := time.Now()
	res := mgr.Submit(context.Background(), happyPathSubmission())
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("Submit took %v, want < 1s (timeout=100ms)", elapsed)
	}
	// Either the submission timed out (preferred) or the context-
	// cancel from SelectMode bubbled up as *ErrKeyLookup. Both are
	// "fail-closed in time" outcomes; assert one of them.
	if !errors.Is(res.Err, ErrSubmissionTimedOut) {
		var keyErr *ErrKeyLookup
		if !errors.As(res.Err, &keyErr) {
			t.Errorf("err = %v, want ErrSubmissionTimedOut or *ErrKeyLookup", res.Err)
		}
	}
}

// recordingPendingStore keeps a count of every Record* call so the
// timeout test can wait for the background retry's outcome to land.
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

func (r *recordingPendingStore) RecordTimeoutResolved(_ context.Context, _ Submission) error {
	r.mu.Lock()
	r.resolved++
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
	return BuildResult{}, nil
}

func (b *concurrencyBuilder) inflightPeak() int {
	return int(b.peak.Load())
}

func (b *concurrencyBuilder) inflightCurrent() int {
	return int(b.inflight.Load())
}
