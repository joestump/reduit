package mcpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/mcpserver"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// TestPerAccountConcurrencyFromEnv covers the env-var override seam:
// empty / invalid / non-positive values fall back to the default;
// valid positive integers parse cleanly.
func TestPerAccountConcurrencyFromEnv(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", mcpserver.DefaultPerAccountConcurrency},
		{"abc", mcpserver.DefaultPerAccountConcurrency},
		{"0", mcpserver.DefaultPerAccountConcurrency},
		{"-1", mcpserver.DefaultPerAccountConcurrency},
		{"7", 7},
		{"  3  ", mcpserver.DefaultPerAccountConcurrency}, // strconv.Atoi rejects whitespace
	} {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got := mcpserver.PerAccountConcurrencyFromEnv(func(k string) string {
				if k == mcpserver.EnvPerAccountConcurrency {
					return tc.raw
				}
				return ""
			})
			if got != tc.want {
				t.Errorf("PerAccountConcurrencyFromEnv(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

// TestConcurrencyLimiter_NoLimiter sanity-checks the test seam:
// NoLimiter() never blocks and never returns an error.
func TestConcurrencyLimiter_NoLimiter(t *testing.T) {
	t.Parallel()
	l := mcpserver.NoLimiter()
	for i := 0; i < 100; i++ {
		release, err := l.Acquire(context.Background(), "any")
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		release()
	}
}

// TestConcurrencyLimiter_DirectOverflow exercises the limiter via its
// public Go API rather than through HTTP, so we don't depend on
// goroutine-scheduling timing to prove the cap+queue overflow shape.
// Synchronous Acquire calls drive the limiter to exact saturation,
// then a non-blocking Acquire call (via a context that's already
// cancelled? no -- via a pre-counted exhaustion path) is asserted to
// return errOverflow. We can't import the unexported errOverflow, so
// we assert on the resulting HTTP shape elsewhere; here we just
// confirm the cap+queue boundary.
//
// Governing: SPEC-0006 REQ "Per-Account Concurrency Limit".
func TestConcurrencyLimiter_DirectOverflow(t *testing.T) {
	t.Parallel()
	const cap = 3
	const queueDepth = 5

	l := mcpserver.NewConcurrencyLimiter(cap, queueDepth)

	// Fill the in-flight cap with synchronous Acquires. Each is a
	// real successful acquisition; defer release() ensures we don't
	// hold them past the test.
	releases := make([]func(), 0, cap+queueDepth)
	for i := 0; i < cap; i++ {
		rel, err := l.Acquire(context.Background(), "acct-x")
		if err != nil {
			t.Fatalf("in-flight Acquire %d: %v", i, err)
		}
		releases = append(releases, rel)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	// Fill the queue. These won't return until we release an
	// in-flight slot, so launch them in goroutines and wait until
	// each is observably blocked. We use a short-deadline context
	// in a separate goroutine because Acquire blocks synchronously
	// on the slot channel; for the queueing assertion we DON'T want
	// a deadline (we want to observe that they got past the
	// reservation send). Instead, we fire the goroutines, then
	// observe via the next overflow Acquire.
	queued := make(chan func(), queueDepth)
	for i := 0; i < queueDepth; i++ {
		go func() {
			rel, err := l.Acquire(context.Background(), "acct-x")
			if err == nil {
				queued <- rel
			}
		}()
	}

	// Coarse wait for goroutines to reach the reservation send.
	// time.Sleep is enough here because reservation send is
	// non-blocking and goroutine scheduling on a quiescent test
	// runner happens in microseconds. We keep this generous (250ms)
	// for race-detector overhead.
	time.Sleep(250 * time.Millisecond)

	// One more Acquire MUST overflow.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rel, err := l.Acquire(ctx, "acct-x")
	if err == nil {
		// We got a slot we shouldn't have -- release it so the
		// test cleanup doesn't hang, then fail.
		rel()
		t.Fatalf("Acquire succeeded past cap+queue; expected overflow")
	}
	// errOverflow is unexported. We can distinguish it from
	// context errors by checking that ctx.Err() is nil at the
	// point Acquire returned -- the limiter should have returned
	// immediately, not waited for the deadline.
	if ctx.Err() != nil {
		t.Fatalf("Acquire returned %v but context also expired (%v); we wanted a non-blocking overflow", err, ctx.Err())
	}

	// Drain: release one in-flight slot, expect one queued goroutine
	// to make progress.
	releases[0]()
	releases = releases[1:]
	select {
	case rel := <-queued:
		releases = append(releases, rel)
	case <-time.After(time.Second):
		t.Fatalf("queued goroutine did not progress after slot release")
	}
}

// TestMCPConcurrency_CapAndOverflow exercises SPEC-0006 REQ
// "Per-Account Concurrency Limit" end-to-end:
//
//   - The first `cap` concurrent requests succeed (in-flight cap).
//   - The next `queueDepth` requests queue.
//   - The (`cap`+`queueDepth`+1)th overflows -- 503 with Retry-After: 5.
//
// A blocking terminal handler holds requests open until the test
// closes a release channel, so we can pin the limiter at exact
// occupancy levels without racing on real Proton calls.
//
// Governing: SPEC-0006 REQ "Per-Account Concurrency Limit".
func TestMCPConcurrency_CapAndOverflow(t *testing.T) {
	t.Parallel()
	const cap = 4
	const queueDepth = 16

	f := newConcurrencyFixture(t, cap, queueDepth)
	defer f.close()
	const acctID = "acct-cc-1"
	storetest.SeedUserAccountActive(t, f.st, acctID)

	tok, err := f.tokens.Issue(context.Background(), mcptoken.IssueParams{AccountID: acctID})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	f.terminal.Store(makeBlockingTerminal(t, release))

	// Saturate the in-flight cap.
	for i := 0; i < cap; i++ {
		go f.firePost(tok.Plaintext)
	}
	if !waitFor(t, time.Second, func() bool {
		return f.terminal.entered() >= cap
	}) {
		t.Fatalf("only %d of %d in-flight requests reached the terminal", f.terminal.entered(), cap)
	}

	// Saturate the queue. We fire `queueDepth` requests, then wait
	// until the limiter reports the reservation channel is at
	// `cap+queueDepth` -- both phases of capacity (in-flight + queue)
	// fully occupied. Polling the limiter directly is more reliable
	// than time.Sleep: the race detector's scheduling jitter would
	// otherwise make a fixed sleep flaky.
	for i := 0; i < queueDepth; i++ {
		go f.firePost(tok.Plaintext)
	}
	if !waitFor(t, 2*time.Second, func() bool {
		return mcpserver.ReservationCount(f.limiter, acctID) >= cap+queueDepth
	}) {
		t.Fatalf("limiter reservations = %d, want >= %d (cap+queue)",
			mcpserver.ReservationCount(f.limiter, acctID), cap+queueDepth)
	}

	// Hard assertion that no queued request leaked into the
	// terminal while the cap is saturated. Reservation parity above
	// implies in-flight count == cap, so terminal.entered() should
	// equal cap exactly.
	if got := f.terminal.entered(); got != cap {
		t.Fatalf("queued requests leaked into the terminal: entered=%d, want %d", got, cap)
	}

	// Now an overflow probe MUST get 503 -- the reservation channel
	// is full so Acquire returns errOverflow synchronously.
	overflowReq, err := http.NewRequest(http.MethodPost, f.srv.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	overflowReq.Header.Set("Authorization", "Bearer "+tok.Plaintext)
	overflowReq.Header.Set("Content-Type", "application/json")
	overflowReq.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(overflowReq)
	if err != nil {
		t.Fatalf("overflow Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("overflow status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want 5", got)
	}
}

// TestMCPConcurrency_PerAccountIsolated proves the cap is per-account
// rather than global: account B can saturate its own cap even while
// account A's cap is fully occupied.
func TestMCPConcurrency_PerAccountIsolated(t *testing.T) {
	t.Parallel()
	const cap = 2
	const queueDepth = 4

	f := newConcurrencyFixture(t, cap, queueDepth)
	defer f.close()

	const acctA = "acct-iso-cap-A"
	const acctB = "acct-iso-cap-B"
	storetest.SeedUserAccountActive(t, f.st, acctA)
	storetest.SeedUserAccountActive(t, f.st, acctB)

	ctx := context.Background()
	tokA, err := f.tokens.Issue(ctx, mcptoken.IssueParams{AccountID: acctA})
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	tokB, err := f.tokens.Issue(ctx, mcptoken.IssueParams{AccountID: acctB})
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}

	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	f.terminal.Store(makeBlockingTerminal(t, release))

	// Saturate account A.
	for i := 0; i < cap; i++ {
		go f.firePost(tokA.Plaintext)
	}
	if !waitFor(t, time.Second, func() bool { return f.terminal.entered() >= cap }) {
		t.Fatalf("A did not saturate; entered=%d", f.terminal.entered())
	}

	// Account B should still be able to enter the terminal because
	// the cap is per-account.
	for i := 0; i < cap; i++ {
		go f.firePost(tokB.Plaintext)
	}
	if !waitFor(t, time.Second, func() bool { return f.terminal.entered() >= 2*cap }) {
		t.Fatalf("B was blocked by A's saturation; entered=%d, want %d", f.terminal.entered(), 2*cap)
	}
}

// --- concurrency fixture ---

type ccFixture struct {
	st       *store.Store
	tokens   *mcptoken.Repository
	srv      *httptest.Server
	terminal *swappableTerminal
	limiter  mcpserver.Limiter
}

func (f *ccFixture) close() { f.st.Close() }

func (f *ccFixture) firePost(bearer string) {
	req, err := http.NewRequest(http.MethodPost, f.srv.URL, strings.NewReader(`{}`))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func newConcurrencyFixture(t *testing.T, cap, queueDepth int) *ccFixture {
	t.Helper()
	st := openTempStore(t)
	tokens := mcptoken.NewRepository(st.DB)
	validator := auth.NewBearerValidator(nil, tokens)

	terminal := &swappableTerminal{}
	limiter := mcpserver.NewConcurrencyLimiter(cap, queueDepth)

	mcpSrv := mcpserver.NewWithTerminal(mcpserver.Deps{
		Validator: validator,
		Accounts:  &fakeAccountsAlwaysActive{},
		Limiter:   limiter,
	}, terminal)

	srv := httptest.NewServer(mcpSrv.Handler())
	t.Cleanup(srv.Close)

	return &ccFixture{
		st:       st,
		tokens:   tokens,
		srv:      srv,
		terminal: terminal,
		limiter:  limiter,
	}
}

// swappableTerminal lets each concurrency test install a different
// downstream handler (typically a blocking one). The atomic
// indirection plus a RWMutex prevents data races on the shared
// fixture state.
type swappableTerminal struct {
	mu       sync.RWMutex
	current  http.Handler
	enteredN atomic.Int32
}

func (s *swappableTerminal) Store(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = h
	s.enteredN.Store(0)
}

func (s *swappableTerminal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.current
	s.mu.RUnlock()
	s.enteredN.Add(1)
	if h == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	h.ServeHTTP(w, r)
}

func (s *swappableTerminal) entered() int { return int(s.enteredN.Load()) }

// makeBlockingTerminal returns an http.Handler that blocks until
// release closes (or the request context cancels). Used to pin the
// limiter at a known concurrency state.
func makeBlockingTerminal(t *testing.T, release <-chan struct{}) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Errorf("blocking terminal still pinned after 5s -- test forgot to close release")
		}
		w.WriteHeader(http.StatusOK)
	})
}

// waitFor polls cond until it returns true or deadline expires. Used
// to synchronise tests against the limiter's internal state without
// hard-coded sleeps.
func waitFor(t *testing.T, deadline time.Duration, cond func() bool) bool {
	t.Helper()
	start := time.Now()
	for time.Since(start) < deadline {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// fakeAccountsAlwaysActive is the minimal account.Service stub the
// concurrency tests need: GetByID always returns an active account
// whose ID matches the requested ID. Other methods panic so a future
// test reaching for one fails loudly rather than silently no-op'ing.
type fakeAccountsAlwaysActive struct{}

func (f *fakeAccountsAlwaysActive) GetByID(_ context.Context, id string) (*account.Account, error) {
	return &account.Account{ID: id, State: account.StateActive, UserID: "user-" + id}, nil
}

func (f *fakeAccountsAlwaysActive) Create(context.Context, account.CreateParams) (*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) Transition(context.Context, string, account.State) (*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) List(context.Context) ([]*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) ListByUser(context.Context, string) ([]*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) Delete(context.Context, string) (*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SealRefreshToken(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) OpenRefreshToken(context.Context, string) ([]byte, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) UpdateRefreshToken(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SealMailboxPassphrase(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) OpenMailboxPassphrase(context.Context, string) ([]byte, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SealSessionUID(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) OpenSessionUID(context.Context, string) (string, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SealIMAPPassword(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) OpenIMAPPassword(context.Context, string) ([]byte, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) RotateIMAPPassword(context.Context, string) (string, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) VerifyIMAPPassword(context.Context, string, []byte) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) OnTransition(account.TransitionCallback) func() {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) GetByPrimaryAlias(context.Context, string) (*account.Account, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SetPrimaryAlias(context.Context, string, string) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SetProtonIdentity(context.Context, string, string, string, string) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) GetSyncState(context.Context, string) (*account.SyncState, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SetSyncState(context.Context, string, string, account.SyncStateTxWork) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) SoftDeleteOldPending(context.Context, time.Duration) (int64, error) {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) MarkCrashed(context.Context, string) error {
	panic("not implemented")
}
func (f *fakeAccountsAlwaysActive) RewrapEnvelopes(context.Context, cryptenv.MasterKey) (int, error) {
	panic("not implemented")
}
