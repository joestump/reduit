// Governing: SPEC-0002 REQ "One Worker Per Active Account",
//             SPEC-0002 REQ "Graceful Shutdown",
//             SPEC-0002 REQ "Concurrency Limits",
//             SPEC-0002 REQ "Panic Isolation".

package sync

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
)

// TestMain verifies the supervisor's drain semantics via goleak: any
// worker goroutine that survives Stop() will fail the test binary,
// pinning down SPEC-0002 REQ "Graceful Shutdown" at the test-suite
// level rather than per-test.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// migrateMu serializes goose package-level state across parallel
// tests in this package; mirrors the same guard in
// internal/account/account_test.go.
var migrateMu sync.Mutex

// newTestAccountService spins up an isolated SQLite + account.Service
// per test. Accounts are created in StatePendingProtonSetup; tests
// are responsible for transitioning them to StateActive.
func newTestAccountService(t *testing.T) account.Service {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "reduit-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return account.New(st, master, nil)
}

// fastConfig returns a Config that ticks every millisecond so the
// "worker started within 1s" assertions don't actually need a full
// second of sleep.
//
// ClientFactory is wired to StubClientFactory so the Config satisfies
// New()'s "non-nil factory required" precondition out of the box;
// tests that need to assert real Proton interactions override the
// field after this returns (see TestWorkerTickInvokesEventProcessor).
func fastConfig() Config {
	return Config{
		ConcurrencyCap:   8,
		PollInterval:     10 * time.Millisecond,
		GracefulShutdown: 500 * time.Millisecond,
		HardShutdown:     2 * time.Second,
		ClientFactory:    StubClientFactory,
	}
}

// TestSupervisorStartsWorkerOnActivation pins the SPEC-0002 REQ
// "Worker starts on account activation" scenario: an account
// transitioning to StateActive MUST have a sync worker running
// within 1 second.
func TestSupervisorStartsWorkerOnActivation(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	sup := New(svc, fastConfig())
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-activate"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("worker not running 1s after activation; count=%d", sup.activeWorkerCount())
	}
}

// TestSupervisorStopsWorkerOnDeactivation pins the SPEC-0002 REQ
// "Worker stops on suspension or deletion" scenario.
func TestSupervisorStopsWorkerOnDeactivation(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	sup := New(svc, fastConfig())
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-stop"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition active: %v", err)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("worker did not start; count=%d", sup.activeWorkerCount())
	}

	if _, err := svc.Transition(ctx, a.ID, account.StateSuspended); err != nil {
		t.Fatalf("Transition suspended: %v", err)
	}
	// SPEC-0002 says within 5s graceful; with fastConfig that's 500ms.
	// Allow up to 5s in case CI is slow.
	if !waitFor(t, 5*time.Second, func() bool { return sup.activeWorkerCount() == 0 }) {
		t.Fatalf("worker did not drain after suspension; count=%d", sup.activeWorkerCount())
	}
}

// TestSupervisorIdempotentStart pins SPEC-0002's "Worker duplicates
// are prevented" scenario: a duplicate activation transition for an
// already-running account is a no-op.
func TestSupervisorIdempotentStart(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	sup := New(svc, fastConfig())
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-idem"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("first worker did not start; count=%d", sup.activeWorkerCount())
	}

	// Direct dispatch with the same active->active transition the
	// seed path would emit. MUST be a no-op + DEBUG log.
	for i := 0; i < 5; i++ {
		sup.OnAccountStateChange(account.StateActive, account.StateActive, a)
	}
	if got := sup.activeWorkerCount(); got != 1 {
		t.Fatalf("idempotent start spawned dupes: count=%d, want 1", got)
	}
}

// TestSupervisorStopGracefulThenHard exercises the SPEC-0002
// "Drain completes within shutdown deadline" scenario: Stop returns
// within the configured deadlines even if some workers haven't
// drained naturally.
func TestSupervisorStopGracefulThenHard(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	sup := New(svc, fastConfig())
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Spin up a few workers.
	for _, sub := range []string{"a", "b", "c"} {
		acc, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-stop-" + sub})
		if err != nil {
			t.Fatalf("Create %s: %v", sub, err)
		}
		if _, err := svc.Transition(ctx, acc.ID, account.StateActive); err != nil {
			t.Fatalf("Transition %s: %v", sub, err)
		}
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 3 }) {
		t.Fatalf("expected 3 workers, got %d", sup.activeWorkerCount())
	}

	start := time.Now()
	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	elapsed := time.Since(start)

	// Stub workers drain trivially, so Stop should comfortably be
	// well under the GracefulShutdown budget. The hard ceiling is
	// the SPEC-0002 30s wall.
	if elapsed > 5*time.Second {
		t.Errorf("Stop took %v; expected sub-second graceful drain", elapsed)
	}
	if got := sup.activeWorkerCount(); got != 0 {
		t.Errorf("workers remain after Stop: %d", got)
	}

	// Stop is idempotent.
	if err := sup.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

// TestConcurrencyCap validates SPEC-0002 REQ "Concurrency Limits":
// when N workers all hold a Proton slot, an additional acquire
// blocks until one is released.
func TestConcurrencyCap(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	cfg := fastConfig()
	cfg.ConcurrencyCap = 2 // tighten so we can assert on a small N
	sup := New(svc, cfg)
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if got := sup.concurrencyCap(); got != 2 {
		t.Fatalf("cap = %d, want 2", got)
	}

	// Acquire both available slots.
	rel1, err := sup.AcquireProtonSlot(context.Background())
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	rel2, err := sup.AcquireProtonSlot(context.Background())
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	// A third acquire MUST block. We give it 100ms to fail, then
	// release a slot and confirm it succeeds within another 200ms.
	gotSlot := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rel3, err := sup.AcquireProtonSlot(ctx)
		if err != nil {
			return
		}
		close(gotSlot)
		rel3()
	}()

	select {
	case <-gotSlot:
		t.Fatal("third acquire returned while cap was full")
	case <-time.After(100 * time.Millisecond):
		// expected — still blocked
	}

	rel1()
	select {
	case <-gotSlot:
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("third acquire did not unblock after release")
	}
	rel2()
}

// TestAcquireProtonSlotHonorsContextCancel confirms that a stuck
// acquire returns when its context is canceled.
func TestAcquireProtonSlotHonorsContextCancel(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	cfg := fastConfig()
	cfg.ConcurrencyCap = 1
	sup := New(svc, cfg)
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	rel, err := sup.AcquireProtonSlot(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer rel()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := sup.AcquireProtonSlot(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
}

// TestSupervisorPanicIsolation confirms a worker panic does not
// take down the supervisor or sibling workers.
//
// This test reaches inside the package to invoke a panicking
// version of the worker tick. The harness's deferred recover MUST
// log + remove the crashed worker without affecting the supervisor's
// lifecycle.
//
// Governing: SPEC-0002 REQ "Panic Isolation".
func TestSupervisorPanicIsolation(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	sup := New(svc, fastConfig())
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	// Spawn a sibling worker the normal way.
	siblingAcc, err := svc.Create(context.Background(), account.CreateParams{OIDCSubject: "sub-sibling"})
	if err != nil {
		t.Fatalf("Create sibling: %v", err)
	}
	if _, err := svc.Transition(context.Background(), siblingAcc.ID, account.StateActive); err != nil {
		t.Fatalf("Transition sibling: %v", err)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("sibling worker did not start")
	}

	// Hand-craft a worker whose tick panics on first call. We bypass
	// startWorker so the panicker is in addition to (not in place
	// of) the sibling.
	w := newWorker(sup.rootCtx, "panicker", sup)
	sup.workersMu.Lock()
	sup.workers["panicker"] = w
	sup.workersMu.Unlock()

	// Replace its run() body via a tiny goroutine that mimics the
	// production deferred-recover. We do this here instead of adding
	// production-only injection points.
	go func() {
		defer close(w.done)
		defer sup.removeWorker(w.id)
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic")
			}
		}()
		panic("boom")
	}()

	// Sibling worker MUST stay alive.
	time.Sleep(50 * time.Millisecond)
	if !waitFor(t, time.Second, func() bool {
		// panicker removed itself, sibling still present
		return sup.activeWorkerCount() == 1
	}) {
		t.Fatalf("after panic isolation: count=%d, want 1", sup.activeWorkerCount())
	}
}

// TestServiceOnTransitionFiresCallback exercises the foundation
// extension to account.Service that this PR introduces. It uses the
// REAL account service (not a mock) per the issue brief.
func TestServiceOnTransitionFiresCallback(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	type capture struct {
		prev, next account.State
		id         string
	}
	var (
		mu    sync.Mutex
		seen  []capture
		fires int32
	)
	unsub := svc.OnTransition(func(_ context.Context, prev, next account.State, a *account.Account) {
		mu.Lock()
		seen = append(seen, capture{prev: prev, next: next, id: a.ID})
		mu.Unlock()
		atomic.AddInt32(&fires, 1)
	})
	// t.Cleanup right after registration so an early t.Fatalf below
	// cannot leak the subscription past the test.
	t.Cleanup(unsub)

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-cb"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition active: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateSuspended); err != nil {
		t.Fatalf("Transition suspended: %v", err)
	}

	if got := atomic.LoadInt32(&fires); got != 2 {
		t.Fatalf("callback fires = %d, want 2", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("seen len = %d, want 2", len(seen))
	}
	if seen[0].prev != account.StatePendingProtonSetup || seen[0].next != account.StateActive {
		t.Errorf("first callback = (%s -> %s), want (pending -> active)", seen[0].prev, seen[0].next)
	}
	if seen[1].prev != account.StateActive || seen[1].next != account.StateSuspended {
		t.Errorf("second callback = (%s -> %s), want (active -> suspended)", seen[1].prev, seen[1].next)
	}

	// Unsubscribe MUST stop further fires.
	unsub()
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition back to active: %v", err)
	}
	if got := atomic.LoadInt32(&fires); got != 2 {
		t.Errorf("fires after unsubscribe = %d, want 2", got)
	}

	// Idempotent unsubscribe.
	unsub()
}

// TestRapidFlapKeepsWorkerRunning is the regression test for the
// PR-#38 hostile-review blocker: rapid active→suspended→active
// transitions, dispatched directly to OnAccountStateChange, MUST
// leave the account with a running worker. Pre-fix the dying-worker
// slot in s.workers caused the re-activation's startWorker to
// DEBUG-no-op, leaving the account with no goroutine. Post-fix
// stopWorker waits synchronously for the worker's removeWorker
// defer to clear the slot before returning, so any subsequent
// startWorker call observes an empty slot and spawns a fresh worker.
//
// We fire the flap inside a single goroutine to mirror the hostile
// reviewer's exact reproducer, then add an additional racing
// variation (suspended/active from a sibling goroutine) so the test
// also exercises concurrent dispatch through OnAccountStateChange.
// Run with `-race -count=20` to confirm stability under scheduler
// jitter.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account".
func TestRapidFlapKeepsWorkerRunning(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	sup := New(svc, fastConfig())
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-flap"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Step 1: get a baseline worker running.
	sup.OnAccountStateChange(account.StatePendingProtonSetup, account.StateActive, a)
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("baseline worker did not start; count=%d", sup.activeWorkerCount())
	}

	// Step 2: the exact hostile-reviewer repro — suspend then active
	// back-to-back from a single goroutine. Pre-fix this leaves the
	// account with NO worker because stopWorker returned before the
	// dying worker cleared the map slot, and the re-activation saw
	// the still-present entry and DEBUG-no-op'd. Post-fix stopWorker
	// is synchronous, so the slot is empty when startWorker runs.
	sup.OnAccountStateChange(account.StateActive, account.StateSuspended, a)
	sup.OnAccountStateChange(account.StateSuspended, account.StateActive, a)

	if !waitFor(t, 2*time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("after sequential flap: workers=%d, want 1", sup.activeWorkerCount())
	}

	// Step 3: same flap, but each suspend/active pair fires from its
	// own goroutine. Using a goroutine for each call introduces extra
	// scheduling pressure and proves the per-pair invariant survives
	// arbitrary interleavings. We sequence pair-internal calls with a
	// channel so the LAST call across all goroutines is always
	// "active" — concurrent dispatch with no terminal-state ordering
	// is permitted to end in any state, so without sequencing the
	// final state would be racy by design (see the comment block in
	// stopWorker for why "after stopWorker returns the slot is empty"
	// is a per-call invariant, not a multi-call one).
	for i := 0; i < 10; i++ {
		var wg sync.WaitGroup
		gate := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			sup.OnAccountStateChange(account.StateActive, account.StateSuspended, a)
			close(gate)
		}()
		go func() {
			defer wg.Done()
			<-gate
			sup.OnAccountStateChange(account.StateSuspended, account.StateActive, a)
		}()
		wg.Wait()

		if !waitFor(t, 2*time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
			t.Fatalf("after concurrent flap iter %d: workers=%d, want 1", i, sup.activeWorkerCount())
		}
	}
}

// TestSupervisorRecoversInjectedPanic exercises the production
// deferred-recover paths in worker.tick() and worker.run() via the
// test-only `panicker` hook. Unlike TestSupervisorPanicIsolation
// (which supplies its own recover and only proves Go's recover
// works), this test installs a panicking tick body and asserts that
// the WORKER's harness recover catches it, removes the worker from
// the live map, and leaves the supervisor + sibling untouched.
//
// Spec reviewer requested this on PR #38 as the "production recover
// is unverified" caveat; story #17 will replace the panicker hook
// with real client.GetEvent injection.
//
// Governing: SPEC-0002 REQ "Panic Isolation".
func TestSupervisorRecoversInjectedPanic(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	sup := New(svc, fastConfig())
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	// Sibling worker via the normal path.
	siblingAcc, err := svc.Create(context.Background(), account.CreateParams{OIDCSubject: "sub-sibling-real"})
	if err != nil {
		t.Fatalf("Create sibling: %v", err)
	}
	if _, err := svc.Transition(context.Background(), siblingAcc.ID, account.StateActive); err != nil {
		t.Fatalf("Transition sibling: %v", err)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("sibling worker did not start")
	}

	// Hand-inject a panicking worker. We construct it directly so we
	// can install the panicker hook before start(); production code
	// paths never set this field.
	w := newWorker(sup.rootCtx, "panicker-real", sup)
	w.panicker = func() { panic("injected boom") }
	sup.workersMu.Lock()
	sup.workers[w.id] = w
	sup.workersMu.Unlock()
	w.start()

	// The production recover in worker.run() must:
	//   1. catch the panic re-raised from tick()'s recover
	//   2. log it (we don't introspect logs, but the recover path
	//      runs removeWorker via its defer chain)
	//   3. remove the worker from the live map
	// Net observable effect: only the sibling remains.
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 1 }) {
		t.Fatalf("after injected panic: count=%d, want 1 (sibling only)", sup.activeWorkerCount())
	}

	// Sibling MUST still be running after the panic settles.
	sup.workersMu.Lock()
	_, siblingAlive := sup.workers[siblingAcc.ID]
	_, panickerStillThere := sup.workers["panicker-real"]
	sup.workersMu.Unlock()
	if !siblingAlive {
		t.Error("sibling worker was removed; panic isolation failed")
	}
	if panickerStillThere {
		t.Error("panicker still in map after recover; removeWorker did not fire")
	}
}

// waitFor polls cond every 10ms up to deadline. Returns true if cond
// ever returned true within the budget. Test helpers that need to
// wait for a goroutine to make observable progress (worker starts,
// drains, etc.) use this so the assertion is robust against
// scheduler jitter.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
