// Governing: SPEC-0002 REQ "Backoff on Failure".

package sync

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
)

// TestBackoffNextWithinSpecBounds pins SPEC-0002's full-jitter
// formula:
//
//	delay = uniform(0, min(maxDelay, baseDelay * 2^attempt))
//
// We pin the rand source to 1 - epsilon (the upper edge of [0, 1))
// so the returned delay is the exclusive upper bound minus a sliver,
// then assert the bound matches the spec for each attempt up to the
// cap.
func TestBackoffNextWithinSpecBounds(t *testing.T) {
	t.Parallel()
	// rand returning the largest representable float < 1 lets us
	// observe the exclusive upper bound directly.
	const upper = 1.0 - 1e-15
	bo := newBackoff(time.Second, 5*time.Minute, func() float64 { return upper })

	cases := []struct {
		attempt    int
		wantUpperD time.Duration
	}{
		{0, 1 * time.Second},   // base * 2^0 = 1s
		{1, 2 * time.Second},   // base * 2^1 = 2s
		{2, 4 * time.Second},   // base * 2^2 = 4s
		{3, 8 * time.Second},   // base * 2^3 = 8s
		{4, 16 * time.Second},  // ...
		{5, 32 * time.Second},  // ...
		{6, 64 * time.Second},  // ...
		{7, 128 * time.Second}, // ...
		{8, 256 * time.Second}, // 4m16s
		{9, 5 * time.Minute},   // 512s would be 8m32s; capped to max
		{10, 5 * time.Minute},  // saturated at max
		{20, 5 * time.Minute},  // still capped
	}
	for _, c := range cases {
		// Reset and fast-forward attempt to the case under test.
		bo.reset()
		bo.attempt = c.attempt
		got := bo.next()
		// Upper bound is exclusive; rand=1-eps makes got just under
		// wantUpperD. Allow 1ms slack for float rounding.
		if got > c.wantUpperD {
			t.Errorf("attempt=%d: got %v, want < %v (rand=1-eps should approach but not equal upper bound)", c.attempt, got, c.wantUpperD)
		}
		if got < c.wantUpperD-time.Millisecond {
			t.Errorf("attempt=%d: got %v, want ~%v (rand=1-eps should hit the upper edge)", c.attempt, got, c.wantUpperD)
		}
	}
}

// TestBackoffNextZeroJitter confirms the lower edge: rand=0 means
// delay=0, regardless of attempt. The spec's `uniform(0, X)` says 0
// is a valid draw.
func TestBackoffNextZeroJitter(t *testing.T) {
	t.Parallel()
	bo := newBackoff(time.Second, time.Minute, func() float64 { return 0 })
	for attempt := 0; attempt < 10; attempt++ {
		bo.reset()
		bo.attempt = attempt
		if got := bo.next(); got != 0 {
			t.Errorf("attempt=%d: got %v, want 0 (rand=0 must yield zero delay)", attempt, got)
		}
	}
}

// TestBackoffAdvancesAttempt confirms next() bumps the attempt
// counter so consecutive calls draw from a strictly non-decreasing
// upper-bound envelope.
func TestBackoffAdvancesAttempt(t *testing.T) {
	t.Parallel()
	bo := newBackoff(time.Second, time.Hour, func() float64 { return 0.5 })
	if got := bo.attempts(); got != 0 {
		t.Fatalf("initial attempts = %d, want 0", got)
	}
	for i := 1; i <= 5; i++ {
		bo.next()
		if got := bo.attempts(); got != i {
			t.Errorf("after %d next() calls: attempts = %d, want %d", i, got, i)
		}
	}
}

// TestBackoffReset clears the counter so the curve restarts from
// `base`. Per SPEC-0002 REQ "Backoff on Failure" — "Failure counter
// resets on success".
func TestBackoffReset(t *testing.T) {
	t.Parallel()
	bo := newBackoff(time.Second, time.Hour, func() float64 { return 1.0 - 1e-15 })
	for i := 0; i < 5; i++ {
		bo.next()
	}
	if got := bo.attempts(); got != 5 {
		t.Fatalf("attempts before reset = %d, want 5", got)
	}
	bo.reset()
	if got := bo.attempts(); got != 0 {
		t.Errorf("attempts after reset = %d, want 0", got)
	}
	// First post-reset draw matches attempt-0 envelope (~1s upper).
	got := bo.next()
	if got >= 2*time.Second {
		t.Errorf("post-reset delay = %v, want < 2s (attempt-0 envelope)", got)
	}
}

// TestBackoffDefaultsAndClamps confirms the zero-config Config and
// pathological max<base both produce a usable backoff.
func TestBackoffDefaultsAndClamps(t *testing.T) {
	t.Parallel()
	// All zeros → defaults.
	bo := newBackoff(0, 0, nil)
	if bo.base != DefaultBackoffBase {
		t.Errorf("base = %v, want %v", bo.base, DefaultBackoffBase)
	}
	if bo.max != DefaultBackoffMax {
		t.Errorf("max = %v, want %v", bo.max, DefaultBackoffMax)
	}

	// max < base → snap to base, do NOT panic.
	bo2 := newBackoff(10*time.Second, time.Second, func() float64 { return 0.5 })
	if bo2.max != bo2.base {
		t.Errorf("max=%v base=%v: misconfigured max should be snapped to base", bo2.max, bo2.base)
	}
	// First draw must respect that clamp.
	if got := bo2.next(); got > bo2.max {
		t.Errorf("delay = %v exceeds clamped max = %v", got, bo2.max)
	}
}

// TestBackoffOverflowGuard confirms an absurdly high attempt counter
// doesn't overflow the int64 << shift math. Without the
// maxBackoffShift cap, `int64(base) << 64` would wrap to zero or
// negative and produce a delay LESS than base — a silent regression
// the spec would never accept.
func TestBackoffOverflowGuard(t *testing.T) {
	t.Parallel()
	bo := newBackoff(time.Second, 5*time.Minute, func() float64 { return 1.0 - 1e-15 })
	bo.attempt = math.MaxInt32 // pathological
	got := bo.next()
	if got > 5*time.Minute {
		t.Errorf("delay = %v, want <= 5min cap (overflow guard failed)", got)
	}
	if got <= 0 {
		t.Errorf("delay = %v, want > 0 (overflow produced zero/negative)", got)
	}
}

// TestSleepCtxHonoursCancel confirms sleepCtx unblocks promptly when
// the context cancels during the sleep.
func TestSleepCtxHonoursCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := sleepCtx(ctx, time.Hour)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("sleepCtx returned in %v; expected ~10ms (cancel honored)", elapsed)
	}
}

// TestSleepCtxZeroDuration returns immediately for d<=0.
func TestSleepCtxZeroDuration(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	// Even with cancelled ctx, d<=0 returns nil per the doc — a
	// zero-jitter draw is a valid spec outcome and we don't want to
	// mask it as a cancellation.
	if err := sleepCtx(ctx, 0); err != nil {
		t.Errorf("d=0: err = %v, want nil", err)
	}
	if err := sleepCtx(ctx, -time.Second); err != nil {
		t.Errorf("d<0: err = %v, want nil", err)
	}
}

// backoffSequence is a thread-safe append-only log of attempt-counter
// snapshots taken inside the BackoffRand closure. Because the closure
// runs on the worker's run goroutine (the only goroutine that touches
// bo.attempt), reading bo's state from the closure is race-free —
// observation from the test goroutine then happens through the
// mutex-guarded log.
type backoffSequence struct {
	mu sync.Mutex
	// shifts[i] is the value of bo.attempt at the moment of the
	// i'th draw (i.e. the shift that produced delay_i).
	shifts []int
}

func (s *backoffSequence) record(shift int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shifts = append(s.shifts, shift)
}

func (s *backoffSequence) snapshot() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, len(s.shifts))
	copy(out, s.shifts)
	return out
}

// TestWorkerBackoffOnFailureThenResetOnSuccess pins the central
// invariant of SPEC-0002 REQ "Backoff on Failure": consecutive
// failures grow the attempt counter; a successful tick resets it so
// a later failure starts from attempt-0 again.
//
// Observation strategy: the BackoffRand closure runs on the worker's
// run goroutine, so it can safely snapshot bo.attempt before the
// helper's post-increment fires. The test forces a clear streak of
// failures (so post-streak shifts climb past 0), then a single
// success, then a final failure. The post-success failure's shift
// MUST be 0 — that's the reset-on-success invariant. The early
// shifts are background noise.
//
// To avoid an early-tick wRef race (the worker's first tick can fire
// before the test stores wRef into the closure), we don't try to
// observe call 1's shift; we drive enough ticks past the worker's
// startup to guarantee wRef is set, then assert against the LATER
// pattern.
//
// Driving the worker is done entirely through state transitions and
// observable side effects (last_event_id, getEventFn calls) — never
// by calling w.tick() from the test goroutine, which would race with
// the run loop.
func TestWorkerBackoffOnFailureThenResetOnSuccess(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-backoff-reset")

	wantErr := errors.New("simulated 5xx")

	// Sequence under deterministic control:
	//   - calls 1..K-1: BLOCK on a startup gate so the worker
	//     waits until the test has wired wRef (eliminates the
	//     early-tick race).
	//   - call K: failure   → records shift S0
	//   - call K+1: SUCCESS → resets the counter
	//   - call K+2: failure → records shift S1; MUST be 0
	//   - call K+3+: BLOCK so no further shifts pollute the assertion.
	//
	// We choose K=2 (one startup-gated call before the observed
	// streak begins) — small enough to keep the test fast, large
	// enough to cover the worker's immediate first tick.
	const startupCalls = 1
	startup := make(chan struct{})
	gateCtx, gateCancel := context.WithCancel(context.Background())
	t.Cleanup(gateCancel)

	var calls int32
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			n := int(atomic.AddInt32(&calls, 1))
			if n <= startupCalls {
				// Wait for the test to release us (signaling that
				// wRef is wired and ready to record shifts).
				select {
				case <-startup:
				case <-gateCtx.Done():
					return nil, false, gateCtx.Err()
				}
				// Return success on these startup calls so they
				// don't perturb the backoff counter.
				return nil, false, nil
			}
			switch n - startupCalls {
			case 1:
				return nil, false, wantErr
			case 2:
				return []proton.Event{{EventID: "evt-good"}}, false, nil
			case 3:
				return nil, false, wantErr
			default:
				// Park: prevent any further shift records from
				// landing before the assertion.
				<-gateCtx.Done()
				return nil, false, gateCtx.Err()
			}
		},
	}

	seq := &backoffSequence{}
	var wRef atomic.Pointer[worker]

	cfg := fastConfig()
	cfg.PollInterval = 5 * time.Millisecond
	cfg.BackoffBase = time.Nanosecond
	cfg.BackoffMax = time.Nanosecond
	cfg.BackoffRand = func() float64 {
		w := wRef.Load()
		if w != nil {
			seq.record(w.bo.attempt)
		}
		return 0
	}
	cfg.ClientFactory = func(context.Context, string) (proton.Client, error) {
		return fc, nil
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	// Wait for the worker to land in the live map and capture its
	// pointer for the rand closure. The closure reads w.bo.attempt
	// only on the run goroutine, so the read is race-free as long as
	// the closure observes a non-nil wRef.
	if !waitFor(t, time.Second, func() bool {
		sup.workersMu.Lock()
		defer sup.workersMu.Unlock()
		w, ok := sup.workers[a.ID]
		if ok {
			wRef.Store(w)
		}
		return ok
	}) {
		t.Fatalf("worker for %q never appeared in the live map", a.ID)
	}

	// Release the startup gate. From this point forward every shift
	// recorded by the rand closure observes a valid wRef.
	close(startup)

	// Wait for the third post-startup call (the "post-success
	// failure") to land. After that the worker parks on the default
	// branch, so no further shifts will be recorded.
	if !waitFor(t, 3*time.Second, func() bool {
		return atomic.LoadInt32(&calls) >= int32(startupCalls+3)
	}) {
		t.Fatalf("post-success failure never landed; calls=%d", atomic.LoadInt32(&calls))
	}
	// Wait for the post-success failure's BackoffRand call to record.
	if !waitFor(t, time.Second, func() bool {
		return len(seq.snapshot()) >= 2
	}) {
		t.Fatalf("BackoffRand recorded %d shifts; want >= 2 (the pre-success and post-success failures)", len(seq.snapshot()))
	}

	got := seq.snapshot()
	// Both observed failures (the pre-success and post-success ones)
	// MUST start the backoff curve at attempt-0. The pre-success
	// failure is the first failure ever (counter starts at 0); the
	// post-success failure proves bo.reset() fired between them.
	if len(got) < 2 {
		t.Fatalf("recorded shifts = %v; want at least 2 entries", got)
	}
	if got[0] != 0 {
		t.Errorf("first failure shift = %d, want 0 (curve starts at attempt-0)", got[0])
	}
	if got[1] != 0 {
		t.Errorf("post-reset failure shift = %d, want 0 (success between failures must reset the counter)", got[1])
	}
}

// TestWorkerProtonSlotDrainDoesNotBumpBackoff pins the
// "errProtonSlotUnavailable on graceful drain" invariant: when a
// worker is parked inside AcquireProtonSlot at Stop time, the
// resulting drain MUST exit silently — the backoff counter MUST NOT
// advance, because there was no upstream failure to retry against.
//
// SPEC-0002 REQ "Backoff on Failure" only counts transient processing
// failures; a context cancel observed by AcquireProtonSlot is a
// shutdown signal, not a retry-worthy event. The early-return in
// tick() (now spelled with errors.Is per nit #2) is what enforces
// that distinction; this test pins the behaviour at the worker level
// so a future refactor that drops the early-return is caught here
// rather than in production telemetry.
//
// Setup: ConcurrencyCap=1 + a sibling that holds the only slot via a
// long-running tick. The account-under-test's worker enters tick(),
// calls AcquireProtonSlot, and parks because the semaphore is full.
// Stop() then cancels every worker's context; the parked
// AcquireProtonSlot returns ctx.Err(), runProcessOnce wraps it in
// errProtonSlotUnavailable, and tick() takes the silent-drain branch.
// After Stop returns we read w.bo.attempt directly — the run goroutine
// has fully exited so there is no race.
func TestWorkerProtonSlotDrainDoesNotBumpBackoff(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	// Sibling holds the slot for as long as its tick body sits inside
	// the holder closure. We block until the test releases `holdRel`,
	// guaranteeing the second worker hits a full semaphore.
	holdAcquired := make(chan struct{})
	holdRel := make(chan struct{})
	var holdOnce sync.Once
	siblingFC := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			// Park the sibling's tick so it keeps the only slot.
			// Multiple ticks may land here over the test's lifetime;
			// only the first signals the gate.
			holdOnce.Do(func() { close(holdAcquired) })
			<-holdRel
			return nil, false, nil
		},
	}

	// The account-under-test's client should NEVER see GetEvent: it
	// must be parked inside AcquireProtonSlot, never reaching the
	// processor's Proton call. A reached call here means the
	// concurrency cap was bypassed and the test is no longer pinning
	// the drain path.
	var targetGetEventCalls int32
	targetFC := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			atomic.AddInt32(&targetGetEventCalls, 1)
			return nil, false, nil
		},
	}

	siblingID := "sub-slot-holder"
	targetID := "sub-slot-parked"
	sibling := createTestAccount(t, svc, usrSvc, siblingID)
	target := createTestAccount(t, svc, usrSvc, targetID)

	cfg := fastConfig()
	cfg.ConcurrencyCap = 1 // Force serialization on the semaphore.
	cfg.PollInterval = 5 * time.Millisecond
	// Long backoffs so any (incorrect) bump would be visible without
	// the test having to race the run loop's sleep.
	cfg.BackoffBase = time.Hour
	cfg.BackoffMax = time.Hour
	cfg.ClientFactory = func(_ context.Context, accountID string) (proton.Client, error) {
		switch accountID {
		case sibling.ID:
			return siblingFC, nil
		case target.ID:
			return targetFC, nil
		default:
			t.Errorf("unexpected ClientFactory call for %q", accountID)
			return nil, errors.New("unexpected account")
		}
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Release the holder before Stop so its tick can return; otherwise
	// Stop's graceful drain has to wait for the holder's full timeout.
	t.Cleanup(func() {
		select {
		case <-holdRel:
		default:
			close(holdRel)
		}
	})

	// Activate the sibling first so it grabs the only slot. Wait until
	// its first tick has actually entered the holder closure — that
	// confirms it owns the slot.
	if _, err := svc.Transition(ctx, sibling.ID, account.StateActive); err != nil {
		t.Fatalf("Transition sibling active: %v", err)
	}
	select {
	case <-holdAcquired:
	case <-time.After(2 * time.Second):
		t.Fatalf("sibling never grabbed the proton slot")
	}

	// Activate the target. Its first tick will call AcquireProtonSlot
	// and park because the only slot is held by the sibling.
	if _, err := svc.Transition(ctx, target.ID, account.StateActive); err != nil {
		t.Fatalf("Transition target active: %v", err)
	}

	// Capture the target worker pointer for the post-drain assertion.
	var targetWorker *worker
	if !waitFor(t, time.Second, func() bool {
		sup.workersMu.Lock()
		defer sup.workersMu.Unlock()
		w, ok := sup.workers[target.ID]
		if ok {
			targetWorker = w
		}
		return ok
	}) {
		t.Fatalf("target worker for %q never appeared in the live map", target.ID)
	}

	// Give the target worker enough time to land inside
	// AcquireProtonSlot. Without a positive signal we sleep briefly;
	// PollInterval=5ms means the first tick has fired well within
	// 50ms, and the worker is then blocked on the semaphore until ctx
	// cancels.
	time.Sleep(50 * time.Millisecond)

	// Drain. signalStop -> cancel -> AcquireProtonSlot returns ctx.Err
	// -> runProcessOnce returns errProtonSlotUnavailable -> tick
	// returns silently. The sibling's holder is released by the
	// cleanup so the supervisor's graceful window is plenty.
	close(holdRel)
	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop returns the run goroutine has exited, so direct read
	// of bo.attempt is race-free. SPEC-0002 invariant: graceful drain
	// MUST NOT bump the consecutive-failure counter.
	if got := targetGetEventCalls; got != 0 {
		t.Errorf("target GetEvent was called %d times; want 0 (worker should have parked at AcquireProtonSlot, not reached processOnce)", got)
	}
	if got := targetWorker.bo.attempts(); got != 0 {
		t.Errorf("target worker bo.attempt = %d after graceful drain; want 0 (errProtonSlotUnavailable must not bump the backoff counter)", got)
	}
}

// TestWorkerBackoffEscalatesAcrossConsecutiveFailures pins the
// "exponential backoff with jitter" scenario: WITHOUT a success
// between failures, the attempt counter climbs strictly so the upper
// bound envelope grows exponentially as the spec requires.
//
// Same observation strategy as the reset test: snapshot bo.attempt
// from inside BackoffRand (run goroutine) and read out via a mutex-
// guarded log. A startup gate prevents the worker's immediate first
// tick from racing the test's wRef store: the first call blocks
// until the test has wired wRef, then returns success so no shift
// gets recorded. After the gate releases, every subsequent call
// returns wantErr so shifts climb monotonically.
func TestWorkerBackoffEscalatesAcrossConsecutiveFailures(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-backoff-escalate")

	wantErr := errors.New("simulated 502")
	startup := make(chan struct{})
	gateCtx, gateCancel := context.WithCancel(context.Background())
	t.Cleanup(gateCancel)
	var calls int32
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				select {
				case <-startup:
				case <-gateCtx.Done():
					return nil, false, gateCtx.Err()
				}
				// First call after the gate releases returns
				// success so no shift gets recorded for it. Every
				// subsequent call returns wantErr.
				return nil, false, nil
			}
			return nil, false, wantErr
		},
	}

	seq := &backoffSequence{}
	var wRef atomic.Pointer[worker]

	cfg := fastConfig()
	cfg.PollInterval = 5 * time.Millisecond
	cfg.BackoffBase = time.Nanosecond
	cfg.BackoffMax = 5 * time.Nanosecond
	cfg.BackoffRand = func() float64 {
		w := wRef.Load()
		if w != nil {
			seq.record(w.bo.attempt)
		}
		return 0
	}
	cfg.ClientFactory = func(context.Context, string) (proton.Client, error) {
		return fc, nil
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	if !waitFor(t, time.Second, func() bool {
		sup.workersMu.Lock()
		defer sup.workersMu.Unlock()
		w, ok := sup.workers[a.ID]
		if ok {
			wRef.Store(w)
		}
		return ok
	}) {
		t.Fatalf("worker for %q never appeared in the live map", a.ID)
	}
	close(startup)

	// Wait for at least 5 failures' worth of recorded shifts.
	if !waitFor(t, 5*time.Second, func() bool {
		return len(seq.snapshot()) >= 5
	}) {
		t.Fatalf("only %d shifts recorded; want >= 5", len(seq.snapshot()))
	}

	got := seq.snapshot()
	// First five recorded shifts MUST be 0,1,2,3,4 — the spec's
	// exponential climb. (Beyond 5 the test ignores; the helper's
	// own unit tests cover the saturation-at-max case.)
	for i := 0; i < 5; i++ {
		if got[i] != i {
			t.Errorf("shift[%d] = %d, want %d (consecutive failures must climb monotonically)", i, got[i], i)
		}
	}
}
