// Governing: ADR-0001 (go-proton-api as Proton client),
//             SPEC-0002 REQ "One Worker Per Active Account",
//             SPEC-0002 REQ "Graceful Shutdown",
//             SPEC-0002 REQ "Concurrency Limits",
//             SPEC-0002 REQ "Panic Isolation".

package sync

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// Default tunables. The values are deliberately conservative — small
// enough that an under-resourced single-tenant deployment can't
// stampede Proton, large enough that a family of ~half a dozen Proton
// accounts polls every 30 seconds with headroom.
const (
	// DefaultConcurrencyCap is the process-wide ceiling on in-flight
	// Proton API calls. Per SPEC-0002 REQ "Concurrency Limits".
	DefaultConcurrencyCap = 8

	// DefaultPollInterval is how often a worker wakes up to do its
	// stub no-op tick. Story #16 replaces this with the cadence
	// implied by Proton's event endpoint (long-poll/coalesced batch).
	DefaultPollInterval = 30 * time.Second

	// DefaultGracefulShutdown is the budget Stop allows workers to
	// drain in-flight work cooperatively. Per SPEC-0002 REQ "Graceful
	// Shutdown".
	DefaultGracefulShutdown = 5 * time.Second

	// DefaultHardShutdown is the absolute deadline Stop enforces; any
	// worker still running at this mark is canceled via context. Per
	// SPEC-0002 REQ "Graceful Shutdown".
	DefaultHardShutdown = 30 * time.Second
)

// Config tunes the Supervisor at construction time. The zero value is
// usable: missing fields are populated from the Default* constants
// above. Tests override PollInterval to milliseconds so they don't
// have to wait 30s for a stub tick.
type Config struct {
	// ConcurrencyCap bounds the total number of in-flight Proton
	// calls across every worker. <= 0 means DefaultConcurrencyCap.
	ConcurrencyCap int

	// PollInterval is the tick cadence for each worker's event-poll
	// loop. <= 0 means DefaultPollInterval.
	PollInterval time.Duration

	// GracefulShutdown is the cooperative drain window honored by
	// Stop. <= 0 means DefaultGracefulShutdown.
	GracefulShutdown time.Duration

	// HardShutdown is the absolute deadline by which Stop returns,
	// even if some workers are still mid-flight. <= 0 means
	// DefaultHardShutdown. MUST be >= GracefulShutdown.
	HardShutdown time.Duration

	// Logger is the supervisor's base logger. Per-worker loggers are
	// derived from this with `account_id` baked in. nil means a
	// discard handler.
	Logger *slog.Logger

	// Now overrides the time source. Used by tests to drive tick
	// loops deterministically. nil means time.Now.
	Now func() time.Time
}

// resolved fills in defaults for every zero-valued field. Returned by
// value so the original Config is never mutated.
func (c Config) resolved() Config {
	if c.ConcurrencyCap <= 0 {
		c.ConcurrencyCap = DefaultConcurrencyCap
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.GracefulShutdown <= 0 {
		c.GracefulShutdown = DefaultGracefulShutdown
	}
	if c.HardShutdown <= 0 {
		c.HardShutdown = DefaultHardShutdown
	}
	if c.HardShutdown < c.GracefulShutdown {
		c.HardShutdown = c.GracefulShutdown
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// discardWriter drops every byte. Used as the fallback log sink when
// the caller does not supply a *slog.Logger.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// ErrNotStarted is returned by OnAccountStateChange and Stop when the
// supervisor has not been Start()ed yet. Callers should treat it as a
// programming error — there's no recovery path other than fixing the
// boot ordering.
var ErrNotStarted = errors.New("sync: supervisor not started")

// Supervisor is the per-process root that owns one *worker per active
// account. It exposes a single state-change entry point
// (OnAccountStateChange) which the account service drives via its
// transition-callback registration; the supervisor itself does not
// poll the database.
//
// Lifecycle:
//
//   - New constructs a stopped supervisor.
//   - Start(ctx) must be called once before any state changes are
//     dispatched. Start subscribes to the account service's
//     OnTransition callback and seeds workers for any accounts already
//     in StateActive at boot time.
//   - OnAccountStateChange spawns/stops workers in response to
//     transitions. Idempotent: a transition INTO active for an
//     account that already has a worker is a no-op + DEBUG log.
//   - Stop drains every worker within Config.GracefulShutdown, then
//     hard-cancels survivors via context up to Config.HardShutdown.
//
// Concurrency model:
//
//   - Each worker is a goroutine carrying its own context.Context and
//     a *slog.Logger with `account_id` baked into the attrs. The
//     worker's body is a stub tick loop in this PR; story #16 replaces
//     the tick with `client.GetEvent`.
//   - Every Proton call site (story #16's GetEvent, the eventual
//     SMTP outbox, MCP tools running through the supervisor) MUST
//     acquire a slot on the process-wide semaphore via
//     AcquireProtonSlot before issuing the request. The slot is
//     released by the returned func.
//   - A worker panic is recovered by the worker harness; the panic
//     value, stack, and account ID are logged at ERROR and the worker
//     is removed from the live map. The supervisor and other workers
//     keep running.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account",
// SPEC-0002 REQ "Graceful Shutdown",
// SPEC-0002 REQ "Concurrency Limits",
// SPEC-0002 REQ "Panic Isolation".
type Supervisor struct {
	cfg     Config
	svc     account.Service
	startMu sync.Mutex
	started bool
	stopped bool

	// rootCtx is the lifetime context for every worker. Cancellation
	// happens in two phases inside Stop: first Stop waits up to
	// GracefulShutdown for natural drain (workers exit on ctx.Done in
	// their own select), then cancels rootCtx to force a hard exit.
	rootCtx    context.Context
	rootCancel context.CancelFunc

	// unsubscribe releases the OnTransition registration installed at
	// Start time. Must be called from Stop so the supervisor doesn't
	// keep firing after shutdown.
	unsubscribe func()

	// sem is the process-wide concurrency semaphore. Workers acquire
	// a slot before each Proton call and release it after. Exposed
	// publicly via AcquireProtonSlot so story #16's worker-body
	// implementation (which lives in this same package) can share the
	// same semaphore without reaching into private state.
	sem chan struct{}

	// workersMu guards workers. Held briefly during start/stop and
	// during the post-panic cleanup; per-worker work happens outside
	// the lock so a slow Proton call cannot block OnAccountStateChange
	// for sibling accounts.
	workersMu sync.Mutex
	workers   map[string]*worker
}

// New constructs a supervisor bound to the given account service.
// The Service must outlive the Supervisor — Stop unsubscribes from
// the service's OnTransition callback before returning, but does NOT
// close the service itself.
//
// The supervisor is created in the stopped state. Call Start to
// activate it.
func New(svc account.Service, cfg Config) *Supervisor {
	if svc == nil {
		panic("sync: New called with nil account.Service")
	}
	resolved := cfg.resolved()
	return &Supervisor{
		cfg:     resolved,
		svc:     svc,
		sem:     make(chan struct{}, resolved.ConcurrencyCap),
		workers: make(map[string]*worker),
	}
}

// Start subscribes to account-state transitions and seeds workers for
// every account currently in StateActive. Calling Start more than
// once returns nil without re-seeding (idempotent for safe boot
// retries).
//
// The supplied ctx becomes the parent of every worker's context — if
// the caller cancels ctx before invoking Stop, every worker exits
// cooperatively at its next select. Stop is still required to release
// the OnTransition subscription.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" — startup
// reconciliation guarantees the post-boot invariant that every active
// account has a worker even if no transition fires after boot.
func (s *Supervisor) Start(ctx context.Context) error {
	s.startMu.Lock()
	if s.started {
		s.startMu.Unlock()
		return nil
	}
	s.started = true
	s.rootCtx, s.rootCancel = context.WithCancel(ctx)
	// Subscribe BEFORE releasing startMu so Stop's read of
	// s.unsubscribe (also under startMu) cannot observe a nil pointer
	// while Start is still mid-flight. SPEC-0002 REQ "Graceful
	// Shutdown" requires Stop to release the subscription deterministically.
	//
	// The OnTransition callback fires synchronously from the account
	// service's Transition path; it is safe to install while startMu
	// is held because the callback only reaches back into the
	// supervisor via OnAccountStateChange (which takes startMu itself
	// AFTER any caller-side mutation completes).
	s.unsubscribe = s.svc.OnTransition(func(cbCtx context.Context, prev, next account.State, a *account.Account) {
		s.OnAccountStateChange(prev, next, a)
	})
	s.startMu.Unlock()

	// Seed: every account already in StateActive needs a worker.
	// Failure to list is logged but does not abort Start — operators
	// can re-trigger seeding by transitioning the account through
	// suspended->active once the underlying issue is resolved.
	accounts, err := s.svc.List(ctx)
	if err != nil {
		s.cfg.Logger.LogAttrs(ctx, slog.LevelError,
			"sync: seed list failed; workers will only start on subsequent transitions",
			slog.Any("err", err),
		)
		return nil
	}
	for _, a := range accounts {
		if a.State == account.StateActive {
			s.OnAccountStateChange(account.StateActive, account.StateActive, a)
		}
	}
	return nil
}

// OnAccountStateChange is the dispatch entry point for account-state
// transitions. It is called by the account service's OnTransition
// callback (registered in Start) and is also safe to call directly
// from tests.
//
// Behavior:
//
//   - Transition INTO StateActive (next == StateActive and the
//     account does not yet have a worker): start a worker.
//   - Transition with next == StateActive and a worker already
//     present: no-op + DEBUG log. This is the seed path's
//     idempotence and the duplicate-start guard required by SPEC-0002
//     "Worker duplicates are prevented".
//   - Transition OUT OF StateActive (prev == StateActive and next !=
//     StateActive, e.g. suspended/soft_deleted): stop the worker.
//   - Any other transition: ignore.
//
// If the supervisor has not been started, OnAccountStateChange logs
// at WARN and returns — there is no panic because the account service
// MUST be free to fire transitions even if a slow Start hasn't
// completed yet (e.g. boot races on a busy SQLite open).
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account".
func (s *Supervisor) OnAccountStateChange(prev, next account.State, a *account.Account) {
	if a == nil {
		return
	}
	s.startMu.Lock()
	started, stopped, rootCtx := s.started, s.stopped, s.rootCtx
	s.startMu.Unlock()

	if !started || stopped {
		s.cfg.Logger.LogAttrs(context.Background(), slog.LevelWarn,
			"sync: state change ignored; supervisor not running",
			slog.String("account_id", a.ID),
			slog.String("prev", string(prev)),
			slog.String("next", string(next)),
		)
		return
	}

	switch {
	case next == account.StateActive:
		s.startWorker(rootCtx, a)
	case prev == account.StateActive && next != account.StateActive:
		s.stopWorker(a.ID)
	default:
		// Not a transition the supervisor cares about
		// (e.g., pending->soft_deleted). No-op.
	}
}

// startWorker spawns a worker for `a` if one does not already exist.
// Idempotent: a duplicate request emits a DEBUG log and returns
// without disturbing the existing worker.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" (the
// "Worker duplicates are prevented" scenario).
func (s *Supervisor) startWorker(ctx context.Context, a *account.Account) {
	s.workersMu.Lock()
	if _, exists := s.workers[a.ID]; exists {
		s.workersMu.Unlock()
		s.cfg.Logger.LogAttrs(ctx, slog.LevelDebug,
			"sync: worker already running; start request is a no-op",
			slog.String("account_id", a.ID),
		)
		return
	}
	w := newWorker(ctx, a.ID, s)
	s.workers[a.ID] = w
	s.workersMu.Unlock()

	w.start()
}

// stopWorker halts the worker for the given account ID, if any. The
// stop is SYNCHRONOUS: stopWorker signals cancellation and then waits
// for the worker goroutine to fully exit (which runs the deferred
// removeWorker that clears the map slot) before returning.
//
// Trade-off: callers of stopWorker that fire from the OnTransition
// callback dispatch will block for the worker's drain window. For the
// stub tick body in this PR that is microseconds; once story #16
// lands real Proton calls under AcquireProtonSlot, drain time grows
// to whatever a single GetEvent round-trip takes (sub-second under
// normal conditions, capped by the HTTP client's own deadline).
//
// We accept this latency because the alternative — returning while a
// dying worker still holds the map slot — corrupts the
// "One Worker Per Active Account" invariant on a rapid
// active→suspended→active flap: the re-activation's startWorker sees
// the dying worker, DEBUG-no-ops, and the account ends up with no
// running goroutine. The hostile reviewer for PR #38 reproduced this
// 100% of the time. Synchronous stop guarantees that after stopWorker
// returns the map slot is empty, so any subsequent startWorker call
// will spawn a fresh worker.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account",
// SPEC-0002 REQ "Worker stops on suspension or deletion"
// (within 5s graceful, 30s hard).
func (s *Supervisor) stopWorker(id string) {
	s.workersMu.Lock()
	w, ok := s.workers[id]
	s.workersMu.Unlock()
	if !ok {
		return
	}
	w.signalStop()
	w.waitDone()
}

// removeWorker takes a worker out of the live map. Called by the
// worker harness once its goroutine returns (whether via clean drain
// or panic recovery).
func (s *Supervisor) removeWorker(id string) {
	s.workersMu.Lock()
	delete(s.workers, id)
	s.workersMu.Unlock()
}

// Stop drains every worker. The two-phase shutdown is explicit:
//
//  1. Phase 1 (graceful): signal every worker to stop, then wait up to
//     Config.GracefulShutdown for them to exit on their own.
//  2. Phase 2 (hard): cancel the supervisor's root context. Every
//     worker's per-tick select hits ctx.Done immediately. Wait up to
//     (HardShutdown - GracefulShutdown) for the runtime to schedule
//     the exits.
//
// Stop is idempotent: a second call returns nil immediately. Calling
// Stop without Start is a no-op (returns nil) — there's nothing to
// drain.
//
// Governing: SPEC-0002 REQ "Graceful Shutdown" (drain within
// shutdown deadline; survivors canceled via context).
func (s *Supervisor) Stop() error {
	s.startMu.Lock()
	if !s.started || s.stopped {
		s.startMu.Unlock()
		return nil
	}
	s.stopped = true
	rootCancel := s.rootCancel
	unsubscribe := s.unsubscribe
	s.startMu.Unlock()

	// Release the account-service subscription so transitions that
	// land mid-shutdown don't spawn new workers. Read under startMu
	// above so we cannot race a partially-initialized Start.
	if unsubscribe != nil {
		unsubscribe()
	}

	// Phase 1: signal cooperative stop on every worker, snapshot the
	// list so we can wait outside the lock.
	s.workersMu.Lock()
	snapshot := make([]*worker, 0, len(s.workers))
	for _, w := range s.workers {
		snapshot = append(snapshot, w)
		w.signalStop()
	}
	s.workersMu.Unlock()

	graceDeadline := s.cfg.Now().Add(s.cfg.GracefulShutdown)
	hardDeadline := s.cfg.Now().Add(s.cfg.HardShutdown)

	// Wait for graceful drain.
	if !waitAll(snapshot, time.Until(graceDeadline)) {
		s.cfg.Logger.LogAttrs(context.Background(), slog.LevelWarn,
			"sync: workers did not drain within graceful window; cancelling root context",
			slog.Duration("graceful", s.cfg.GracefulShutdown),
		)
		// Phase 2: hard cancel.
		rootCancel()
		if !waitAll(snapshot, time.Until(hardDeadline)) {
			s.cfg.Logger.LogAttrs(context.Background(), slog.LevelError,
				"sync: workers still alive past hard shutdown deadline; abandoning",
				slog.Duration("hard", s.cfg.HardShutdown),
			)
		}
	} else {
		// Even on graceful drain we still cancel rootCtx so any
		// stragglers (e.g., a worker that was mid-spawn at Stop time)
		// see a cancelled parent and exit immediately.
		rootCancel()
	}
	return nil
}

// waitAll returns true if every worker exited within d, false on
// timeout. A non-positive d is treated as zero.
//
// On timeout the helper goroutine is unblocked via the abort channel
// so it does not leak past Stop. The helper races each worker's
// waitDone against abort; when abort closes the helper returns even
// if some worker is still mid-drain. This matters in production
// because a wedged worker would otherwise leak a supervisor goroutine
// on every Stop call.
func waitAll(workers []*worker, d time.Duration) bool {
	if len(workers) == 0 {
		return true
	}
	if d <= 0 {
		// Best-effort: poll once with a tiny budget.
		d = time.Millisecond
	}
	deadline := time.NewTimer(d)
	defer deadline.Stop()

	done := make(chan struct{})
	abort := make(chan struct{})
	go func() {
		defer close(done)
		for _, w := range workers {
			select {
			case <-w.done:
				// worker exited
			case <-abort:
				return
			}
		}
	}()
	select {
	case <-done:
		return true
	case <-deadline.C:
		close(abort)
		return false
	}
}

// AcquireProtonSlot blocks until a slot on the global concurrency
// semaphore is available, then returns a release func the caller MUST
// invoke (typically via defer) once the Proton call returns. ctx
// cancellation is honored: if ctx fires before a slot is free, the
// returned error wraps ctx.Err() and the release func is a no-op.
//
// Story #16 will call this around `client.GetEvent`. The semaphore
// lives on the Supervisor (not on the worker) so future call sites
// outside the worker loop — e.g. the SMTP outbox or an admin-driven
// "force resync" tool — share the same global cap.
//
// Governing: SPEC-0002 REQ "Concurrency Limits" (default cap 8).
func (s *Supervisor) AcquireProtonSlot(ctx context.Context) (release func(), err error) {
	noopRelease := func() {}
	select {
	case s.sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-s.sem })
		}, nil
	case <-ctx.Done():
		return noopRelease, ctx.Err()
	}
}

// concurrencyCap is exposed for tests that need to verify the
// process-wide cap. Production callers should not introspect this.
func (s *Supervisor) concurrencyCap() int { return cap(s.sem) }

// activeWorkerCount returns the number of workers currently in the
// live map. Exposed for tests; production callers have no business
// reaching past the public API.
func (s *Supervisor) activeWorkerCount() int {
	s.workersMu.Lock()
	defer s.workersMu.Unlock()
	return len(s.workers)
}
