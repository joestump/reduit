// Governing: ADR-0001 (go-proton-api as Proton client),
//             SPEC-0002 REQ "One Worker Per Active Account",
//             SPEC-0002 REQ "Panic Isolation",
//             SPEC-0002 REQ "Concurrency Limits".

package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/joestump/reduit/internal/notify"
)

// worker is the per-account goroutine harness. The harness handles
// lifecycle (start/stop, panic recovery, drain notification) and the
// per-tick event-stream consumption added by story #16.
//
// Governing: SPEC-0002 — the harness is the substrate every later
// story depends on; story #17 layers backoff/IMAP-notify/permanent-
// error semantics on top.
type worker struct {
	id     string
	sup    *Supervisor
	logger *slog.Logger

	// ctx is derived from sup.rootCtx by start(). cancel signals the
	// worker to drain. Both are owned by this struct.
	ctx    context.Context
	cancel context.CancelFunc

	// done closes when the worker goroutine has fully exited (after
	// any deferred cleanup). waitDone blocks on this channel.
	done chan struct{}

	// stopOnce guards signalStop so multiple stop signals collapse
	// into a single cancel.
	stopOnce sync.Once

	// proc is the event processor for this worker. Constructed
	// synchronously by start() before the run goroutine spawns; nil
	// only if start() failed (in which case the worker exits via
	// bootstrapFailed without ever entering run()). Single-goroutine
	// (only the run loop touches it), so no lock.
	proc *eventProcessor

	// panicker is an optional test-only hook invoked at the top of
	// each tick body. Production never sets it (nil → no-op). Tests
	// install a `func(){ panic("boom") }` here to exercise the real
	// production deferred-recover paths in tick() and run() without
	// the test having to supply its own recover. Story #17 replaces
	// this with a real injection-based panic test once the Proton
	// call plumbing lands.
	panicker func()

	// bo is the per-worker backoff state. Touched only from the run
	// goroutine (next() after a transient failure, reset() after a
	// successful processOnce), so no lock. The supervisor's Config
	// supplies base, max, and the RNG source.
	//
	// Governing: SPEC-0002 REQ "Backoff on Failure".
	bo *backoff
}

// newWorker constructs an unstarted worker bound to the supervisor's
// root context.
func newWorker(parent context.Context, id string, sup *Supervisor) *worker {
	ctx, cancel := context.WithCancel(parent)
	logger := sup.cfg.Logger.With(slog.String("account_id", id))
	return &worker{
		id:     id,
		sup:    sup,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
		bo:     newBackoff(sup.cfg.BackoffBase, sup.cfg.BackoffMax, sup.cfg.BackoffRand),
	}
}

// start launches the worker goroutine. Must be called exactly once
// per worker (the supervisor's startWorker enforces this via the
// dedup map).
//
// Bootstrap (ClientFactory + newEventProcessor) runs synchronously
// here, BEFORE the goroutine is spawned. A failure logs at ERROR,
// closes w.done so waitDone() returns immediately, and the worker
// is removed from the supervisor's live map. We chose this over the
// previous "lazy bootstrap inside tick()" because the lazy path
// only retried until proc became non-nil — once cached, a stale
// processor would never be rebuilt, so a transient ClientFactory
// error at the FIRST tick masked itself but every subsequent tick
// hit the same cached processor anyway. Moving bootstrap here makes
// the configuration error loud at activation time, which pairs with
// New()'s nil-ClientFactory rejection: both paths fail fast with an
// operator-visible signal rather than producing a worker that
// silently never syncs anything.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" — the
// worker must be running within 1 second of the activation
// transition. Synchronous bootstrap adds at most one Proton round-
// trip (GetLatestEventID on first boot; cursor-only DB read on
// resume) which is well inside that budget.
func (w *worker) start() {
	w.logger.LogAttrs(w.ctx, slog.LevelInfo, "sync: worker starting")

	client, err := w.sup.cfg.ClientFactory(w.ctx, w.id)
	if err != nil {
		w.logger.LogAttrs(w.ctx, slog.LevelError,
			"sync: client factory failed at startup; worker will not run",
			slog.Any("err", err),
		)
		w.bootstrapFailed()
		return
	}
	proc, err := newEventProcessor(w.ctx, w.id, w.sup.svc, client, w.logger, w.sup.cfg.Publisher, w.sup.cfg.Reconciler, w.sup.cfg.Notifier)
	if err != nil {
		w.logger.LogAttrs(w.ctx, slog.LevelError,
			"sync: event processor bootstrap failed; worker will not run",
			slog.Any("err", err),
		)
		w.bootstrapFailed()
		return
	}
	// The detached permanent-transition goroutine must outlive this
	// worker's own context (a permanent failure cancels w.ctx, but the
	// transition it dispatches still has to run). Hand it the
	// supervisor's rootCtx so it abandons quietly only when the WHOLE
	// supervisor shuts down, not when this single worker stops.
	//
	// Governing: SPEC-0002 REQ "Graceful Shutdown".
	proc.lifetimeCtx = w.sup.rootCtx
	w.proc = proc

	go w.run()
}

// bootstrapFailed cleans up after a synchronous bootstrap failure in
// start(): close done so waitDone() returns immediately, and remove
// ourselves from the supervisor's live map so a subsequent
// startWorker for the same account spawns a fresh worker rather than
// no-op'ing on the stale entry.
func (w *worker) bootstrapFailed() {
	close(w.done)
	w.sup.removeWorker(w.id)
}

// signalStop requests cooperative shutdown. Idempotent: subsequent
// calls are no-ops. The supervisor's Stop() calls signalStop on
// every live worker before its drain wait.
func (w *worker) signalStop() {
	w.stopOnce.Do(func() {
		w.logger.LogAttrs(w.ctx, slog.LevelInfo, "sync: worker stop requested")
		w.cancel()
	})
}

// waitDone blocks until the worker goroutine has fully exited.
func (w *worker) waitDone() { <-w.done }

// notifier returns the supervisor's admin-notification sink, falling
// back to nopNotifier when none was wired so emit sites never nil-check.
func (w *worker) notifier() Notifier {
	if w.sup.cfg.Notifier == nil {
		return nopNotifier{}
	}
	return w.sup.cfg.Notifier
}

// run is the worker goroutine entry point. It pumps tick() under a
// time.Ticker, exits on ctx.Done, and recovers any panic so the
// supervisor and other workers are unaffected.
//
// Governing: SPEC-0002 REQ "Panic Isolation" — the deferred recover
// is in place from day one even though the stub body cannot panic
// today, because story #16 will introduce real Proton calls inside
// tick() and we want the safety net there before the dangerous code
// lands.
func (w *worker) run() {
	defer close(w.done)
	defer w.sup.removeWorker(w.id)
	defer func() {
		if r := recover(); r != nil {
			w.logger.LogAttrs(context.Background(), slog.LevelError,
				"sync: worker panic recovered",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			// Mark the account row's `crashed` flag so the admin UI
			// (SPEC-0005) can surface "needs manual reset" without
			// polling. We use context.Background() because w.ctx may
			// already be cancelled by the outer Stop, and a cancelled
			// ctx would otherwise prevent the DB write that the spec
			// requires. SPEC-0002 REQ "Panic Isolation" mandates the
			// flag be set; admin reset is deferred to SPEC-0005.
			//
			// Governing: SPEC-0002 REQ "Panic Isolation".
			if mcErr := w.sup.svc.MarkCrashed(context.Background(), w.id); mcErr != nil {
				w.logger.LogAttrs(context.Background(), slog.LevelError,
					"sync: failed to mark account crashed after panic",
					slog.Any("err", mcErr),
				)
			}
			// Emit an admin notification alongside the crashed flag so the
			// operator is ACTIVELY told (admin-UI list/badge) rather than
			// having to notice the flag. The flag answers "is it broken?";
			// the notification answers "what broke?" -- it carries the
			// panic value so an operator can investigate before clearing
			// the flag. Best-effort: a failed notification must not mask
			// the panic-recovery path, so we log and move on.
			//
			// Governing: SPEC-0002 REQ "Panic Isolation".
			if _, nErr := w.notifier().Record(context.Background(), w.id,
				notify.KindWorkerCrashed,
				"Sync worker crashed and was stopped; clear the crashed flag to retry.",
				fmt.Sprintf("panic: %v", r),
			); nErr != nil {
				w.logger.LogAttrs(context.Background(), slog.LevelError,
					"sync: failed to record worker-crash admin notification",
					slog.Any("err", nErr),
				)
			}
		}
	}()

	// Fire one tick immediately so the supervisor's "worker started"
	// promise (within 1s of activation) is observable in logs and
	// tests without waiting for the first PollInterval.
	w.tick()

	t := time.NewTicker(w.sup.cfg.PollInterval)
	defer t.Stop()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.LogAttrs(context.Background(), slog.LevelInfo,
				"sync: worker draining",
				slog.String("cause", w.ctx.Err().Error()),
			)
			return
		case <-t.C:
			w.tick()
		}
	}
}

// tick is one cycle of the worker loop. The body runs the event-stream
// processor up to MaxConsecutiveTicks times to drain any backlog, AND
// owns the transient-retry cadence: on a transient processOnce failure
// it sleeps the full-jitter backoff window and retries in-loop rather
// than yielding to the run loop's time.Ticker, so the realized
// inter-retry gap is exactly the SPEC-0002 envelope (the ticker's
// PollInterval is NOT added on top). It acquires a process-wide Proton
// concurrency slot AROUND EACH processOnce call (not held across the
// whole burst) so a contending worker can interleave between
// iterations.
//
// Consequence: a sustained transient outage keeps tick() resident,
// sleeping growing (max-capped) backoff windows, until processOnce
// succeeds or w.ctx is cancelled. That is the intended envelope
// behaviour; the cancel-aware backoff sleep and the per-iteration
// ctx.Err() check keep graceful shutdown immediate throughout.
//
// Governing: SPEC-0002 REQ "Concurrency Limits" — the
// AcquireProtonSlot call is what enforces the global cap. PR #41's
// hostile review pointed out that holding the slot across the entire
// burst converts the semaphore from "in-flight ceiling" to "burst
// ceiling": with cap=8 and 8 workers all bursting, sibling work
// (admin force-resync, future SMTP outbox, MCP) wedges behind up to
// 8×20=160 sequential round-trips before getting a turn. We now
// release between iterations so the semaphore behaves as designed.
// The cost is one extra acquire per chained iteration, which is
// O(<<1ms) under the lock-free Go select fast path when slots are
// free.
//
// Within the burst we honour both ctx.Done and the
// MaxConsecutiveTicks cap so the worker stays responsive to graceful
// shutdown and so a runaway "More=true" loop cannot starve the ticker.
//
// Panic-recover ordering: the recover defer wraps each individual
// processOnce call (via runProcessOnce) rather than the whole tick.
// runProcessOnce's defer ordering — recover first, slot release
// second — preserves the SPEC-0002 REQ "Panic Isolation" invariant
// that the panic is logged BEFORE the slot returns to the pool, so a
// sibling worker cannot grab the slot before the operator sees the
// crash.
func (w *worker) tick() {
	// Test-only hook from #15. Story #17 replaces this with a real
	// injection-based panic test once the proton.Client mock can fire
	// panics inside GetEvent.
	if w.panicker != nil {
		w.panicker()
	}

	// The processor was constructed by start() before this goroutine
	// began ticking. If start() failed to bootstrap, the worker would
	// have logged + exited there, so reaching tick() with proc==nil
	// is an internal invariant violation, not an expected runtime
	// state.
	if w.proc == nil {
		w.logger.LogAttrs(w.ctx, slog.LevelError,
			"sync: tick reached with nil processor; worker should have exited at bootstrap")
		return
	}

	// Drain the backlog AND own the transient-retry cadence. Two
	// distinct loop-continuation reasons share this loop:
	//
	//  1. Backlog drain: processOnce reported more=true, so we
	//     immediately call again rather than waiting for the next ticker
	//     fire ("Tick the loop ASAP after a non-empty batch"). These
	//     iterations are bounded by MaxConsecutiveTicks so a runaway
	//     More-loop cannot starve graceful shutdown.
	//
	//  2. Transient-failure retry: processOnce failed transiently, so we
	//     sleep the full-jitter backoff window and retry IN-LOOP. The
	//     retry deliberately does NOT yield back to the time.Ticker.
	//     Yielding would make the realized inter-retry gap
	//     `backoff_delay + remaining_tick_interval`, which exceeds the
	//     SPEC-0002 envelope uniform(0, min(max, base*2^attempt)) by up
	//     to a whole PollInterval. By looping in place after the
	//     backoff sleep, the realized gap IS the backoff delay, honoring
	//     the envelope exactly.
	//
	// Only the backlog-drain reason (1) consumes the MaxConsecutiveTicks
	// budget: a sustained outage retried under backoff must not be capped
	// at MaxConsecutiveTicks attempts and then fall back to the slower
	// ticker cadence (which would re-introduce the slack this fix
	// removes). Backoff itself is the throttle there -- its growing,
	// max-capped delay is what prevents a hot loop -- so transient
	// retries loop without decrementing the drain budget. ctx.Done is
	// still honored every iteration (and inside the cancel-aware sleep)
	// so graceful shutdown wins immediately.
	//
	// Governing: SPEC-0002 REQ "Backoff on Failure" (envelope honored
	// without tick-interval slack), REQ "Graceful Shutdown" (ctx.Done
	// checked every iteration and during the backoff sleep).
	drainBudget := w.sup.cfg.MaxConsecutiveTicks
	for {
		if w.ctx.Err() != nil {
			return
		}
		more, err := w.runProcessOnce()
		if err != nil {
			// errProtonSlotUnavailable is a special case: ctx was
			// canceled while waiting for a slot (e.g. graceful
			// shutdown), so we exit silently rather than logging an
			// error or bumping the backoff counter — there was no
			// upstream failure to retry against. Use errors.Is so a
			// future caller that wraps the sentinel (e.g. through
			// fmt.Errorf("...: %w", errProtonSlotUnavailable)) still
			// hits this drain branch instead of walking the backoff
			// curve on a graceful-shutdown event.
			if errors.Is(err, errProtonSlotUnavailable) {
				return
			}
			// Permanent-failure paths: processOnce has already dispatched
			// the account transition (both refresh-token-revoked and any
			// other unrecoverable authorization failure revert the
			// account to pending_proton_setup), so the worker MUST exit
			// without logging another error or bumping backoff. Cancel
			// our own context so the run loop's outer select hits
			// ctx.Done on the next iteration.
			//
			// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent
			// errors do not retry indefinitely".
			if errors.Is(err, errRefreshTokenRevoked) || errors.Is(err, errUnrecoverableAuth) {
				w.cancel()
				return
			}
			// Transient error path: log, then sleep for a
			// jitter-bounded backoff window and retry IN-LOOP. Per
			// SPEC-0002 REQ "Backoff on Failure", consecutive failures
			// grow the upper bound exponentially up to BackoffMax; a
			// successful processOnce later resets the curve via
			// bo.reset().
			//
			// Permanent failures never reach here: processOnce
			// classifies refresh-token-revoked and other permanent
			// Proton failures upstream and returns the dedicated
			// sentinels handled above, so only genuinely transient
			// errors (network blips, Proton 5xx/429) walk this curve.
			delay := w.bo.next()
			w.logger.LogAttrs(w.ctx, slog.LevelError,
				"sync: event processing failed; backing off before retry",
				slog.Any("err", err),
				slog.Duration("delay", delay),
				slog.Int("attempt", w.bo.attempts()),
			)
			// Sleep cancel-aware so a graceful Stop wakes us
			// immediately. On a clean wake we continue the loop to retry
			// directly: the backoff delay IS the realized inter-retry
			// gap, which is exactly the SPEC-0002 envelope. We do NOT
			// yield to the ticker here -- doing so would add the
			// remaining tick interval on top of the backoff delay and
			// blow the envelope (the bug this fix removes). On a
			// cancelled wake sleepCtx returns ctx.Err(); the loop's
			// top-of-iteration ctx.Err() check then exits, so we don't
			// retry into a draining worker.
			//
			// Governing: SPEC-0002 REQ "Backoff on Failure" (envelope
			// honored), REQ "Graceful Shutdown" (cancel-aware sleep).
			_ = sleepCtx(w.ctx, delay)
			continue
		}
		// Success — reset the backoff curve so the next failure starts
		// from `base` rather than wherever the prior streak left off.
		// Reset on every successful processOnce (not just on the final
		// iteration of the burst) so a partial-progress streak that
		// later fails doesn't carry an inflated counter from before
		// the recovery began.
		//
		// Governing: SPEC-0002 REQ "Backoff on Failure" — "Failure
		// counter resets on success".
		w.bo.reset()
		if !more {
			return
		}
		// Backlog drain: consume one unit of the bounded budget so a
		// runaway More=true loop cannot starve graceful shutdown or
		// sibling workers. When the budget is exhausted we yield to the
		// ticker; the next fire resumes the drain. (Transient retries
		// above deliberately bypass this budget -- backoff is their
		// throttle.)
		drainBudget--
		if drainBudget <= 0 {
			w.logger.LogAttrs(w.ctx, slog.LevelDebug,
				"sync: max consecutive ticks reached; yielding to ticker",
				slog.Int("limit", w.sup.cfg.MaxConsecutiveTicks),
			)
			return
		}
	}
}

// errProtonSlotUnavailable is a sentinel returned by runProcessOnce
// when AcquireProtonSlot fails because ctx was canceled. tick() uses
// this to distinguish "graceful drain in progress" from a real
// processOnce error — the former should exit silently, the latter
// gets logged at ERROR.
var errProtonSlotUnavailable = errSentinel("sync: proton slot acquisition canceled")

// errSentinel is a tiny named type so package-level error variables
// stay comparable via ==.
type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// runProcessOnce wraps a single processOnce call in slot-acquire +
// panic-recover. Releasing the slot between burst iterations is what
// gives sibling workers a chance to interleave (see tick()).
//
// Defer ordering: recover() is registered AFTER release() so panics
// unwind LIFO with recover running FIRST, the slot release happening
// only after the panic has been logged and re-raised. A sibling
// worker therefore cannot grab the slot before the operator sees the
// crash. The recover re-panics so worker.run()'s outer recover still
// observes it and performs the live-map cleanup.
//
// Governing: SPEC-0002 REQ "Concurrency Limits" + REQ "Panic Isolation".
func (w *worker) runProcessOnce() (bool, error) {
	release, err := w.sup.AcquireProtonSlot(w.ctx)
	if err != nil {
		return false, errProtonSlotUnavailable
	}
	defer release()
	defer func() {
		if r := recover(); r != nil {
			w.logger.LogAttrs(context.Background(), slog.LevelError,
				"sync: worker tick panic; logged before slot release",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			panic(r) // propagate to worker.run()'s recover for cleanup
		}
	}()
	return w.proc.processOnce(w.ctx)
}
