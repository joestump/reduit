// Governing: ADR-0001 (go-proton-api as Proton client),
//             SPEC-0002 REQ "One Worker Per Active Account",
//             SPEC-0002 REQ "Panic Isolation",
//             SPEC-0002 REQ "Concurrency Limits".

package sync

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
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
	proc, err := newEventProcessor(w.ctx, w.id, w.sup.svc, client, w.logger)
	if err != nil {
		w.logger.LogAttrs(w.ctx, slog.LevelError,
			"sync: event processor bootstrap failed; worker will not run",
			slog.Any("err", err),
		)
		w.bootstrapFailed()
		return
	}
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
			// Story #17 will mark the account `crashed` here and
			// emit an admin-UI notification. For now the panic is
			// just logged — the worker exits and is removed from
			// the live map by the deferred removeWorker call above.
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

// tick is one cycle of the worker loop. The body acquires a
// process-wide Proton concurrency slot, runs the event-stream
// processor up to MaxConsecutiveTicks times to drain any backlog, and
// releases the slot.
//
// Governing: SPEC-0002 REQ "Concurrency Limits" — the AcquireProtonSlot
// call is what enforces the global cap. The slot is held across the
// entire chained burst (not re-acquired per processOnce call) for two
// reasons: (1) we already hold one upstream HTTP keep-alive
// connection, so re-acquiring would just thrash the semaphore; (2)
// the per-call cap is "in-flight calls", and chained calls in a tight
// loop are still serially in-flight from this worker's perspective.
//
// Within the burst we honour both ctx.Done and the
// MaxConsecutiveTicks cap so the worker stays responsive to graceful
// shutdown and so a runaway "More=true" loop cannot starve the ticker.
//
// Defer ordering matters: the recover() defer is registered AFTER the
// release() defer so that, on panic, defers unwind LIFO and the
// recover-and-log runs FIRST, with the slot release happening only
// after the panic has been logged and re-raised. Without this
// ordering, a panicking tick would release its slot back into the
// semaphore and a sibling worker could grab it before the operator
// ever sees the panic in the logs. The recover here re-panics so the
// outer worker.run() recover still observes the panic and performs
// the worker map cleanup.
//
// Governing: SPEC-0002 REQ "Panic Isolation" (panic surfaced in logs
// before resources recycle).
func (w *worker) tick() {
	release, err := w.sup.AcquireProtonSlot(w.ctx)
	if err != nil {
		// ctx canceled while waiting for a slot — fine, we're
		// draining anyway.
		return
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

	// Drain the backlog. SPEC-0002's "Tick the loop ASAP after a
	// non-empty batch" intent is implemented here: if processOnce
	// reports more=true we immediately call again rather than waiting
	// for the next ticker fire. The MaxConsecutiveTicks cap and the
	// ctx.Done check ensure the loop cannot starve graceful shutdown.
	for i := 0; i < w.sup.cfg.MaxConsecutiveTicks; i++ {
		if w.ctx.Err() != nil {
			return
		}
		more, err := w.proc.processOnce(w.ctx)
		if err != nil {
			// Story #17 will classify (transient vs permanent) and
			// emit backoff. For #16 plumbing we just log + bail; the
			// next ticker fire retries.
			w.logger.LogAttrs(w.ctx, slog.LevelError,
				"sync: event processing failed; will retry next tick",
				slog.Any("err", err),
			)
			return
		}
		if !more {
			return
		}
	}
	w.logger.LogAttrs(w.ctx, slog.LevelDebug,
		"sync: max consecutive ticks reached; yielding to ticker",
		slog.Int("limit", w.sup.cfg.MaxConsecutiveTicks),
	)
}
