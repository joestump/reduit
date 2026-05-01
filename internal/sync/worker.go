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

	// proc is the lazily-constructed event processor. Built on the
	// first tick that successfully resolves a proton.Client via the
	// supervisor's ClientFactory; nil until then. Single-goroutine
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
// Governing: SPEC-0002 REQ "One Worker Per Active Account" — the
// worker must be running within 1 second of the activation
// transition. We achieve this by spawning the goroutine
// synchronously here; the goroutine itself begins its first tick
// immediately on entry rather than waiting for the first ticker fire.
func (w *worker) start() {
	w.logger.LogAttrs(w.ctx, slog.LevelInfo, "sync: worker starting")
	go w.run()
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

	// "No-Proton" mode: ClientFactory was nil at supervisor
	// construction. The worker still runs (so lifecycle tests don't
	// need a stub Proton client) but emits no Proton calls.
	if w.sup.cfg.ClientFactory == nil {
		w.logger.LogAttrs(w.ctx, slog.LevelDebug, "sync: worker tick (no-Proton mode)")
		return
	}

	// Lazy bootstrap of the per-worker event processor. We do this in
	// tick() rather than at start() so a transient ClientFactory
	// failure (e.g. account secrets briefly missing right after
	// activation) does not permanently disable the worker — the next
	// tick will retry. A persistent failure manifests as a steady
	// stream of ERROR logs, which is the observable signal we want.
	if w.proc == nil {
		client, err := w.sup.cfg.ClientFactory(w.ctx, w.id)
		if err != nil {
			w.logger.LogAttrs(w.ctx, slog.LevelError,
				"sync: client factory failed; will retry next tick",
				slog.Any("err", err),
			)
			return
		}
		proc, err := newEventProcessor(w.ctx, w.id, w.sup.svc, client, w.logger)
		if err != nil {
			w.logger.LogAttrs(w.ctx, slog.LevelError,
				"sync: event processor bootstrap failed; will retry next tick",
				slog.Any("err", err),
			)
			return
		}
		w.proc = proc
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
