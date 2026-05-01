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
// lifecycle (start/stop, panic recovery, drain notification) and a
// stub tick loop. Story #16 replaces the stub body inside tick() with
// a real call to client.GetEvent under AcquireProtonSlot.
//
// Governing: SPEC-0002 — the harness is the substrate every later
// story depends on. The body is intentionally tiny in this PR.
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

// tick is one cycle of the worker loop. In this PR it is a stub:
// acquire a Proton-call slot, log "alive", release. Story #16
// replaces the body with `client.GetEvent` plumbing.
//
// Governing: SPEC-0002 REQ "Concurrency Limits" — the AcquireProtonSlot
// call is what enforces the global cap. Wiring it now (even around a
// no-op) means story #16 inherits the constraint without having to
// remember to add it.
func (w *worker) tick() {
	release, err := w.sup.AcquireProtonSlot(w.ctx)
	if err != nil {
		// ctx canceled while waiting for a slot — fine, we're
		// draining anyway.
		return
	}
	defer release()

	w.logger.LogAttrs(w.ctx, slog.LevelDebug, "sync: worker tick (stub)")
	// TODO(#16): client.GetEvent + cursor persistence goes here.
}
