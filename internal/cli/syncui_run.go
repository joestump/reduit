// Package cli — the TTY gate and Bubble Tea program lifecycle for `reduit sync`.
//
// runSyncGated is the single decision point (SPEC-0012 "TTY Gate: detect once,
// choose a mode, never mix"): if stderr is an interactive terminal it runs the
// sync under a pinned bubbles progress bar (syncModel) with the run's logs
// routed below it; otherwise it runs EXACTLY today's plain path — the same
// logger, no progress adapter, no Bubble Tea program, no ANSI. The gate is
// evaluated once at startup and reused for every --watch iteration, so a run
// never flips modes mid-flight.
//
// Teardown order is load-bearing (SPEC-0012 "Clean Teardown"): the program
// quits → the log writer is restored/flushed → the buffered summary table
// prints to the real output → the exit code is returned. The TUI is strictly a
// display; it never owns or swallows the run's error or summary.
//
// Governing: ADR-0023, SPEC-0012 (Sync Progress UI — "TTY Gate And
// Non-Interactive Fallback", "Clean Teardown", "Concurrency Safety").
package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/joestump/reduit/internal/config"
	"github.com/joestump/reduit/internal/store"
	syncengine "github.com/joestump/reduit/internal/sync"
)

// engineBuilder builds the sync engine with a specific logger and progress
// reporter. runSyncGated calls it once it has decided the mode: the plain path
// passes the base logger and a nil reporter (today's wiring); the TUI path
// passes a logger writing into the program and a progressAdapter.
type engineBuilder func(logger *slog.Logger, reporter syncengine.ProgressReporter) syncEngine

// isTerminal reports whether stderr is an interactive terminal. It is a package
// var so tests can force either branch of the gate without a real TTY. stderr is
// checked (not stdout) because that is where reduit's logs go (ADR-0022) and
// what the pinned bar shares (SPEC-0012 "detect once … the same check charm
// uses for color").
var isTerminal = func() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// newSyncProgram constructs the Bubble Tea program for the model. It is a
// package var so tests can (a) assert the plain path NEVER constructs a program
// and (b) substitute a fake. Output goes to stderr so stdout stays clean for the
// summary table and any piped consumer.
//
// The program is bound to the RUN's cancellable ctx (not context.Background):
// tea.Program.Send/Println select on p.ctx.Done(), so once a SIGINT cancels ctx
// the engine goroutine's post-cancel log lines and progress events drop instead
// of blocking on the drained msgs channel after Run() has returned. Binding to
// context.Background() deadlocked teardown — <-runErrCh waited on a goroutine
// wedged inside a blocked Send (SPEC-0012 "Interrupt restores the terminal").
var newSyncProgram = func(ctx context.Context, m tea.Model) *tea.Program {
	return tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithContext(ctx))
}

// runSyncGated applies the TTY gate once and dispatches to the plain or TUI
// runner. baseLogger/loggerCfg are the run's configured logger and its config
// (the TUI path rebuilds an equivalent logger over the program's writer so
// records render below the bar).
func runSyncGated(
	ctx context.Context,
	st *store.Store,
	build engineBuilder,
	baseLogger *slog.Logger,
	loggerCfg config.LoggerConfig,
	opts syncOptions,
	out io.Writer,
) error {
	if !isTerminal() {
		// Non-interactive: byte-identical to today. No program, no writer swap,
		// nil reporter (SPEC-0012 "Piped run stays byte-clean").
		eng := build(baseLogger, nil)
		return runSync(ctx, st, eng, opts, out)
	}
	return runSyncTUI(ctx, st, build, loggerCfg, opts, out)
}

// runSyncTUI runs the sync under a pinned progress bar. It starts the Bubble Tea
// program, swaps the run's logger onto a writer that forwards records into the
// program (records scroll below the bar), runs the sync loop on a background
// goroutine, and on completion tears down in the load-bearing order: quit the
// program, flush/restore the writer, THEN print the buffered summary and return
// the run's error unchanged (SPEC-0012 "Clean Teardown").
func runSyncTUI(
	ctx context.Context,
	st *store.Store,
	build engineBuilder,
	loggerCfg config.LoggerConfig,
	opts syncOptions,
	out io.Writer,
) error {
	// Bind the program to a child of the run's ctx we cancel at teardown. Two
	// distinct wedges are closed by this: (1) an interrupt cancels the parent ctx,
	// which cancels progCtx, so the program quits and any progressAdapter Send
	// blocked on the stopped event loop unblocks via p.ctx.Done(); (2) on a NORMAL
	// finish the parent ctx is still live, so we cancelProg() explicitly after Run
	// returns to release a pump Send that raced the model's quit. Without this the
	// pump goroutine wedges in Send and adapter.Close()'s wg.Wait() hangs — the ^C
	// hang (SPEC-0012 "Interrupt restores the terminal").
	progCtx, cancelProg := context.WithCancel(ctx)
	defer cancelProg()

	prog := newSyncProgram(progCtx, newSyncModel())

	// The engine's logs and progress both flow into the program. Build the log
	// writer BEFORE the engine starts so no record escapes to bare stderr and
	// tears the bar (design.md "construct the logger writer BEFORE the engine
	// starts"). The writer drops once the parent ctx is cancelled: bubbletea's
	// Println is a bare channel send with no ctx guard, so a post-teardown log
	// line would block forever otherwise.
	logWriter := newSyncLogWriter(prog, ctx.Done())
	tuiLogger := buildLoggerTo(logWriter, loggerCfg)
	adapter := newProgressAdapter(prog)
	eng := build(tuiLogger, adapter)

	// The summary table must print AFTER teardown (restored terminal), so the
	// sync loop writes it to a buffer the caller flushes post-teardown rather
	// than to the real output mid-render.
	var summaryBuf bytes.Buffer

	// Run the sync on a background goroutine; p.Run() owns this goroutine until
	// the program quits. When the run finishes (or ctx cancels), signal the
	// model to quit via syncDoneMsg (SPEC-0012 "Clean Teardown": the run's
	// completion decides when to stop).
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- runSync(ctx, st, eng, opts, &summaryBuf)
		prog.Send(syncDoneMsg{})
	}()

	// p.Run blocks until the model quits (syncDoneMsg, Ctrl-C, or ctx cancel via
	// the program's context). A program error is not the run's error; the run's
	// error/summary are authoritative (SPEC-0012 "TUI must never swallow the
	// error/summary").
	_, _ = prog.Run()

	// Teardown order is load-bearing:
	//  1. cancelProg() — the event loop has stopped draining p.msgs; cancelling
	//     progCtx unblocks any adapter Send wedged on it (Send selects on
	//     p.ctx.Done()), so the pump can exit.
	//  2. logWriter.Close() — stop forwarding log lines to the stopped program
	//     (Println has no ctx guard and would block).
	//  3. adapter.Close() — join the pump goroutine (now guaranteed to exit).
	//  4. drain runErrCh, flush a trailing partial log line to stderr, print the
	//     buffered summary, and return the run's authoritative error.
	cancelProg()
	logWriter.Close()
	adapter.Close()
	runErr := <-runErrCh
	logWriter.Flush()
	_, _ = io.Copy(out, &summaryBuf)
	return runErr
}
