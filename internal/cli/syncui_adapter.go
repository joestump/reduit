// Package cli — the engine⇄TUI progress adapter and log-writer plumbing.
//
// This file bridges the sync engine's ProgressReporter seam to the Bubble Tea
// program without ever blocking the engine (SPEC-0012 "Concurrency Safety": a
// slow UI consumer MUST NOT stall sync). The engine calls the reporter
// synchronously from its sync goroutines; progressAdapter turns each call into
// a Bubble Tea message and hands it off through a buffered channel that it
// DROPS onto when full — so the engine's per-message backfill loop never waits
// on the terminal. A single pump goroutine drains that channel into
// program.Send.
//
// It also carries syncLogWriter: the io.Writer the run's logger is pointed at
// while the TUI is active, so each complete log line is delivered via
// program.Println into the terminal's native scrollback below the pinned bar
// (SPEC-0012 "Logs scroll below the pinned bar").
//
// Governing: ADR-0023, SPEC-0012 (Sync Progress UI).
package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	syncengine "github.com/joestump/reduit/internal/sync"
)

// program is the subset of *tea.Program this file needs, extracted as an
// interface so tests drive the adapter and writer without a live terminal.
type program interface {
	Send(msg tea.Msg)
	Println(args ...interface{})
}

// progressAdapter implements syncengine.ProgressReporter by converting engine
// events to Bubble Tea messages and handing them off NON-BLOCKING. Every
// reporter method runs on an engine goroutine; none of them may block, so each
// enqueues onto a buffered channel and DROPS the event if the channel is full
// (display is lossy — the authoritative counts live in RunSummary). A pump
// goroutine drains the channel into the program.
type progressAdapter struct {
	prog program
	ch   chan tea.Msg
	done chan struct{}
	wg   sync.WaitGroup
}

// newProgressAdapter starts the pump goroutine draining events into prog. Call
// Close when the run ends to stop the pump. The buffer is generous but bounded;
// once full, emits drop rather than block the engine (the DROP/COALESCE point
// that enforces the non-blocking contract).
func newProgressAdapter(prog program) *progressAdapter {
	a := &progressAdapter{
		prog: prog,
		ch:   make(chan tea.Msg, 1024),
		done: make(chan struct{}),
	}
	a.wg.Add(1)
	go a.pump()
	return a
}

// pump drains queued messages into the program until Close closes done.
func (a *progressAdapter) pump() {
	defer a.wg.Done()
	for {
		select {
		case <-a.done:
			return
		case msg := <-a.ch:
			a.prog.Send(msg)
		}
	}
}

// Close stops the pump and waits for it to exit, so no goroutine leaks past the
// run (SPEC-0012 "no leaked event-loop workers").
func (a *progressAdapter) Close() {
	close(a.done)
	a.wg.Wait()
}

// enqueue hands a message to the pump WITHOUT blocking: a full buffer drops the
// event. This is the single point that enforces the non-blocking contract.
func (a *progressAdapter) enqueue(msg tea.Msg) {
	select {
	case a.ch <- msg:
	default:
		// Buffer full: drop this display update. Coalescing is implicit —
		// the next MessageApplied carries the latest Done/Total.
	}
}

func (a *progressAdapter) MailboxStarted(ev syncengine.MailboxStarted) {
	a.enqueue(mailboxStartedMsg{ev: ev})
}

func (a *progressAdapter) BackfillEnumerated(ev syncengine.BackfillEnumerated) {
	a.enqueue(backfillEnumeratedMsg{ev: ev})
}

func (a *progressAdapter) MessageApplied(ev syncengine.MessageApplied) {
	a.enqueue(messageAppliedMsg{ev: ev})
}

func (a *progressAdapter) TailBatchApplied(ev syncengine.TailBatchApplied) {
	a.enqueue(tailBatchAppliedMsg{ev: ev})
}

func (a *progressAdapter) MailboxDone(ev syncengine.MailboxDone) {
	a.enqueue(mailboxDoneMsg{ev: ev})
}

// syncLogWriter is the io.Writer the run's logger is pointed at while the TUI is
// active. charmbracelet/log writes one record per Write call, but to be robust
// this buffers and splits on newlines, forwarding each COMPLETE line to the
// program via Println so it lands in native scrollback above the pinned header.
// It is safe for concurrent Write calls (the logger may log from several
// goroutines).
type syncLogWriter struct {
	prog     program
	done     <-chan struct{} // the run's ctx.Done(); once closed, forwarding drops
	fallback io.Writer       // where a leftover partial line goes at teardown (stderr)
	mu       sync.Mutex
	buf      bytes.Buffer
	closed   bool // set by Close on teardown; Write forwards no further lines
}

func newSyncLogWriter(prog program, done <-chan struct{}) *syncLogWriter {
	return &syncLogWriter{prog: prog, done: done, fallback: os.Stderr}
}

// dead reports whether forwarding to the program is no longer safe: either the
// run's ctx was cancelled (interrupt — the engine goroutine keeps logging as it
// unwinds, but the program's event loop is stopping) or Close has run. bubbletea
// Println is a BARE `p.msgs <- msg` with no ctx guard (unlike Send), so a
// Println after the loop stops blocks FOREVER — the wedge behind the ^C hang.
// Dropping display lines is safe: the authoritative output is the summary table,
// not these lines (SPEC-0012 "Display is lossy").
func (w *syncLogWriter) dead() bool {
	if w.closed {
		return true
	}
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// Write buffers p and forwards every complete (newline-terminated) line to the
// program via Println. A trailing partial line stays buffered until the next
// Write or Flush. Once the run is dead (ctx cancelled or Close called) it drops,
// so a record racing teardown never blocks on a stopped program.
func (w *syncLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead() {
		return len(p), nil
	}
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// No newline yet — put the partial line back and wait for more.
			w.buf.Reset()
			w.buf.WriteString(line)
			break
		}
		w.prog.Println(strings.TrimRight(line, "\n"))
	}
	return len(p), nil
}

// Flush emits any buffered partial line so a final unterminated record is not
// lost. It is called AFTER the program has torn down, so it writes straight to
// the fallback (stderr, the restored terminal) rather than via Println — which
// would block on the stopped program. In practice charm always writes
// newline-terminated records, so the buffer is normally empty here.
func (w *syncLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		fmt.Fprintln(w.fallback, strings.TrimRight(w.buf.String(), "\n"))
		w.buf.Reset()
	}
}

// Close stops forwarding: later Writes from the engine goroutine (still
// unwinding after the program has stopped draining) drop instead of blocking on
// Println. Called in the teardown sequence once prog.Run has returned.
func (w *syncLogWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}
