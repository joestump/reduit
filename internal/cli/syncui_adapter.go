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
	prog program
	mu   sync.Mutex
	buf  bytes.Buffer
}

func newSyncLogWriter(prog program) *syncLogWriter {
	return &syncLogWriter{prog: prog}
}

// Write buffers p and flushes every complete (newline-terminated) line to the
// program. A trailing partial line stays buffered until the next Write or Flush.
func (w *syncLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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

// Flush emits any buffered partial line, called on teardown so a final
// unterminated record is not lost.
func (w *syncLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.prog.Println(strings.TrimRight(w.buf.String(), "\n"))
		w.buf.Reset()
	}
}
