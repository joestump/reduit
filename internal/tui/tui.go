package tui

import (
	"context"
	"errors"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/joestump/reduit/internal/tui/store"
)

// ErrNotATerminal is returned by Run when stdin or stdout is not an interactive
// terminal. A full-screen TUI has no meaningful non-TTY fallback (unlike sync,
// whose fallback is plain logs), so it refuses rather than spraying ANSI into a
// pipe (SPEC-0005 REQ "Terminal Discipline": non-TTY exits with a clear message
// and non-zero status, and never renders ANSI into the pipe). The cli command
// surfaces this as `reduit: <message>` on stderr with exit code 1.
var ErrNotATerminal = errors.New("the tui requires an interactive terminal (stdin/stdout must be a tty); it does not render into a pipe or a non-interactive shell")

// stdinIsTTY / stdoutIsTTY are package vars so tests can exercise the gate
// without a real terminal. stdin AND stdout are both checked: the program reads
// keys from stdin and paints the alt-screen to stdout, so either being a pipe
// makes the TUI meaningless.
var (
	stdinIsTTY  = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdoutIsTTY = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
)

// newProgram builds the Bubble Tea program. It is a package var so tests can
// assert the gate refuses non-TTY before any program is constructed, and can
// substitute a fake. The program uses the alt-screen (so the TUI never scrolls
// into and corrupts the user's scrollback) and binds the run to ctx so a
// cancelled context tears the program down cleanly. Bubble Tea installs the
// signal handlers that restore the terminal on SIGINT/SIGTERM and suspend/
// resume on ctrl-z (SPEC-0005 REQ "Terminal Discipline": restore completely on
// exit, suspend, and signal; never corrupt the scrollback).
var newProgram = func(ctx context.Context, m tea.Model) *tea.Program {
	return tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
}

// Run gates on an interactive terminal and, if satisfied, runs the TUI to
// completion over the read-only reader. It returns ErrNotATerminal (before
// constructing any program) when stdin/stdout is not a TTY, and otherwise the
// program's run error (nil on a normal quit). Bubble Tea restores the terminal
// on every exit path — normal quit, interrupt, or context cancel.
func Run(ctx context.Context, r tuistore.Reader) error {
	if !stdinIsTTY() || !stdoutIsTTY() {
		return ErrNotATerminal
	}
	prog := newProgram(ctx, NewModel(ctx, r))
	_, err := prog.Run()
	if err != nil {
		// A panic surfaced by Bubble Tea's recover paths is wrapped as
		// ErrProgramKilled too, so it must be checked FIRST and never
		// swallowed — a crashed TUI must exit non-zero (SPEC-0005 REQ
		// "Terminal Discipline").
		if errors.Is(err, tea.ErrProgramPanic) {
			return err
		}
		// Only a genuine context cancel is a clean shutdown. ErrProgramKilled
		// also wraps ordinary event-loop errors, so gate the swallow on the
		// run context actually being cancelled.
		if ctx != nil && ctx.Err() != nil && errors.Is(err, tea.ErrProgramKilled) {
			return nil
		}
	}
	return err
}
