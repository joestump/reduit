// Package cli — the TTY gate, program lifecycle, and log routing for the
// interactive auth TUI (ADR-0026, SPEC-0013).
//
// The gate mirrors the sync UI (runSyncGated): on an interactive terminal the
// auth flow runs a Bubble Tea program; otherwise it runs EXACTLY today's plain
// prompter path, byte-for-byte. The auth commands build their proton dialer's
// logger over a switchWriter so, while the TUI is active, the dialer's
// diagnostics (with the benign-scope notice already applied) are redirected into
// the program's scrolling log region below the pinned header instead of tearing
// it; when the program exits, the sink is restored to stderr.
//
// Teardown carries the Phase-1 sync lesson: the program is bound to the run's
// ctx and a child context is cancelled at teardown so an in-flight command
// unblocks, and the log writer drops once the run is dead (bubbletea Println has
// no ctx guard).
//
// Governing: ADR-0026 (interactive auth TUI), ADR-0023 (pinned-header/log
// injection pattern reused), SPEC-0013.
package cli

import (
	"context"
	"io"
	"os"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/tui/styles"
)

// switchWriter is an io.Writer whose target can be swapped atomically. The auth
// dialer's logger writes through it; the interactive TUI redirects it into the
// Bubble Tea program for the run's duration and restores it to stderr on
// teardown, so proton diagnostics never tear the pinned header.
type switchWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newSwitchWriter(w io.Writer) *switchWriter { return &switchWriter{w: w} }

func (s *switchWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	w := s.w
	s.mu.Unlock()
	return w.Write(p)
}

func (s *switchWriter) Swap(w io.Writer) {
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
}

// authOutcome is what the interactive recovery returns to the auth command.
type authOutcome struct {
	// resumeDone means the refresh cheap-resume probe reactivated the mailbox and
	// no re-login was needed (only meaningful for refresh).
	resumeDone bool
	// passphrase is set when the interactive re-login unlocked the mailbox; the
	// caller persists and zeroes it.
	passphrase []byte
}

// newAuthProgram constructs the Bubble Tea program for the auth model. A package
// var so tests can assert the plain path never constructs one and can substitute
// a headless program. Output goes to stderr so stdout stays clean for the
// caller's success line, printed after teardown.
var newAuthProgram = func(ctx context.Context, m tea.Model) *tea.Program {
	return tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithContext(ctx))
}

// runInteractiveAuthGated collects credentials for the add flow: the Bubble Tea
// form on a TTY (with sw wired), else today's plain prompter path. Returns the
// mailbox passphrase (caller-owned, caller-zeroed).
func runInteractiveAuthGated(ctx context.Context, client proton.Client, p prompter, sw *switchWriter, address, verb string, out io.Writer) ([]byte, error) {
	if sw == nil || !isTerminal() {
		return interactiveAuth(ctx, client, p, address, out)
	}
	outcome, err := runAuthTUI(ctx, client, sw, address, verb, nil)
	if err != nil {
		return nil, err
	}
	return outcome.passphrase, nil
}

// runRefreshRecoveryGated runs the refresh recovery: the cheap-resume probe (when
// preflight != nil) and, on fall-through, the interactive re-login. On a TTY both
// happen inside ONE Bubble Tea program — the probe as a spinner phase whose
// benign 403/9101 streams as a notice, then the input fields — so the operator
// sees one continuous flow. Otherwise it runs today's sequential plain path.
func runRefreshRecoveryGated(ctx context.Context, client proton.Client, p prompter, sw *switchWriter, address string, preflight func(context.Context) (bool, error), out io.Writer) (authOutcome, error) {
	if sw == nil || !isTerminal() {
		if preflight != nil {
			done, err := preflight(ctx)
			if err != nil {
				return authOutcome{}, err
			}
			if done {
				return authOutcome{resumeDone: true}, nil
			}
		}
		pass, err := interactiveAuth(ctx, client, p, address, out)
		if err != nil {
			return authOutcome{}, err
		}
		return authOutcome{passphrase: pass}, nil
	}
	return runAuthTUI(ctx, client, sw, address, "re-authenticate", preflight)
}

// runAuthTUI runs the auth model in a Bubble Tea program. When preflight != nil
// (refresh) it starts on the cheap-resume spinner phase and runs the probe on a
// background goroutine, sending its result into the program; otherwise (add) it
// opens on the password field. It routes the dialer's diagnostics into the
// program via sw for the run's duration, then tears down and reads the outcome
// off the final model (SPEC-0013 "Clean Teardown").
func runAuthTUI(ctx context.Context, client proton.Client, sw *switchWriter, address, verb string, preflight func(context.Context) (bool, error)) (authOutcome, error) {
	st := styles.New()
	g := styles.NewGlyphs(styles.NerdFontsEnabled())

	// Bind the program to a child of the run's ctx; cancel it at teardown so any
	// in-flight command unblocks (mirrors runSyncTUI). Commands use progCtx so an
	// abort cancels in-flight network calls.
	progCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	model := newAuthModel(progCtx, client, address, verb, preflight != nil, st, g)
	prog := newAuthProgram(progCtx, model)

	// Redirect the dialer's diagnostics into the program's scrolling region for
	// the run's duration. Swap BEFORE any network call so no record escapes to
	// bare stderr and tears the header. Restore on teardown.
	logWriter := newSyncLogWriter(prog, ctx.Done())
	sw.Swap(logWriter)

	if preflight != nil {
		go func() {
			done, err := preflight(progCtx)
			prog.Send(resumeResultMsg{done: done, err: err})
		}()
	}

	final, _ := prog.Run()

	// Teardown order (mirrors runSyncTUI): cancel so a pump/command unblocks,
	// restore the sink, stop and flush the writer. A program error is not the auth
	// error — the model is authoritative.
	cancel()
	sw.Swap(os.Stderr)
	logWriter.Close()
	logWriter.Flush()

	am, _ := final.(authModel)
	if am.err != nil {
		return authOutcome{}, am.err
	}
	return authOutcome{resumeDone: am.resumeDone, passphrase: am.passphrase}, nil
}
