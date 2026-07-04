package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/config"
	"github.com/joestump/reduit/internal/proton"
	syncengine "github.com/joestump/reduit/internal/sync"
)

// --- TUI model unit tests ---------------------------------------------------

// updateModel is a test helper folding one message into the model and returning
// the concrete syncModel (Update returns tea.Model).
func updateModel(m syncModel, msg tea.Msg) syncModel {
	next, _ := m.Update(msg)
	return next.(syncModel)
}

// TestSyncModel_MailboxStartedPinsRowBeforeEnumeration verifies that the first
// event of a run (MailboxStarted) creates a pinned row with the address so the
// header is alive during the long enumeration, before any BackfillEnumerated
// (SPEC-0012 "The header is alive from the first moment of a run"). Without it
// the header renders empty until enumeration completes — the "sync shows nothing"
// bug.
func TestSyncModel_MailboxStartedPinsRowBeforeEnumeration(t *testing.T) {
	m := newSyncModel()
	// Before any event the header is empty (no rows).
	if strings.TrimSpace(m.View()) != "" {
		t.Fatalf("view before any event = %q, want empty", m.View())
	}

	m = updateModel(m, mailboxStartedMsg{ev: syncengine.MailboxStarted{MailboxID: "mb-1", Address: "joe@proton.test"}})
	mp := m.boxes["mb-1"]
	if mp == nil || mp.phase != phaseStarting {
		t.Fatalf("after started: %+v, want a row in phaseStarting", mp)
	}
	if view := m.View(); !strings.Contains(view, "joe@proton.test") {
		t.Errorf("view after started missing address (empty header during enumeration): %q", view)
	}
}

// TestSyncModel_BackfillAdvancesBar verifies MessageApplied moves the bar's
// percent and View renders the bar with the mailbox line (SPEC-0012 "Backfill
// has a denominator", "Bar visible during backfill").
func TestSyncModel_BackfillAdvancesBar(t *testing.T) {
	m := newSyncModel()
	m = updateModel(m, backfillEnumeratedMsg{ev: syncengine.BackfillEnumerated{MailboxID: "mb-1", Address: "joe@proton.test", Total: 4}})

	mp := m.boxes["mb-1"]
	if mp == nil || mp.phase != phaseBackfill || mp.total != 4 {
		t.Fatalf("after enumerate: %+v, want backfill total=4", mp)
	}
	if mp.percent() != 0 {
		t.Errorf("percent at done=0 = %v, want 0", mp.percent())
	}

	m = updateModel(m, messageAppliedMsg{ev: syncengine.MessageApplied{MailboxID: "mb-1", Done: 2, Total: 4}})
	if got := m.boxes["mb-1"].percent(); got != 0.5 {
		t.Errorf("percent at 2/4 = %v, want 0.5", got)
	}

	view := m.View()
	if !strings.Contains(view, "joe@proton.test") {
		t.Errorf("view missing mailbox address: %q", view)
	}
	if !strings.Contains(view, "2/4") {
		t.Errorf("view missing determinate count 2/4: %q", view)
	}
}

// TestSyncModel_BackfillToTailSwitchesIndeterminate verifies a TailBatchApplied
// after backfill flips the phase to the indeterminate indicator (SPEC-0012
// "Tail has no denominator").
func TestSyncModel_BackfillToTailSwitchesIndeterminate(t *testing.T) {
	m := newSyncModel()
	m = updateModel(m, backfillEnumeratedMsg{ev: syncengine.BackfillEnumerated{MailboxID: "mb-1", Address: "joe@proton.test", Total: 2}})
	m = updateModel(m, messageAppliedMsg{ev: syncengine.MessageApplied{MailboxID: "mb-1", Done: 2, Total: 2}})
	if m.boxes["mb-1"].phase != phaseBackfill {
		t.Fatalf("phase before tail = %v, want backfill", m.boxes["mb-1"].phase)
	}

	m = updateModel(m, tailBatchAppliedMsg{ev: syncengine.TailBatchApplied{MailboxID: "mb-1", Events: 3}})
	if m.boxes["mb-1"].phase != phaseTail {
		t.Fatalf("phase after tail batch = %v, want tail", m.boxes["mb-1"].phase)
	}
	view := m.View()
	if strings.Contains(view, "2/2") {
		t.Errorf("tail view should not show a determinate count: %q", view)
	}
	if !strings.Contains(view, "tailing") {
		t.Errorf("tail view missing indeterminate label: %q", view)
	}
}

// TestSyncModel_MultiMailboxRendersPerMailbox verifies concurrent mailboxes each
// get their own line rather than one aggregate (SPEC-0012 "Multi-mailbox
// progress").
func TestSyncModel_MultiMailboxRendersPerMailbox(t *testing.T) {
	m := newSyncModel()
	m = updateModel(m, backfillEnumeratedMsg{ev: syncengine.BackfillEnumerated{MailboxID: "mb-a", Address: "a@proton.test", Total: 3}})
	m = updateModel(m, backfillEnumeratedMsg{ev: syncengine.BackfillEnumerated{MailboxID: "mb-b", Address: "b@proton.test", Total: 5}})
	m = updateModel(m, messageAppliedMsg{ev: syncengine.MessageApplied{MailboxID: "mb-a", Done: 1, Total: 3}})
	m = updateModel(m, tailBatchAppliedMsg{ev: syncengine.TailBatchApplied{MailboxID: "mb-b", Events: 1}})

	view := m.View()
	if !strings.Contains(view, "a@proton.test") || !strings.Contains(view, "b@proton.test") {
		t.Errorf("view missing a per-mailbox line: %q", view)
	}
	// a is backfilling (1/3), b is tailing.
	if !strings.Contains(view, "1/3") {
		t.Errorf("view missing mailbox a backfill count: %q", view)
	}
	if !strings.Contains(view, "tailing") {
		t.Errorf("view missing mailbox b tail state: %q", view)
	}
}

// TestSyncModel_DoneMsgQuits verifies syncDoneMsg quits the program.
func TestSyncModel_DoneMsgQuits(t *testing.T) {
	m := newSyncModel()
	next, cmd := m.Update(syncDoneMsg{})
	if !next.(syncModel).done {
		t.Error("model not marked done after syncDoneMsg")
	}
	if cmd == nil {
		t.Fatal("syncDoneMsg returned no command, want tea.Quit")
	}
	// tea.Quit's command returns a QuitMsg.
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("done command = %T, want tea.QuitMsg", cmd())
	}
}

// TestSyncModel_MailboxDoneMarksStatus verifies a failed MailboxDone renders
// FAILED and a clean one renders done.
func TestSyncModel_MailboxDoneMarksStatus(t *testing.T) {
	m := newSyncModel()
	m = updateModel(m, mailboxDoneMsg{ev: syncengine.MailboxDone{
		MailboxID: "mb-1",
		Summary:   syncengine.RunSummary{Address: "joe@proton.test", Err: context.Canceled},
	}})
	if !strings.Contains(m.View(), "FAILED") {
		t.Errorf("failed mailbox not shown FAILED: %q", m.View())
	}
	if !m.boxes["mb-1"].failed {
		t.Error("mailbox not marked failed")
	}
}

// --- adapter drop / non-blocking test ---------------------------------------

// blockingProgram is a program stub whose Send blocks until released,
// simulating a UI consumer that never drains — the worst case the non-blocking
// contract must survive (SPEC-0012 "Slow consumer does not stall sync"). Once
// released, Send returns immediately so the pump can drain and exit on Close.
type blockingProgram struct {
	release chan struct{}
}

func (p *blockingProgram) Send(tea.Msg)           { <-p.release }
func (p *blockingProgram) Println(...interface{}) { <-p.release }

// TestProgressAdapter_FullBufferDropsInsteadOfBlocking verifies the adapter's
// enqueue never blocks even when the program's Send is wedged and the buffer
// fills: the DROP is the point that enforces the engine's non-blocking contract.
func TestProgressAdapter_FullBufferDropsInsteadOfBlocking(t *testing.T) {
	prog := &blockingProgram{release: make(chan struct{})}
	a := newProgressAdapter(prog)
	t.Cleanup(func() {
		close(prog.release) // unwedge the pump so Close's Wait returns
		a.Close()
	})

	// Fire far more events than the buffer holds. If enqueue blocked, this
	// goroutine would never finish; the pump is wedged on the first Send.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ {
			a.MessageApplied(syncengine.MessageApplied{MailboxID: "mb-1", Done: i, Total: 100000})
		}
		close(done)
	}()

	select {
	case <-done:
		// Completed without blocking → drops held the contract.
	case <-time.After(5 * time.Second):
		t.Fatal("adapter blocked the caller: non-blocking contract violated")
	}
}

// --- log writer test --------------------------------------------------------

// capturingProgram records Println args so the log-writer forwarding can be
// asserted without a terminal.
type capturingProgram struct {
	mu    sync.Mutex
	lines []string
}

func (p *capturingProgram) Send(tea.Msg) {}
func (p *capturingProgram) Println(args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, fmt.Sprint(args...))
}

// TestSyncLogWriter_ForwardsCompleteLines verifies each complete line is
// forwarded via Println and a trailing partial line is held until Flush
// (SPEC-0012 "Logs scroll below the pinned bar" — the delivery path).
func TestSyncLogWriter_ForwardsCompleteLines(t *testing.T) {
	prog := &capturingProgram{}
	w := newSyncLogWriter(prog, make(chan struct{}))
	var fallback bytes.Buffer
	w.fallback = &fallback

	_, _ = w.Write([]byte("line one\nline two\npart"))
	prog.mu.Lock()
	got := append([]string(nil), prog.lines...)
	prog.mu.Unlock()
	if len(got) != 2 || got[0] != "line one" || got[1] != "line two" {
		t.Fatalf("forwarded lines = %v, want [line one, line two]", got)
	}

	// The partial "part" is buffered, not yet forwarded to the program.
	prog.mu.Lock()
	nLines := len(prog.lines)
	prog.mu.Unlock()
	if nLines != 2 {
		t.Fatalf("partial line forwarded early: %v", prog.lines)
	}

	// Flush emits the trailing partial to the fallback (the restored terminal),
	// NOT via Println — the program has torn down by flush time.
	w.Flush()
	if got := strings.TrimSpace(fallback.String()); got != "part" {
		t.Errorf("flush fallback = %q, want %q", got, "part")
	}
}

// TestSyncLogWriter_DropsWhenDead proves a log line racing teardown never blocks
// on the stopped program: once the run ctx is cancelled (interrupt) or Close has
// run, Write drops rather than calling the forever-blocking Println (a torn-down
// bubbletea program's Println is a bare send that never returns). A regression
// guard for the ^C hang (SPEC-0012 "Interrupt restores the terminal").
func TestSyncLogWriter_DropsWhenDead(t *testing.T) {
	blocker := &blockingProgram{release: make(chan struct{})} // never released → Println blocks

	// (a) Cancelled ctx: the writer must drop, not forward.
	done := make(chan struct{})
	close(done)
	w := newSyncLogWriter(blocker, done)
	assertReturns(t, "write after ctx cancel", func() {
		_, _ = w.Write([]byte("late line after interrupt\n"))
	})

	// (b) Explicit Close on a live ctx: same drop.
	w2 := newSyncLogWriter(blocker, make(chan struct{}))
	w2.Close()
	assertReturns(t, "write after Close", func() {
		_, _ = w2.Write([]byte("late line after teardown\n"))
	})
}

// assertReturns fails if fn does not return within a short deadline (i.e. it
// deadlocked).
func assertReturns(t *testing.T, what string, fn func()) {
	t.Helper()
	returned := make(chan struct{})
	go func() { fn(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: did not return (deadlocked)", what)
	}
}

// --- TTY gate seams ---------------------------------------------------------

// withGate swaps isTerminal and newSyncProgram for a test and restores them.
func withGate(t *testing.T, tty bool, progHook func()) {
	t.Helper()
	origTTY, origProg := isTerminal, newSyncProgram
	t.Cleanup(func() { isTerminal, newSyncProgram = origTTY, origProg })
	isTerminal = func() bool { return tty }
	newSyncProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		if progHook != nil {
			progHook()
		}
		return origProg(ctx, m)
	}
}

// TestRunSyncGated_NonTTY_PlainAndNoProgram verifies the non-interactive gate
// produces byte-clean output (no ESC sequences) and NEVER constructs a Bubble
// Tea program (SPEC-0012 "Piped run stays byte-clean", "TTY Gate").
func TestRunSyncGated_NonTTY_PlainAndNoProgram(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedSyncFake("tok-1", "uid-1", "ev-1", []string{"m1"}, map[string]proton.DecryptedMessage{
		"m1": syncMsg("m1", "Hello"),
	})

	var programBuilt bool
	withGate(t, false, func() { programBuilt = true })

	build := func(logger *slog.Logger, reporter syncengine.ProgressReporter) syncEngine {
		// Non-TTY path MUST pass a nil reporter (no progress adapter).
		if reporter != nil {
			t.Errorf("non-TTY path built engine with a non-nil reporter")
		}
		return syncengine.New(syncengine.Deps{Store: st, Keychain: ks, Dialer: &syncTestDialer{clients: map[string]proton.Client{"user-1": fake}}, Logger: logger})
	}

	var out strings.Builder
	err := runSyncGated(ctx, st, build, discardLogger(), config.LoggerConfig{}, syncOptions{}, &out)
	if err != nil {
		t.Fatalf("runSyncGated: %v", err)
	}
	if programBuilt {
		t.Error("non-TTY path constructed a Bubble Tea program; it must not")
	}
	got := out.String()
	if strings.ContainsRune(got, '\x1b') {
		t.Errorf("non-TTY output contains an ESC sequence: %q", got)
	}
	if !strings.Contains(got, "joe@proton.test") || !strings.Contains(got, "TOTAL (1)") {
		t.Errorf("non-TTY summary malformed: %q", got)
	}
}

// withHeadlessProgram forces the TTY branch but builds a HEADLESS Bubble Tea
// program (no renderer, empty input) so runSyncTUI's teardown path can be
// exercised without a terminal: Run returns as soon as the sync goroutine sends
// syncDoneMsg → Quit.
func withHeadlessProgram(t *testing.T) {
	t.Helper()
	origTTY, origProg := isTerminal, newSyncProgram
	t.Cleanup(func() { isTerminal, newSyncProgram = origTTY, origProg })
	isTerminal = func() bool { return true }
	newSyncProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		return tea.NewProgram(m,
			tea.WithInput(bytes.NewReader(nil)),
			tea.WithoutRenderer(),
			tea.WithContext(ctx),
		)
	}
}

// TestRunSyncTUI_SummaryPrintsAfterTeardown verifies the TUI path still prints
// the final summary table to the real output after the program tears down
// (SPEC-0012 "Summary survives the TUI").
func TestRunSyncTUI_SummaryPrintsAfterTeardown(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	fake := authedSyncFake("tok-1", "uid-1", "ev-1", []string{"m1"}, map[string]proton.DecryptedMessage{
		"m1": syncMsg("m1", "Hello"),
	})

	withHeadlessProgram(t)
	build := func(logger *slog.Logger, reporter syncengine.ProgressReporter) syncEngine {
		if reporter == nil {
			t.Error("TUI path built engine with a nil reporter; want the adapter")
		}
		return syncengine.New(syncengine.Deps{Store: st, Keychain: ks, Dialer: &syncTestDialer{clients: map[string]proton.Client{"user-1": fake}}, Logger: logger, Progress: reporter})
	}

	var out bytes.Buffer
	err := runSyncGated(ctx, st, build, discardLogger(), config.LoggerConfig{}, syncOptions{}, &out)
	if err != nil {
		t.Fatalf("runSyncGated (TUI): %v", err)
	}
	if !strings.Contains(out.String(), "joe@proton.test") || !strings.Contains(out.String(), "TOTAL (1)") {
		t.Errorf("summary not printed after teardown: %q", out.String())
	}
}

// TestRunSyncTUI_MailboxErrorKeepsNonZeroExit verifies a mailbox failure still
// yields the non-zero exit path through the TUI teardown (SPEC-0012 "Errors keep
// their exit code").
func TestRunSyncTUI_MailboxErrorKeepsNonZeroExit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	resumeErr := errors.New("invalid refresh token")

	withHeadlessProgram(t)
	build := func(logger *slog.Logger, reporter syncengine.ProgressReporter) syncEngine {
		return syncengine.New(syncengine.Deps{Store: st, Keychain: ks, Dialer: &syncTestDialer{errs: map[string]error{"user-1": resumeErr}}, Logger: logger, Progress: reporter})
	}

	var out bytes.Buffer
	err := runSyncGated(ctx, st, build, discardLogger(), config.LoggerConfig{}, syncOptions{}, &out)
	if err == nil {
		t.Fatal("TUI path returned nil for a failed mailbox; want non-zero exit error")
	}
	if !strings.Contains(err.Error(), "failed to sync") {
		t.Errorf("err = %v, want failure summary", err)
	}
	if !strings.Contains(out.String(), "invalid refresh token") {
		t.Errorf("summary missing failure cause after teardown: %q", out.String())
	}
}
