// Package cli — the sync progress TUI (SPEC-0012).
//
// This file is the presentation layer for `reduit sync` in an interactive
// terminal: a Bubble Tea program whose PINNED header is a charmbracelet/bubbles
// progress bar plus a per-mailbox status line, with the run's log lines
// scrolling in the terminal's native scrollback below it. The sync engine
// (internal/sync) knows nothing about any of this — it emits typed progress
// events through its ProgressReporter seam, and progressAdapter here turns each
// event into a Bubble Tea message. The engine and this program never share
// mutable state; the only hand-off is tea.Program.Send, which is safe from the
// engine's goroutines (SPEC-0012 "Concurrency Safety").
//
// Determinate vs indeterminate: the backfill phase has a real denominator (the
// enumerated message total) so the bar renders a percent; the tail phase has no
// total so the header shows a spinner instead of a fabricated percent (SPEC-0012
// "Determinate Backfill, Indeterminate Tail").
//
// Governing: ADR-0023 (sync progress bar via charmbracelet/bubbles),
// SPEC-0012 (Sync Progress UI).
package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	syncengine "github.com/joestump/reduit/internal/sync"
)

// syncPhase is a mailbox's current phase, driving determinate vs indeterminate
// rendering (SPEC-0012 "Determinate Backfill, Indeterminate Tail").
type syncPhase int

const (
	phaseStarting syncPhase = iota // enumerating / resuming — no total yet
	phaseBackfill                  // determinate: Done of Total
	phaseTail                      // indeterminate: spinner + batch activity
	phaseDone                      // mailbox complete
)

// mailboxProgress is the display state for one mailbox in a (possibly
// multi-mailbox) run. Kept per-mailbox so concurrent mailboxes never collapse
// into one misleading aggregate (SPEC-0012 "Multi-mailbox progress").
type mailboxProgress struct {
	id      string
	address string
	phase   syncPhase
	done    int // backfill messages applied
	total   int // backfill enumerated total (0 until BackfillEnumerated)
	batches int // tail batches applied (indeterminate activity counter)
	failed  bool
}

// percent returns the determinate backfill fraction in [0,1]. Zero total (not
// yet enumerated, or an empty backfill) reads as 0.
func (mp mailboxProgress) percent() float64 {
	if mp.total <= 0 {
		return 0
	}
	if mp.done >= mp.total {
		return 1
	}
	return float64(mp.done) / float64(mp.total)
}

// --- Bubble Tea messages (engine events, adapted) ---------------------------
//
// Each mirrors a syncengine progress event; progressAdapter converts events to
// these and Sends them into the program. They are plain values (no pointers to
// shared state) so the hand-off is race-free.

type mailboxStartedMsg struct{ ev syncengine.MailboxStarted }
type backfillEnumeratedMsg struct{ ev syncengine.BackfillEnumerated }
type messageAppliedMsg struct{ ev syncengine.MessageApplied }
type tailBatchAppliedMsg struct{ ev syncengine.TailBatchApplied }
type mailboxDoneMsg struct{ ev syncengine.MailboxDone }

// syncDoneMsg tells the model the whole run is finished (all mailboxes) so it
// can quit. Sent by the CLI after the engine returns (SPEC-0012 "Clean
// Teardown": the run's completion, not the TUI, decides when to stop).
type syncDoneMsg struct{}

// --- model ------------------------------------------------------------------

// syncModel is the Bubble Tea model rendering the pinned progress header. The
// log region below it is NOT held in the model: log records are printed via
// tea.Println (see syncLogWriter) into the terminal's native scrollback, and
// Bubble Tea re-renders the pinned header above them.
type syncModel struct {
	bar   progress.Model
	spin  spinner.Model
	order []string                    // mailbox ids in first-seen order (stable render)
	boxes map[string]*mailboxProgress // per-mailbox display state
	done  bool                        // whole run finished → quit
}

// newSyncModel builds the model with a bubbles progress bar and a spinner for
// the indeterminate tail phase.
func newSyncModel() syncModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return syncModel{
		bar:   progress.New(progress.WithDefaultGradient()),
		spin:  sp,
		order: nil,
		boxes: make(map[string]*mailboxProgress),
	}
}

// box returns the tracked state for a mailbox, creating (and ordering) it on
// first sight so an event for a not-yet-seen mailbox is handled gracefully.
func (m *syncModel) box(id string) *mailboxProgress {
	mp, ok := m.boxes[id]
	if !ok {
		mp = &mailboxProgress{id: id, phase: phaseStarting}
		m.boxes[id] = mp
		m.order = append(m.order, id)
	}
	return mp
}

func (m syncModel) Init() tea.Cmd {
	// Tick the spinner so the indeterminate tail indicator animates.
	return m.spin.Tick
}

// Update folds one message into the model. Progress messages advance the
// per-mailbox state; the spinner tick keeps animating; syncDoneMsg (or a real
// interrupt surfaced as a KeyMsg/quit) ends the program (SPEC-0012 "Clean
// Teardown").
func (m syncModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Leave room for the percent + padding; the bar clamps its own width.
		m.bar.Width = clampWidth(msg.Width - 4)
		return m, nil

	case mailboxStartedMsg:
		// First event of a run: create the row so the header shows an alive
		// "starting…" spinner during the long enumeration, before any total is
		// known (SPEC-0012 "The header is alive from the first moment of a run").
		mp := m.box(msg.ev.MailboxID)
		mp.address = msg.ev.Address
		mp.phase = phaseStarting
		return m, nil

	case backfillEnumeratedMsg:
		mp := m.box(msg.ev.MailboxID)
		mp.address = msg.ev.Address
		mp.phase = phaseBackfill
		mp.total = msg.ev.Total
		mp.done = 0
		return m, nil

	case messageAppliedMsg:
		mp := m.box(msg.ev.MailboxID)
		mp.phase = phaseBackfill
		mp.done = msg.ev.Done
		mp.total = msg.ev.Total
		return m, nil

	case tailBatchAppliedMsg:
		mp := m.box(msg.ev.MailboxID)
		// A batch after backfill (or with no backfill at all) means the tail
		// phase: switch to the indeterminate indicator (SPEC-0012 "Tail has no
		// denominator").
		mp.phase = phaseTail
		mp.batches++
		return m, nil

	case mailboxDoneMsg:
		mp := m.box(msg.ev.MailboxID)
		if mp.address == "" {
			mp.address = msg.ev.Summary.Address
		}
		mp.phase = phaseDone
		mp.failed = msg.ev.Summary.Err != nil
		return m, nil

	case syncDoneMsg:
		m.done = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		// Ctrl-C: request quit. The CLI's signal.NotifyContext also cancels the
		// run's context, so the engine stops too (SPEC-0012 "Interrupt restores
		// the terminal").
		if msg.Type == tea.KeyCtrlC {
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the pinned header: one line per mailbox (address + phase +
// progress) with the shared bar on the currently-backfilling mailbox. Bubble
// Tea keeps this pinned above the scrolling log region.
func (m syncModel) View() string {
	if m.done {
		// Nothing pinned once we've quit; the summary table prints after teardown.
		return ""
	}
	var b strings.Builder
	for _, id := range m.order {
		mp := m.boxes[id]
		b.WriteString(m.renderMailbox(mp))
		b.WriteByte('\n')
	}
	return b.String()
}

// renderMailbox renders a single mailbox's status line. Backfill shows the
// determinate bar and Done/Total; tail shows the spinner and a batch counter;
// starting/done show a short phase label.
func (m syncModel) renderMailbox(mp *mailboxProgress) string {
	addr := mp.address
	if addr == "" {
		addr = mp.id
	}
	label := lipgloss.NewStyle().Bold(true).Render(addr)

	switch mp.phase {
	case phaseBackfill:
		bar := m.bar.ViewAs(mp.percent())
		return fmt.Sprintf("%s  backfill  %s  %d/%d", label, bar, mp.done, mp.total)
	case phaseTail:
		return fmt.Sprintf("%s  %s tailing  (%d batch(es))", label, m.spin.View(), mp.batches)
	case phaseDone:
		status := "done"
		if mp.failed {
			status = "FAILED"
		}
		return fmt.Sprintf("%s  %s", label, status)
	default:
		return fmt.Sprintf("%s  %s starting…", label, m.spin.View())
	}
}

// clampWidth keeps the bar within a sane range regardless of terminal size.
func clampWidth(w int) int {
	const (
		minWidth = 10
		maxWidth = 60
	)
	if w < minWidth {
		return minWidth
	}
	if w > maxWidth {
		return maxWidth
	}
	return w
}
