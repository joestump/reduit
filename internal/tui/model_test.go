package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	tuistore "github.com/joestump/reduit/internal/tui/store"
)

// fakeReader is an in-memory Reader for model tests: no SQLite, no network. It
// lets a test drive the model against a cold cache, a populated cache, or a
// failing read, and — because Reader has no write methods — a test literally
// cannot make the model mutate anything.
type fakeReader struct {
	stats     tuistore.Stats
	mailboxes []tuistore.Mailbox
	schema    int64
	statsErr  error
}

func (f fakeReader) Stats(context.Context) (tuistore.Stats, error) {
	return f.stats, f.statsErr
}
func (f fakeReader) MailboxStats(context.Context) ([]tuistore.MailboxStat, error) { return nil, nil }
func (f fakeReader) ListMailboxes(context.Context) ([]tuistore.Mailbox, error) {
	return f.mailboxes, nil
}
func (f fakeReader) LatestSyncRun(context.Context, string) (tuistore.SyncRun, bool, error) {
	return tuistore.SyncRun{}, false, nil
}
func (f fakeReader) SchemaVersion(context.Context) (int64, error) { return f.schema, nil }
func (f fakeReader) DBPath() string                               { return "/tmp/reduit-test.db" }

func mailbox(addr string) tuistore.Mailbox { return tuistore.Mailbox{Address: addr} }

// sized returns a model that has received a window size (ready to render) and
// the loaded summary, so View() and key handling exercise the real paths.
func sized(r tuistore.Reader) Model {
	m := NewModel(context.Background(), r)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(Model)
	m = m.Update2(m.loadSummary())
	return m
}

// Update2 is a tiny test helper to apply a message and return the concrete type.
func (m Model) Update2(msg tea.Msg) Model {
	updated, _ := m.Update(msg)
	return updated.(Model)
}

func keyPress(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func TestModel_NotReadyRendersStartupLine(t *testing.T) {
	m := NewModel(context.Background(), fakeReader{})
	if got := m.View(); !strings.Contains(got, "starting reduit tui") {
		t.Errorf("pre-size View() = %q, want startup line", got)
	}
}

func TestModel_HomeRendersSectionsAndFooter(t *testing.T) {
	m := sized(fakeReader{
		stats:     tuistore.Stats{Messages: 1200},
		mailboxes: []tuistore.Mailbox{mailbox("joe@proton.me")},
		schema:    3,
	})
	out := m.View()
	for _, want := range []string{"Search", "Attachments", "Contact Facts", "Metadata", "Stats"} {
		if !strings.Contains(out, want) {
			t.Errorf("home view missing section %q", want)
		}
	}
	if !strings.Contains(out, "joe@proton.me") {
		t.Error("home view should list the configured mailbox")
	}
	if !strings.Contains(out, "1200 msgs") {
		t.Error("status bar should show the message count")
	}
	// The footer's help hints are always present.
	if !strings.Contains(out, "open") || !strings.Contains(out, "help") {
		t.Error("help footer missing on home view")
	}
}

func TestModel_StatusBarStaysOneLineOnNarrowTerminal(t *testing.T) {
	// Regression: at a width narrower than the status bar's natural content
	// width, the bar must truncate to ONE physical line, not wrap and shove the
	// footer off-screen.
	r := fakeReader{
		stats:     tuistore.Stats{Messages: 123456},
		mailboxes: []tuistore.Mailbox{mailbox("someone@example.com"), mailbox("family@example.com")},
		schema:    20260703000001,
	}
	for _, w := range []int{20, 30, 40, 55, 60, 80, 120} {
		m := NewModel(context.Background(), r)
		u, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		m = u.(Model)
		m = m.Update2(m.loadSummary())
		bar := m.statusBar()
		if strings.Contains(bar, "\n") {
			t.Errorf("width=%d: status bar wrapped to multiple lines:\n%q", w, bar)
		}
		// The whole frame must also keep the footer as the last line.
		frame := m.View()
		lines := strings.Split(frame, "\n")
		if len(lines) != 24 {
			t.Errorf("width=%d: frame has %d lines, want 24 (status wrap likely)", w, len(lines))
		}
	}
}

func TestModel_ColdCacheShowsEmptyState(t *testing.T) {
	m := sized(fakeReader{}) // zero mailboxes, zero messages
	out := m.View()
	if !strings.Contains(out, "no mailboxes yet") {
		t.Errorf("cold cache should render an empty state, got:\n%s", out)
	}
}

func TestModel_FacadeErrorDoesNotCrash(t *testing.T) {
	m := sized(fakeReader{statsErr: errors.New("db locked")})
	out := m.View()
	// Degrades to a note, never errors or panics.
	if !strings.Contains(out, "cache could not be read") {
		t.Errorf("facade error should degrade gracefully, got:\n%s", out)
	}
	if !strings.Contains(m.statusBar(), "cache unavailable") {
		t.Error("status bar should note the unavailable cache")
	}
}

func TestModel_NavigateDownAndOpenSection(t *testing.T) {
	m := sized(fakeReader{mailboxes: []tuistore.Mailbox{mailbox("a@b.co")}})
	// Move cursor down twice, then open → should be in the Contact Facts section.
	m = m.Update2(keyPress("j"))
	m = m.Update2(keyPress("j"))
	if m.cursor != 2 {
		t.Fatalf("cursor after two downs = %d, want 2", m.cursor)
	}
	m = m.Update2(keyPress("enter"))
	if !m.inSection || m.active != secContacts {
		t.Fatalf("after enter: inSection=%v active=%v, want section secContacts", m.inSection, m.active)
	}
	if !strings.Contains(m.View(), "Contact Facts") {
		t.Error("section body should show the Contact Facts title")
	}
	// q returns to the menu.
	m = m.Update2(keyPress("q"))
	if m.inSection {
		t.Error("q in a section should return to the menu")
	}
}

func TestModel_CursorClampsAtBounds(t *testing.T) {
	m := sized(fakeReader{})
	m = m.Update2(keyPress("k")) // already at top
	if m.cursor != 0 {
		t.Errorf("cursor should clamp at 0, got %d", m.cursor)
	}
	for i := 0; i < len(sections)+3; i++ {
		m = m.Update2(keyPress("j"))
	}
	if m.cursor != len(sections)-1 {
		t.Errorf("cursor should clamp at %d, got %d", len(sections)-1, m.cursor)
	}
}

func TestModel_SlashJumpsToSearch(t *testing.T) {
	m := sized(fakeReader{})
	m = m.Update2(keyPress("/"))
	if !m.inSection || m.active != secSearch {
		t.Errorf("`/` should jump to search: inSection=%v active=%v", m.inSection, m.active)
	}
}

func TestModel_HelpToggles(t *testing.T) {
	m := sized(fakeReader{})
	m = m.Update2(keyPress("?"))
	if !m.showHelp {
		t.Fatal("? should open help")
	}
	if !strings.Contains(m.View(), "keys") {
		t.Error("help overlay should render the keys panel")
	}
	// Any key closes the modal overlay.
	m = m.Update2(keyPress("j"))
	if m.showHelp {
		t.Error("a key press should close the help overlay")
	}
}

func TestModel_QuitFromMenu(t *testing.T) {
	m := sized(fakeReader{})
	_, cmd := m.Update(keyPress("q"))
	if cmd == nil {
		t.Fatal("q at the top level should return a quit command")
	}
	if msg := cmd(); msg == nil {
		t.Error("quit command should produce a message")
	}
}

func TestModel_CtrlCAlwaysQuits(t *testing.T) {
	m := sized(fakeReader{})
	m = m.Update2(keyPress("/")) // enter a section first
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("ctrl+c should quit from anywhere")
	}
}
