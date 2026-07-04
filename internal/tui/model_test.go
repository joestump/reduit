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
	stats       tuistore.Stats
	mailboxes   []tuistore.Mailbox
	schema      int64
	statsErr    error
	mailboxStat []tuistore.MailboxStat
	attachments []tuistore.AttachmentRow
	contacts    []tuistore.ContactRow
	facts       []tuistore.ContactFactRow
	syncRun     tuistore.SyncRun
	syncRunOK   bool
	hits        []tuistore.SearchHit
	message     tuistore.MessageDetail
	messageOK   bool
}

func (f fakeReader) Stats(context.Context) (tuistore.Stats, error) {
	return f.stats, f.statsErr
}
func (f fakeReader) MailboxStats(context.Context) ([]tuistore.MailboxStat, error) {
	return f.mailboxStat, nil
}
func (f fakeReader) ListMailboxes(context.Context) ([]tuistore.Mailbox, error) {
	return f.mailboxes, nil
}
func (f fakeReader) LatestSyncRun(context.Context, string) (tuistore.SyncRun, bool, error) {
	return f.syncRun, f.syncRunOK, nil
}
func (f fakeReader) SchemaVersion(context.Context) (int64, error) { return f.schema, nil }
func (f fakeReader) DBPath() string                               { return "/tmp/reduit-test.db" }
func (f fakeReader) ListAttachments(context.Context, int) ([]tuistore.AttachmentRow, error) {
	return f.attachments, nil
}
func (f fakeReader) AttachmentText(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (f fakeReader) ListContacts(context.Context, int) ([]tuistore.ContactRow, error) {
	return f.contacts, nil
}
func (f fakeReader) ContactFacts(context.Context, string) ([]tuistore.ContactFactRow, error) {
	return f.facts, nil
}
func (f fakeReader) SearchMessages(context.Context, string, int) ([]tuistore.SearchHit, error) {
	return f.hits, nil
}
func (f fakeReader) GetMessage(context.Context, string) (tuistore.MessageDetail, bool, error) {
	return f.message, f.messageOK, nil
}

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
	if !m.inSection || m.section == nil || m.section.Title() != "contact facts" {
		t.Fatalf("after enter: inSection=%v section=%v, want the contact facts view", m.inSection, m.section)
	}
	// The status bar reflects the open section's context.
	if !strings.Contains(m.View(), "contact facts") {
		t.Error("status bar should show the contact facts context")
	}
	// q returns to the menu (the view emits exitSection, which the root applies).
	_, cmd := m.Update(keyPress("q"))
	if cmd == nil {
		t.Fatal("q in a section should emit a command (exitSection)")
	}
	m = m.Update2(cmd())
	if m.inSection {
		t.Error("exitSection should return to the menu")
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
	if !m.inSection || m.section == nil || m.section.Title() != "search" {
		t.Errorf("`/` should jump to search: inSection=%v section=%v", m.inSection, m.section)
	}
}

func TestModel_QuestionMarkTypedIntoSearchPrompt(t *testing.T) {
	// Regression: `?` must reach the focused search prompt as a query character,
	// not toggle the global help overlay.
	m := sized(fakeReader{})
	m = m.Update2(keyPress("/")) // open search (prompt focused)
	m = m.Update2(keyPress("a"))
	m = m.Update2(keyPress("?"))
	if m.showHelp {
		t.Error("? opened the help overlay instead of typing into the search prompt")
	}
	sv, ok := m.section.(*searchView)
	if !ok {
		t.Fatalf("section is %T, want *searchView", m.section)
	}
	if sv.input.Value() != "a?" {
		t.Errorf("search input = %q, want %q", sv.input.Value(), "a?")
	}
	// Outside a text prompt, ? still opens help.
	m2 := sized(fakeReader{})
	m2 = m2.Update2(keyPress("?"))
	if !m2.showHelp {
		t.Error("? should still open help from the menu")
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
