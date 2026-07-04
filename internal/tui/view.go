package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/tui/sanitize"
	"github.com/joestump/reduit/internal/tui/styles"
)

// sectionView is a destination the root routes to when a menu entry is opened
// (search in #169; the insights views here). Each is its own Bubble Tea-shaped
// model so it is unit-testable via Update/View with no terminal, matching the
// pattern the progress bar and the root model established. The root owns global
// keys (help, quit) and the status/footer chrome; a view owns its local keys
// and body. To return to the menu, a view emits exitSection from its Update.
//
// Governing: ADR-0025 (Bubble Tea TUI), SPEC-0005 REQ "Insights Views".
type sectionView interface {
	Init() tea.Cmd
	Update(msg tea.Msg) (sectionView, tea.Cmd)
	View() string
	SetSize(width, height int)
	Title() string
	Hints() []key.Binding
}

// exitSectionMsg asks the root to close the active section and return to the
// menu. A view emits it (via exitSection) when the operator backs out past the
// view's own top level.
type exitSectionMsg struct{}

func exitSection() tea.Msg { return exitSectionMsg{} }

// indexList is the reusable mutt-style index: a dense, vertically-scrolling list
// of single-line rows with the pink active-row rail. It owns cursor movement
// and a scroll window so a large result set never renders past the visible
// height (design.md pagination/virtualization). Rows are pre-sanitized display
// strings; the owning view maps the selected index back to its data.
type indexList struct {
	rows   []string
	cursor int
	top    int // index of the first visible row (scroll offset)
	height int // visible row budget
	st     styles.Styles
	rail   string
}

func newIndexList(st styles.Styles, rail string) indexList {
	return indexList{st: st, rail: rail}
}

// SetRows replaces the list contents, clamping the cursor into range. Each row
// is sanitized here so callers cannot forget the render-boundary defense.
func (l *indexList) SetRows(rows []string) {
	safe := make([]string, len(rows))
	for i, r := range rows {
		safe[i] = sanitize.Line(r)
	}
	l.rows = safe
	if l.cursor >= len(l.rows) {
		l.cursor = max(0, len(l.rows)-1)
	}
	l.clampWindow()
}

func (l *indexList) SetHeight(h int) {
	if h < 1 {
		h = 1
	}
	l.height = h
	l.clampWindow()
}

func (l *indexList) Len() int      { return len(l.rows) }
func (l *indexList) Selected() int { return l.cursor }

func (l *indexList) MoveUp() {
	if l.cursor > 0 {
		l.cursor--
		l.clampWindow()
	}
}

func (l *indexList) MoveDown() {
	if l.cursor < len(l.rows)-1 {
		l.cursor++
		l.clampWindow()
	}
}

// clampWindow keeps the cursor visible within [top, top+height).
func (l *indexList) clampWindow() {
	if l.height < 1 {
		l.height = 1
	}
	if l.cursor < l.top {
		l.top = l.cursor
	}
	if l.cursor >= l.top+l.height {
		l.top = l.cursor - l.height + 1
	}
	if l.top < 0 {
		l.top = 0
	}
}

// View renders the visible window with the pink rail on the active row and a
// dim "N more" affordance when the list scrolls past the bottom.
func (l *indexList) View() string {
	if len(l.rows) == 0 {
		return ""
	}
	var b strings.Builder
	end := min(l.top+l.height, len(l.rows))
	for i := l.top; i < end; i++ {
		if i == l.cursor {
			b.WriteString(l.st.Rail.Render(l.rail))
			b.WriteString(" ")
			b.WriteString(l.st.RowActive.Render(l.rows[i]))
		} else {
			b.WriteString("  ")
			b.WriteString(l.st.RowNormal.Render(l.rows[i]))
		}
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	if end < len(l.rows) {
		b.WriteString("\n")
		b.WriteString(l.st.Faint.Render("  ↓ " + strconv.Itoa(len(l.rows)-end) + " more"))
	}
	return b.String()
}
