// Package tui is Reduit's local human surface: a full-screen Bubble Tea program
// styled as a mutt homage in a cutesy-cyberpunk design language (ADR-0025). It
// reads the cache exclusively through a read-only facade (internal/tui/store),
// the same store methods the MCP tools use, and never writes, syncs, or touches
// Proton (ADR-0017 no-drift; SPEC-0005 REQ "Read-Only Shared-Store Access").
//
// The root Model owns the global keymap, the persistent status line, the help
// footer, and routing among view models. This foundation ships the shell — a
// mutt-style menu index with a pink active-row rail, a status line, a help
// footer, a `?` overlay, and placeholder bodies — plus the read-only facade,
// the hostile-string sanitizer at the render boundary, the design-system style
// tokens, and the TTY discipline. The real destinations (search index + pager,
// insights views) land in #169 and #170 behind this same keymap and facade.
//
// Governing: ADR-0025 (Bubble Tea TUI, mutt design language), ADR-0022 (charm
// ecosystem), ADR-0017 (shared store, MCP primary), ADR-0012 (single-user
// local-first), SPEC-0005 REQ "Bubble Tea Application, Mutt Design Language",
// REQ "Read-Only Shared-Store Access".
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/joestump/reduit/internal/tui/sanitize"
	"github.com/joestump/reduit/internal/tui/store"
	"github.com/joestump/reduit/internal/tui/styles"
)

// Model is the root Bubble Tea model. It is constructed with a read-only Reader
// and never holds anything that can write the store or reach the network.
type Model struct {
	ctx    context.Context
	reader tuistore.Reader
	styles styles.Styles
	glyphs styles.Glyphs
	keys   keyMap

	width, height int
	ready         bool

	cursor    int         // active menu row
	inSection bool        // false: menu; true: a section body is open
	section   sectionView // the active section view when inSection
	showHelp  bool        // `?` overlay visible

	summary summary
	loaded  bool
	loadErr error
}

// summary is the small cache read-out the home view and status line show. It is
// loaded once via a command in Init so the render path stays synchronous.
type summary struct {
	schema    int64
	messages  int64
	mailboxes []string // sanitized addresses
}

// summaryMsg carries the async facade read back into Update.
type summaryMsg struct {
	s   summary
	err error
}

// NewModel builds the root model over a read-only Reader. ctx bounds the facade
// reads issued from Init; a nil ctx falls back to context.Background so the
// model is safe to construct in tests without plumbing a context.
func NewModel(ctx context.Context, r tuistore.Reader) Model {
	if ctx == nil {
		ctx = context.Background()
	}
	return Model{
		ctx:    ctx,
		reader: r,
		styles: styles.New(),
		glyphs: styles.NewGlyphs(styles.NerdFontsEnabled()),
		keys:   newKeyMap(),
	}
}

// Init kicks off the one-shot cache summary read. Everything the model draws is
// derived from that read plus the window size; there are no tickers.
func (m Model) Init() tea.Cmd {
	return m.loadSummary
}

// loadSummary reads the cache summary through the read-only facade. Any facade
// error is carried, not fatal: the view renders an empty/degraded state so a
// cold or offline cache never errors the TUI (SPEC-0005 REQ "Read-Only
// Shared-Store Access": offline/cold-cache renders empty states, not errors).
// Every mail-derived string (mailbox addresses) is passed through the sanitizer
// at this boundary.
func (m Model) loadSummary() tea.Msg {
	st, err := m.reader.Stats(m.ctx)
	if err != nil {
		return summaryMsg{err: err}
	}
	ver, _ := m.reader.SchemaVersion(m.ctx)
	mbs, _ := m.reader.ListMailboxes(m.ctx)
	addrs := make([]string, 0, len(mbs))
	for _, mb := range mbs {
		addrs = append(addrs, sanitize.Line(mb.Address))
	}
	return summaryMsg{s: summary{schema: ver, messages: st.Messages, mailboxes: addrs}}
}

// Update handles window size, the async summary, and keys. It is pure: it
// mutates only the returned copy of the model and issues no store writes.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		if m.section != nil {
			bw, bh := m.sectionSize()
			m.section.SetSize(bw, bh)
		}
		return m, nil

	case summaryMsg:
		m.loaded = true
		m.loadErr = msg.err
		m.summary = msg.s
		return m, nil

	case exitSectionMsg:
		m.inSection = false
		m.section = nil
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Non-key, non-lifecycle messages (async loads, viewport ticks) flow to the
	// active section view so its data loads and pager scrolling work.
	if m.inSection && m.section != nil {
		var cmd tea.Cmd
		m.section, cmd = m.section.Update(msg)
		return m, cmd
	}
	return m, nil
}

// sectionSize returns the inner width/height a section view renders within,
// accounting for the status line, footer, and the body's padding.
func (m Model) sectionSize() (int, int) {
	bw := m.width - 4
	bh := m.height - 4
	if bw < 1 {
		bw = 1
	}
	if bh < 1 {
		bh = 1
	}
	return bw, bh
}

// handleKey applies the mutt keymap. Global keys (quit, help) win first; then
// the help overlay swallows input; then routing depends on whether a section
// body is open.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit): // ctrl+c always quits
		return m, tea.Quit
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
		return m, nil
	}

	// The `?` overlay is modal: any key closes it and is otherwise swallowed.
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	// A section owns all its keys (including its own back/quit semantics); the
	// root only forwards. The view emits exitSectionMsg to pop back to the menu.
	if m.inSection && m.section != nil {
		var cmd tea.Cmd
		m.section, cmd = m.section.Update(msg)
		return m, cmd
	}

	// Menu context.
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(msg, m.keys.Down):
		if m.cursor < len(sections)-1 {
			m.cursor++
		}
	case key.Matches(msg, m.keys.Open):
		return m.openSection(sections[m.cursor].id)
	case key.Matches(msg, m.keys.Search): // mutt `/` jumps straight to search
		return m.openSection(secSearch)
	case key.Matches(msg, m.keys.Back): // q at the top level quits
		return m, tea.Quit
	}
	return m, nil
}

// openSection constructs the view for id, sizes it, and returns its Init cmd so
// its data loads immediately.
func (m Model) openSection(id sectionID) (tea.Model, tea.Cmd) {
	m.inSection = true
	m.section = newSectionView(m.ctx, id, m.reader, m.styles, m.glyphs)
	bw, bh := m.sectionSize()
	m.section.SetSize(bw, bh)
	return m, m.section.Init()
}

// View composes the persistent status line, the body, and the help footer into
// a full-screen frame sized to the terminal.
func (m Model) View() string {
	if !m.ready {
		return "\n  starting reduit tui…\n"
	}

	status := m.statusBar()
	footer := m.helpFooter()

	// The body fills the height between the one-line status bar and one-line
	// footer.
	bodyHeight := m.height - 2
	if bodyHeight < 1 {
		bodyHeight = 1
	}

	var body string
	switch {
	case m.showHelp:
		body = m.helpOverlay()
	case m.inSection && m.section != nil:
		body = lipgloss.NewStyle().Padding(1, 2).Render(m.section.View())
	default:
		body = m.menuBody()
	}

	body = lipgloss.NewStyle().
		Width(m.width).
		Height(bodyHeight).
		MaxHeight(bodyHeight).
		Render(body)

	return lipgloss.JoinVertical(lipgloss.Left, status, body, footer)
}

// statusBar renders the persistent top line: the wordmark, the current context,
// and a right-aligned cache read-out.
func (m Model) statusBar() string {
	context := "menu"
	if m.inSection && m.section != nil {
		context = m.section.Title()
	}
	left := m.styles.Title.Render("reduit") + " " +
		m.styles.StatusKey.Render(m.glyphs.Prompt) + " " +
		m.styles.Dim.Render("tui") + "  " +
		m.styles.HelpSep.Render(m.glyphs.Bullet) + "  " +
		m.styles.StatusKey.Render(context)

	right := m.cacheReadout()

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	line := left + strings.Repeat(" ", gap) + right
	// Truncate the composed line to exactly m.width display columns BEFORE the
	// background fill. lipgloss.Width(w) hard-WRAPS content wider than w onto
	// extra rows (and MaxWidth cannot undo that height), so on a terminal
	// narrower than the natural content width the status bar would spill onto a
	// second line and shove the footer off-screen. ansi.Truncate is
	// escape-aware, so it clips display width without cutting a color code
	// mid-sequence. With line already ≤ m.width, Width only pads/backgrounds.
	line = ansi.Truncate(line, m.width, "")
	return m.styles.StatusBar.Width(m.width).Render(line)
}

// cacheReadout is the right side of the status bar: mailbox and message counts
// and the schema version, or a "loading"/"unavailable" note while/if the facade
// read is pending or failed.
func (m Model) cacheReadout() string {
	if !m.loaded {
		return m.styles.Faint.Render("reading cache…")
	}
	if m.loadErr != nil {
		return m.styles.Warn.Render("cache unavailable")
	}
	return m.styles.Dim.Render(fmt.Sprintf(
		"%d mailboxes %s %d msgs %s schema v%d",
		len(m.summary.mailboxes), m.glyphs.Bullet,
		m.summary.messages, m.glyphs.Bullet,
		m.summary.schema,
	))
}

// menuBody renders the home view: a title, the cache summary (or a cold-cache
// empty state), and the mutt-style section index with a pink active-row rail.
func (m Model) menuBody() string {
	var b strings.Builder

	b.WriteString(m.styles.Title.Render("your local mail, in the terminal"))
	b.WriteString("\n")
	b.WriteString(m.styles.Subtitle.Render("read-only over the cache — the same data your agents see"))
	b.WriteString("\n\n")

	b.WriteString(m.mailboxSummaryBlock())
	b.WriteString("\n\n")

	for i, s := range sections {
		b.WriteString(m.menuRow(i, s))
		b.WriteString("\n")
	}

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

// mailboxSummaryBlock shows the configured mailboxes, or a cold-cache empty
// state pointing the operator at the next step. Rendering (not erroring) on an
// empty or unavailable cache is REQ "Read-Only Shared-Store Access".
func (m Model) mailboxSummaryBlock() string {
	if !m.loaded {
		return m.styles.Faint.Render("reading the cache…")
	}
	if m.loadErr != nil {
		return m.styles.Empty.Render("the cache could not be read yet — it may not be migrated.\nrun `reduit migrate`, then reopen the tui.")
	}
	if len(m.summary.mailboxes) == 0 {
		return m.styles.Empty.Render("no mailboxes yet — run `reduit auth add` to connect one,\nthen `reduit sync` to fill the cache.")
	}
	var b strings.Builder
	b.WriteString(m.styles.Dim.Render("mailboxes"))
	b.WriteString("\n")
	for _, addr := range m.summary.mailboxes {
		b.WriteString("  ")
		b.WriteString(m.styles.HelpSep.Render(m.glyphs.Bullet))
		b.WriteString(" ")
		b.WriteString(m.styles.Text.Render(addr))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// menuRow renders one section entry. The active row carries the pink rail (the
// mutt `>` analog) and a highlighted label; inactive rows get a blank gutter so
// the glyph column stays aligned.
func (m Model) menuRow(i int, s sectionMeta) string {
	glyph := s.glyph(m.glyphs)
	label := s.title
	if i == m.cursor {
		rail := m.styles.Rail.Render(m.glyphs.Rail)
		return rail + " " + m.styles.RowActive.Render(glyph+"  "+label)
	}
	return "  " + m.styles.RowNormal.Render(glyph+"  "+label)
}

// helpOverlay renders the `?` overlay: the full keymap in a focused panel.
func (m Model) helpOverlay() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("keys"))
	b.WriteString("\n\n")
	for _, bnd := range m.keys.fullHelp() {
		h := bnd.Help()
		b.WriteString("  ")
		b.WriteString(m.styles.HelpKey.Render(padRight(h.Key, 10)))
		b.WriteString(m.styles.Dim.Render(h.Desc))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.styles.Faint.Render("press any key to close"))
	panel := m.styles.PanelFocused.Render(b.String())
	return lipgloss.NewStyle().Padding(1, 2).Render(panel)
}

// helpFooter renders the dim `key • action` footer present on every view. When
// a section is open, its own hints replace the menu-navigation hints (the
// global `?` help and quit stay reachable via the `?` overlay).
func (m Model) helpFooter() string {
	binds := m.keys.shortHelp()
	if m.inSection && m.section != nil {
		binds = append(m.section.Hints(), m.keys.Help)
	}
	parts := make([]string, 0, len(binds))
	for _, bnd := range binds {
		h := bnd.Help()
		parts = append(parts, m.styles.HelpKey.Render(h.Key)+" "+m.styles.Help.Render(h.Desc))
	}
	sep := " " + m.styles.HelpSep.Render(m.glyphs.Bullet) + " "
	// MaxWidth keeps the footer to a single line on any terminal; a leading
	// space insets it without the width/padding overflow the status bar hit.
	return m.styles.Help.MaxWidth(m.width).Render(" " + strings.Join(parts, sep))
}

// padRight right-pads s with spaces to at least n display columns.
func padRight(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s + " "
}
