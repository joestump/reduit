package tui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/tui/sanitize"
	tuistore "github.com/joestump/reduit/internal/tui/store"
	"github.com/joestump/reduit/internal/tui/styles"
)

// newSectionView builds the view for a menu destination. Search is a scaffold
// until #169; the four insights destinations are real (#170).
func newSectionView(ctx context.Context, id sectionID, r tuistore.Reader, st styles.Styles, g styles.Glyphs) sectionView {
	switch id {
	case secSearch:
		return newSearchView(ctx, r, st, g)
	case secAttachments:
		return newAttachmentsView(ctx, r, st, g)
	case secContacts:
		return newFactsView(ctx, r, st, g)
	case secMetadata:
		return newMetadataView(ctx, r, st, g)
	case secStats:
		return newStatsView(ctx, r, st, g)
	default:
		// All section ids are covered above; search is the safe fallback.
		return newSearchView(ctx, r, st, g)
	}
}

// humanSize renders a byte count in a compact human unit.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// relTime renders a time as a short "Nd ago" style relative string, or "never"
// for a nil pointer. now is passed in so views stay deterministic under test.
func relTime(t *time.Time, now time.Time) string {
	if t == nil {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	}
}

// backKey / scaffold sizing shared by the views.
func viewFooterBack(g styles.Glyphs) key.Binding {
	return key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "back"))
}

// floorOne clamps a dimension to at least 1 so a viewport never gets a zero or
// negative height (bubbles tolerates it but renders nothing scrollable).
func floorOne(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// ---- metadata (per-mailbox coverage) -------------------------------------

type metadataView struct {
	ctx    context.Context
	r      tuistore.Reader
	st     styles.Styles
	g      styles.Glyphs
	w, h   int
	loaded bool
	err    error
	rows   []tuistore.MailboxStat
}

type metadataLoadedMsg struct {
	rows []tuistore.MailboxStat
	err  error
}

func newMetadataView(ctx context.Context, r tuistore.Reader, st styles.Styles, g styles.Glyphs) *metadataView {
	return &metadataView{ctx: ctx, r: r, st: st, g: g}
}

func (v *metadataView) Init() tea.Cmd {
	return func() tea.Msg {
		rows, err := v.r.MailboxStats(v.ctx)
		return metadataLoadedMsg{rows: rows, err: err}
	}
}

func (v *metadataView) Update(msg tea.Msg) (sectionView, tea.Cmd) {
	switch msg := msg.(type) {
	case metadataLoadedMsg:
		v.loaded, v.rows, v.err = true, msg.rows, msg.err
	case tea.KeyMsg:
		if s := msg.String(); s == "q" || s == "esc" || s == "h" {
			return v, exitSection
		}
	}
	return v, nil
}

func (v *metadataView) SetSize(w, h int)     { v.w, v.h = w, h }
func (v *metadataView) Title() string        { return "metadata" }
func (v *metadataView) Hints() []key.Binding { return []key.Binding{viewFooterBack(v.g)} }

func (v *metadataView) View() string {
	if !v.loaded {
		return v.st.Faint.Render("reading the cache…")
	}
	if v.err != nil {
		return v.st.Empty.Render("the cache could not be read.")
	}
	if len(v.rows) == 0 {
		return v.st.Empty.Render("no mailboxes yet — run `reduit auth add` to connect one.")
	}
	var b strings.Builder
	b.WriteString(v.st.Title.Render("mailbox coverage"))
	b.WriteString("\n\n")
	b.WriteString(v.st.Dim.Render(fmt.Sprintf("%-30s %-10s %8s %8s  %s",
		"mailbox", "state", "msgs", "embedded", "last sync")))
	b.WriteString("\n")
	now := time.Now()
	for _, m := range v.rows {
		cov := "—"
		if m.Messages > 0 {
			cov = strconv.FormatInt(m.Embedded*100/m.Messages, 10) + "%"
		}
		b.WriteString(v.st.Text.Render(fmt.Sprintf("%-30s %-10s %8d %8s  %s",
			truncCol(sanitize.Line(m.Address), 30), sanitize.Line(m.State),
			m.Messages, cov, relTime(m.LastSyncAt, now))))
		b.WriteString("\n")
	}
	return b.String()
}

// ---- stats (aggregate coverage + cache size) -----------------------------

type statsView struct {
	ctx    context.Context
	r      tuistore.Reader
	st     styles.Styles
	g      styles.Glyphs
	w, h   int
	loaded bool
	err    error
	stats  tuistore.Stats
	dbSize int64
	runs   []syncRunRow
}

// syncRunRow is the latest sync run for one mailbox, or ok=false when the
// mailbox has never synced.
type syncRunRow struct {
	address string
	run     tuistore.SyncRun
	ok      bool
}

type statsLoadedMsg struct {
	stats  tuistore.Stats
	dbSize int64
	runs   []syncRunRow
	err    error
}

func newStatsView(ctx context.Context, r tuistore.Reader, st styles.Styles, g styles.Glyphs) *statsView {
	return &statsView{ctx: ctx, r: r, st: st, g: g}
}

func (v *statsView) Init() tea.Cmd {
	return func() tea.Msg {
		s, err := v.r.Stats(v.ctx)
		var size int64
		if fi, statErr := os.Stat(v.r.DBPath()); statErr == nil {
			size = fi.Size()
		}
		// Sync run history from sync_runs (SPEC-0005 REQ "Insights Views"): the
		// latest run per mailbox, resolved via the per-mailbox roster.
		var runs []syncRunRow
		if mbs, mbErr := v.r.MailboxStats(v.ctx); mbErr == nil {
			for _, mb := range mbs {
				run, ok, _ := v.r.LatestSyncRun(v.ctx, mb.ID)
				runs = append(runs, syncRunRow{address: mb.Address, run: run, ok: ok})
			}
		}
		return statsLoadedMsg{stats: s, dbSize: size, runs: runs, err: err}
	}
}

func (v *statsView) Update(msg tea.Msg) (sectionView, tea.Cmd) {
	switch msg := msg.(type) {
	case statsLoadedMsg:
		v.loaded, v.stats, v.dbSize, v.runs, v.err = true, msg.stats, msg.dbSize, msg.runs, msg.err
	case tea.KeyMsg:
		if s := msg.String(); s == "q" || s == "esc" || s == "h" {
			return v, exitSection
		}
	}
	return v, nil
}

func (v *statsView) SetSize(w, h int)     { v.w, v.h = w, h }
func (v *statsView) Title() string        { return "stats" }
func (v *statsView) Hints() []key.Binding { return []key.Binding{viewFooterBack(v.g)} }

func (v *statsView) View() string {
	if !v.loaded {
		return v.st.Faint.Render("reading the cache…")
	}
	if v.err != nil {
		return v.st.Empty.Render("the cache could not be read.")
	}
	s := v.stats
	cov := "—"
	if s.Messages > 0 {
		cov = strconv.FormatInt(s.Embedded*100/s.Messages, 10) + "%"
	}
	row := func(label, val string) string {
		return v.st.Dim.Render(fmt.Sprintf("%-22s", label)) + v.st.Text.Render(val) + "\n"
	}
	var b strings.Builder
	b.WriteString(v.st.Title.Render("cache stats"))
	b.WriteString("\n\n")
	b.WriteString(row("mailboxes", strconv.FormatInt(s.Mailboxes, 10)))
	b.WriteString(row("cached messages", strconv.FormatInt(s.Messages, 10)))
	b.WriteString(row("attachments", strconv.FormatInt(s.Attachments, 10)))
	b.WriteString(row("embedding coverage", fmt.Sprintf("%d / %d  (%s)", s.Embedded, s.Messages, cov)))
	b.WriteString(row("database size", humanSize(v.dbSize)))

	// Sync run history (SPEC-0005 REQ "Insights Views": "sync run history from
	// sync_runs").
	b.WriteString("\n")
	b.WriteString(v.st.Title.Render("sync runs"))
	b.WriteString("\n\n")
	if len(v.runs) == 0 {
		b.WriteString(v.st.Empty.Render("no mailboxes to sync yet."))
		return b.String()
	}
	now := time.Now()
	for _, sr := range v.runs {
		addr := truncCol(sanitize.Line(sr.address), 28)
		if !sr.ok {
			b.WriteString(v.st.Dim.Render(fmt.Sprintf("%-28s ", addr)) + v.st.Faint.Render("never synced"))
			b.WriteString("\n")
			continue
		}
		when := relTime(&sr.run.FinishedAt, now)
		detail := fmt.Sprintf("%s  +%d ~%d -%d", when, sr.run.Added, sr.run.Updated, sr.run.Deleted)
		if sr.run.Errors > 0 {
			b.WriteString(v.st.Dim.Render(fmt.Sprintf("%-28s ", addr)) + v.st.Text.Render(detail) + "  " + v.st.Bad.Render(fmt.Sprintf("%d err", sr.run.Errors)))
		} else {
			b.WriteString(v.st.Dim.Render(fmt.Sprintf("%-28s ", addr)) + v.st.Text.Render(detail))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---- attachments (index → extracted-text pager) --------------------------

type attachmentsView struct {
	ctx    context.Context
	r      tuistore.Reader
	st     styles.Styles
	g      styles.Glyphs
	w, h   int
	loaded bool
	err    error
	rows   []tuistore.AttachmentRow
	list   indexList
	detail bool
	vp     viewport.Model
}

type attachmentsLoadedMsg struct {
	rows []tuistore.AttachmentRow
	err  error
}
type attachmentTextMsg struct {
	text  string
	found bool
	err   error
}

func newAttachmentsView(ctx context.Context, r tuistore.Reader, st styles.Styles, g styles.Glyphs) *attachmentsView {
	return &attachmentsView{ctx: ctx, r: r, st: st, g: g, list: newIndexList(st, g.Rail)}
}

func (v *attachmentsView) Init() tea.Cmd {
	return func() tea.Msg {
		rows, err := v.r.ListAttachments(v.ctx, 0)
		return attachmentsLoadedMsg{rows: rows, err: err}
	}
}

func (v *attachmentsView) SetSize(w, h int) {
	v.w, v.h = w, h
	v.list.SetHeight(h - 2)
	v.vp.Width = w
	v.vp.Height = floorOne(h - 1)
}

func (v *attachmentsView) Title() string { return "attachments" }

func (v *attachmentsView) Hints() []key.Binding {
	if v.detail {
		return []key.Binding{
			key.NewBinding(key.WithKeys("j/k"), key.WithHelp("j/k", "scroll")),
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "index")),
		}
	}
	return []key.Binding{
		key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "read text")),
		viewFooterBack(v.g),
	}
}

func (v *attachmentsView) Update(msg tea.Msg) (sectionView, tea.Cmd) {
	switch msg := msg.(type) {
	case attachmentsLoadedMsg:
		v.loaded, v.err = true, msg.err
		v.rows = msg.rows
		v.list.SetRows(v.attachmentRows())
		return v, nil
	case attachmentTextMsg:
		// Guard against a text message arriving for a selection that is no
		// longer in range (e.g. a since-emptied list) before renderText indexes
		// v.rows[Selected()].
		if v.list.Len() == 0 || v.list.Selected() >= len(v.rows) {
			return v, nil
		}
		v.detail = true
		v.vp.SetContent(v.renderText(msg))
		v.vp.GotoTop()
		return v, nil
	case tea.KeyMsg:
		return v.handleKey(msg)
	}
	if v.detail {
		var cmd tea.Cmd
		v.vp, cmd = v.vp.Update(msg)
		return v, cmd
	}
	return v, nil
}

func (v *attachmentsView) handleKey(msg tea.KeyMsg) (sectionView, tea.Cmd) {
	if v.detail {
		switch msg.String() {
		case "q", "esc", "h":
			v.detail = false
			return v, nil
		}
		var cmd tea.Cmd
		v.vp, cmd = v.vp.Update(msg)
		return v, cmd
	}
	switch msg.String() {
	case "q", "esc", "h":
		return v, exitSection
	case "j", "down":
		v.list.MoveDown()
	case "k", "up":
		v.list.MoveUp()
	case "enter", "l", "right":
		if v.list.Len() == 0 {
			return v, nil
		}
		id := v.rows[v.list.Selected()].ID
		return v, func() tea.Msg {
			text, found, err := v.r.AttachmentText(v.ctx, id)
			return attachmentTextMsg{text: text, found: found, err: err}
		}
	}
	return v, nil
}

func (v *attachmentsView) attachmentRows() []string {
	out := make([]string, len(v.rows))
	for i, a := range v.rows {
		name := a.Filename
		if name == "" {
			name = "(unnamed)"
		}
		subj := a.MessageSubj
		if subj == "" {
			subj = "(no subject)"
		}
		mark := " "
		if a.HasText {
			mark = v.g.Check
		}
		out[i] = fmt.Sprintf("%s %-28s %-22s %9s  %s",
			mark, truncCol(name, 28), truncCol(a.MIME, 22), humanSize(a.SizeBytes), subj)
	}
	return out
}

func (v *attachmentsView) renderText(msg attachmentTextMsg) string {
	a := v.rows[v.list.Selected()]
	var b strings.Builder
	b.WriteString(v.st.Title.Render(sanitize.Line(a.Filename)))
	b.WriteString("\n")
	b.WriteString(v.st.Dim.Render(sanitize.Line(a.MIME) + " · " + humanSize(a.SizeBytes)))
	b.WriteString("\n")
	b.WriteString(v.st.Faint.Render("from: " + sanitize.Line(a.MessageSubj)))
	b.WriteString("\n\n")
	switch {
	case msg.err != nil:
		b.WriteString(v.st.Empty.Render("could not read the extracted text."))
	case !msg.found:
		b.WriteString(v.st.Empty.Render("this attachment is no longer in the cache."))
	case strings.TrimSpace(msg.text) == "":
		b.WriteString(v.st.Empty.Render("no extracted text yet — run `reduit embed` after a sync.\n\n(raw attachment bytes are not cached, so open-in-app is not available here.)"))
	default:
		b.WriteString(v.st.Text.Render(sanitize.Block(msg.text)))
	}
	return b.String()
}

func (v *attachmentsView) View() string {
	if !v.loaded {
		return v.st.Faint.Render("reading attachments…")
	}
	if v.err != nil {
		return v.st.Empty.Render("attachments could not be read.")
	}
	if v.detail {
		return v.vp.View()
	}
	if len(v.rows) == 0 {
		return v.st.Empty.Render("no attachments cached yet — run `reduit sync`, then `reduit embed`\nto extract attachment text.")
	}
	var b strings.Builder
	b.WriteString(v.st.Dim.Render(fmt.Sprintf("  %-28s %-22s %9s  %s", "file", "type", "size", "message")))
	b.WriteString("\n")
	b.WriteString(v.list.View())
	return b.String()
}

// ---- contact facts (contacts index → facts pager) ------------------------

type factsView struct {
	ctx      context.Context
	r        tuistore.Reader
	st       styles.Styles
	g        styles.Glyphs
	w, h     int
	loaded   bool
	err      error
	contacts []tuistore.ContactRow
	list     indexList
	detail   bool
	vp       viewport.Model
}

type contactsLoadedMsg struct {
	rows []tuistore.ContactRow
	err  error
}
type factsLoadedMsg struct {
	facts []tuistore.ContactFactRow
	err   error
}

func newFactsView(ctx context.Context, r tuistore.Reader, st styles.Styles, g styles.Glyphs) *factsView {
	return &factsView{ctx: ctx, r: r, st: st, g: g, list: newIndexList(st, g.Rail)}
}

func (v *factsView) Init() tea.Cmd {
	return func() tea.Msg {
		rows, err := v.r.ListContacts(v.ctx, 0)
		return contactsLoadedMsg{rows: rows, err: err}
	}
}

func (v *factsView) SetSize(w, h int) {
	v.w, v.h = w, h
	v.list.SetHeight(h - 2)
	v.vp.Width = w
	v.vp.Height = floorOne(h - 1)
}

func (v *factsView) Title() string { return "contact facts" }

func (v *factsView) Hints() []key.Binding {
	if v.detail {
		return []key.Binding{
			key.NewBinding(key.WithKeys("j/k"), key.WithHelp("j/k", "scroll")),
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "contacts")),
		}
	}
	return []key.Binding{
		key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "facts")),
		viewFooterBack(v.g),
	}
}

func (v *factsView) Update(msg tea.Msg) (sectionView, tea.Cmd) {
	switch msg := msg.(type) {
	case contactsLoadedMsg:
		v.loaded, v.err = true, msg.err
		v.contacts = msg.rows
		v.list.SetRows(v.contactRows())
		return v, nil
	case factsLoadedMsg:
		// Guard against a facts message for an out-of-range selection before
		// renderFacts indexes v.contacts[Selected()].
		if v.list.Len() == 0 || v.list.Selected() >= len(v.contacts) {
			return v, nil
		}
		v.detail = true
		v.vp.SetContent(v.renderFacts(msg))
		v.vp.GotoTop()
		return v, nil
	case tea.KeyMsg:
		return v.handleKey(msg)
	}
	if v.detail {
		var cmd tea.Cmd
		v.vp, cmd = v.vp.Update(msg)
		return v, cmd
	}
	return v, nil
}

func (v *factsView) handleKey(msg tea.KeyMsg) (sectionView, tea.Cmd) {
	if v.detail {
		switch msg.String() {
		case "q", "esc", "h":
			v.detail = false
			return v, nil
		}
		var cmd tea.Cmd
		v.vp, cmd = v.vp.Update(msg)
		return v, cmd
	}
	switch msg.String() {
	case "q", "esc", "h":
		return v, exitSection
	case "j", "down":
		v.list.MoveDown()
	case "k", "up":
		v.list.MoveUp()
	case "enter", "l", "right":
		if v.list.Len() == 0 {
			return v, nil
		}
		id := v.contacts[v.list.Selected()].ID
		return v, func() tea.Msg {
			facts, err := v.r.ContactFacts(v.ctx, id)
			return factsLoadedMsg{facts: facts, err: err}
		}
	}
	return v, nil
}

func (v *factsView) contactRows() []string {
	out := make([]string, len(v.contacts))
	for i, c := range v.contacts {
		name := c.DisplayName
		if name == "" {
			name = c.Address
		}
		if name == "" {
			name = "(unknown)"
		}
		out[i] = fmt.Sprintf("%-28s %-30s %3d facts",
			truncCol(name, 28), truncCol(c.Address, 30), c.FactCount)
	}
	return out
}

func (v *factsView) renderFacts(msg factsLoadedMsg) string {
	c := v.contacts[v.list.Selected()]
	name := c.DisplayName
	if name == "" {
		name = c.Address
	}
	var b strings.Builder
	b.WriteString(v.st.Title.Render(sanitize.Line(name)))
	b.WriteString("\n")
	b.WriteString(v.st.Dim.Render(sanitize.Line(c.Address)))
	b.WriteString("\n\n")
	switch {
	case msg.err != nil:
		b.WriteString(v.st.Empty.Render("could not read this contact's facts."))
	case len(msg.facts) == 0:
		b.WriteString(v.st.Empty.Render("no facts extracted yet — run `reduit facts` after a sync."))
	default:
		for _, f := range msg.facts {
			b.WriteString(v.st.Rail.Render(v.g.Bullet))
			b.WriteString(" ")
			b.WriteString(v.st.Text.Render(sanitize.Line(f.Fact)))
			b.WriteString("\n")
			cat := ""
			if f.Category != "" {
				cat = sanitize.Line(f.Category) + " · "
			}
			b.WriteString(v.st.Faint.Render("    " + cat + "cited from " + shortHash(f.SourceMessageHash)))
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func (v *factsView) View() string {
	if !v.loaded {
		return v.st.Faint.Render("reading contacts…")
	}
	if v.err != nil {
		return v.st.Empty.Render("contacts could not be read.")
	}
	if v.detail {
		return v.vp.View()
	}
	if len(v.contacts) == 0 {
		return v.st.Empty.Render("no contacts yet — sync a mailbox, then run `reduit facts`\nto extract per-contact facts.")
	}
	var b strings.Builder
	b.WriteString(v.st.Dim.Render(fmt.Sprintf("  %-28s %-30s %s", "contact", "address", "facts")))
	b.WriteString("\n")
	b.WriteString(v.list.View())
	return b.String()
}

// truncCol truncates s to at most n display columns with an ellipsis.
func truncCol(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// shortHash renders the first 8 chars of a stable hash for a compact citation.
func shortHash(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8]
}
