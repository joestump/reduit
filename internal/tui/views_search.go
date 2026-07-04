package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/tui/sanitize"
	tuistore "github.com/joestump/reduit/internal/tui/store"
	"github.com/joestump/reduit/internal/tui/styles"
)

// searchView is the keyword/FTS search destination (#169): a mutt-style `/`
// prompt, a bm25-ranked results index, and a read-only message pager. It reads
// through the facade only (SearchMessages, GetMessage) and never writes or
// touches Proton.
//
// Governing: ADR-0025 (Bubble Tea TUI), SPEC-0005 REQ "Keyword Search With
// Index And Pager", ADR-0017 (shared store), SPEC-0008 (keyword floor).
type searchMode int

const (
	modePrompt searchMode = iota
	modeResults
	modePager
)

type searchView struct {
	ctx  context.Context
	r    tuistore.Reader
	st   styles.Styles
	g    styles.Glyphs
	w, h int

	mode  searchMode
	input textinput.Model
	list  indexList
	vp    viewport.Model

	query    string
	searched bool // a query has been run at least once
	hits     []tuistore.SearchHit
	err      error
	status   string // e.g. "no matches"
}

type searchDoneMsg struct {
	query string
	hits  []tuistore.SearchHit
	err   error
}
type messageLoadedMsg struct {
	hash   string // the hit hash this load was requested for (staleness check)
	detail tuistore.MessageDetail
	found  bool
	err    error
}

func newSearchView(ctx context.Context, r tuistore.Reader, st styles.Styles, g styles.Glyphs) *searchView {
	ti := textinput.New()
	ti.Placeholder = "search your cached mail…"
	ti.Prompt = g.Prompt + " "
	ti.CharLimit = 256
	return &searchView{ctx: ctx, r: r, st: st, g: g, mode: modePrompt, input: ti, list: newIndexList(st, g.Rail)}
}

func (v *searchView) Init() tea.Cmd { return v.input.Focus() }

// CapturesText reports whether this view currently owns raw text keystrokes (a
// focused search prompt). The root checks this before treating a key like `?`
// as the global help toggle, so `?` can be typed into a query instead of being
// stolen for the overlay.
func (v *searchView) CapturesText() bool { return v.mode == modePrompt }

func (v *searchView) SetSize(w, h int) {
	v.w, v.h = w, h
	v.input.Width = w - 4
	v.list.SetHeight(floorOne(h - 3))
	v.vp.Width = w
	v.vp.Height = floorOne(h - 1)
}

func (v *searchView) Title() string { return "search" }

func (v *searchView) Hints() []key.Binding {
	switch v.mode {
	case modePrompt:
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "search")),
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		}
	case modePager:
		return []key.Binding{
			key.NewBinding(key.WithKeys("j/k"), key.WithHelp("j/k", "scroll")),
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "results")),
		}
	default: // results
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "read")),
			key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "back")),
		}
	}
}

func (v *searchView) Update(msg tea.Msg) (sectionView, tea.Cmd) {
	switch msg := msg.(type) {
	case searchDoneMsg:
		// A superseded search result must not yank a reader out of the message
		// they are currently paging.
		if v.mode == modePager {
			return v, nil
		}
		v.searched = true
		v.query, v.hits, v.err = msg.query, msg.hits, msg.err
		v.mode = modeResults
		v.input.Blur()
		if msg.err != nil {
			v.status = "search failed"
		} else if len(msg.hits) == 0 {
			v.status = fmt.Sprintf("no matches for %q", msg.query)
		} else {
			v.status = fmt.Sprintf("%d result(s) for %q", len(msg.hits), msg.query)
		}
		v.list.SetRows(v.hitRows())
		return v, nil
	case messageLoadedMsg:
		// Only open the pager from the results list, and only for a load that
		// still matches the selected hit. A late/stale load must not (a) rip the
		// user out of the prompt or another mode, nor (b) staple this hit's
		// header onto a different message's body after the hit set changed.
		if v.mode != modeResults || v.list.Len() == 0 || v.list.Selected() >= len(v.hits) {
			return v, nil
		}
		if msg.hash != "" && msg.hash != v.hits[v.list.Selected()].Hash {
			return v, nil // stale: the selection moved since this load was dispatched
		}
		v.mode = modePager
		v.vp.SetContent(v.renderMessage(msg))
		v.vp.GotoTop()
		return v, nil
	case tea.KeyMsg:
		return v.handleKey(msg)
	}
	// Non-key messages flow to whichever component is active.
	return v.forward(msg)
}

func (v *searchView) forward(msg tea.Msg) (sectionView, tea.Cmd) {
	var cmd tea.Cmd
	switch v.mode {
	case modePrompt:
		v.input, cmd = v.input.Update(msg)
	case modePager:
		v.vp, cmd = v.vp.Update(msg)
	}
	return v, cmd
}

func (v *searchView) handleKey(msg tea.KeyMsg) (sectionView, tea.Cmd) {
	switch v.mode {
	case modePrompt:
		switch msg.String() {
		case "enter":
			q := strings.TrimSpace(v.input.Value())
			if q == "" {
				return v, nil
			}
			return v, func() tea.Msg {
				hits, err := v.r.SearchMessages(v.ctx, q, 0)
				return searchDoneMsg{query: q, hits: hits, err: err}
			}
		case "esc":
			// esc backs out: to results if we have them, else leave the section.
			if v.searched {
				v.mode = modeResults
				v.input.Blur()
				return v, nil
			}
			return v, exitSection
		}
		var cmd tea.Cmd
		v.input, cmd = v.input.Update(msg)
		return v, cmd

	case modePager:
		switch msg.String() {
		case "q", "esc", "h":
			v.mode = modeResults
			return v, nil
		}
		var cmd tea.Cmd
		v.vp, cmd = v.vp.Update(msg)
		return v, cmd

	default: // modeResults
		switch msg.String() {
		case "q", "esc", "h":
			return v, exitSection
		case "/":
			// Re-open the prompt for a FRESH search; clear the prior query so
			// typing does not append to it.
			v.mode = modePrompt
			v.input.SetValue("")
			v.input.Focus()
			return v, textinput.Blink
		case "j", "down":
			v.list.MoveDown()
		case "k", "up":
			v.list.MoveUp()
		case "enter", "l", "right":
			if v.list.Len() == 0 {
				return v, nil
			}
			hash := v.hits[v.list.Selected()].Hash
			return v, func() tea.Msg {
				d, found, err := v.r.GetMessage(v.ctx, hash)
				return messageLoadedMsg{hash: hash, detail: d, found: found, err: err}
			}
		}
		return v, nil
	}
}

func (v *searchView) hitRows() []string {
	out := make([]string, len(v.hits))
	for i, hit := range v.hits {
		subj := hit.Subject
		if subj == "" {
			subj = "(no subject)"
		}
		out[i] = fmt.Sprintf("%s  %-26s %s",
			hit.Ts.Format("2006-01-02"), truncCol(hit.Sender, 26), subj)
	}
	return out
}

func (v *searchView) renderMessage(msg messageLoadedMsg) string {
	h := v.hits[v.list.Selected()]
	var b strings.Builder
	subj := h.Subject
	if subj == "" {
		subj = "(no subject)"
	}
	b.WriteString(v.st.Title.Render(sanitize.Line(subj)))
	b.WriteString("\n")
	b.WriteString(v.st.Dim.Render("from " + sanitize.Line(h.Sender)))
	b.WriteString("\n")
	b.WriteString(v.st.Faint.Render(h.Ts.Format(time.RFC1123) + " · " + sanitize.Line(h.Folder)))
	b.WriteString("\n\n")
	switch {
	case msg.err != nil:
		b.WriteString(v.st.Empty.Render("could not read the message body."))
	case !msg.found:
		b.WriteString(v.st.Empty.Render("this message is no longer in the cache."))
	case strings.TrimSpace(msg.detail.Body) == "":
		b.WriteString(v.st.Empty.Render("(empty body)"))
	default:
		b.WriteString(v.st.Text.Render(sanitize.Block(msg.detail.Body)))
	}
	return b.String()
}

func (v *searchView) View() string {
	switch v.mode {
	case modePrompt:
		var b strings.Builder
		b.WriteString(v.st.Title.Render("search"))
		b.WriteString("\n\n")
		b.WriteString(v.input.View())
		b.WriteString("\n\n")
		b.WriteString(v.st.Faint.Render("keyword search over your cached mail (FTS). prefix matches, e.g. \"recei\"."))
		return b.String()
	case modePager:
		return v.vp.View()
	default: // results
		var b strings.Builder
		st := v.status
		if st == "" {
			st = "type / to search"
		}
		b.WriteString(v.st.Dim.Render(st))
		b.WriteString("\n\n")
		if len(v.hits) == 0 {
			b.WriteString(v.st.Empty.Render("press / to search, or q to go back."))
			return b.String()
		}
		b.WriteString(v.list.View())
		return b.String()
	}
}
