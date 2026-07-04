package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	tuistore "github.com/joestump/reduit/internal/tui/store"
)

func typeStr(v sectionView, s string) sectionView {
	for _, r := range s {
		v, _ = v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return v
}

func TestSearchView_PromptToResultsToPager(t *testing.T) {
	hit := tuistore.SearchHit{
		Hash: "h1", Ts: time.Date(2026, 7, 4, 7, 0, 0, 0, time.UTC),
		Sender: "billing@shop.example", Subject: "Your receipt #4432", Folder: "Inbox", Snippet: "Total [42]",
	}
	r := fakeReader{
		hits:      []tuistore.SearchHit{hit},
		message:   tuistore.MessageDetail{Hash: "h1", Sender: hit.Sender, Subject: hit.Subject, Body: "Thanks for your order. Total $42.00."},
		messageOK: true,
	}
	st, g := testStyleG()
	var v sectionView = newSearchView(context.Background(), r, st, g)
	v.SetSize(100, 20)
	v.Init()

	// Prompt mode shows the input.
	if !strings.Contains(v.View(), "search") {
		t.Fatalf("prompt view missing:\n%s", v.View())
	}
	// Type a query and submit.
	v = typeStr(v, "receipt")
	got, cmd := v.Update(kp("enter"))
	v = got
	if cmd == nil {
		t.Fatal("enter should dispatch a search command")
	}
	v = send(v, cmd()) // deliver searchDoneMsg
	out := v.View()
	if !strings.Contains(out, "Your receipt #4432") || !strings.Contains(out, "1 result") {
		t.Fatalf("results view missing hit:\n%s", out)
	}
	// Open the hit → pager with the body.
	got, cmd = v.Update(kp("enter"))
	v = got
	if cmd == nil {
		t.Fatal("enter on a result should load the message")
	}
	v = send(v, cmd())
	if !strings.Contains(v.View(), "Total $42.00") {
		t.Errorf("pager missing message body:\n%s", v.View())
	}
	// q returns to results, not out of the section.
	got, cmd = v.Update(kp("q"))
	if cmd != nil {
		t.Error("q in the pager should not exit the section")
	}
	v = got
	if !strings.Contains(v.View(), "Your receipt #4432") {
		t.Error("q should return to the results index")
	}
}

func TestSearchView_NoMatchesStaysUsable(t *testing.T) {
	st, g := testStyleG()
	var v sectionView = newSearchView(context.Background(), fakeReader{hits: nil}, st, g)
	v.SetSize(100, 20)
	v.Init()
	v = typeStr(v, "zzz")
	_, cmd := v.Update(kp("enter"))
	v = send(v, cmd())
	out := v.View()
	if !strings.Contains(out, "no matches") {
		t.Errorf("no-matches status missing:\n%s", out)
	}
	// The view is still usable: / re-opens the prompt.
	got, _ := v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if !strings.Contains(got.View(), "search") {
		t.Error("/ should re-open the search prompt after no matches")
	}
}

func TestSearchView_SlashStartsFreshQuery(t *testing.T) {
	// Regression: re-opening the prompt with / must clear the prior query so a
	// new search does not append to the old one.
	st, g := testStyleG()
	var v sectionView = newSearchView(context.Background(), fakeReader{}, st, g)
	v.SetSize(100, 20)
	v.Init()
	v = typeStr(v, "receipt")
	_, cmd := v.Update(kp("enter"))
	v = send(v, cmd()) // -> results
	// Re-open with / and type a new query.
	v, _ = v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	v = typeStr(v, "flight")
	got, cmd := v.Update(kp("enter"))
	v = send(got, cmd())
	if strings.Contains(v.View(), "receiptflight") {
		t.Errorf("/ did not clear the prior query; got accumulated search:\n%s", v.View())
	}
	if !strings.Contains(v.View(), `"flight"`) {
		t.Errorf("fresh query should be just 'flight':\n%s", v.View())
	}
}

func TestSearchView_StaleLoadIgnoredInPromptMode(t *testing.T) {
	// Regression (blocker): a late messageLoadedMsg arriving after the user has
	// re-opened the prompt must NOT force the pager open under the focused input.
	st, g := testStyleG()
	hit := tuistore.SearchHit{Hash: "h1", Sender: "s@x.co", Subject: "Old subject"}
	r := fakeReader{hits: []tuistore.SearchHit{hit}, message: tuistore.MessageDetail{Hash: "h1", Body: "old body"}, messageOK: true}
	sv := newSearchView(context.Background(), r, st, g)
	sv.SetSize(100, 20)
	sv.Init()
	// prompt -> results
	var v sectionView = sv
	v = typeStr(v, "x")
	_, cmd := v.Update(kp("enter"))
	v = send(v, cmd())
	// dispatch a load from results, capture without delivering
	_, loadCmd := v.Update(kp("enter"))
	// re-open the prompt (fresh) and type a new query while the load is in flight
	v, _ = v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	v = typeStr(v, "abc")
	// now the stale load lands
	v = send(v, loadCmd())
	sv2 := v.(*searchView)
	if sv2.mode == modePager {
		t.Error("stale load switched to pager mode under a focused prompt")
	}
	if sv2.input.Value() != "abc" {
		t.Errorf("prompt input clobbered: got %q, want %q", sv2.input.Value(), "abc")
	}
}

func TestSearchView_StaleLoadHashMismatchDropped(t *testing.T) {
	// Regression (major): a load for h_old must not render over a different hit
	// after the hit set changed under the cursor.
	st, g := testStyleG()
	r := fakeReader{}
	sv := newSearchView(context.Background(), r, st, g)
	sv.SetSize(100, 20)
	// Put it in results mode with a single NEW hit selected.
	sv.mode = modeResults
	sv.hits = []tuistore.SearchHit{{Hash: "h_new", Subject: "New"}}
	sv.list.SetRows([]string{"new row"})
	// A stale load for h_old arrives.
	var v sectionView = sv
	v = send(v, messageLoadedMsg{hash: "h_old", detail: tuistore.MessageDetail{Hash: "h_old", Body: "old body"}, found: true})
	if v.(*searchView).mode == modePager {
		t.Error("hash-mismatched stale load should be dropped, not opened")
	}
}

func TestSearchView_EscFromEmptyPromptExits(t *testing.T) {
	st, g := testStyleG()
	var v sectionView = newSearchView(context.Background(), fakeReader{}, st, g)
	v.SetSize(100, 20)
	v.Init()
	// esc before any search backs out of the section.
	_, cmd := v.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc from an unsearched prompt should exitSection")
	}
	if _, ok := cmd().(exitSectionMsg); !ok {
		t.Error("esc should emit exitSection")
	}
}

func TestSearchView_SanitizesHostileHitFields(t *testing.T) {
	st, g := testStyleG()
	hostile := "Re: pwn\x1b[31m\x1b]0;x\x07"
	r := fakeReader{hits: []tuistore.SearchHit{{Hash: "h", Sender: hostile, Subject: hostile}}}
	var v sectionView = newSearchView(context.Background(), r, st, g)
	v.SetSize(100, 20)
	v.Init()
	v = typeStr(v, "x")
	_, cmd := v.Update(kp("enter"))
	v = send(v, cmd())
	if strings.ContainsRune(v.View(), 0x1b) {
		t.Error("search results leaked an ESC from a hostile sender/subject")
	}
}
