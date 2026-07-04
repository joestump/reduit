package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	tuistore "github.com/joestump/reduit/internal/tui/store"
	"github.com/joestump/reduit/internal/tui/styles"
)

func testStyleG() (styles.Styles, styles.Glyphs) {
	return styles.New(), styles.NewGlyphs(false)
}

// drive runs a view's Init command and applies the resulting message, returning
// the loaded view — the same path the root takes minus the terminal.
func drive(t *testing.T, v sectionView) sectionView {
	t.Helper()
	v.SetSize(100, 20)
	if cmd := v.Init(); cmd != nil {
		v, _ = v.Update(cmd())
	}
	return v
}

func send(v sectionView, msg tea.Msg) sectionView {
	v, _ = v.Update(msg)
	return v
}

func kp(s string) tea.KeyMsg {
	if s == "enter" {
		return tea.KeyMsg{Type: tea.KeyEnter}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestMetadataView(t *testing.T) {
	st, g := testStyleG()
	now := time.Now()
	r := fakeReader{mailboxStat: []tuistore.MailboxStat{
		{ID: "1", Address: "joe@proton.me", State: "active", Messages: 100, Embedded: 40, LastSyncAt: &now},
	}}
	v := drive(t, newMetadataView(context.Background(), r, st, g))
	out := v.View()
	if !strings.Contains(out, "joe@proton.me") || !strings.Contains(out, "40%") {
		t.Errorf("metadata view missing mailbox/coverage:\n%s", out)
	}
	// Empty cache → empty state, not an error.
	ev := drive(t, newMetadataView(context.Background(), fakeReader{}, st, g))
	if !strings.Contains(ev.View(), "no mailboxes yet") {
		t.Errorf("metadata empty state missing:\n%s", ev.View())
	}
	// q backs out.
	if _, cmd := v.Update(kp("q")); cmd == nil {
		t.Error("q should emit exitSection")
	}
}

func TestStatsView(t *testing.T) {
	st, g := testStyleG()
	r := fakeReader{
		stats:       tuistore.Stats{Mailboxes: 2, Messages: 1000, Attachments: 30, Embedded: 250},
		mailboxStat: []tuistore.MailboxStat{{ID: "1", Address: "joe@proton.me"}, {ID: "2", Address: "fam@proton.me"}},
		syncRun:     tuistore.SyncRun{Added: 12, Updated: 3, Deleted: 1, Errors: 0, FinishedAt: time.Now().Add(-2 * time.Hour)},
		syncRunOK:   true,
	}
	v := drive(t, newStatsView(context.Background(), r, st, g))
	out := v.View()
	for _, want := range []string{"cache stats", "1000", "25%", "database size"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats view missing %q:\n%s", want, out)
		}
	}
	// REQ "Insights Views": the stats view SHALL include sync run history.
	for _, want := range []string{"sync runs", "joe@proton.me", "+12"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats view missing sync-run history %q:\n%s", want, out)
		}
	}
	// A never-synced mailbox reads "never synced", not a crash.
	nr := fakeReader{mailboxStat: []tuistore.MailboxStat{{ID: "1", Address: "new@proton.me"}}, syncRunOK: false}
	nv := drive(t, newStatsView(context.Background(), nr, st, g))
	if !strings.Contains(nv.View(), "never synced") {
		t.Errorf("never-synced mailbox missing:\n%s", nv.View())
	}
}

func TestViews_NoPanicOnStaleLoadedMsg(t *testing.T) {
	st, g := testStyleG()
	// A text/facts message must never index into an empty list (guards the
	// desync-on-reload hazard the review flagged).
	av := newAttachmentsView(context.Background(), fakeReader{}, st, g)
	av.SetSize(80, 20)
	_, _ = av.Update(attachmentTextMsg{text: "x", found: true}) // empty rows
	_ = av.View()                                               // must not panic

	fv := newFactsView(context.Background(), fakeReader{}, st, g)
	fv.SetSize(80, 20)
	_, _ = fv.Update(factsLoadedMsg{facts: []tuistore.ContactFactRow{{Fact: "x"}}}) // empty contacts
	_ = fv.View()
}

func TestViews_TinyTerminalNoPanic(t *testing.T) {
	st, g := testStyleG()
	for _, v := range []sectionView{
		newAttachmentsView(context.Background(), fakeReader{attachments: []tuistore.AttachmentRow{{ID: "a", Filename: "f"}}}, st, g),
		newFactsView(context.Background(), fakeReader{contacts: []tuistore.ContactRow{{ID: "c", DisplayName: "n"}}}, st, g),
	} {
		v = drive(t, v)
		v.SetSize(1, 0) // degenerate: viewport height must floor, not go negative
		_ = v.View()
	}
}

func TestAttachmentsView_IndexToDetailAndBack(t *testing.T) {
	st, g := testStyleG()
	r := fakeReader{attachments: []tuistore.AttachmentRow{
		{ID: "a1", Filename: "invoice.pdf", MIME: "application/pdf", SizeBytes: 2048, MessageSubj: "Your receipt", HasText: true},
	}}
	v := drive(t, newAttachmentsView(context.Background(), r, st, g))
	if !strings.Contains(v.View(), "invoice.pdf") {
		t.Fatalf("attachments index missing file:\n%s", v.View())
	}
	// enter opens the detail; the fake returns found=false → the "no longer in
	// cache" note (found=false path), which still must render without crashing.
	v = send(v, kp("enter"))
	// The Init returned a cmd; simulate the text-load message.
	v = send(v, attachmentTextMsg{text: "Total due: $9.99", found: true})
	if !strings.Contains(v.View(), "Total due: $9.99") {
		t.Errorf("attachment detail missing extracted text:\n%s", v.View())
	}
	// q returns to the index (not exitSection).
	got, cmd := v.Update(kp("q"))
	if cmd != nil {
		t.Error("q in the detail pager should not exit the section")
	}
	v = got
	if !strings.Contains(v.View(), "invoice.pdf") {
		t.Error("q should return to the attachments index")
	}
}

func TestAttachmentsView_EmptyAndNoText(t *testing.T) {
	st, g := testStyleG()
	// Empty cache.
	e := drive(t, newAttachmentsView(context.Background(), fakeReader{}, st, g))
	if !strings.Contains(e.View(), "no attachments cached yet") {
		t.Errorf("attachments empty state missing:\n%s", e.View())
	}
	// An attachment with no extracted text yet.
	r := fakeReader{attachments: []tuistore.AttachmentRow{{ID: "a1", Filename: "x.bin"}}}
	v := drive(t, newAttachmentsView(context.Background(), r, st, g))
	v = send(v, kp("enter"))
	v = send(v, attachmentTextMsg{text: "", found: true})
	if !strings.Contains(v.View(), "no extracted text yet") {
		t.Errorf("no-text note missing:\n%s", v.View())
	}
}

func TestFactsView_ContactsToFacts(t *testing.T) {
	st, g := testStyleG()
	r := fakeReader{contacts: []tuistore.ContactRow{
		{ID: "c1", DisplayName: "Alice", Address: "alice@x.co", FactCount: 2},
	}}
	v := drive(t, newFactsView(context.Background(), r, st, g))
	if !strings.Contains(v.View(), "Alice") {
		t.Fatalf("contacts index missing name:\n%s", v.View())
	}
	v = send(v, kp("enter"))
	v = send(v, factsLoadedMsg{facts: []tuistore.ContactFactRow{
		{Fact: "based in Berlin", Category: "location", SourceMessageHash: "abcdef1234567890"},
	}})
	out := v.View()
	if !strings.Contains(out, "based in Berlin") || !strings.Contains(out, "abcdef12") {
		t.Errorf("facts detail missing fact/citation:\n%s", out)
	}
	// Facts view is read-only: no key produces a store write (there is no write
	// path on the Reader), and there is no add/edit/delete binding.
}

func TestFactsView_Empty(t *testing.T) {
	st, g := testStyleG()
	e := drive(t, newFactsView(context.Background(), fakeReader{}, st, g))
	if !strings.Contains(e.View(), "no contacts yet") {
		t.Errorf("facts empty state missing:\n%s", e.View())
	}
}

// Hostile mail-derived strings must be sanitized at the render boundary in the
// views, not just in the root.
func TestViews_SanitizeHostileStrings(t *testing.T) {
	st, g := testStyleG()
	hostile := "Invoice\x1b[31m\x1b]0;pwned\x07"
	r := fakeReader{attachments: []tuistore.AttachmentRow{
		{ID: "a1", Filename: hostile, MIME: "text/plain", MessageSubj: hostile},
	}}
	v := drive(t, newAttachmentsView(context.Background(), r, st, g))
	if strings.ContainsRune(v.View(), 0x1b) {
		t.Error("attachments index leaked an ESC from a hostile filename/subject")
	}
}
