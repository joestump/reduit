package tui

import "github.com/joestump/reduit/internal/tui/styles"

// sectionID identifies a top-level TUI destination. The foundation ships the
// menu shell and routes to placeholder bodies for each; the real views land in
// #169 (search) and #170 (insights).
type sectionID int

const (
	secSearch sectionID = iota
	secAttachments
	secContacts
	secMetadata
	secStats
)

// sectionMeta describes one menu entry: its title, its glyph (from the active
// glyph set, base or Nerd), and a one-line blurb the placeholder body shows so
// a tester can see what each destination will hold and which issue delivers it.
type sectionMeta struct {
	id    sectionID
	title string
	glyph func(styles.Glyphs) string
	blurb string
}

// sections is the ordered menu. The order is the reading order of the product:
// search first (the primary act), then the derived-insight views.
var sections = []sectionMeta{
	{
		id:    secSearch,
		title: "Search",
		glyph: func(g styles.Glyphs) string { return g.Search },
		blurb: "keyword search over your cached mail, with a results index and a\nreader pager. Arrives in #169.",
	},
	{
		id:    secAttachments,
		title: "Attachments",
		glyph: func(g styles.Glyphs) string { return g.Attach },
		blurb: "extracted attachments — filename, type, size, owning message — with\ntheir extracted text. Arrives in #170.",
	},
	{
		id:    secContacts,
		title: "Contact Facts",
		glyph: func(g styles.Glyphs) string { return g.Contact },
		blurb: "per-contact facts with citations, read-only. Arrives in #170.",
	},
	{
		id:    secMetadata,
		title: "Metadata",
		glyph: func(g styles.Glyphs) string { return g.Meta },
		blurb: "per-mailbox coverage — counts, date ranges, folders. Arrives in #170.",
	},
	{
		id:    secStats,
		title: "Stats",
		glyph: func(g styles.Glyphs) string { return g.Stats },
		blurb: "sync run history, embedding/extraction coverage, and cache size on\ndisk. Arrives in #170.",
	},
}

// sectionByID returns the meta for an id (used by the section placeholder body).
func sectionByID(id sectionID) sectionMeta {
	for _, s := range sections {
		if s.id == id {
			return s
		}
	}
	return sections[0]
}
