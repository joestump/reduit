package styles

import "os"

// Glyphs is the icon set the TUI draws with. The base layer is plain Unicode +
// box-drawing characters that render in ANY terminal font (design.md
// "Iconography" base layer). An optional Nerd Fonts layer swaps in richer
// glyphs when — and only when — the operator has opted in, and every Nerd Font
// glyph has a plain-Unicode fallback so an un-patched terminal never shows
// tofu boxes.
//
// Governing: ADR-0025 (Bubble Tea TUI), SPEC-0005 REQ "Bubble Tea Application,
// Mutt Design Language" (design.md optional Nerd Fonts enhancement layer,
// gated behind detection or explicit config opt-in, with a plain-Unicode
// fallback for every glyph).
type Glyphs struct {
	// Rail is the active-row marker — mutt's `>` cursor analog.
	Rail string
	// Bullet, Arrow, and Prompt are common list/nav/prompt marks.
	Bullet string
	Arrow  string
	Prompt string
	// Check and Cross are status marks (healthy / failed).
	Check string
	Cross string
	// Section glyphs for the menu index; Nerd Fonts gives these file-type-ish
	// icons, the base layer gives neutral geometric marks.
	Search  string
	Attach  string
	Contact string
	Meta    string
	Stats   string
	// nerd records whether the Nerd Font layer is active (for diagnostics/tests).
	nerd bool
}

// baseGlyphs is the always-safe layer: everything renders in a stock terminal
// font (design.md base-layer set — nav, status, prompt, box-drawing).
func baseGlyphs() Glyphs {
	return Glyphs{
		Rail:    "▌",
		Bullet:  "•",
		Arrow:   "→",
		Prompt:  "❯",
		Check:   "✓",
		Cross:   "✗",
		Search:  "◆",
		Attach:  "◇",
		Contact: "●",
		Meta:    "▤",
		Stats:   "▦",
		nerd:    false,
	}
}

// nerdGlyphs overlays the base layer with Nerd Font code points for a richer
// index/status line. Only the section icons change; the safe nav/status marks
// from the base layer are kept so nothing depends on a patched font for core
// navigation. Every value here is intentionally paired with a base fallback in
// baseGlyphs above.
func nerdGlyphs() Glyphs {
	g := baseGlyphs()
	g.Search = ""  // nf-fa-search
	g.Attach = ""  // nf-fa-paperclip
	g.Contact = "" // nf-fa-user
	g.Meta = ""    // nf-fa-info_circle
	g.Stats = ""   // nf-fa-bar_chart
	g.nerd = true
	return g
}

// NerdFontsEnabled reports whether the operator opted into the Nerd Font layer.
// Detection is explicit-opt-in only (design.md "gated behind detection or an
// explicit config opt-in ... Never assume a Nerd Font is present"): auto-
// detecting a patched font is unreliable, so we require an explicit signal.
// REDUIT_NERD_FONT=1 (or true/yes/on) turns it on.
func NerdFontsEnabled() bool {
	switch os.Getenv("REDUIT_NERD_FONT") {
	case "1", "true", "yes", "on", "TRUE", "YES", "ON":
		return true
	default:
		return false
	}
}

// NewGlyphs returns the Nerd Font layer when nerd is true, otherwise the base
// layer. Callers pass NerdFontsEnabled() (or a config-derived bool) so the
// choice stays a single explicit decision.
func NewGlyphs(nerd bool) Glyphs {
	if nerd {
		return nerdGlyphs()
	}
	return baseGlyphs()
}

// UsesNerdFonts reports whether this glyph set is the Nerd Font layer.
func (g Glyphs) UsesNerdFonts() bool { return g.nerd }
