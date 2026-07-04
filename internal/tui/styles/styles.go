// Package styles holds the TUI's lipgloss style tokens — the mutt-inspired,
// cutesy-cyberpunk design language from SPEC-0005's design.md, rendered with
// terminal-native means only.
//
// The design system's colors, borders, and rails transfer directly to lipgloss;
// its web-CSS "glow" does NOT — a terminal cannot render a drop-shadow halo, so
// emphasis and "elevation" here are expressed only with foreground/background
// color, bold, and border style/color (design.md "No glow / drop-shadow
// system"). The signature is the Lip Gloss rounded border (╭ ╮ ╰ ╯); focus
// shifts a border to cyan; the active index row carries a pink rail — the
// terminal analog of mutt's `>` cursor.
//
// Governing: ADR-0025 (Bubble Tea TUI, mutt design language), ADR-0022 (charm
// ecosystem), SPEC-0005 REQ "Bubble Tea Application, Mutt Design Language".
package styles

import "github.com/charmbracelet/lipgloss"

// Palette — the design-system tokens (design.md "Tokens"). Named by role so
// call sites read intent, not hex.
const (
	colVoid      = "#08080F" // deepest background — the blue-black void
	colSurface   = "#12122A" // panel surface a step above the void
	colSurfaceHi = "#1E1E38" // raised surface / selected background
	colPurple    = "#7D56F4" // Charm brand purple — primary accent, titles
	colPink      = "#FF5FA2" // hot pink — the active-row rail, mutt's `>` cursor
	colCyan      = "#4EE6FF" // Tron cyan — focus border, interactive emphasis
	colMint      = "#00F0A8" // mint — success / healthy state
	colPhosphor  = "#F4F4FF" // phosphor near-white — primary text
	colDim       = "#8B8BB0" // dim indigo-grey — secondary text, help footer
	colFaint     = "#565676" // faint — tertiary metadata, inactive chrome
	colGold      = "#FFC24E" // gold — warnings
	colCoral     = "#FF7A6B" // coral — danger / errors
)

// Styles is the resolved set of lipgloss styles the TUI renders through. Build
// it once (New) and thread it into every view model so the look is defined in
// exactly one place.
type Styles struct {
	// App is the outermost frame color context (foreground on the void).
	App lipgloss.Style

	// Title is a wordmark/section title — bold purple.
	Title lipgloss.Style
	// Subtitle is dimmer supporting text next to a title.
	Subtitle lipgloss.Style

	// Panel is an unfocused rounded-border panel; PanelFocused shifts the
	// border to cyan to show which region has focus.
	Panel        lipgloss.Style
	PanelFocused lipgloss.Style

	// Rail is the pink active-row marker (mutt's `>`); RailPad is the matching
	// blank gutter for inactive rows so columns stay aligned.
	Rail    lipgloss.Style
	RailPad lipgloss.Style
	// RowActive / RowNormal style the text of the selected vs. other index rows.
	RowActive lipgloss.Style
	RowNormal lipgloss.Style

	// StatusBar is the persistent top status line; StatusKey highlights the
	// current context (view name) within it.
	StatusBar lipgloss.Style
	StatusKey lipgloss.Style

	// Help is the dim `key • action` footer; HelpKey is the key glyph, HelpSep
	// the middot separator.
	Help    lipgloss.Style
	HelpKey lipgloss.Style
	HelpSep lipgloss.Style

	// Text tiers.
	Text  lipgloss.Style // primary phosphor text
	Dim   lipgloss.Style // secondary
	Faint lipgloss.Style // tertiary metadata

	// Status colors for callouts.
	Good lipgloss.Style // mint
	Warn lipgloss.Style // gold
	Bad  lipgloss.Style // coral

	// Empty styles a cold-cache empty-state message (dim, centered by caller).
	Empty lipgloss.Style
}

// New returns the resolved mutt/cutesy-cyberpunk style set. It takes no
// arguments: the palette is fixed by the design system. (A future light-mode
// variant, if ever added, would branch here on lipgloss adaptive colors.)
func New() Styles {
	var s Styles

	s.App = lipgloss.NewStyle().Foreground(lipgloss.Color(colPhosphor))

	s.Title = lipgloss.NewStyle().Foreground(lipgloss.Color(colPurple)).Bold(true)
	s.Subtitle = lipgloss.NewStyle().Foreground(lipgloss.Color(colDim))

	s.Panel = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(colFaint)).
		Padding(0, 1)
	s.PanelFocused = s.Panel.
		BorderForeground(lipgloss.Color(colCyan))

	s.Rail = lipgloss.NewStyle().Foreground(lipgloss.Color(colPink)).Bold(true)
	s.RailPad = lipgloss.NewStyle()
	s.RowActive = lipgloss.NewStyle().
		Foreground(lipgloss.Color(colPhosphor)).
		Background(lipgloss.Color(colSurfaceHi)).
		Bold(true)
	s.RowNormal = lipgloss.NewStyle().Foreground(lipgloss.Color(colDim))

	// StatusBar carries a background across the full width, so it takes NO
	// padding: callers build a line exactly the terminal width and render it
	// here. Padding plus a width-exact line would overflow and wrap the bar
	// onto a second row.
	s.StatusBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color(colPhosphor)).
		Background(lipgloss.Color(colSurface))
	s.StatusKey = lipgloss.NewStyle().
		Foreground(lipgloss.Color(colCyan)).
		Bold(true)

	s.Help = lipgloss.NewStyle().Foreground(lipgloss.Color(colDim))
	s.HelpKey = lipgloss.NewStyle().Foreground(lipgloss.Color(colCyan))
	s.HelpSep = lipgloss.NewStyle().Foreground(lipgloss.Color(colFaint))

	s.Text = lipgloss.NewStyle().Foreground(lipgloss.Color(colPhosphor))
	s.Dim = lipgloss.NewStyle().Foreground(lipgloss.Color(colDim))
	s.Faint = lipgloss.NewStyle().Foreground(lipgloss.Color(colFaint))

	s.Good = lipgloss.NewStyle().Foreground(lipgloss.Color(colMint))
	s.Warn = lipgloss.NewStyle().Foreground(lipgloss.Color(colGold))
	s.Bad = lipgloss.NewStyle().Foreground(lipgloss.Color(colCoral))

	s.Empty = lipgloss.NewStyle().Foreground(lipgloss.Color(colFaint)).Italic(true)

	return s
}
