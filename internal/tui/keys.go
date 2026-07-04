package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap is the TUI's mutt-familiar, keyboard-first binding set. The root owns
// the global keys (help, quit, back) and the shared navigation keys (j/k,
// enter); view models layer their own local keys on top. Bindings carry help
// text so the footer and the `?` overlay render straight from this one source
// (SPEC-0005 REQ "Bubble Tea Application, Mutt Design Language": keyboard-first,
// mutt-familiar single-key bindings; a load-bearing help footer).
//
// Governing: ADR-0025 (Bubble Tea TUI, mutt design language), SPEC-0005 REQ
// "Bubble Tea Application, Mutt Design Language".
type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Open   key.Binding
	Back   key.Binding
	Search key.Binding
	Help   key.Binding
	Quit   key.Binding
}

func newKeyMap() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("k", "up"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("j", "down"),
			key.WithHelp("↓/j", "down"),
		),
		Open: key.NewBinding(
			key.WithKeys("enter", "l", "right"),
			key.WithHelp("enter", "open"),
		),
		Back: key.NewBinding(
			key.WithKeys("q", "esc", "h", "left"),
			key.WithHelp("q", "back"),
		),
		Search: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "search"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", "quit"),
		),
	}
}

// shortHelp is the footer's `key • action` set — the load-bearing dim help
// footer present on every view (design.md "Voice": a help footer of key•action
// pairs on every view).
func (k keyMap) shortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Open, k.Search, k.Help, k.Back}
}

// fullHelp is the `?` overlay's complete binding list.
func (k keyMap) fullHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Open, k.Back, k.Search, k.Help, k.Quit}
}
