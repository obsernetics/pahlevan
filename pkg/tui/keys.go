package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap is the console's entire keyboard surface, declared once.
//
// The help screen is generated from these bindings rather than typed out
// beside them. A hand-written help list is a second copy of the truth, and the
// copy that rots is always the one a person reads when they are already stuck.
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding

	NextView key.Binding
	PrevView key.Binding
	Jump     key.Binding

	Enter key.Binding
	Back  key.Binding

	Filter  key.Binding
	Pause   key.Binding
	Clear   key.Binding
	Refresh key.Binding

	Help key.Binding
	Quit key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+b"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+f"),
			key.WithHelp("pgdn", "page down"),
		),
		Top: key.NewBinding(
			key.WithKeys("home", "g"),
			key.WithHelp("g", "first row"),
		),
		Bottom: key.NewBinding(
			key.WithKeys("end", "G"),
			key.WithHelp("G", "last row"),
		),
		NextView: key.NewBinding(
			key.WithKeys("tab", "right", "l"),
			key.WithHelp("tab", "next view"),
		),
		PrevView: key.NewBinding(
			key.WithKeys("shift+tab", "left", "h"),
			key.WithHelp("shift+tab", "previous view"),
		),
		Jump: key.NewBinding(
			key.WithKeys("1", "2", "3", "4", "5", "6", "7", "8"),
			key.WithHelp("1-8", "jump to a view"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "open the detail"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back, or clear the filter"),
		),
		Filter: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "filter"),
		),
		Pause: key.NewBinding(
			key.WithKeys(" "),
			key.WithHelp("space", "pause the event list"),
		),
		Clear: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "clear the event list"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "re-read the cluster"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

// ShortHelp is the one-line help in the status bar: the keys someone needs
// before they have read anything.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextView, k.Up, k.Down, k.Enter, k.Filter, k.Help, k.Quit}
}

// FullHelp is the help screen, grouped by what the keys are for.
//
// Three columns rather than four: the help widget drops a whole column that
// does not fit rather than wrapping it, and on an eighty-column terminal a
// fourth column is exactly what goes missing - along with the quit key.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.NextView, k.PrevView, k.Jump, k.Help},
		{k.Up, k.Down, k.PageUp, k.PageDown, k.Top, k.Bottom},
		{k.Enter, k.Back, k.Filter, k.Pause, k.Clear, k.Refresh, k.Quit},
	}
}
