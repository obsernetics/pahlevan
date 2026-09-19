package tui

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

// Colours are ANSI-256 with sensible fallbacks rather than truecolour hex,
// because a lot of the terminals this runs in are somebody's ssh session into
// a jump host, and lipgloss degrades these correctly on a 16-colour term.
const (
	colorAccent   = lipgloss.Color("81")
	colorText     = lipgloss.Color("231")
	colorDim      = lipgloss.Color("245")
	colorFaint    = lipgloss.Color("240")
	colorDeny     = lipgloss.Color("203")
	colorAllow    = lipgloss.Color("114")
	colorWarn     = lipgloss.Color("214")
	colorSelectBG = lipgloss.Color("238")
	colorTabBG    = lipgloss.Color("24")
)

var (
	styleAccent   = lipgloss.NewStyle().Foreground(colorAccent)
	styleHeader   = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleTabOn    = lipgloss.NewStyle().Bold(true).Foreground(colorText).Background(colorTabBG).Padding(0, 1)
	styleTabOff   = lipgloss.NewStyle().Foreground(colorDim).Padding(0, 1)
	styleDim      = lipgloss.NewStyle().Foreground(colorDim)
	styleFaint    = lipgloss.NewStyle().Foreground(colorFaint)
	styleDeny     = lipgloss.NewStyle().Bold(true).Foreground(colorDeny)
	styleAllow    = lipgloss.NewStyle().Foreground(colorAllow)
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(colorText).Background(colorSelectBG)
	styleKey      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("222"))
	styleWarn     = lipgloss.NewStyle().Foreground(colorWarn)
	styleErr      = lipgloss.NewStyle().Bold(true).Foreground(colorDeny)
	styleLabel    = lipgloss.NewStyle().Foreground(colorDim)
	styleValue    = lipgloss.NewStyle().Bold(true).Foreground(colorText)
)

// newTable builds the one table widget every tabular view reuses. The styles
// live here rather than per view so a row means the same thing on every
// screen: bold-on-grey is the cursor, wherever you are.
func newTable() table.Model {
	t := table.New(table.WithFocused(true))
	t.SetStyles(table.Styles{
		Header:   lipgloss.NewStyle().Bold(true).Foreground(colorDim).Padding(0, 1),
		Cell:     lipgloss.NewStyle().Padding(0, 1),
		Selected: styleSelected,
	})
	return t
}

// cellPadding is the horizontal padding the table styles add to every cell,
// counted here because column widths have to be budgeted against the pane
// width, not against the width the cells happen to take afterwards.
const cellPadding = 2

func newHelp() help.Model {
	h := help.New()
	h.Styles.ShortKey = styleKey
	h.Styles.FullKey = styleKey
	h.Styles.ShortDesc = styleDim
	h.Styles.FullDesc = styleDim
	h.Styles.ShortSeparator = styleFaint
	h.Styles.FullSeparator = styleFaint
	return h
}

// colSpec describes one column before it knows how wide it can be.
//
// prio orders which columns survive a narrow terminal, independently of the
// order they are drawn in: on the events view the description is the last
// column and the first thing worth keeping, so dropping columns right to left
// would throw away the only part anyone reads.
type colSpec struct {
	title string
	min   int
	// max caps how far an elastic column grows; zero means uncapped. A name
	// column given a whole 200-column terminal to itself turns a table into
	// two words and an ocean of whitespace.
	max    int
	weight int
	prio   int
}

// fitColumns lays columns out in a pane of the given width. Columns that
// cannot be given their minimum get a width of zero, which bubbles' table
// skips entirely - that is the reflow: a 40-column terminal shows fewer
// columns rather than a wrapped mess.
func fitColumns(width int, specs []colSpec) []table.Column {
	cols := make([]table.Column, len(specs))
	for i, s := range specs {
		cols[i] = table.Column{Title: s.title}
	}
	if width <= 0 || len(specs) == 0 {
		return cols
	}

	order := make([]int, len(specs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return specs[order[a]].prio < specs[order[b]].prio })

	kept := make([]int, 0, len(specs))
	used := 0
	for _, i := range order {
		need := specs[i].min + cellPadding
		if used+need > width {
			continue
		}
		used += need
		kept = append(kept, i)
	}
	if len(kept) == 0 {
		return cols
	}
	sort.Ints(kept)

	spare := width - used
	totalWeight := 0
	for _, i := range kept {
		totalWeight += specs[i].weight
	}
	uncapped := -1
	for _, i := range kept {
		cols[i].Width = specs[i].min
		if totalWeight <= 0 || specs[i].weight <= 0 {
			continue
		}
		grow := spare * specs[i].weight / totalWeight
		if capped := specs[i].max; capped > 0 {
			grow = min(grow, max(0, capped-specs[i].min))
		} else {
			uncapped = i
		}
		cols[i].Width += grow
	}
	// Integer division and the caps leave columns over. Handing the remainder
	// to the last uncapped column makes the table fill the pane exactly, so
	// the right-hand edge does not sit in a different place on every view.
	// With nothing left to grow, the remainder stays as trailing space rather
	// than stretching a name column across half the screen.
	if uncapped >= 0 {
		total := 0
		for _, i := range kept {
			total += cols[i].Width + cellPadding
		}
		cols[uncapped].Width += width - total
	}
	return cols
}

// box draws a bordered pane of exactly w by h cells, with the title set into
// the top rule. Below the size where a border would cost more than it
// explains, it draws the content alone: at eight columns a frame is four of
// them.
func box(title, content string, w, h int, focused bool) string {
	if w < 8 || h < 3 {
		return fit(content, w, h)
	}
	edge := styleFaint
	if focused {
		edge = styleAccent
	}
	inner := w - 4

	label := truncate(title, max(0, w-6))
	fill := w - 5 - lipgloss.Width(label)
	if fill < 0 {
		fill = 0
	}
	top := edge.Render("╭─") + styleHeader.Render(" "+label+" ") + edge.Render(strings.Repeat("─", fill)+"╮")

	body := fit(content, inner, h-2)
	lines := strings.Split(body, "\n")
	rows := make([]string, 0, h)
	rows = append(rows, top)
	for _, l := range lines {
		rows = append(rows, edge.Render("│")+" "+padRight(l, inner)+" "+edge.Render("│"))
	}
	rows = append(rows, edge.Render("╰")+edge.Render(strings.Repeat("─", w-2))+edge.Render("╯"))
	return strings.Join(rows, "\n")
}

// bordered reports whether there is room for pane borders. Borders cost two
// rows and two columns; on a 24-row terminal that is fine and on a two-row
// one it is the whole screen.
func (m *Model) bordered() bool {
	return m.width >= 40 && m.height-chromeHeight >= 5
}

// split reports whether a view has room to show its list and its detail pane
// side by side. Narrower than this, the detail pane would be a column of
// hyphenated words, so enter swaps the body to the detail instead.
func (m *Model) split() bool {
	return m.width >= 72 && m.bodyHeight() >= 5
}

// detailWidth is the right-hand pane's share of a split body. A third, within
// bounds: too narrow and a file path is unreadable, too wide and the list it
// is describing loses its columns.
func (m *Model) detailWidth() int {
	w := m.width / 3
	if w < 28 {
		w = 28
	}
	if w > 56 {
		w = 56
	}
	return w
}

// fit forces a block to exactly w by h cells: truncating long lines, dropping
// extra ones and padding short ones.
//
// Every frame goes through it. A frame taller than the terminal scrolls the
// screen and leaves the previous frame's tail behind; a wider one wraps and
// pushes the status bar off the bottom. Either way the display stops matching
// the model, and it happens at exactly the sizes nobody tests by hand.
func fit(s string, w, h int) string {
	if w < 1 || h < 1 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	// Truncation is ANSI-aware: cutting a styled line by bytes would leave a
	// colour escape unterminated and bleed it across the rest of the screen.
	cut := lipgloss.NewStyle().MaxWidth(w)
	out := make([]string, 0, h)
	for _, l := range lines {
		out = append(out, cut.Render(l))
	}
	for len(out) < h {
		out = append(out, "")
	}
	return strings.Join(out, "\n")
}

// truncate shortens a string to n cells, counting runes rather than bytes: a
// path with non-ASCII in it should not be cut in half, and a terminal measures
// columns, not bytes.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	// Styled strings carry escape sequences that are not visible width.
	if lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func padRight(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// padTo makes a block exactly n lines, so the status bar does not wander up
// and down the screen as content changes height.
func padTo(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	for len(lines) < n {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
