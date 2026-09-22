package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// View renders the current frame: one header row, a body, one status row,
// clamped to exactly the terminal's size.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	w, h := max(1, m.width), max(1, m.height)

	parts := []string{fit(m.headerRow(w), w, 1)}
	if h >= 3 {
		parts = append(parts, m.bodyBlock(w, h-2))
	}
	if h >= 2 {
		parts = append(parts, fit(m.statusRow(w), w, 1))
	}
	return fit(strings.Join(parts, "\n"), w, h)
}

// headerRow draws the product name and the tabs.
//
// It steps down through progressively shorter labellings rather than letting
// the tabs run off the edge: a tab strip cut short at a narrow width hides the
// views that exist, and "which screens are there" is the one thing a header
// has to answer.
func (m *Model) headerRow(w int) string {
	name := styleHeader.Render("pahlevan")
	attempts := []struct {
		level   int
		product bool
	}{
		{tabsFull, true}, {tabsFull, false},
		{tabsShort, true}, {tabsShort, false},
		{tabsAbbrev, true}, {tabsAbbrev, false},
		{tabsNumbers, false}, {tabsCurrent, false},
	}
	var line string
	for _, a := range attempts {
		line = m.tabs(a.level)
		if a.product {
			line = name + " " + line
		}
		if lipgloss.Width(line) <= w {
			return line
		}
	}
	return line
}

// Tab labellings, widest first.
const (
	tabsFull = iota
	tabsShort
	tabsAbbrev
	tabsNumbers
	tabsCurrent
)

func (m *Model) tabs(level int) string {
	out := make([]string, 0, len(views)+1)
	for i, v := range views {
		var label string
		switch level {
		case tabsFull:
			label = fmt.Sprintf("%d %s", i+1, v)
		case tabsShort:
			label = fmt.Sprintf("%d %s", i+1, v.short())
		case tabsAbbrev:
			label = fmt.Sprintf("%d %s", i+1, v.abbrev())
		case tabsNumbers:
			if v == m.view {
				label = fmt.Sprintf("%d %s", i+1, v.abbrev())
			} else {
				label = strconv.Itoa(i + 1)
			}
		default:
			if v != m.view {
				continue
			}
			label = fmt.Sprintf("%d/%d %s", i+1, len(views), v.short())
		}
		if v == m.view {
			out = append(out, styleTabOn.Render(label))
		} else {
			out = append(out, styleTabOff.Render(label))
		}
	}
	if level <= tabsAbbrev {
		hint := "? help"
		if level == tabsAbbrev {
			hint = "? hlp"
		}
		if m.view == ViewHelp {
			out = append(out, styleTabOn.Render(hint))
		} else {
			out = append(out, styleTabOff.Render(hint))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, out...)
}

func (m *Model) bodyBlock(w, h int) string {
	var body string
	switch m.view {
	case ViewOverview:
		body = m.overviewBody(w, h)
	case ViewPolicies:
		body = m.policiesBody(w, h)
	case ViewProfiles:
		body = m.profilesBody(w, h)
	case ViewWorkloads:
		body = m.workloadsBody(w, h)
	case ViewEvents:
		body = m.eventsBody(w, h)
	case ViewFlows:
		body = m.flowsBody(w, h)
	case ViewSurface:
		body = m.surfaceBody(w, h)
	case ViewCoverage:
		body = m.coverageBody(w, h)
	case ViewHelp:
		body = m.helpBody(w, h)
	}
	return fit(body, w, h)
}

// statusRow is the bottom line: what the session has seen on the left, the
// generated key hints on the right when there is room for them.
func (m *Model) statusRow(w int) string {
	parts := make([]string, 0, 8)
	if m.paused {
		parts = append(parts, styleWarn.Render("PAUSED"))
	}
	// Where the cursor is in the list. Without it a long table scrolled to
	// the middle gives no clue whether there are three more rows or three
	// hundred.
	if n := m.rowCount(); n > 0 {
		parts = append(parts, styleDim.Render(fmt.Sprintf("row %d/%d", m.cursor()+1, n)))
	}
	parts = append(parts, fmt.Sprintf("%d events", m.total))
	if m.denied > 0 {
		parts = append(parts, styleDeny.Render(fmt.Sprintf("%d denied", m.denied)))
	}
	if d := m.events.dropped; d > 0 {
		parts = append(parts, styleDim.Render(fmt.Sprintf("%d rolled off", d)))
	}
	if m.filtering {
		parts = append(parts, m.input.View())
	} else if f := m.filterText(); f != "" {
		parts = append(parts, styleKey.Render("/"+f))
	}
	if m.loading() {
		parts = append(parts, m.spin.View()+styleDim.Render(" reading cluster"))
	}
	if m.sourceName != "" {
		parts = append(parts, styleDim.Render(m.sourceName))
	}
	parts = append(parts, styleDim.Render(m.Elapsed(m.now()).Round(time.Second).String()))
	switch {
	case m.err != nil:
		parts = append(parts, styleErr.Render("error: "+truncate(m.err.Error(), 60)))
	case m.ended:
		parts = append(parts, styleWarn.Render("stream ended"))
	}

	left := strings.Join(parts, styleDim.Render(" · "))
	right := m.help.ShortHelpView(m.keys.ShortHelp())
	if gap := w - lipgloss.Width(left) - lipgloss.Width(right); gap >= 2 {
		return left + strings.Repeat(" ", gap) + right
	}
	return truncate(left, w)
}

// tableBlock renders one window of rows through the shared table widget.
//
// Only the visible rows are built. Handing the table every row instead would
// allocate one []string per event per frame, and the frame is rebuilt on every
// arriving event - on a busy node that is the whole ring, sixty times a
// second, to draw twenty lines.
func (m *Model) tableBlock(specs []colSpec, rowsFn func(start, end int) []table.Row, empty string, w, h int) string {
	if w < 1 || h < 1 {
		return ""
	}
	// Every setter on the table re-renders its rows, so each one that can be
	// skipped is a full pass over the visible screen that is not paid for. On
	// a tailing event view nothing but the rows changes from frame to frame.
	//
	// The rows are cleared before the columns are replaced, and that order
	// matters: the widget is shared across views and re-renders against the
	// current columns the moment either is set, so leaving a ten-column
	// profile row in place while setting another view's seven columns indexes
	// off the end of the column slice and takes the program down.
	if cols := fitColumns(w, specs); !slices.Equal(m.tblCols, cols) {
		m.tbl.SetRows(nil)
		m.tbl.SetColumns(cols)
		m.tblCols = cols
	}
	if m.tbl.Width() != w {
		m.tbl.SetWidth(w)
	}
	if m.tbl.Height() != h-1 {
		m.tbl.SetHeight(h)
	}

	rowsH := max(0, h-1)
	total := m.rowCount()
	start := min(m.offset(), max(0, total-1))
	end := min(total, start+rowsH)
	if total == 0 || end <= start {
		m.tbl.SetRows(nil)
		head := m.tbl.View()
		if i := strings.IndexByte(head, '\n'); i >= 0 {
			head = head[:i]
		}
		return fit(head+"\n"+styleDim.Render("  "+empty), w, h)
	}

	m.tbl.SetRows(rowsFn(start, end))
	if want := m.cursor() - start; m.tbl.Cursor() != want {
		m.tbl.SetCursor(want)
	}
	return fit(m.tbl.View(), w, h)
}

// detailBlock renders scrollable detail through the viewport widget.
//
// The content is set here, at render time, rather than in Update: it depends
// on the pane's width, and the width is not known until the layout has decided
// how to split the body. SetContent re-clamps the scroll offset itself, so a
// pane that shrinks under a scrolled viewport cannot scroll past its end.
func (m *Model) detailBlock(content string, w, h int) string {
	if w < 1 || h < 1 {
		return ""
	}
	m.detail.Width, m.detail.Height = w, h
	m.detail.SetContent(content)
	return fit(m.detail.View(), w, h)
}

// splitBody lays out a list and its detail pane.
//
// Wide enough, they sit side by side and the detail follows the cursor. Narrow,
// enter swaps the body to the detail alone: a 30-column detail pane beside a
// 30-column table is two unreadable things instead of one readable one.
func (m *Model) splitBody(listTitle string, specs []colSpec, rowsFn func(start, end int) []table.Row, empty string,
	detailTitle string, detailFn func(w int) string, w, h int,
) string {
	if !m.split() {
		if m.focus == paneDetail {
			dw, dh := m.boxInner(w, h)
			return m.box(detailTitle, m.detailBlock(detailFn(dw), dw, dh), w, h, true)
		}
		lw, lh := m.boxInner(w, h)
		return m.box(listTitle, m.tableBlock(specs, rowsFn, empty, lw, lh), w, h, true)
	}

	dw := m.detailWidth()
	lw := w - dw
	liw, lih := m.boxInner(lw, h)
	diw, dih := m.boxInner(dw, h)
	list := m.box(listTitle, m.tableBlock(specs, rowsFn, empty, liw, lih), lw, h, m.focus == paneList)
	detail := m.box(detailTitle, m.detailBlock(detailFn(diw), diw, dih), dw, h, m.focus == paneDetail)
	return lipgloss.JoinHorizontal(lipgloss.Top, list, detail)
}

// box draws a pane with a border when the terminal has room for one, and the
// bare content when it does not. The decision is the model's rather than the
// pane's so that the cursor arithmetic and the drawing agree about how many
// rows a list actually has.
func (m *Model) box(title, content string, w, h int, focused bool) string {
	if !m.bordered() {
		return fit(content, w, h)
	}
	return box(title, content, w, h, focused)
}

func (m *Model) boxInner(w, h int) (int, int) {
	if m.bordered() && w >= 8 && h >= 3 {
		return w - 4, h - 2
	}
	return w, h
}

// describeEvent renders the interesting part of an event in one line. It is
// shared by the event list and the per-workload denial list, so the same
// operation reads the same way in both.
func describeEvent(e export.Event) string {
	switch {
	case e.File != nil:
		op := e.File.SyscallName
		if op == "" {
			op = "open"
		}
		return op + " " + e.File.Path
	case e.Network != nil:
		n := e.Network
		return fmt.Sprintf("%s %s:%d", strings.ToLower(n.Protocol), n.DestinationIP, n.DestinationPort)
	case e.Exec != nil:
		if e.Exec.AncestryChain != "" {
			return "exec " + e.Exec.Binary + "  " + e.Exec.AncestryChain
		}
		return "exec " + e.Exec.Binary
	case e.Capability != nil:
		return "capability " + e.Capability.Name
	case e.Syscall != nil:
		if e.Syscall.Name != "" {
			return "syscall " + e.Syscall.Name
		}
		return fmt.Sprintf("syscall %d", e.Syscall.Number)
	}
	return ""
}

// eventHaystack is what the filter matches against: everything a person might
// reasonably type. Filtering only the rendered line would make the match
// depend on the terminal width, which is a surprising thing for a filter to do.
func eventHaystack(e export.Event) string {
	var b strings.Builder
	b.WriteString(string(e.Type))
	b.WriteByte(' ')
	b.WriteString(string(e.Action))
	b.WriteByte(' ')
	b.WriteString(e.Process.Comm)
	b.WriteByte(' ')
	b.WriteString(describeEvent(e))
	if k := e.Kubernetes; k != nil {
		b.WriteByte(' ')
		b.WriteString(k.Namespace)
		b.WriteByte(' ')
		b.WriteString(k.Pod)
		b.WriteByte(' ')
		b.WriteString(k.WorkloadName)
		b.WriteByte(' ')
		b.WriteString(k.Node)
	}
	return b.String()
}
