package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/coverage"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// Styles. Colours are ANSI-256 with sensible fallbacks rather than truecolour
// hex, because a lot of the terminals this runs in are somebody's ssh session
// into a jump host, and lipgloss degrades these correctly on a 16-colour term.
var (
	styleHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	styleTabOn    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("24")).Padding(0, 1)
	styleTabOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleDeny     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	styleAllow    = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("238"))
	styleKey      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("222"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
)

// View renders the current frame.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteByte('\n')
	b.WriteString(m.body())
	b.WriteByte('\n')
	b.WriteString(m.status())
	return b.String()
}

func (m *Model) header() string {
	tabs := make([]string, 0, len(views))
	for i, v := range views {
		label := fmt.Sprintf("%d %s", i+1, v)
		if v == ViewHelp {
			label = "? help"
		}
		if v == m.view || (m.view == ViewDetail && v == ViewWorkloads) {
			tabs = append(tabs, styleTabOn.Render(label))
		} else {
			tabs = append(tabs, styleTabOff.Render(label))
		}
	}
	left := styleHeader.Render("pahlevan") + "  " + strings.Join(tabs, " ")
	return left + "\n" + styleDim.Render(strings.Repeat("─", max(1, m.width)))
}

func (m *Model) body() string {
	switch m.view {
	case ViewEvents:
		return m.eventsView()
	case ViewWorkloads:
		return m.workloadsView()
	case ViewDetail:
		return m.detailView()
	case ViewCoverage:
		return m.coverageView()
	case ViewHelp:
		return m.helpView()
	}
	return ""
}

func (m *Model) eventsView() string {
	h := m.bodyHeight()
	// Following the tail is the common case and needs only the last h events,
	// so it avoids copying the whole ring on every redraw. Scrolled or paused,
	// the offset can point anywhere and the full slice is needed.
	if !m.paused && m.cursor == 0 {
		evs := m.filteredWindow(h)
		if len(evs) == 0 {
			return m.emptyBody("no events yet")
		}
		lines := make([]string, 0, len(evs))
		for _, e := range evs {
			lines = append(lines, m.eventLine(e, false))
		}
		return padTo(strings.Join(lines, "\n"), h)
	}

	evs := m.filteredEvents()
	if len(evs) == 0 {
		return m.emptyBody("no events yet")
	}
	start := m.offset
	if start < 0 {
		start = 0
	}
	end := min(len(evs), start+h)

	lines := make([]string, 0, h)
	for i := start; i < end; i++ {
		lines = append(lines, m.eventLine(evs[i], i == m.cursor && (m.paused || m.cursor > 0)))
	}
	return padTo(strings.Join(lines, "\n"), h)
}

func (m *Model) eventLine(e export.Event, selected bool) string {
	ts := e.Timestamp.Time().Format("15:04:05")
	verdict := styleAllow.Render("allow")
	if e.Denied() {
		verdict = styleDeny.Render("DENY ")
	}
	who := e.Process.Comm
	if who == "" {
		who = "?"
	}
	line := fmt.Sprintf("%s %s %-9s %-14s %s",
		styleDim.Render(ts), verdict, e.Type, truncate(who, 14), describeEvent(e))
	line = truncate(line, m.width)
	if selected {
		return styleSelected.Render(padRight(line, m.width))
	}
	return line
}

func (m *Model) workloadsView() string {
	ws := m.filteredWorkloads()
	h := m.bodyHeight()
	if len(ws) == 0 {
		return m.emptyBody("no workloads seen yet")
	}
	head := fmt.Sprintf("%-38s %7s %7s %6s %6s %8s %8s",
		"WORKLOAD", "FILE", "NET", "EXEC", "CAP", "SYSCALL", "DENIED")
	lines := []string{styleDim.Render(truncate(head, m.width))}
	end := min(len(ws), m.offset+h-1)
	for i := m.offset; i < end; i++ {
		w := ws[i]
		denied := fmt.Sprintf("%8d", w.Denials)
		if w.Denials > 0 {
			denied = styleDeny.Render(denied)
		}
		row := fmt.Sprintf("%-38s %7d %7d %6d %6d %8d %s",
			truncate(w.Key, 38), w.Files, w.Network, w.Execs, w.Caps, w.Syscalls, denied)
		row = truncate(row, m.width)
		if i == m.cursor {
			row = styleSelected.Render(padRight(row, m.width))
		}
		lines = append(lines, row)
	}
	return padTo(strings.Join(lines, "\n"), h)
}

func (m *Model) detailView() string {
	w := m.selectedWorkload()
	h := m.bodyHeight()
	if w == nil {
		return m.emptyBody("no workload selected")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(w.Key))
	if w.Node != "" {
		fmt.Fprintf(&b, "%s\n", styleDim.Render("node "+w.Node))
	}
	b.WriteByte('\n')

	// The comparison the project is about: what the workload did, and what was
	// refused. Both drawn from the same stream, so they cannot disagree.
	fmt.Fprintf(&b, "%s\n", styleDim.Render("OBSERVED"))
	fmt.Fprintf(&b, "  files %d   network %d   execs %d   capabilities %d   syscalls %d\n",
		w.Files, w.Network, w.Execs, w.Caps, w.Syscalls)
	b.WriteByte('\n')
	if w.Denials == 0 {
		fmt.Fprintf(&b, "%s\n  %s\n", styleDim.Render("REFUSED"),
			styleAllow.Render("nothing refused; every operation was in the learned set"))
	} else {
		fmt.Fprintf(&b, "%s  %s\n", styleDim.Render("REFUSED"),
			styleDeny.Render(fmt.Sprintf("%d", w.Denials)))
		for i, d := range w.DeniedWhat {
			line := "  " + truncate(d, max(1, m.width-2))
			if i == m.cursor {
				line = styleSelected.Render(padRight(line, m.width))
			}
			b.WriteString(line + "\n")
		}
		if w.Denials > len(w.DeniedWhat) {
			fmt.Fprintf(&b, "  %s\n", styleDim.Render(fmt.Sprintf(
				"and %d earlier denials not shown", w.Denials-len(w.DeniedWhat))))
		}
	}
	return padTo(strings.TrimRight(b.String(), "\n"), h)
}

func (m *Model) coverageView() string {
	h := m.bodyHeight()
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleDim.Render(fmt.Sprintf("%-34s %-9s %s", "PROGRAM", "NEEDS LSM", "ATT&CK")))
	for _, e := range coverage.Table {
		needs := styleAllow.Render("no ")
		if e.NeedsLSM {
			needs = styleWarn.Render("yes")
		}
		ids := make([]string, 0, len(e.Techniques))
		for _, t := range e.Techniques {
			ids = append(ids, t.ID)
		}
		fmt.Fprintf(&b, "%-34s %-9s %s\n", truncate(e.Hook, 34), needs, strings.Join(ids, " "))
	}
	b.WriteByte('\n')
	b.WriteString(styleDim.Render(
		"programs needing the BPF LSM require lsm=bpf on the kernel command line"))
	return padTo(b.String(), h)
}

func (m *Model) helpView() string {
	rows := [][2]string{
		{"tab / shift-tab", "next / previous view"},
		{"1 2 3 ?", "events, workloads, coverage, help"},
		{"j k / arrows", "move the cursor"},
		{"pgup pgdn", "page"},
		{"g G", "first / last row"},
		{"enter", "open the selected workload"},
		{"space", "pause the event list (counters keep running)"},
		{"/", "filter; enter accepts, esc clears"},
		{"c", "clear the retained events"},
		{"esc", "clear the filter, or leave detail and help"},
		{"q ctrl-c", "quit"},
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", styleHeader.Render("keys"))
	for _, r := range rows {
		fmt.Fprintf(&b, "  %s  %s\n", styleKey.Render(padRight(r[0], 16)), r[1])
	}
	fmt.Fprintf(&b, "\n%s\n", styleDim.Render(
		"this view is a reader; it never changes a policy or a mode"))
	return padTo(b.String(), m.bodyHeight())
}

func (m *Model) emptyBody(msg string) string {
	return padTo(styleDim.Render("  "+msg), m.bodyHeight())
}

func (m *Model) status() string {
	parts := []string{}
	if m.paused {
		parts = append(parts, styleWarn.Render("PAUSED"))
	}
	parts = append(parts, fmt.Sprintf("%d events", m.total))
	if m.denied > 0 {
		parts = append(parts, styleDeny.Render(fmt.Sprintf("%d denied", m.denied)))
	}
	if d := m.events.dropped; d > 0 {
		parts = append(parts, styleDim.Render(fmt.Sprintf("%d rolled off", d)))
	}
	if m.filter != "" || m.typing {
		f := "/" + m.filter
		if m.typing {
			f += "▏"
		}
		parts = append(parts, styleKey.Render(f))
	}
	if m.sourceName != "" {
		parts = append(parts, styleDim.Render(m.sourceName))
	}
	switch {
	case m.err != nil:
		parts = append(parts, styleErr.Render("error: "+truncate(m.err.Error(), 60)))
	case m.ended:
		parts = append(parts, styleWarn.Render("stream ended"))
	}
	line := strings.Join(parts, styleDim.Render(" · "))
	return styleDim.Render(strings.Repeat("─", max(1, m.width))) + "\n" + truncate(line, m.width)
}

// describeEvent renders the interesting part of an event in one line. It is
// shared by the event list and the denial list, so the same operation reads
// the same way in both.
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

// Rendering helpers. truncate counts runes rather than bytes: a path with
// non-ASCII in it should not cut a character in half, and a terminal measures
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

// padTo makes a block exactly n lines, so the status line does not wander up
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

// Elapsed is exported for the status line in tests.
func (m *Model) Elapsed(now time.Time) time.Duration { return now.Sub(m.started) }
