package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/coverage"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// noCluster is what every cluster pane says when there is nothing to read.
// An empty table would look like a cluster with no policies in it, which is a
// very different thing from a console that was never given a cluster.
const noCluster = "no cluster connected - this session is reading a capture, not an API server"

// Table cells are plain text on purpose.
//
// bubbles' table truncates each cell with runewidth.Truncate, which counts the
// bytes of an ANSI escape as visible width. A styled cell would be cut in the
// middle of a colour sequence and bleed that colour across the rest of the
// row. Emphasis in a table is carried by glyphs and by the cursor row's own
// style; colour belongs in the detail pane, which is not truncated that way.

// ---------------------------------------------------------------- overview

// overviewBody is the landing pane: how much of the fleet is learning, how
// much is enforcing, and what has been refused. It is the screen someone
// leaves open on a second monitor, so it must answer those three questions
// without a keystroke.
func (m *Model) overviewBody(w, h int) string {
	cards := []card{
		m.policyCard(),
		m.containerCard(),
		m.denialCard(),
		m.streamCard(),
	}
	top := m.cardsBlock(cards, w, h)
	used := lipgloss.Height(top)
	if used >= h {
		return fit(top, w, h)
	}
	rest := m.learningBlock(w, h-used)
	return fit(top+"\n"+rest, w, h)
}

// card is one overview tile. The rows are kept as label and value rather than
// as finished lines because the value is right-aligned against the card's
// width, and the width is not known until the layout has counted how many
// cards fit across the terminal.
type card struct {
	title string
	rows  []cardRow
}

type cardRow struct {
	label string
	value string
	style lipgloss.Style
}

// render lays one row out in w columns: the label on the left, the value hard
// against the right edge, so a column of numbers reads as a column.
func (r cardRow) render(w int) string {
	if r.label == "" {
		return truncate(r.style.Render(r.value), w)
	}
	value := truncate(r.value, w)
	label := truncate(r.label, max(0, w-lipgloss.Width(value)-1))
	gap := w - lipgloss.Width(label) - lipgloss.Width(value)
	if gap < 1 {
		gap = 1
	}
	return styleLabel.Render(label) + strings.Repeat(" ", gap) + r.style.Render(value)
}

// cardMin is the narrowest a card can be and still read as a label and a
// number rather than two truncations.
const cardMin = 22

// cardsBlock lays cards out in as many columns as the terminal can take, and
// falls back to a single column rather than shrinking them below cardMin.
func (m *Model) cardsBlock(cards []card, w, h int) string {
	if len(cards) == 0 || w < 1 || h < 1 {
		return ""
	}
	perRow := clampInt(w/cardMin, 1, len(cards))

	inner := 0
	for _, c := range cards {
		inner = max(inner, len(c.rows))
	}
	cardH := inner + 1
	if m.bordered() {
		cardH = inner + 2
	}

	var rows []string
	height := 0
	for start := 0; start < len(cards); start += perRow {
		end := min(len(cards), start+perRow)
		if height+cardH > h {
			break
		}
		cw := w / (end - start)
		var cells []string
		for i := start; i < end; i++ {
			width := cw
			if i == end-1 {
				width = w - cw*(end-start-1) // the remainder, so the row fills
			}
			iw, ih := m.boxInner(width, cardH)
			lines := make([]string, 0, len(cards[i].rows))
			for _, r := range cards[i].rows {
				lines = append(lines, r.render(iw))
			}
			cells = append(cells, m.box(cards[i].title, fit(strings.Join(lines, "\n"), iw, ih), width, cardH, false))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cells...))
		height += cardH
	}
	return strings.Join(rows, "\n")
}

func (m *Model) policyCard() card {
	if m.cluster == nil {
		return card{title: "policies", rows: []cardRow{note(styleDim, "no cluster")}}
	}
	if m.policies.err != nil {
		return card{title: "policies", rows: []cardRow{note(styleErr, "unreadable")}}
	}
	byPhase := map[string]int{}
	for _, p := range m.policies.items {
		byPhase[displayPhase(p.Phase)]++
	}
	rows := []cardRow{count("total", len(m.policies.items), styleValue)}
	// Only the phases that are actually present. A column of zeroes pushes
	// the phase that matters off a card four lines tall.
	for _, phase := range []string{"Learning", "Transition", "Enforcing", "Failed", "RollingBack", "Pending"} {
		if n := byPhase[phase]; n > 0 {
			rows = append(rows, count(strings.ToLower(phase), n, phaseStyle(phase)))
		}
	}
	return card{title: "policies", rows: rows}
}

func (m *Model) containerCard() card {
	if m.cluster == nil {
		return card{title: "containers", rows: []cardRow{note(styleDim, "no cluster")}}
	}
	if m.profiles.err != nil {
		return card{title: "containers", rows: []cardRow{note(styleErr, "unreadable")}}
	}
	var learning, enforcing int
	for _, p := range m.profiles.items {
		switch p.Phase {
		case "Enforcing":
			enforcing++
		default:
			learning++
		}
	}
	return card{title: "containers", rows: []cardRow{
		count("profiles", len(m.profiles.items), styleValue),
		count("learning", learning, styleWarn),
		count("enforcing", enforcing, styleAllow),
	}}
}

func (m *Model) denialCard() card {
	var fromCluster int64
	for _, p := range m.policies.items {
		fromCluster += p.Denials
	}
	var noisy int
	for _, w := range m.workloads {
		if w.Denials > 0 {
			noisy++
		}
	}
	style := styleAllow
	if m.denied > 0 || fromCluster > 0 {
		style = styleDeny
	}
	rows := []cardRow{
		count("this stream", int(m.denied), style),
		count("workloads hit", noisy, style),
	}
	if m.cluster != nil {
		rows = append(rows, count("policies", int(fromCluster), style))
	}
	return card{title: "denials", rows: rows}
}

func (m *Model) streamCard() card {
	rows := []cardRow{
		count("events", int(m.total), styleValue),
		count("workloads", len(m.order), styleValue),
	}
	switch {
	case m.err != nil:
		rows = append(rows, note(styleErr, truncate(m.err.Error(), 40)))
	case m.ended:
		rows = append(rows, note(styleWarn, "stream ended"))
	case m.paused:
		rows = append(rows, note(styleWarn, "paused"))
	default:
		rows = append(rows, note(styleAllow, "live"))
	}
	return card{title: "stream", rows: rows}
}

func count(label string, n int, style lipgloss.Style) cardRow {
	return cardRow{label: label, value: strconv.Itoa(n), style: style}
}

func note(style lipgloss.Style, text string) cardRow {
	return cardRow{value: text, style: style}
}

// learningBlock shows the progress of anything still learning. It is bounded
// by the space available rather than by the size of the cluster: a thousand
// learning containers must not turn one pane into a thousand-line render.
func (m *Model) learningBlock(w, h int) string {
	if h < 1 {
		return ""
	}
	iw, ih := m.boxInner(w, h)
	if ih < 1 || iw < 1 {
		return ""
	}

	var lines []string
	for _, p := range m.policies.items {
		if !p.Learning || len(lines) >= ih {
			continue
		}
		lines = append(lines, m.progressLine(p.Key(), p.Progress, iw))
	}
	// Containers still learning, under the policies that cover them. A policy
	// can read Enforcing while a container that joined late is still building
	// its baseline, and that container is the one about to be denied.
	for _, p := range m.profiles.items {
		if p.Phase == "Enforcing" || len(lines) >= ih {
			continue
		}
		lines = append(lines, styleDim.Render(truncate("  "+p.Key()+" - learning, "+
			strconv.Itoa(p.Learned())+" operations seen so far", iw)))
	}
	if len(lines) == 0 {
		switch {
		case m.cluster == nil:
			lines = []string{styleDim.Render(noCluster)}
		case len(m.policies.items) == 0:
			lines = []string{styleDim.Render("no policies yet")}
		default:
			lines = []string{styleAllow.Render("nothing is still learning; every policy has a baseline")}
		}
	}
	return m.box("learning", fit(strings.Join(lines, "\n"), iw, ih), w, h, false)
}

// progressLine draws one learning window as a bar. The label is truncated
// before the bar is sized, so the bar never pushes the percentage off the
// right-hand edge of the pane.
func (m *Model) progressLine(label string, percent, w int) string {
	percent = clampInt(percent, 0, 100)
	name := truncate(label, max(1, w/2))
	suffix := fmt.Sprintf(" %3d%%", percent)
	barW := w - lipgloss.Width(name) - lipgloss.Width(suffix) - 1
	if barW < 4 {
		return truncate(name+suffix, w)
	}
	m.prog.Width = barW
	return name + " " + m.prog.ViewAs(float64(percent)/100) + suffix
}

// ---------------------------------------------------------------- policies

func (m *Model) policiesBody(w, h int) string {
	specs := []colSpec{
		{title: "NAMESPACE", min: 9, max: 22, weight: 2, prio: 3},
		{title: "POLICY", min: 10, max: 34, weight: 3, prio: 0},
		{title: "PHASE", min: 9, weight: 0, prio: 1},
		{title: "MODE", min: 10, weight: 0, prio: 4},
		{title: "LEARNING", min: 8, weight: 0, prio: 5},
		{title: "ENFORCING", min: 9, weight: 0, prio: 6},
		{title: "DENIED", min: 6, weight: 0, prio: 2},
	}
	rows := func(start, end int) []table.Row {
		items := m.filteredPolicies()
		out := make([]table.Row, 0, end-start)
		for _, p := range items[start:end] {
			learning := "-"
			if p.Learning {
				learning = strconv.Itoa(clampInt(p.Progress, 0, 100)) + "%"
			}
			out = append(out, table.Row{
				p.Namespace, p.Name, displayPhase(p.Phase), orDash(p.Mode), learning,
				fmt.Sprintf("%d/%d", p.Enforcing, p.Containers),
				strconv.FormatInt(p.Denials, 10),
			})
		}
		return out
	}
	return m.splitBody(
		paneTitle("policies", m.policies.err, m.policies.loading), specs, rows,
		emptyNote(m.cluster, m.policies.err, m.policies.loading, "no policies"),
		"policy", m.policyDetail, w, h)
}

func (m *Model) selectedPolicy() (Policy, bool) {
	items := m.filteredPolicies()
	i := m.cursor()
	if i < 0 || i >= len(items) {
		return Policy{}, false
	}
	return items[i], true
}

func (m *Model) policyDetail(w int) string {
	p, ok := m.selectedPolicy()
	if !ok {
		return styleDim.Render(emptyNote(m.cluster, m.policies.err, m.policies.loading, "no policy selected"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(p.Key(), w)))
	b.WriteString(kv("phase", phaseStyle(p.Phase).Render(displayPhase(p.Phase)), w))
	b.WriteString(kv("mode", orDash(p.Mode), w))
	b.WriteString(kv("selector", orDash(p.Selector), w))
	b.WriteString(kv("enforcing", fmt.Sprintf("%d of %d containers", p.Enforcing, p.Containers), w))
	b.WriteString(kv("denied", strconv.FormatInt(p.Denials, 10), w))
	if p.Learning {
		b.WriteByte('\n')
		b.WriteString(m.progressLine("learning", p.Progress, w) + "\n")
	}
	if len(p.Workloads) > 0 {
		b.WriteString("\n" + styleDim.Render("TARGETS") + "\n")
		for _, t := range p.Workloads {
			b.WriteString("  " + truncate(t, max(1, w-2)) + "\n")
		}
	}
	b.WriteString("\n" + styleDim.Render("RESOLVED RULES") + "\n")
	if len(p.Rules) == 0 {
		b.WriteString("  " + styleDim.Render("none resolved yet") + "\n")
	}
	for _, r := range p.Rules {
		b.WriteString("  " + truncate(r, max(1, w-2)) + "\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- profiles

func (m *Model) profilesBody(w, h int) string {
	specs := []colSpec{
		{title: "NAMESPACE", min: 9, max: 20, weight: 2, prio: 4},
		{title: "PROFILE", min: 12, max: 34, weight: 3, prio: 0},
		{title: "NODE", min: 6, max: 18, weight: 2, prio: 6},
		{title: "PHASE", min: 9, weight: 0, prio: 1},
		{title: "SYSCALL", min: 7, weight: 0, prio: 2},
		{title: "FILE", min: 5, weight: 0, prio: 3},
		{title: "NET", min: 4, weight: 0, prio: 5},
		{title: "EXEC", min: 4, weight: 0, prio: 7},
		{title: "CAP", min: 3, weight: 0, prio: 8},
		{title: "DENIED", min: 6, weight: 0, prio: 2},
	}
	rows := func(start, end int) []table.Row {
		items := m.filteredProfiles()
		out := make([]table.Row, 0, end-start)
		for _, p := range items[start:end] {
			out = append(out, table.Row{
				p.Namespace, p.Name, orDash(p.Node), displayPhase(p.Phase),
				strconv.Itoa(p.Syscalls), strconv.Itoa(p.Files), strconv.Itoa(p.Network),
				strconv.Itoa(p.Execs), strconv.Itoa(p.Capabilities), strconv.Itoa(p.Denials),
			})
		}
		return out
	}
	return m.splitBody(
		paneTitle("profiles", m.profiles.err, m.profiles.loading), specs, rows,
		emptyNote(m.cluster, m.profiles.err, m.profiles.loading, "no profiles"),
		"profile", m.profileDetail, w, h)
}

func (m *Model) selectedProfile() (Profile, bool) {
	items := m.filteredProfiles()
	i := m.cursor()
	if i < 0 || i >= len(items) {
		return Profile{}, false
	}
	return items[i], true
}

func (m *Model) profileDetail(w int) string {
	p, ok := m.selectedProfile()
	if !ok {
		return styleDim.Render(emptyNote(m.cluster, m.profiles.err, m.profiles.loading, "no profile selected"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(p.Key(), w)))
	b.WriteString(kv("phase", phaseStyle(p.Phase).Render(displayPhase(p.Phase)), w))
	b.WriteString(kv("node", orDash(p.Node), w))
	b.WriteString(kv("container", orDash(p.Container), w))
	b.WriteString("\n" + styleDim.Render("LEARNED") + "\n")
	b.WriteString(kv("syscalls", strconv.Itoa(p.Syscalls), w))
	b.WriteString(kv("files", strconv.Itoa(p.Files), w))
	b.WriteString(kv("network", strconv.Itoa(p.Network), w))
	b.WriteString(kv("executables", strconv.Itoa(p.Execs), w))
	b.WriteString(kv("capabilities", strconv.Itoa(p.Capabilities), w))
	b.WriteByte('\n')
	if p.Denials == 0 {
		b.WriteString(styleAllow.Render("nothing refused; every operation was in the learned set") + "\n")
	} else {
		b.WriteString(styleDeny.Render(fmt.Sprintf("%d operations refused in-kernel", p.Denials)) + "\n")
	}
	if !p.FirstSeen.IsZero() {
		b.WriteString(kv("first seen", p.FirstSeen.Format("2006-01-02 15:04:05"), w))
	}
	if !p.EnforcingSince.IsZero() {
		b.WriteString(kv("enforcing", p.EnforcingSince.Format("2006-01-02 15:04:05"), w))
	}
	return b.String()
}

// --------------------------------------------------------------- workloads

func (m *Model) workloadsBody(w, h int) string {
	specs := []colSpec{
		{title: "WORKLOAD", min: 14, max: 56, weight: 4, prio: 0},
		{title: "NODE", min: 6, max: 18, weight: 2, prio: 7},
		{title: "FILE", min: 5, weight: 0, prio: 2},
		{title: "NET", min: 4, weight: 0, prio: 3},
		{title: "EXEC", min: 4, weight: 0, prio: 4},
		{title: "CAP", min: 3, weight: 0, prio: 5},
		{title: "SYSCALL", min: 7, weight: 0, prio: 6},
		{title: "DENIED", min: 6, weight: 0, prio: 1},
	}
	rows := func(start, end int) []table.Row {
		items := m.filteredWorkloads()
		out := make([]table.Row, 0, end-start)
		for _, wl := range items[start:end] {
			out = append(out, table.Row{
				wl.Display(), orDash(wl.Node),
				strconv.Itoa(wl.Files), strconv.Itoa(wl.Network), strconv.Itoa(wl.Execs),
				strconv.Itoa(wl.Caps), strconv.Itoa(wl.Syscalls), strconv.Itoa(wl.Denials),
			})
		}
		return out
	}
	return m.splitBody("workloads", specs, rows, "no workloads seen yet",
		"workload", m.workloadDetail, w, h)
}

func (m *Model) selectedWorkload() *Workload {
	items := m.filteredWorkloads()
	i := m.cursor()
	if i < 0 || i >= len(items) {
		return nil
	}
	return items[i]
}

func (m *Model) workloadDetail(w int) string {
	wl := m.selectedWorkload()
	if wl == nil {
		return styleDim.Render("no workload selected")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(wl.Key, w)))
	if wl.Node != "" {
		b.WriteString(styleDim.Render("node "+wl.Node) + "\n")
	}
	if !wl.LastSeen.IsZero() {
		b.WriteString(styleDim.Render("last seen "+wl.LastSeen.Format("15:04:05")) + "\n")
	}

	// The comparison the project is about: what the workload did, and what was
	// refused. Both drawn from the same stream, so they cannot disagree.
	b.WriteString("\n" + styleDim.Render("OBSERVED") + "\n")
	b.WriteString(kv("files", strconv.Itoa(wl.Files), w))
	b.WriteString(kv("network", strconv.Itoa(wl.Network), w))
	b.WriteString(kv("execs", strconv.Itoa(wl.Execs), w))
	b.WriteString(kv("capabilities", strconv.Itoa(wl.Caps), w))
	b.WriteString(kv("syscalls", strconv.Itoa(wl.Syscalls), w))

	b.WriteString("\n" + styleDim.Render("REFUSED") + "\n")
	if wl.Denials == 0 {
		b.WriteString("  " + styleAllow.Render("nothing refused; every operation was in the learned set") + "\n")
		return b.String()
	}
	b.WriteString("  " + styleDeny.Render(strconv.Itoa(wl.Denials)+" refused in-kernel") + "\n")
	for _, d := range wl.DeniedWhat {
		b.WriteString("  " + truncate(d, max(1, w-2)) + "\n")
	}
	if wl.Denials > len(wl.DeniedWhat) {
		b.WriteString("  " + styleDim.Render(fmt.Sprintf(
			"and %d earlier denials not shown", wl.Denials-len(wl.DeniedWhat))) + "\n")
	}
	return b.String()
}

// ------------------------------------------------------------------ events

func (m *Model) eventsBody(w, h int) string {
	specs := []colSpec{
		{title: "TIME", min: 8, weight: 0, prio: 2},
		{title: "VERDICT", min: 7, weight: 0, prio: 1},
		{title: "TYPE", min: 7, weight: 0, prio: 3},
		{title: "PROCESS", min: 8, max: 18, weight: 1, prio: 4},
		{title: "WORKLOAD", min: 10, max: 40, weight: 2, prio: 5},
		{title: "DETAIL", min: 14, weight: 4, prio: 0},
	}
	rows := func(start, end int) []table.Row {
		evs := m.eventWindow(start, end)
		out := make([]table.Row, 0, len(evs))
		for _, e := range evs {
			verdict := "allow"
			if e.Denied() {
				verdict = "✖ DENY"
			}
			comm := e.Process.Comm
			if comm == "" {
				comm = "?"
			}
			out = append(out, table.Row{
				e.Timestamp.Time().Format("15:04:05"), verdict, string(e.Type),
				comm, eventWorkload(e), describeEvent(e),
			})
		}
		return out
	}
	iw, ih := m.boxInner(w, h)
	title := "events"
	if m.paused {
		title = "events (paused)"
	}
	return m.box(title, m.tableBlock(specs, rows, "no events yet", iw, ih), w, h, true)
}

// eventWindow returns rows [start, end) of the event list, newest first.
//
// Newest first because the stream is a tail: the line that just arrived is the
// one being looked at, and it should not move. Oldest-first would slide every
// row under the cursor down one place per event, which on a busy node makes
// the list unreadable and the cursor meaningless.
//
// Only the requested rows are built. The window is what fits on the screen, so
// this is a few dozen events however many the ring is holding - the frame is
// redrawn at the event rate, and copying four thousand events to draw forty of
// them was most of what the console did.
func (m *Model) eventWindow(start, end int) []export.Event {
	if end <= start {
		return nil
	}
	out := make([]export.Event, 0, end-start)
	if m.filterText() == "" {
		n := m.events.len()
		for i := start; i < end; i++ {
			e, ok := m.events.at(n - 1 - i)
			if !ok {
				break
			}
			out = append(out, e)
		}
		return out
	}
	// Filtered, the matches are already in hand from the row count, cached
	// against the ring's generation, so this walks them rather than rescanning.
	all := m.filteredEvents()
	for i := start; i < end; i++ {
		j := len(all) - 1 - i
		if j < 0 {
			break
		}
		out = append(out, all[j])
	}
	return out
}

// ---------------------------------------------------------- attack surface

func (m *Model) surfaceBody(w, h int) string {
	specs := []colSpec{
		{title: "NAMESPACE", min: 9, max: 20, weight: 2, prio: 3},
		{title: "SURFACE", min: 10, max: 34, weight: 3, prio: 0},
		{title: "RISK", min: 9, weight: 0, prio: 1},
		{title: "PORTS", min: 5, weight: 0, prio: 2},
		{title: "SYSCALLS", min: 8, weight: 0, prio: 4},
		{title: "WRITABLE", min: 8, weight: 0, prio: 5},
		{title: "CAPS", min: 4, weight: 0, prio: 6},
	}
	rows := func(start, end int) []table.Row {
		items := m.filteredSurfaces()
		out := make([]table.Row, 0, end-start)
		for _, a := range items[start:end] {
			out = append(out, table.Row{
				a.Namespace, a.Name, riskCell(a.Risk),
				strconv.Itoa(len(a.Ports)), strconv.Itoa(len(a.Syscalls)),
				strconv.Itoa(len(a.WritableFiles)), strconv.Itoa(len(a.Capabilities)),
			})
		}
		return out
	}
	return m.splitBody(
		paneTitle("attack surface", m.surfaces.err, m.surfaces.loading), specs, rows,
		emptyNote(m.cluster, m.surfaces.err, m.surfaces.loading, "no attack surfaces"),
		"exposure", m.surfaceDetail, w, h)
}

func (m *Model) selectedSurface() (AttackSurface, bool) {
	items := m.filteredSurfaces()
	i := m.cursor()
	if i < 0 || i >= len(items) {
		return AttackSurface{}, false
	}
	return items[i], true
}

func (m *Model) surfaceDetail(w int) string {
	a, ok := m.selectedSurface()
	if !ok {
		return styleDim.Render(emptyNote(m.cluster, m.surfaces.err, m.surfaces.loading, "no attack surface selected"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(a.Key(), w)))
	b.WriteString(kv("risk", riskStyle(a.Risk).Render(riskCell(a.Risk)), w))
	b.WriteString(kv("exposure", strconv.Itoa(a.Exposure())+" findings", w))
	if !a.Analyzed.IsZero() {
		b.WriteString(kv("analyzed", a.Analyzed.Format("2006-01-02 15:04:05"), w))
	}

	ports := make([]string, 0, len(a.Ports))
	for _, p := range a.Ports {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	for _, section := range []struct {
		title string
		items []string
	}{
		{"EXPOSED PORTS", ports},
		{"EXPOSED SYSCALLS", a.Syscalls},
		{"WRITABLE FILES", a.WritableFiles},
		{"CAPABILITIES", a.Capabilities},
	} {
		b.WriteString("\n" + styleDim.Render(section.title) + "\n")
		if len(section.items) == 0 {
			b.WriteString("  " + styleAllow.Render("none") + "\n")
			continue
		}
		for _, it := range section.items {
			b.WriteString("  " + truncate(it, max(1, w-2)) + "\n")
		}
	}
	return b.String()
}

// riskCell renders a score as a bar and a number, in plain text so the table
// can truncate it safely.
func riskCell(score int) string {
	score = clampInt(score, 0, 100)
	const width = 5
	filled := score * width / 100
	return strings.Repeat("█", filled) + strings.Repeat("·", width-filled) + fmt.Sprintf(" %3d", score)
}

func riskStyle(score int) lipgloss.Style {
	switch {
	case score >= 70:
		return styleDeny
	case score >= 40:
		return styleWarn
	default:
		return styleAllow
	}
}

// ---------------------------------------------------------------- coverage

func (m *Model) coverageBody(w, h int) string {
	specs := []colSpec{
		{title: "DETECTOR", min: 8, max: 14, weight: 1, prio: 1},
		{title: "HOOK", min: 14, max: 40, weight: 3, prio: 0},
		{title: "LSM", min: 3, weight: 0, prio: 3},
		{title: "ATT&CK", min: 10, weight: 3, prio: 2},
	}
	rows := func(start, end int) []table.Row {
		out := make([]table.Row, 0, end-start)
		for _, e := range coverage.Table[start:end] {
			ids := make([]string, 0, len(e.Techniques))
			for _, t := range e.Techniques {
				ids = append(ids, t.ID)
			}
			lsm := "no"
			if e.NeedsLSM {
				lsm = "yes"
			}
			out = append(out, table.Row{string(e.Detector), e.Hook, lsm, strings.Join(ids, " ")})
		}
		return out
	}
	return m.splitBody("coverage", specs, rows, "the coverage table is empty",
		"detector", m.coverageDetail, w, h)
}

func (m *Model) coverageDetail(w int) string {
	i := m.cursor()
	if i < 0 || i >= len(coverage.Table) {
		return styleDim.Render("no detector selected")
	}
	e := coverage.Table[i]
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(e.Hook, w)))
	b.WriteString(kv("detector", string(e.Detector), w))
	if e.NeedsLSM {
		b.WriteString(kv("needs", styleWarn.Render("lsm=bpf on the kernel command line"), w))
	} else {
		b.WriteString(kv("needs", styleAllow.Render("no BPF LSM required"), w))
	}
	b.WriteString("\n" + styleDim.Render("OBSERVES") + "\n")
	b.WriteString(wrap(e.Observes, w) + "\n")
	b.WriteString("\n" + styleDim.Render("EVIDENCE FOR") + "\n")
	for _, t := range e.Techniques {
		b.WriteString("  " + styleKey.Render(t.ID) + " " + truncate(t.Name, max(1, w-len(t.ID)-3)) + "\n")
	}
	b.WriteString("\n" + styleDim.Render(wrap(
		"A technique listed here means this detector's events are evidence for it, "+
			"not that Pahlevan blocks it.", w)))
	return b.String()
}

// -------------------------------------------------------------------- help

// helpBody is generated from the key bindings rather than typed out beside
// them, so a binding that changes cannot leave a help screen that lies.
func (m *Model) helpBody(w, h int) string {
	iw, ih := m.boxInner(w, h)
	// The width given to the help widget is the pane's inside, not the body's:
	// with the border's four columns counted twice it drops a whole group of
	// bindings off the right-hand edge rather than wrapping them.
	m.help.Width = max(1, iw)
	body := m.help.FullHelpView(m.keys.FullHelp())
	note := styleDim.Render(wrap(
		"The event list runs newest first, and pause freezes it without freezing the "+
			"counters. This console is a reader: no key here changes a policy, a mode or a "+
			"profile, so it cannot be the thing that turns enforcement off during an "+
			"incident.", iw))
	return m.box("keys", fit(body+"\n\n"+note, iw, ih), w, h, true)
}

// ----------------------------------------------------------------- helpers

func kv(label, value string, w int) string {
	return styleLabel.Render(padRight(label, 13)) + truncate(value, max(1, w-13)) + "\n"
}

func wrap(s string, w int) string {
	if w < 1 {
		return ""
	}
	return lipgloss.NewStyle().Width(w).Render(s)
}

// eventWorkload names the owner of an event the way a person reads it:
// namespace and name. The Kind is in the key because the key has to be unique;
// it is noise in a column that is already competing for width.
func eventWorkload(e export.Event) string {
	k := e.Kubernetes
	if k == nil {
		return workloadKey(e)
	}
	name := k.WorkloadName
	if name == "" {
		name = k.Pod
	}
	if name == "" {
		return workloadKey(e)
	}
	if k.Namespace == "" {
		return name
	}
	return k.Namespace + "/" + name
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// displayPhase keeps an empty phase from rendering as an empty cell. A status
// that has not been written yet and one that says nothing look the same in a
// table, and only one of them is worth waiting on.
func displayPhase(p string) string {
	if p == "" {
		return "Pending"
	}
	return p
}

func phaseStyle(phase string) lipgloss.Style {
	switch phase {
	case "Enforcing":
		return styleAllow
	case "Learning", "Transition":
		return styleWarn
	case "Failed", "RollingBack":
		return styleDeny
	default:
		return styleDim
	}
}

// paneTitle folds the fetch state into the pane's title, which is the one
// place on a split screen that is always visible.
func paneTitle(base string, err error, loading bool) string {
	switch {
	case err != nil:
		return base + " - stale"
	case loading:
		return base + " - reading"
	}
	return base
}

// emptyNote explains an empty list. "No policies" and "I could not ask" are
// different answers, and a console that renders both as an empty table is
// telling an operator the cluster is clean when it might be unreachable.
func emptyNote(c Cluster, err error, loading bool, none string) string {
	switch {
	case c == nil:
		return noCluster
	case err != nil:
		return "cannot read the cluster: " + err.Error()
	case loading:
		return "reading the cluster…"
	}
	return none
}

func clampInt(v, lo, hi int) int { return max(lo, min(hi, v)) }
