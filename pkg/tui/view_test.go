package tui

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/coverage"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// allViews is every screen the console can be asked to draw.
var allViews = []View{
	ViewOverview, ViewPolicies, ViewProfiles, ViewWorkloads,
	ViewEvents, ViewSurface, ViewCoverage, ViewHelp,
}

// populated builds a model with something on every screen, so a rendering
// test is not quietly passing because most panes are empty.
func populated(t testing.TB) *Model {
	t.Helper()
	m := New(Options{Capacity: 64, Cluster: fixtureCluster()})
	sized(m, 120, 30)
	for i := 0; i < 40; i++ {
		feed(m, ev(export.EventTypeFile, i%3 == 0, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
	}
	feed(m, ev(export.EventTypeNetwork, true, "curl", "kube-system", "DaemonSet", "cni"))
	drainCluster(m)
	return m
}

func TestEveryViewFillsTheTerminalExactlyAtEverySize(t *testing.T) {
	// A frame taller than the terminal scrolls the screen and leaves the
	// previous frame's tail behind; a shorter one leaves the old frame's
	// bottom rows on screen; a wider one wraps and pushes the status bar off
	// the bottom. Either way the display stops matching the model, and the
	// sizes where that happens are the extreme ones.
	for _, fixture := range []struct {
		name  string
		build func() *Model
	}{
		{"a console with data on every screen", func() *Model { return populated(t) }},
		{"a console with nothing in it", func() *Model { return New(Options{}) }},
	} {
		for _, v := range allViews {
			for _, w := range []int{1, 40, 200} {
				for _, h := range []int{1, 2, 5, 100} {
					name := fmt.Sprintf("%s/%s/%dx%d", fixture.name, v, w, h)
					t.Run(name, func(t *testing.T) {
						m := fixture.build()
						m.view = v
						sized(m, w, h)

						out := m.View()
						lines := strings.Split(out, "\n")
						if len(lines) != h {
							t.Fatalf("the frame is %d lines at %dx%d, want %d", len(lines), w, h, h)
						}
						for i, l := range lines {
							if got := lipgloss.Width(l); got > w {
								t.Fatalf("line %d is %d columns wide at %dx%d: %q", i, got, w, h, l)
							}
							if !utf8.ValidString(l) {
								t.Fatalf("line %d is not valid UTF-8 at %dx%d", i, w, h)
							}
						}
					})
				}
			}
		}
	}
}

func TestEveryViewRendersWithTheDetailPaneFocused(t *testing.T) {
	// The narrow layout swaps the body for the detail pane. That path has its
	// own sizing arithmetic, so it gets the same treatment as the list.
	for _, v := range allViews {
		for _, w := range []int{1, 40, 200} {
			for _, h := range []int{1, 3, 24} {
				m := populated(t)
				m.view = v
				sized(m, w, h)
				m.focus = paneDetail
				out := m.View()
				if got := len(strings.Split(out, "\n")); got != h {
					t.Fatalf("%v with the detail focused is %d lines at %dx%d, want %d", v, got, w, h, h)
				}
			}
		}
	}
}

func TestTheHeaderKeepsTheTabsVisibleAsTheTerminalNarrows(t *testing.T) {
	// A tab strip cut off at the edge hides the screens that exist, and
	// "which screens are there" is the one thing a header has to answer.
	m := populated(t)
	m.view = ViewProfiles
	for _, w := range []int{200, 100, 60, 30, 12, 4} {
		sized(m, w, 24)
		header := strings.Split(m.View(), "\n")[0]
		if lipgloss.Width(header) > w {
			t.Fatalf("the header is %d columns wide at width %d", lipgloss.Width(header), w)
		}
		if w >= 12 && !strings.Contains(header, "3") {
			t.Errorf("the header at width %d does not mark the current view: %q", w, header)
		}
	}
	sized(m, 200, 24)
	header := strings.Split(m.View(), "\n")[0]
	for _, v := range views {
		if !strings.Contains(header, v.String()) {
			t.Errorf("the wide header does not name %v: %q", v, header)
		}
	}
}

func TestTheStatusBarReportsWhatRolledOff(t *testing.T) {
	// A list that starts where the buffer happens to begin, with no note of
	// what was dropped, is a screen that quietly misrepresents the node.
	m := sized(New(Options{Capacity: 4}), 200, 30)
	for i := 0; i < 10; i++ {
		feed(m, ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
	}
	out := m.View()
	if !strings.Contains(out, "6 rolled off") {
		t.Errorf("the status bar does not report the 6 evicted events:\n%s", out)
	}
	if !strings.Contains(out, "10 events") {
		t.Error("the status bar does not report the session total")
	}
}

func TestThePausedEventListSaysSo(t *testing.T) {
	m := populated(t)
	m.view = ViewEvents
	press(m, " ")
	out := m.View()
	if !strings.Contains(out, "PAUSED") {
		t.Errorf("the status bar does not show the pause:\n%s", out)
	}
	if !strings.Contains(out, "paused") {
		t.Errorf("the events pane does not show the pause:\n%s", out)
	}
}

func TestTheHelpScreenIsGeneratedFromTheBindings(t *testing.T) {
	// The help is rendered from the key map, not typed out beside it, so a
	// binding that changes cannot leave a help screen that lies.
	m := sized(New(Options{}), 200, 40)
	m.view = ViewHelp
	out := m.View()

	for _, group := range m.keys.FullHelp() {
		for _, b := range group {
			if !strings.Contains(out, b.Help().Desc) {
				t.Errorf("the help screen does not describe %q (%s)", b.Help().Key, b.Help().Desc)
			}
		}
	}
	if !strings.Contains(out, "reader") {
		t.Error("the help screen does not say the console is a reader")
	}
}

func TestTheCoverageViewListsEveryHookInTheTable(t *testing.T) {
	// The coverage screen is the project's claim about what it detects. A hook
	// that is in the table but missing from the screen is a detector nobody
	// knows they have; the reverse is a claim with nothing behind it.
	m := sized(New(Options{}), 200, 100)
	m.view = ViewCoverage
	m.clampCursor()
	out := m.View()

	if len(coverage.Table) == 0 {
		t.Fatal("the coverage table is empty, so this test proves nothing")
	}
	for _, e := range coverage.Table {
		if !strings.Contains(out, e.Hook) {
			t.Errorf("the coverage view does not list the hook %q", e.Hook)
		}
		for _, tech := range e.Techniques {
			if !strings.Contains(out, tech.ID) {
				t.Errorf("the coverage view does not list technique %s for hook %q", tech.ID, e.Hook)
			}
		}
	}
	if !strings.Contains(out, "lsm=bpf") {
		t.Error("the coverage view does not say how to enable the programs that need the BPF LSM")
	}
}

func TestRenderingSurvivesAFilterThatMatchesNothing(t *testing.T) {
	// An empty result set is the most common state of a filter while it is
	// being typed, and it is the state where the row count is zero while the
	// cursor still has a value.
	m := populated(t)
	sized(m, 80, 24)
	m.input.SetValue("nothing-matches-this")
	for _, v := range allViews {
		m.view = v
		m.clampCursor()
		if got := len(strings.Split(m.View(), "\n")); got != 24 {
			t.Errorf("%v renders %d lines under an empty filter, want 24", v, got)
		}
	}
}

func TestColumnsAreDroppedByPriorityNotByPosition(t *testing.T) {
	// On the events view the description is the last column and the first
	// thing worth keeping. Dropping columns right to left would throw away
	// the only part anyone reads.
	specs := []colSpec{
		{title: "TIME", min: 8, prio: 2},
		{title: "VERDICT", min: 7, prio: 1},
		{title: "DETAIL", min: 12, weight: 4, prio: 0},
	}
	cols := fitColumns(16, specs)
	if cols[2].Width == 0 {
		t.Error("the description column was dropped before the timestamp")
	}
	if cols[0].Width != 0 {
		t.Error("a column was kept that does not fit")
	}

	// Whatever survives, the table must fill the pane exactly rather than
	// leaving a ragged right edge on one view and not another.
	for _, w := range []int{1, 5, 16, 17, 40, 41, 200} {
		cols := fitColumns(w, specs)
		total := 0
		for _, c := range cols {
			if c.Width > 0 {
				total += c.Width + cellPadding
			}
		}
		if total > w {
			t.Errorf("columns total %d at width %d", total, w)
		}
		if total > 0 && total != w {
			t.Errorf("columns total %d at width %d, want the pane filled exactly", total, w)
		}
	}
}

func TestTruncateCountsRunesNotBytes(t *testing.T) {
	// A container image path with an accent in it is perfectly ordinary, and
	// cutting one in half emits an invalid byte sequence that a terminal draws
	// as a replacement glyph - or, worse, desynchronises the line.
	for _, tc := range []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"a width of zero renders nothing", "/etc/shadow", 0, ""},
		{"a negative width renders nothing", "/etc/shadow", -5, ""},
		{"a string that fits is untouched", "/etc/shadow", 40, "/etc/shadow"},
		{"a string exactly the width is untouched", "abcd", 4, "abcd"},
		{"ascii longer than the width loses its tail", "abcdef", 4, "abc…"},
		{"a width of one is the ellipsis alone", "abcdef", 1, "…"},
		// "café" is five bytes and four columns. Measuring bytes would trim a
		// string that already fits, which is how accented paths lose a letter
		// on a wide terminal for no reason at all.
		{"multi-byte text within the width is untouched", "café", 4, "café"},
		{"multi-byte text is cut on a rune boundary", "файл-café", 5, "файл…"},
		{"an all multi-byte string keeps whole runes", "ααααα", 3, "αα…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.s, tc.n)
			if got != tc.want {
				t.Fatalf("truncate(%q, %d) is %q, want %q", tc.s, tc.n, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("truncate(%q, %d) produced invalid UTF-8: %q", tc.s, tc.n, got)
			}
			if tc.n > 0 && lipgloss.Width(got) > tc.n {
				t.Errorf("truncate(%q, %d) is %d columns wide, which overflows the line",
					tc.s, tc.n, lipgloss.Width(got))
			}
		})
	}
}

func TestTruncateKeepsAPrefixOfTheOriginalRunes(t *testing.T) {
	// The cut has to land between runes at every width, not only at the ones
	// a table happens to pick: a resize walks the width across all of them.
	const path = "/var/lib/données/naïve-café/файл.log"
	runes := []rune(path)
	for n := 1; n <= len(runes)+2; n++ {
		got := truncate(path, n)
		if !utf8.ValidString(got) {
			t.Fatalf("truncate at width %d produced invalid UTF-8: %q", n, got)
		}
		if w := lipgloss.Width(got); w > n {
			t.Fatalf("truncate at width %d is %d columns wide", n, w)
		}
		body := strings.TrimSuffix(got, "…")
		if !strings.HasPrefix(path, body) {
			t.Fatalf("truncate at width %d is not a prefix of the input: %q", n, got)
		}
		if n >= len(runes) && got != path {
			t.Fatalf("truncate at width %d shortened a string that fits: %q", n, got)
		}
		if n < len(runes) && lipgloss.Width(got) != n {
			t.Fatalf("truncate at width %d is %d columns, want the full width used",
				n, lipgloss.Width(got))
		}
	}
}

func TestFitForcesTheExactBlockSize(t *testing.T) {
	// Every frame goes through fit. If it ever returned the wrong size the
	// status bar would wander, so it is checked on the shapes that break it.
	for _, tc := range []struct {
		name string
		in   string
		w, h int
	}{
		{"shorter than the box", "one\ntwo", 10, 6},
		{"a single line in a tall box", "only", 10, 20},
		{"exactly the box", "a\nb\nc", 3, 3},
		{"longer than the box is cut", "a\nb\nc\nd\ne\nf\ng", 3, 3},
		{"empty input still fills the box", "", 8, 4},
		{"a one line box", "a\nb\nc", 4, 1},
		{"a styled line wider than the box", styleDeny.Render("DENY /etc/shadow"), 6, 1},
		{"a one column box", "hello", 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fit(tc.in, tc.w, tc.h)
			lines := strings.Split(got, "\n")
			if len(lines) != tc.h {
				t.Errorf("fit returned %d lines, want %d", len(lines), tc.h)
			}
			for _, l := range lines {
				if lipgloss.Width(l) > tc.w {
					t.Errorf("fit returned a %d column line, want at most %d: %q",
						lipgloss.Width(l), tc.w, l)
				}
			}
		})
	}
	if got := fit("anything", 0, 5); got != "" {
		t.Errorf("fit to zero width is %q, want empty", got)
	}
}

func TestDescribeEventNamesTheOperationForEveryEventType(t *testing.T) {
	// The description is shared by the event list and the per-workload denial
	// list, so an event type it does not understand shows up as a blank line
	// in both - a denial you cannot read is a denial you cannot act on.
	fileNoSyscall := ev(export.EventTypeFile, false, "sh", "prod", "Deployment", "api")
	fileNoSyscall.File.SyscallName = ""

	execWithAncestry := ev(export.EventTypeProcess, false, "xmrig", "prod", "Deployment", "api")
	execWithAncestry.Exec.AncestryChain = "nginx -> sh -> xmrig"

	syscallNoName := ev(export.EventTypeSyscall, false, "nc", "prod", "Deployment", "api")
	syscallNoName.Syscall.Name = ""

	noDetail := ev(export.EventTypeFile, false, "sh", "prod", "Deployment", "api")
	noDetail.File = nil

	for _, tc := range []struct {
		name string
		e    export.Event
		want string
	}{
		{"a file access names the syscall and the path",
			ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"), "read /etc/shadow"},
		{"a file access with no syscall name falls back to open", fileNoSyscall, "open /etc/shadow"},
		{"a connection names the protocol, address and port",
			ev(export.EventTypeNetwork, false, "curl", "prod", "Deployment", "api"), "tcp 203.0.113.7:4444"},
		{"an exec names the binary",
			ev(export.EventTypeProcess, false, "xmrig", "prod", "Deployment", "api"), "exec /tmp/xmrig"},
		{"an exec with an ancestry names who started it", execWithAncestry,
			"exec /tmp/xmrig  nginx -> sh -> xmrig"},
		{"a capability names the capability",
			ev(export.EventTypeCapability, false, "sh", "prod", "Deployment", "api"), "capability CAP_SYS_ADMIN"},
		{"a syscall names the syscall",
			ev(export.EventTypeSyscall, false, "nc", "prod", "Deployment", "api"), "syscall ptrace"},
		{"an unnamed syscall falls back to its number", syscallNoName, "syscall 101"},
		{"an event with no detail describes nothing", noDetail, ""},
		{"a zero event describes nothing", export.Event{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeEvent(tc.e); got != tc.want {
				t.Errorf("describeEvent is %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEventHaystackIncludesTheAttributionTheFilterIsTypedAgainst(t *testing.T) {
	// A person filtering types a namespace, a pod, a workload or a node name.
	// Leaving any of them out of the haystack makes the filter silently match
	// nothing, which reads as "there is no such traffic".
	e := ev(export.EventTypeNetwork, true, "curl", "kube-system", "DaemonSet", "cni")
	e.Kubernetes.Pod = "cni-7c9b4"
	e.Kubernetes.Node = "node-42"

	hay := eventHaystack(e)
	for _, want := range []string{
		"network",     // type
		"deny",        // action
		"curl",        // comm
		"203.0.113.7", // the described operation
		"kube-system", // namespace
		"cni-7c9b4",   // pod
		"cni",         // workload name
		"node-42",     // node
	} {
		if !strings.Contains(hay, want) {
			t.Errorf("the haystack %q does not contain %q, so a filter for it would match nothing", hay, want)
		}
	}
}

func TestEventHaystackHandlesAnUnattributedEvent(t *testing.T) {
	// Events from a cgroup Pahlevan cannot attribute still have to be
	// filterable, and a nil Kubernetes reference must not take the console down.
	e := ev(export.EventTypeFile, false, "sh", "", "", "")
	e.Kubernetes = nil
	hay := eventHaystack(e)
	if !strings.Contains(hay, "sh") || !strings.Contains(hay, "/etc/shadow") {
		t.Errorf("the haystack for an unattributed event is %q", hay)
	}
}

func TestClusterHaystacksCoverWhatSomebodyWouldTypeToFindARow(t *testing.T) {
	p := fixtureCluster().policies[0]
	for _, want := range []string{"prod", "api", "enforcing", "blocking", "app=api"} {
		if !strings.Contains(policyHaystack(p), want) {
			t.Errorf("the policy haystack does not contain %q", want)
		}
	}
	pr := fixtureCluster().profiles[0]
	for _, want := range []string{"prod", "api-7c9b4-nginx", "node-1", "nginx", "enforcing"} {
		if !strings.Contains(profileHaystack(pr), want) {
			t.Errorf("the profile haystack does not contain %q", want)
		}
	}
	as := fixtureCluster().surfaces[0]
	for _, want := range []string{"prod", "api", "ptrace", "cap_sys_admin", "/tmp"} {
		if !strings.Contains(surfaceHaystack(as), want) {
			t.Errorf("the attack surface haystack does not contain %q", want)
		}
	}
}

func TestRiskIsDrawnAsABarAndANumber(t *testing.T) {
	for _, tc := range []struct{ score, want int }{{0, 0}, {19, 0}, {20, 1}, {50, 2}, {100, 5}, {140, 5}, {-3, 0}} {
		cell := riskCell(tc.score)
		if got := strings.Count(cell, "█"); got != tc.want {
			t.Errorf("riskCell(%d) has %d filled blocks, want %d: %q", tc.score, got, tc.want, cell)
		}
		if lipgloss.Width(cell) != 9 {
			t.Errorf("riskCell(%d) is %d columns, want a fixed 9: %q", tc.score, lipgloss.Width(cell), cell)
		}
	}
}

// Screenshots. These render whole frames into the test log so a change in the
// layout is something a person can look at, not only a line count that still
// passes.
func TestScreenshots(t *testing.T) {
	for _, tc := range []struct {
		name string
		view View
		w, h int
		prep func(*Model)
	}{
		{name: "overview", view: ViewOverview, w: 96, h: 22},
		{name: "policies", view: ViewPolicies, w: 96, h: 18},
		{name: "events", view: ViewEvents, w: 96, h: 16},
		{name: "attack surface", view: ViewSurface, w: 96, h: 18},
		{name: "coverage", view: ViewCoverage, w: 96, h: 18},
		{name: "workloads narrow", view: ViewWorkloads, w: 60, h: 14},
		{name: "help", view: ViewHelp, w: 96, h: 18},
		{
			name: "policies with a broken cluster", view: ViewPolicies, w: 96, h: 12,
			prep: func(m *Model) {
				m.policies.err = fmt.Errorf("Get \"https://10.96.0.1/apis\": connection refused")
				m.policies.items = nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := populated(t)
			m.view = tc.view
			sized(m, tc.w, tc.h)
			if tc.prep != nil {
				tc.prep(m)
			}
			m.clampCursor()
			t.Logf("\n%s\n", m.View())
		})
	}
}

// BenchmarkView draws a full frame from a model holding a realistic backlog.
// The frame is rebuilt on every event, so its cost is paid at the event rate,
// not at the redraw rate a person perceives.
func BenchmarkView(b *testing.B) {
	m := sized(New(Options{}), 120, 40)
	m.view = ViewEvents
	for i := 0; i < 2000; i++ {
		m.ingest(ev(export.EventTypeFile, i%10 == 0, "nginx", "prod", "Deployment", "api"))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

// BenchmarkViewFiltered is the same frame with a filter on, which cannot read
// the ring's tail directly and has to scan.
func BenchmarkViewFiltered(b *testing.B) {
	m := sized(New(Options{}), 120, 40)
	m.view = ViewEvents
	for i := 0; i < 2000; i++ {
		m.ingest(ev(export.EventTypeFile, i%10 == 0, "nginx", "prod", "Deployment", "api"))
	}
	m.input.SetValue("shadow")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

func BenchmarkViewOverview(b *testing.B) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 120, 40)
	drainCluster(m)
	m.view = ViewOverview
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

// BenchmarkViewCoverage isolates a static screen, which should not get more
// expensive as the event stream grows.
func BenchmarkViewCoverage(b *testing.B) {
	m := sized(New(Options{}), 120, 40)
	m.view = ViewCoverage
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

// BenchmarkTruncate runs the per-cell cost: every rendered row goes through it
// at least twice, so it is called tens of times per frame.
func BenchmarkTruncate(b *testing.B) {
	const path = "read /var/lib/données/naïve-café/файл.log by a process with a long name"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncate(path, 40)
	}
}

// BenchmarkFitColumns is the layout arithmetic every table redraw repeats.
func BenchmarkFitColumns(b *testing.B) {
	specs := []colSpec{
		{title: "TIME", min: 8, prio: 2},
		{title: "VERDICT", min: 7, prio: 1},
		{title: "TYPE", min: 7, prio: 3},
		{title: "PROCESS", min: 8, weight: 1, prio: 4},
		{title: "WORKLOAD", min: 10, weight: 2, prio: 5},
		{title: "DETAIL", min: 12, weight: 4, prio: 0},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fitColumns(120, specs)
	}
}
