package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/coverage"
	"github.com/obsernetics/pahlevan/pkg/export"
)

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

func TestPadToAlwaysReturnsExactlyTheRequestedLines(t *testing.T) {
	// The status line sits below the body. If the body's height followed its
	// content, the status line would wander up and down the screen every time
	// an event arrived.
	for _, tc := range []struct {
		name string
		in   string
		n    int
	}{
		{"shorter than the box", "one\ntwo", 6},
		{"a single line in a tall box", "only", 20},
		{"exactly the box", "a\nb\nc", 3},
		{"longer than the box is cut", "a\nb\nc\nd\ne\nf\ng", 3},
		{"empty input still fills the box", "", 4},
		{"a one line box", "a\nb\nc", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := padTo(tc.in, tc.n)
			if lines := strings.Split(got, "\n"); len(lines) != tc.n {
				t.Errorf("padTo returned %d lines, want %d", len(lines), tc.n)
			}
		})
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
	// filterable, and a nil Kubernetes reference must not take the UI down.
	e := ev(export.EventTypeFile, false, "sh", "", "", "")
	e.Kubernetes = nil
	hay := eventHaystack(e)
	if !strings.Contains(hay, "sh") || !strings.Contains(hay, "/etc/shadow") {
		t.Errorf("the haystack for an unattributed event is %q", hay)
	}
}

// allViews is every screen View() can be asked to draw, including the detail
// screen that is not in the tab cycle.
var allViews = []View{ViewEvents, ViewWorkloads, ViewDetail, ViewCoverage, ViewHelp}

func TestEveryViewRendersTheExactWindowHeightAtEverySize(t *testing.T) {
	// A frame taller than the terminal scrolls the screen and leaves the
	// previous frame's tail behind; a shorter one leaves the old frame's
	// bottom rows on screen. Either way the display stops matching the model,
	// and the sizes where that happens are the extreme ones.
	populated := func() *Model {
		m := New(Options{Capacity: 64})
		for i := 0; i < 40; i++ {
			feed(m, ev(export.EventTypeFile, i%3 == 0, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
		}
		feed(m, ev(export.EventTypeNetwork, true, "curl", "kube-system", "DaemonSet", "cni"))
		m.selected = "prod/Deployment/api"
		return m
	}

	for _, fixture := range []struct {
		name  string
		build func() *Model
	}{
		{"a model with events", populated},
		{"a model with nothing in it", func() *Model { return New(Options{}) }},
	} {
		for _, v := range allViews {
			for _, w := range []int{1, 10, 200} {
				for _, h := range []int{1, 2, 5, 100} {
					name := fmt.Sprintf("%s/%s/%dx%d", fixture.name, v, w, h)
					t.Run(name, func(t *testing.T) {
						m := fixture.build()
						m.view = v
						sized(m, w, h)

						out := m.View()
						// The header and the status line are two rows each,
						// around a body padded to the window height.
						want := max(1, h-chromeHeight) + chromeHeight
						if got := len(strings.Split(out, "\n")); got != want {
							t.Errorf("the frame is %d lines at %dx%d, want %d", got, w, h, want)
						}
					})
				}
			}
		}
	}
}

func TestRenderingSurvivesAFilterThatMatchesNothing(t *testing.T) {
	// An empty result set is the most common state of a filter while it is
	// being typed, and it is the state where the row count is zero while the
	// cursor still has a value.
	m := sized(New(Options{}), 80, 24)
	feed(m, ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"))
	m.filter = "nothing-matches-this"
	for _, v := range allViews {
		m.view = v
		m.clampCursor()
		if got, want := len(strings.Split(m.View(), "\n")), max(1, 24-chromeHeight)+chromeHeight; got != want {
			t.Errorf("%v renders %d lines under an empty filter, want %d", v, got, want)
		}
	}
}

func TestTheCoverageViewListsEveryHookInTheTable(t *testing.T) {
	// The coverage screen is the project's claim about what it detects. A hook
	// that is in the table but missing from the screen is a detector nobody
	// knows they have; the reverse is a claim with nothing behind it.
	m := sized(New(Options{}), 200, 100)
	m.view = ViewCoverage
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

func TestTheStatusLineReportsWhatRolledOff(t *testing.T) {
	// A list that starts where the buffer happens to begin, with no note of
	// what was dropped, is a screen that quietly misrepresents the node.
	m := sized(New(Options{Capacity: 4}), 120, 30)
	for i := 0; i < 10; i++ {
		feed(m, ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
	}
	out := m.View()
	if !strings.Contains(out, "6 rolled off") {
		t.Errorf("the status line does not report the 6 evicted events:\n%s", out)
	}
	if !strings.Contains(out, "10 events") {
		t.Error("the status line does not report the session total")
	}
}

// BenchmarkView draws a full frame from a model holding a realistic backlog.
// The frame is rebuilt on every event, so its cost is paid at the event rate,
// not at the redraw rate a person perceives.
func BenchmarkView(b *testing.B) {
	m := sized(New(Options{}), 120, 40)
	for i := 0; i < 2000; i++ {
		m.ingest(ev(export.EventTypeFile, i%10 == 0, "nginx", "prod", "Deployment", "api"))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

// BenchmarkViewCoverage isolates the static screen, which should not get more
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

func TestElapsedMeasuresFromTheInjectedStart(t *testing.T) {
	// A quiet stream and a dead stream look identical without a clock, so the
	// start time is injectable rather than read from the wall: a test that
	// depended on real time would be a test that fails on a slow machine.
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	m := New(Options{Now: func() time.Time { return start }})
	if got := m.Elapsed(start.Add(90 * time.Second)); got != 90*time.Second {
		t.Errorf("Elapsed is %v, want 90s", got)
	}
}
