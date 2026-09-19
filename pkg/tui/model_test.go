package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/obsernetics/pahlevan/pkg/export"
)

func ev(t export.EventType, denied bool, comm string, ns, kind, name string) export.Event {
	e := export.Event{
		Timestamp: export.Timestamp(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)),
		Type:      t,
		Action:    export.ActionObserve,
		Process:   export.ProcessInfo{PID: 1, Comm: comm},
		Kubernetes: &export.KubernetesRef{
			Namespace: ns, WorkloadKind: kind, WorkloadName: name, Pod: name + "-x", Node: "node-1",
		},
	}
	if denied {
		e.Action = export.ActionDeny
	}
	switch t {
	case export.EventTypeFile:
		e.File = &export.FileInfo{Path: "/etc/shadow", SyscallName: "read"}
	case export.EventTypeNetwork:
		e.Network = &export.NetworkInfo{DestinationIP: "203.0.113.7", DestinationPort: 4444, Protocol: "TCP"}
	case export.EventTypeProcess:
		e.Exec = &export.ExecInfo{Binary: "/tmp/xmrig"}
	case export.EventTypeCapability:
		e.Capability = &export.CapabilityInfo{Name: "CAP_SYS_ADMIN"}
	case export.EventTypeSyscall:
		e.Syscall = &export.SyscallInfo{Name: "ptrace", Number: 101}
	}
	return e
}

func feed(m *Model, events ...export.Event) {
	for _, e := range events {
		m.Update(EventMsg{Event: e})
	}
}

func sized(m *Model, w, h int) *Model {
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

// keyMsg builds the message bubbletea would deliver for a key, so tests drive
// the same path the terminal does rather than calling handlers directly.
func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case " ", "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		return tea.KeyMsg{Type: tea.KeyEnd}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func press(m *Model, s string) tea.Cmd {
	_, cmd := m.Update(keyMsg(s))
	return cmd
}

// typeFilter opens the filter, types it and accepts it, the way a person does.
func typeFilter(m *Model, s string) {
	press(m, "/")
	for _, r := range s {
		press(m, string(r))
	}
	press(m, "enter")
}

func TestWorkloadsAreKeyedByOwnerNotPod(t *testing.T) {
	// A Deployment rolling out replaces every pod name. Keying on the pod
	// would reset the history mid-rollout, which is exactly when somebody is
	// watching.
	m := New(Options{})
	a := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	a.Kubernetes.Pod = "api-aaaa"
	b := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	b.Kubernetes.Pod = "api-bbbb"
	feed(m, a, b)

	if got := len(m.workloads); got != 1 {
		t.Fatalf("%d workloads, want 1: a rollout must not split the history", got)
	}
	if got := m.workloads["prod/Deployment/api"].Files; got != 2 {
		t.Errorf("file count is %d, want 2", got)
	}
}

func TestUnattributedEventsAreGroupedNotDropped(t *testing.T) {
	m := New(Options{})
	e := ev(export.EventTypeFile, false, "sh", "", "", "")
	e.Kubernetes = nil
	e.CgroupID = 4242
	feed(m, e)

	if _, ok := m.workloads["cgroup:4242"]; !ok {
		t.Fatalf("an unattributed event was dropped; workloads are %v", m.order)
	}
}

func TestDenialsAreCountedAndDescribed(t *testing.T) {
	m := New(Options{})
	feed(m,
		ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"),
		ev(export.EventTypeNetwork, true, "curl", "prod", "Deployment", "api"),
		ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"),
	)
	w := m.workloads["prod/Deployment/api"]
	if w.Denials != 2 {
		t.Errorf("denials is %d, want 2", w.Denials)
	}
	if m.denied != 2 || m.total != 3 {
		t.Errorf("totals are denied=%d total=%d, want 2 and 3", m.denied, m.total)
	}
	if len(w.DeniedWhat) != 2 {
		t.Fatalf("%d descriptions, want 2", len(w.DeniedWhat))
	}
	if !strings.Contains(w.DeniedWhat[0], "/etc/shadow") {
		t.Errorf("the first denial does not name the path: %q", w.DeniedWhat[0])
	}
}

func TestTheDenialListIsBounded(t *testing.T) {
	// The per-workload denial list is a hint for the detail pane, not an audit
	// log. Unbounded, a workload in a deny loop would grow it forever.
	m := New(Options{})
	for i := 0; i < deniedWhatCap*3; i++ {
		feed(m, ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"))
	}
	w := m.workloads["prod/Deployment/api"]
	if len(w.DeniedWhat) != deniedWhatCap {
		t.Errorf("kept %d descriptions, want the cap of %d", len(w.DeniedWhat), deniedWhatCap)
	}
	if w.Denials != deniedWhatCap*3 {
		t.Errorf("the count was capped too: %d, want %d", w.Denials, deniedWhatCap*3)
	}
}

func TestRetainedEventsStayInTheBoundedRing(t *testing.T) {
	// The console's memory must not grow with the node's syscall rate, on the
	// one machine where somebody is already watching something go wrong.
	m := sized(New(Options{Capacity: 16}), 120, 30)
	for i := 0; i < 5000; i++ {
		feed(m, ev(export.EventTypeFile, i%7 == 0, "nginx", "prod", "Deployment", "api"))
	}
	if got := m.events.len(); got != 16 {
		t.Errorf("the ring holds %d events, want its capacity of 16", got)
	}
	if m.events.dropped != 5000-16 {
		t.Errorf("dropped %d events, want %d", m.events.dropped, 5000-16)
	}
	if m.total != 5000 {
		t.Errorf("the session total is %d, want 5000", m.total)
	}
}

func TestPauseFreezesTheListButNotTheCounters(t *testing.T) {
	// Returning from a pause to counters that pretended nothing happened would
	// be a lie about what the node did while you were reading.
	m := sized(New(Options{}), 100, 30)
	feed(m, ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"))
	press(m, " ")
	if !m.paused {
		t.Fatal("space did not pause")
	}
	before := m.events.len()
	feed(m, ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"))

	if m.events.len() != before {
		t.Errorf("the event list grew while paused: %d then %d", before, m.events.len())
	}
	if m.total != 2 || m.denied != 1 {
		t.Errorf("counters froze while paused: total=%d denied=%d, want 2 and 1", m.total, m.denied)
	}
	if m.workloads["prod/Deployment/api"].Denials != 1 {
		t.Error("the workload denial count froze while paused")
	}
}

func TestFilterMatchesFieldsNotTheRenderedLine(t *testing.T) {
	// Matching the rendered line would make the filter depend on the terminal
	// width, which is a surprising thing for a filter to do.
	m := sized(New(Options{}), 40, 20) // deliberately narrow
	feed(m,
		ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"),
		ev(export.EventTypeNetwork, false, "curl", "kube-system", "DaemonSet", "cni"),
	)
	typeFilter(m, "kube-system")

	got := m.filteredEvents()
	if len(got) != 1 {
		t.Fatalf("%d events matched %q, want 1", len(got), m.filterText())
	}
	if got[0].Type != export.EventTypeNetwork {
		t.Errorf("matched the wrong event: %v", got[0].Type)
	}
}

func TestTypingInTheFilterDoesNotTriggerCommands(t *testing.T) {
	// The filter shares the keyboard with q, c, space and the number keys.
	// Typing "quiet cron" into it must not quit, clear the ring, pause, or
	// jump to another view.
	m := sized(New(Options{}), 120, 30)
	feed(m, ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"))
	press(m, "5") // events
	before := m.events.len()

	press(m, "/")
	for _, r := range "quiet cron 2" {
		if cmd := press(m, string(r)); cmd != nil {
			if msg := cmd(); msg != nil {
				if _, quit := msg.(tea.QuitMsg); quit {
					t.Fatalf("typing %q in the filter quit the program", r)
				}
			}
		}
	}
	if m.quitting {
		t.Error("typing q in the filter set quitting")
	}
	if m.paused {
		t.Error("typing a space in the filter paused the stream")
	}
	if m.view != ViewEvents {
		t.Errorf("typing a digit in the filter changed the view to %v", m.view)
	}
	if m.events.len() != before {
		t.Error("typing c in the filter cleared the retained events")
	}
	if m.filterText() != "quiet cron 2" {
		t.Errorf("the filter holds %q, want %q", m.filterText(), "quiet cron 2")
	}
}

func TestEscapeClearsTheFilterThenLeavesTheDetailPane(t *testing.T) {
	m := sized(New(Options{}), 60, 30) // narrow: the detail pane replaces the list
	feed(m, ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"))
	press(m, "4") // workloads
	// Opening the filter returns to the list, because a filter narrows the
	// list rather than the thing the detail pane is describing.
	typeFilter(m, "prod")
	if m.filterText() != "prod" {
		t.Fatalf("the filter holds %q, want prod", m.filterText())
	}
	if m.focus != paneList {
		t.Fatal("filtering did not return the focus to the list")
	}
	press(m, "enter")
	if m.focus != paneDetail {
		t.Fatal("enter did not focus the detail pane")
	}

	press(m, "esc")
	if m.filterText() != "" {
		t.Errorf("esc did not clear the filter, it holds %q", m.filterText())
	}
	if m.focus != paneDetail {
		t.Error("esc left the detail pane while a filter was set; it should clear the filter first")
	}
	press(m, "esc")
	if m.focus != paneList {
		t.Error("a second esc did not leave the detail pane")
	}
}

func TestTheDetailPaneFollowsTheCursor(t *testing.T) {
	m := sized(New(Options{}), 200, 40)
	feed(m,
		ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"),
		ev(export.EventTypeFile, false, "cni", "kube-system", "DaemonSet", "cni"),
	)
	press(m, "4") // workloads

	// Workloads are sorted, so kube-system sorts before prod.
	if got := m.selectedWorkload(); got == nil || got.Key != "kube-system/DaemonSet/cni" {
		t.Fatalf("the first row selects %v", got)
	}
	if !strings.Contains(m.View(), "kube-system/DaemonSet/cni") {
		t.Error("the detail pane does not name the selected workload")
	}
	press(m, "j")
	if got := m.selectedWorkload(); got == nil || got.Key != "prod/Deployment/api" {
		t.Fatalf("moving down selects %v", got)
	}
	if out := m.View(); !strings.Contains(out, "refused in-kernel") {
		t.Errorf("the detail pane does not report the denial:\n%s", out)
	}
}

func TestEachViewRemembersItsOwnCursor(t *testing.T) {
	// Tabbing away from row 20 of the profiles list and back again should
	// return to row 20. A single shared cursor sends you to the top of a list
	// you were reading because you glanced at another tab.
	m := sized(New(Options{}), 200, 40)
	for i := 0; i < 40; i++ {
		feed(m, ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", fmt.Sprintf("api-%02d", i)))
	}
	press(m, "4") // workloads
	for i := 0; i < 5; i++ {
		press(m, "j")
	}
	want := m.cursor()
	if want != 5 {
		t.Fatalf("the workloads cursor is %d, want 5", want)
	}
	press(m, "5") // events
	press(m, "4") // back to workloads
	if got := m.cursor(); got != want {
		t.Errorf("the workloads cursor is %d after a round trip, want %d", got, want)
	}
}

func TestEveryViewIsReachableByTabAndByNumber(t *testing.T) {
	m := sized(New(Options{}), 200, 40)
	seen := map[View]bool{}
	for i := 0; i < len(views); i++ {
		seen[m.view] = true
		press(m, "tab")
	}
	for _, v := range views {
		if !seen[v] {
			t.Errorf("tabbing never reaches %v", v)
		}
	}
	if m.view != views[0] {
		t.Errorf("tabbing %d times did not return to the first view, it is at %v", len(views), m.view)
	}
	for i, v := range views {
		press(m, fmt.Sprintf("%d", i+1))
		if m.view != v {
			t.Errorf("key %d opened %v, want %v", i+1, m.view, v)
		}
	}
	press(m, "shift+tab")
	if m.view != views[len(views)-2] {
		t.Errorf("shift+tab from the last view opened %v", m.view)
	}
}

func TestHelpTogglesAndComesBack(t *testing.T) {
	m := sized(New(Options{}), 120, 30)
	press(m, "3")
	press(m, "?")
	if m.view != ViewHelp {
		t.Fatalf("? opened %v, want help", m.view)
	}
	press(m, "?")
	if m.view != ViewProfiles {
		t.Errorf("? from help returned to %v, want the profiles view", m.view)
	}
	press(m, "?")
	press(m, "esc")
	if m.view != ViewProfiles {
		t.Errorf("esc from help returned to %v, want the profiles view", m.view)
	}
}

func TestCursorStaysInRangeAcrossResizeAndFilter(t *testing.T) {
	// An off-by-one in a viewport is how a terminal UI panics on a resize, so
	// this drives the combinations rather than one happy path, on every view
	// and at every size the terminal can actually be.
	for _, v := range allViews {
		t.Run(v.String(), func(t *testing.T) {
			m := sized(New(Options{Cluster: fixtureCluster()}), 120, 40)
			for i := 0; i < 50; i++ {
				feed(m, ev(export.EventTypeFile, i%4 == 0, fmt.Sprintf("p%d", i), "prod", "Deployment", fmt.Sprintf("api-%02d", i%7)))
			}
			drainCluster(m)
			m.view = v
			m.clampCursor()

			for _, filter := range []string{"", "api", "no-such-thing"} {
				m.input.SetValue(filter)
				m.clampCursor()
				for _, h := range []int{40, 5, 2, 1, 200, 3} {
					for _, w := range []int{1, 40, 200} {
						sized(m, w, h)
						for _, k := range []string{"j", "k", "G", "g", "j", "enter", "pgdown", "pgup", "esc"} {
							press(m, k)
							if m.cursor() < 0 || (m.rowCount() > 0 && m.cursor() >= m.rowCount()) {
								t.Fatalf("cursor %d out of range for %d rows at %dx%d (filter %q, key %q)",
									m.cursor(), m.rowCount(), w, h, filter, k)
							}
							if m.offset() < 0 {
								t.Fatalf("offset %d is negative at %dx%d", m.offset(), w, h)
							}
							if m.offset() > max(0, m.rowCount()-1) {
								t.Fatalf("offset %d is past the last of %d rows at %dx%d",
									m.offset(), m.rowCount(), w, h)
							}
							// Rendering must not panic at any of these sizes.
							_ = m.View()
						}
					}
				}
			}
		})
	}
}

func TestClearEmptiesTheEventsButKeepsTheTotals(t *testing.T) {
	m := sized(New(Options{}), 100, 30)
	feed(m, ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"))
	press(m, "c")
	if m.events.len() != 0 {
		t.Errorf("c did not clear the events, %d remain", m.events.len())
	}
	if m.total != 1 || m.denied != 1 {
		t.Errorf("c reset the session totals: total=%d denied=%d", m.total, m.denied)
	}
}

func TestQuitSetsQuittingSoTheLastFrameIsEmpty(t *testing.T) {
	// Leaving a half-drawn screen behind after the program returns is the most
	// common way a TUI makes a mess of somebody's terminal.
	m := sized(New(Options{}), 80, 24)
	cmd := press(m, "q")
	if cmd == nil {
		t.Fatal("q returned no command, so the program would not quit")
	}
	if !m.quitting {
		t.Error("q did not mark the model as quitting")
	}
	if m.View() != "" {
		t.Error("the final frame is not empty")
	}
}

func TestStreamEndReportsTheError(t *testing.T) {
	m := sized(New(Options{}), 120, 24)
	want := errors.New("connection refused")
	m.Update(SourceEndedMsg{Err: want})
	if !m.ended || m.err == nil {
		t.Fatal("the stream end was not recorded")
	}
	if !strings.Contains(m.View(), "connection refused") {
		t.Error("the status bar does not show why the stream ended")
	}
}

func TestStreamDeliversEventsAndThenTheEnd(t *testing.T) {
	src := &SliceSource{Events: []export.Event{
		ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"),
		ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"),
	}, Name: "test"}

	msgs := make(chan tea.Msg, 8)
	Stream(context.Background(), src, func(m tea.Msg) { msgs <- m })

	var events, ends int
	deadline := time.After(2 * time.Second)
	for events+ends < 3 {
		select {
		case m := <-msgs:
			switch m.(type) {
			case EventMsg:
				events++
			case SourceEndedMsg:
				ends++
			}
		case <-deadline:
			t.Fatalf("timed out after %d events and %d ends", events, ends)
		}
	}
	if events != 2 || ends != 1 {
		t.Errorf("got %d events and %d ends, want 2 and 1", events, ends)
	}
}

func TestStreamStopsOnContextCancel(t *testing.T) {
	// A source that keeps producing must not outlive the program, or quitting
	// the console leaks a goroutine and a connection.
	ctx, cancel := context.WithCancel(context.Background())
	src := &SliceSource{Events: make([]export.Event, 10000)}
	// Only the terminal message is forwarded. Buffering events here and
	// dropping on a full channel made the test flaky about one run in six: the
	// first event filled the buffer, the SourceEndedMsg was dropped, and the
	// test waited out its deadline unless cancel happened to win the race.
	got := make(chan tea.Msg, 1)
	Stream(ctx, src, func(m tea.Msg) {
		if _, ok := m.(SourceEndedMsg); ok {
			got <- m
		}
	})
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case m := <-got:
			if _, ok := m.(SourceEndedMsg); ok {
				return
			}
		case <-deadline:
			t.Fatal("the stream did not end after the context was cancelled")
		}
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

func BenchmarkIngest(b *testing.B) {
	m := New(Options{})
	e := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ingest(e)
	}
}

func BenchmarkIngestDenied(b *testing.B) {
	m := New(Options{})
	e := ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ingest(e)
	}
}

func BenchmarkFilteredEvents(b *testing.B) {
	m := sized(New(Options{}), 120, 40)
	for i := 0; i < 2000; i++ {
		m.ingest(ev(export.EventTypeFile, i%10 == 0, "nginx", "prod", "Deployment", "api"))
	}
	m.input.SetValue("shadow")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.filteredEvents()
	}
}

func BenchmarkWorkloadKey(b *testing.B) {
	e := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = workloadKey(e)
	}
}

func TestTheEventListIsNewestFirstAndBuildsOnlyItsWindow(t *testing.T) {
	// The stream is a tail: the line that just arrived is the one being
	// looked at. Oldest-first would slide every row under the cursor down one
	// place per event, which on a busy node makes the cursor meaningless.
	m := sized(New(Options{Capacity: 128}), 200, 40)
	m.view = ViewEvents
	for i := 0; i < 20; i++ {
		e := ev(export.EventTypeFile, false, fmt.Sprintf("p%02d", i), "prod", "Deployment", "api")
		e.File.Path = fmt.Sprintf("/etc/file-%02d", i)
		feed(m, e)
	}

	win := m.eventWindow(0, 3)
	if len(win) != 3 {
		t.Fatalf("the window holds %d events, want 3", len(win))
	}
	for i, want := range []string{"/etc/file-19", "/etc/file-18", "/etc/file-17"} {
		if got := win[i].File.Path; got != want {
			t.Errorf("row %d is %s, want %s", i, got, want)
		}
	}
	// A window past the end is bounded by what is held, not by the request.
	if got := len(m.eventWindow(18, 40)); got != 2 {
		t.Errorf("a window past the end returned %d events, want the 2 that remain", got)
	}
	if got := m.eventWindow(5, 5); got != nil {
		t.Errorf("an empty window returned %v", got)
	}

	// The same ordering under a filter, which reads the cached match list.
	m.input.SetValue("file-1")
	if got := m.rowCount(); got != 10 {
		t.Fatalf("%d rows match the filter, want 10", got)
	}
	if got := m.eventWindow(0, 1)[0].File.Path; got != "/etc/file-19" {
		t.Errorf("the filtered list starts at %s, want the newest match", got)
	}
}

func TestTheFilterScanIsCachedUntilTheRingChanges(t *testing.T) {
	// One frame asks for the matches three times: to count the rows, to size
	// the window and to draw it. Rescanning the ring for each, at the event
	// rate, was most of what the console did with its CPU.
	m := sized(New(Options{Capacity: 64}), 120, 30)
	m.view = ViewEvents
	for i := 0; i < 20; i++ {
		feed(m, ev(export.EventTypeFile, false, fmt.Sprintf("p%02d", i), "prod", "Deployment", "api"))
	}
	m.input.SetValue("shadow")

	first := m.filteredEvents()
	if len(first) != 20 {
		t.Fatalf("%d events matched, want 20", len(first))
	}
	if second := m.filteredEvents(); &second[0] != &first[0] {
		t.Error("a second call rescanned the ring instead of reusing the scan")
	}
	// A new event invalidates it, or the list would freeze while the stream
	// kept running - the exact failure that makes a console untrustworthy.
	feed(m, ev(export.EventTypeFile, false, "new", "prod", "Deployment", "api"))
	if got := len(m.filteredEvents()); got != 21 {
		t.Errorf("after one more event the filter matches %d, want 21", got)
	}
	// So does clearing the retained events.
	press(m, "c")
	if got := len(m.filteredEvents()); got != 0 {
		t.Errorf("after clearing, the filter matches %d, want 0", got)
	}
}
