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

func key(m *Model, s string) {
	var msg tea.KeyMsg
	switch s {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "space":
		msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "backspace":
		msg = tea.KeyMsg{Type: tea.KeyBackspace}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
	m.Update(msg)
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

func TestPauseFreezesTheListButNotTheCounters(t *testing.T) {
	// Returning from a pause to counters that pretended nothing happened would
	// be a lie about what the node did while you were reading.
	m := sized(New(Options{}), 100, 30)
	feed(m, ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"))
	key(m, " ")
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
	key(m, "/")
	for _, r := range "kube-system" {
		key(m, string(r))
	}
	key(m, "enter")

	got := m.filteredEvents()
	if len(got) != 1 {
		t.Fatalf("%d events matched %q, want 1", len(got), m.filter)
	}
	if got[0].Type != export.EventTypeNetwork {
		t.Errorf("matched the wrong event: %v", got[0].Type)
	}
}

func TestEscapeClearsTheFilterThenLeavesTheView(t *testing.T) {
	m := sized(New(Options{}), 100, 30)
	feed(m, ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"))
	key(m, "2")
	key(m, "enter") // into detail
	if m.view != ViewDetail {
		t.Fatalf("enter did not open the detail view, at %v", m.view)
	}
	key(m, "/")
	key(m, "x")
	key(m, "enter")
	if m.filter != "x" {
		t.Fatalf("filter is %q, want x", m.filter)
	}
	key(m, "esc")
	if m.filter != "" {
		t.Errorf("esc did not clear the filter, it is %q", m.filter)
	}
	if m.view != ViewDetail {
		t.Errorf("esc left the view while a filter was set; it should clear the filter first")
	}
	key(m, "esc")
	if m.view == ViewDetail {
		t.Error("a second esc did not leave the detail view")
	}
}

func TestCursorStaysInRangeAcrossResizeAndFilter(t *testing.T) {
	// An off-by-one in a viewport is how a terminal UI panics on a resize, so
	// this drives the combinations rather than one happy path.
	m := sized(New(Options{}), 120, 40)
	for i := 0; i < 50; i++ {
		feed(m, ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
	}
	key(m, "2")
	key(m, "G")
	for _, h := range []int{40, 5, 1, 200, 3} {
		sized(m, 120, h)
		for _, k := range []string{"j", "k", "G", "g", "j"} {
			key(m, k)
			if m.cursor < 0 || (m.rowCount() > 0 && m.cursor >= m.rowCount()) {
				t.Fatalf("cursor %d out of range for %d rows at height %d", m.cursor, m.rowCount(), h)
			}
			if m.offset < 0 {
				t.Fatalf("offset %d is negative at height %d", m.offset, h)
			}
			// Rendering must not panic at any of these sizes.
			_ = m.View()
		}
	}
}

func TestSelectingAWorkloadOpensItsDetail(t *testing.T) {
	m := sized(New(Options{}), 120, 30)
	feed(m,
		ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"),
		ev(export.EventTypeFile, false, "cni", "kube-system", "DaemonSet", "cni"),
	)
	key(m, "2")
	key(m, "enter")
	if m.view != ViewDetail {
		t.Fatalf("view is %v, want detail", m.view)
	}
	// Workloads are sorted, so kube-system sorts before prod.
	if m.selected != "kube-system/DaemonSet/cni" {
		t.Errorf("selected %q", m.selected)
	}
	out := m.View()
	if !strings.Contains(out, "kube-system/DaemonSet/cni") {
		t.Error("the detail view does not name the workload")
	}
}

func TestClearEmptiesTheEventsButKeepsTheTotals(t *testing.T) {
	m := sized(New(Options{}), 100, 30)
	feed(m, ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api"))
	key(m, "c")
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
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
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
	m := sized(New(Options{}), 80, 24)
	want := errors.New("connection refused")
	m.Update(SourceEndedMsg{Err: want})
	if !m.ended || m.err == nil {
		t.Fatal("the stream end was not recorded")
	}
	if !strings.Contains(m.View(), "connection refused") {
		t.Error("the status line does not show why the stream ended")
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
	// the UI leaks a goroutine and a connection.
	ctx, cancel := context.WithCancel(context.Background())
	src := &SliceSource{Events: make([]export.Event, 10000)}
	got := make(chan tea.Msg, 1)
	Stream(ctx, src, func(m tea.Msg) {
		select {
		case got <- m:
		default:
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
	m.filter = "shadow"
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
