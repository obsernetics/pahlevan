package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// flowEvent is one network event with the identity the agents put on it.
func flowEvent(sec int, denied bool, ns, name, ip, dstName, dstKind string, port uint16) export.Event {
	e := export.Event{
		Timestamp: export.Timestamp(time.Date(2026, 9, 19, 12, 0, sec, 0, time.UTC)),
		Type:      export.EventTypeNetwork,
		Action:    export.ActionObserve,
		Process:   export.ProcessInfo{Comm: "python3"},
		Kubernetes: &export.KubernetesRef{
			Namespace: ns, WorkloadKind: "Deployment", WorkloadName: name, Pod: name + "-x", Node: "node-1",
		},
		Network: &export.NetworkInfo{
			DestinationIP: ip, DestinationPort: port, Protocol: "TCP",
			DestinationName: dstName, DestinationKind: dstKind,
		},
	}
	if denied {
		e.Action = export.ActionDeny
	}
	return e
}

func flowModel(t testing.TB, events ...export.Event) *Model {
	t.Helper()
	m := sized(New(Options{Capacity: 64}), 100, 24)
	feed(m, events...)
	m.setView(ViewFlows)
	return m
}

func TestFlowsFoldByIdentityRatherThanByConnection(t *testing.T) {
	// Three connections to the same peer are one flow. The events view is the
	// per-connection tail; this view exists because reading a thousand of
	// those and folding them by hand is the work it should have done.
	m := flowModel(t,
		flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(2, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(3, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 6432),
	)

	flows := m.filteredFlows()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want one flow to one peer", len(flows))
	}
	f := flows[0]
	if f.Source != "prod/api" || f.Peer != "db/postgres" {
		t.Errorf("flow is %s -> %s, want prod/api -> db/postgres", f.Source, f.Peer)
	}
	if f.Allowed != 3 || f.Denied != 0 {
		t.Errorf("got %d allowed and %d denied, want 3 and 0", f.Allowed, f.Denied)
	}
	if len(f.Ports) != 2 {
		t.Fatalf("got %d ports, want 5432 and 6432", len(f.Ports))
	}
	if f.Ports[0].Port != 5432 || f.Ports[0].Allowed != 2 {
		t.Errorf("port 5432 shows %+v, want two allowed connections", f.Ports[0])
	}
}

func TestFlowsKeepDeniedAndAllowedTogether(t *testing.T) {
	// A denied flow is only meaningful next to the allowed ones it sits
	// between, so it is marked in the list rather than filed in its own view.
	m := flowModel(t,
		flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(2, true, "prod", "api", "203.0.113.7", "", "", 4444),
		flowEvent(3, true, "prod", "api", "203.0.113.7", "", "", 4444),
	)

	flows := m.filteredFlows()
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want the allowed one and the refused one", len(flows))
	}
	var refused *Flow
	for _, f := range flows {
		if f.Peer == "203.0.113.7" {
			refused = f
		}
	}
	if refused == nil {
		t.Fatal("the refused flow is not in the list")
	}
	if refused.Denied != 2 || refused.Allowed != 0 {
		t.Errorf("got %d denied and %d allowed, want 2 and 0", refused.Denied, refused.Allowed)
	}
	if refused.PeerKind != "" {
		t.Errorf("peer kind is %q; an address the cluster could not name has no kind", refused.PeerKind)
	}
	if got := deniedCell(refused.Denied); got != "✖ 2" {
		t.Errorf("denied cell is %q, want the same mark the events view uses", got)
	}
	if got := deniedCell(0); got != "-" {
		t.Errorf("a flow with no denials renders %q, want a dash", got)
	}
}

func TestFlowsRollUpNamespaceToNamespace(t *testing.T) {
	m := flowModel(t,
		flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(2, false, "prod", "web", "10.0.1.6", "prod/api", "pod", 8080),
		flowEvent(3, true, "prod", "api", "203.0.113.7", "", "", 4444),
		flowEvent(4, false, "prod", "api", "192.168.1.10", "node-1", "node", 10250),
	)

	got := map[string]*NamespaceFlow{}
	for _, k := range m.nsFlowOrder {
		got[k] = m.nsFlows[k]
	}
	for _, want := range []string{
		"prod \u2192 db", "prod \u2192 prod", "prod \u2192 (outside the cluster)", "prod \u2192 (nodes)",
	} {
		if got[want] == nil {
			t.Errorf("no namespace rollup for %q; the coarse axis is the shape of the cluster", want)
		}
	}
	if f := got["prod \u2192 (outside the cluster)"]; f != nil && f.Denied != 1 {
		t.Errorf("the refused external flow shows %d denials, want 1", f.Denied)
	}
}

func TestFlowsSeparateUnattributedTrafficFromTrafficThatLeft(t *testing.T) {
	// Traffic Pahlevan could not attribute and traffic that genuinely left the
	// cluster are different findings. Merging them under one label would hide
	// the first inside the second.
	e := flowEvent(1, false, "", "", "203.0.113.7", "", "", 443)
	e.Kubernetes = nil
	e.CgroupID = 99
	m := flowModel(t, e)

	if len(m.nsFlowOrder) != 1 {
		t.Fatalf("got %d rollups, want one", len(m.nsFlowOrder))
	}
	key := m.nsFlowOrder[0]
	if !strings.HasPrefix(key, "(unattributed)") {
		t.Errorf("rollup key is %q, want the source marked unattributed", key)
	}
	if !strings.HasSuffix(key, "(outside the cluster)") {
		t.Errorf("rollup key is %q, want the destination marked as having left", key)
	}
	if got := m.filteredFlows()[0].Source; got != "cgroup:99" {
		t.Errorf("source is %q; an event with no attribution is grouped by cgroup, not dropped", got)
	}
}

func TestFlowsAreNotFrozenByPause(t *testing.T) {
	// Pause freezes the event list somebody is reading a line of. Returning to
	// a view that pretended the intervening minute did not happen would be a
	// lie about the cluster.
	m := flowModel(t, flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432))
	m.paused = true
	feed(m, flowEvent(2, true, "prod", "api", "203.0.113.7", "", "", 4444))

	if got := len(m.filteredFlows()); got != 2 {
		t.Errorf("got %d flows while paused, want the new one folded anyway", got)
	}
}

func TestFlowsAreBounded(t *testing.T) {
	// A port scan makes every refused address a new peer. The view that exists
	// to show an operator an attack must not be the thing that exhausts the
	// node's memory during one.
	m := sized(New(Options{Capacity: 64}), 100, 24)
	for i := 0; i < maxFlows+20; i++ {
		feed(m, flowEvent(1, true, "prod", "api", fmt.Sprintf("203.0.113.%d", i), "", "", uint16(1000+i)))
	}
	m.setView(ViewFlows)

	if got := len(m.flows); got != maxFlows {
		t.Errorf("tracking %d flows, want the cap of %d", got, maxFlows)
	}
	if m.flowsDropped != 20 {
		t.Errorf("dropped %d, want 20 counted rather than silently discarded", m.flowsDropped)
	}
}

func TestFlowPortsAreBounded(t *testing.T) {
	m := sized(New(Options{Capacity: 64}), 100, 24)
	for i := 0; i < maxPortsPerFlow+10; i++ {
		feed(m, flowEvent(1, true, "prod", "api", "10.0.9.9", "prod/scanned", "pod", uint16(1000+i)))
	}
	m.setView(ViewFlows)

	f := m.filteredFlows()[0]
	if len(f.Ports) != maxPortsPerFlow {
		t.Errorf("kept %d ports, want the cap of %d: a workload on four hundred ports is a scan, "+
			"and the count is the finding rather than the list", len(f.Ports), maxPortsPerFlow)
	}
	if f.Denied != maxPortsPerFlow+10 {
		t.Errorf("counted %d denials, want all %d even though the ports were capped",
			f.Denied, maxPortsPerFlow+10)
	}
}

func TestFlowsFilterOnIdentityAndPorts(t *testing.T) {
	m := flowModel(t,
		flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(2, false, "prod", "web", "10.0.1.6", "prod/api", "pod", 8080),
	)

	m.input.SetValue("5432")
	if got := len(m.filteredFlows()); got != 1 {
		t.Errorf("filtering on a port matched %d flows, want 1: a port is how somebody finds "+
			"every workload talking to a database", got)
	}
	m.input.SetValue("postgres")
	if got := len(m.filteredFlows()); got != 1 {
		t.Errorf("filtering on a peer name matched %d flows, want 1", got)
	}
	m.input.SetValue("nothing here")
	if got := len(m.filteredFlows()); got != 0 {
		t.Errorf("a filter matching nothing returned %d flows", got)
	}
}

func TestFlowsViewIsInTheTabOrderAndReachable(t *testing.T) {
	m := sized(New(Options{Capacity: 64}), 100, 24)
	found := false
	for i, v := range views {
		if v != ViewFlows {
			continue
		}
		found = true
		m.Update(keyMsg(fmt.Sprint(i + 1)))
		if m.view != ViewFlows {
			t.Errorf("the number key for position %d opened %s, not the flows view", i+1, m.view)
		}
	}
	if !found {
		t.Fatal("the flows view is not in the tab order, so nothing but a number key reaches it")
	}
	if !m.hasDetail() {
		t.Error("the flows view has a detail pane and must report one, or enter does nothing")
	}
	if got := ViewFlows.abbrev(); len(got) != 3 {
		t.Errorf("abbrev is %q; the narrow tab strip needs three letters like every other view", got)
	}
	if got := ViewFlows.short(); got != "flows" {
		t.Errorf("short is %q, want flows", got)
	}
}

func TestEveryViewHasANumberKey(t *testing.T) {
	// The jump binding is a list of literal keys, so adding a view without
	// adding its number leaves a tab that only tab reaches.
	keys := defaultKeys().Jump.Keys()
	if len(keys) != len(views) {
		t.Fatalf("%d number keys for %d views; the last view cannot be jumped to", len(keys), len(views))
	}
}

func TestFlowsRenderAndDegrade(t *testing.T) {
	events := []export.Event{
		flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432),
		flowEvent(2, true, "prod", "api", "203.0.113.7", "", "", 4444),
	}
	for _, size := range []struct{ w, h int }{
		{120, 40}, {100, 24}, {84, 24}, {72, 20}, {60, 12}, {40, 8}, {20, 5}, {8, 3}, {1, 1},
	} {
		m := sized(New(Options{Capacity: 64}), size.w, size.h)
		feed(m, events...)
		m.setView(ViewFlows)

		frame := m.View()
		lines := strings.Split(frame, "\n")
		if len(lines) != size.h {
			t.Errorf("%dx%d rendered %d lines, want exactly %d", size.w, size.h, len(lines), size.h)
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > size.w {
				t.Errorf("%dx%d line %d is %d cells wide, want at most %d", size.w, size.h, i, w, size.w)
			}
		}

		// The detail pane has to survive the same sizes, including the narrow
		// ones where it replaces the list rather than sitting beside it.
		m.focus = paneDetail
		frame = m.View()
		if len(strings.Split(frame, "\n")) != size.h {
			t.Errorf("%dx%d detail pane broke the frame height", size.w, size.h)
		}
	}
}

func TestFlowDetailExplainsThePeer(t *testing.T) {
	m := flowModel(t, flowEvent(1, true, "prod", "api", "203.0.113.7", "", "", 4444))
	got := m.flowDetail(60)

	for _, want := range []string{"prod/api", "203.0.113.7", "could not name it", "refused in-kernel"} {
		if !strings.Contains(got, want) {
			t.Errorf("the detail pane does not say %q:\n%s", want, got)
		}
	}
}

func TestFlowDetailOfNothing(t *testing.T) {
	m := sized(New(Options{Capacity: 64}), 100, 24)
	m.setView(ViewFlows)
	if got := m.flowDetail(40); !strings.Contains(got, "no network events yet") {
		t.Errorf("an empty flows view says %q; an empty table looks like a quiet cluster", got)
	}
	m.flowsDropped = 1
	if got := m.flowDetail(40); !strings.Contains(got, "no flow selected") {
		t.Errorf("with flows dropped but none selected the pane says %q", got)
	}
}

func TestFlowDetailReportsTheCaps(t *testing.T) {
	m := sized(New(Options{Capacity: 64}), 100, 24)
	for i := 0; i < maxPortsPerFlow+2; i++ {
		feed(m, flowEvent(1, true, "prod", "api", "10.0.9.9", "prod/scanned", "pod", uint16(1000+i)))
	}
	m.flowsDropped = 7
	m.setView(ViewFlows)

	got := m.flowDetail(70)
	if !strings.Contains(got, "per-flow limit") {
		t.Errorf("the detail pane does not say the port list was capped:\n%s", got)
	}
	if !strings.Contains(got, "7 further destinations") {
		t.Errorf("the detail pane does not say what was dropped:\n%s", got)
	}
}

func TestFlowDetailOfAnUnrefusedFlow(t *testing.T) {
	m := flowModel(t, flowEvent(1, false, "prod", "api", "10.0.1.5", "db/postgres", "service", 5432))
	got := m.flowDetail(60)

	if !strings.Contains(got, "1 connections, none refused") {
		t.Errorf("a clean flow reads %q; it must say so rather than leaving a blank", got)
	}
	if !strings.Contains(got, "1 allowed") {
		t.Errorf("an allowed port is not shown:\n%s", got)
	}
	if strings.Contains(got, "denied") {
		t.Errorf("a clean flow mentions denials:\n%s", got)
	}
}

func TestFlowPortsKeepProtocolsApart(t *testing.T) {
	// TCP/53 and UDP/53 are two observations. Folding them would make a
	// generated rule permit a protocol nobody watched.
	udp := flowEvent(1, false, "prod", "api", "10.96.0.10", "kube-system/kube-dns", "service", 53)
	udp.Network.Protocol = "UDP"
	m := flowModel(t,
		flowEvent(1, false, "prod", "api", "10.96.0.10", "kube-system/kube-dns", "service", 53),
		udp,
	)

	f := m.filteredFlows()[0]
	if len(f.Ports) != 2 {
		t.Fatalf("got %d ports, want TCP/53 and UDP/53 kept apart", len(f.Ports))
	}
	if f.Ports[0].Protocol != "tcp" || f.Ports[1].Protocol != "udp" {
		t.Errorf("ports are %v, want a stable order that does not move under the cursor", f.Ports)
	}
}

func TestNamespaceRollupIsBounded(t *testing.T) {
	// The coarse axis has no cap of its own: a namespace pair only appears by
	// way of an accepted flow, so the flow cap bounds it. This asserts that
	// derivation, because a change to the flow key could quietly break it.
	m := sized(New(Options{Capacity: 64}), 100, 24)
	for i := 0; i < maxFlows+5; i++ {
		feed(m, flowEvent(1, false, fmt.Sprintf("ns%d", i), "api", "10.0.0.1", "db/pg", "service", 5432))
	}
	if got := len(m.nsFlows); got != maxFlows {
		t.Errorf("tracking %d namespace pairs, want the cap of %d", got, maxFlows)
	}
}

func TestPeerKindNote(t *testing.T) {
	for kind, want := range map[string]string{
		"service":  "Service",
		"pod":      "Pod",
		"node":     "a node of this cluster",
		"loopback": "loopback",
		"external": "external - outside this cluster",
		"":         "unresolved - the cluster could not name it",
		"weird":    "weird",
	} {
		if got := peerKindNote(kind); got != want {
			t.Errorf("peerKindNote(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestPortsCell(t *testing.T) {
	if got := portsCell(nil); got != "-" {
		t.Errorf("a flow with no ports renders %q, want a dash rather than an empty cell", got)
	}
	got := portsCell([]FlowPort{{Port: 53}, {Port: 5432}})
	if got != "53,5432" {
		t.Errorf("ports render as %q, want a comma list that a narrow column can truncate", got)
	}
}

func TestNamespaceLinesWhenNothingIsFolded(t *testing.T) {
	m := sized(New(Options{Capacity: 64}), 100, 24)
	lines := m.namespaceLines(40)
	if len(lines) != 1 || !strings.Contains(lines[0], "nothing folded yet") {
		t.Errorf("an empty rollup renders %v", lines)
	}
}

func TestNamespaceLinesAreBoundedByThePane(t *testing.T) {
	// The frame is rebuilt on every arriving event. Rendering five hundred
	// pairs into a pane that shows twenty is the whole cost of the view.
	m := sized(New(Options{Capacity: 64}), 100, 24)
	for i := 0; i < nsLineLimit+9; i++ {
		feed(m, flowEvent(1, false, fmt.Sprintf("ns%03d", i), "api", "10.0.0.1", "db/pg", "service", 5432))
	}
	lines := m.namespaceLines(60)

	if len(lines) != nsLineLimit+1 {
		t.Fatalf("rendered %d lines, want %d pairs plus the count of the rest", len(lines), nsLineLimit)
	}
	if !strings.Contains(lines[len(lines)-1], "and 9 more namespace pair(s)") {
		t.Errorf("the last line is %q; what was left out has to be said, not dropped", lines[len(lines)-1])
	}
}

func TestFlowsIgnoreAnEventWithNoNetworkPayload(t *testing.T) {
	// A network-typed event with no payload is a malformed event, not a flow
	// to an address of zero.
	m := sized(New(Options{Capacity: 64}), 100, 24)
	e := ev(export.EventTypeNetwork, false, "curl", "prod", "Deployment", "api")
	e.Network = nil
	feed(m, e)

	if got := len(m.flows); got != 0 {
		t.Errorf("folded %d flows from an event with no network payload", got)
	}
}

// ---------------------------------------------------------------- benchmarks

func benchFlowEvents(n int) []export.Event {
	out := make([]export.Event, 0, n)
	for i := 0; i < n; i++ {
		denied := i%17 == 0
		out = append(out, flowEvent(i%60, denied, "prod", fmt.Sprintf("w%d", i%32),
			fmt.Sprintf("10.0.%d.%d", i%8, i%251), fmt.Sprintf("db/svc%d", i%16), "service",
			uint16(5000+i%12)))
	}
	return out
}

func BenchmarkFoldFlow(b *testing.B) {
	events := benchFlowEvents(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := New(Options{Capacity: 64})
		for _, e := range events {
			m.foldFlow(e)
		}
	}
}

func BenchmarkFlowsFrame(b *testing.B) {
	m := sized(New(Options{Capacity: 4096}), 120, 40)
	for _, e := range benchFlowEvents(4096) {
		m.Update(EventMsg{Event: e})
	}
	m.setView(ViewFlows)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

func BenchmarkFilteredFlows(b *testing.B) {
	m := sized(New(Options{Capacity: 4096}), 120, 40)
	for _, e := range benchFlowEvents(4096) {
		m.Update(EventMsg{Event: e})
	}
	m.setView(ViewFlows)
	m.input.SetValue("5432")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.filteredFlows()
	}
}

func BenchmarkFlowDetail(b *testing.B) {
	m := sized(New(Options{Capacity: 4096}), 120, 40)
	for _, e := range benchFlowEvents(2048) {
		m.Update(EventMsg{Event: e})
	}
	m.setView(ViewFlows)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.flowDetail(56)
	}
}
