package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// The flows view answers the question the events view cannot.
//
// The events view is a tail: one line per connection, newest first, scrolling
// away at the rate the node generates them. It is the right shape for "what is
// happening right now" and the wrong one for "who talks to whom", which is the
// question anybody asks before they write a NetworkPolicy. Reading a thousand
// lines and folding them into a picture of the cluster is work the console
// should have done.
//
// So this folds the same stream by identity. Two axes, because a person needs
// both: namespace to namespace is the shape of the cluster, and workload to
// workload with ports is the thing you can turn into a rule. Denied flows are
// marked in the list rather than filtered into their own view, because a denied
// flow is only meaningful next to the allowed ones it sits between.
//
// Nothing here resolves an address. The agents already did: an event carries
// the identity the cluster gave the destination, so the console folds what it
// was told rather than inventing an index of its own.

// Flow is everything observed between one workload and one peer identity.
type Flow struct {
	Key string

	// Source is the workload that made the connections, as a person reads it.
	Source string
	// SourceNamespace is kept apart for the namespace rollup, which cannot be
	// recovered from Source once a workload has no namespace.
	SourceNamespace string

	// Peer is what the cluster called the destination: "prod/postgres", a node
	// name, or the bare address when nothing knew it. PeerKind is the agent's
	// word for what it is - service, pod, node, external - and is empty when
	// the address resolved to nothing, which is a different finding.
	Peer            string
	PeerKind        string
	PeerNamespace   string
	Ports           []FlowPort
	Allowed, Denied int
	LastSeen        time.Time
}

// FlowPort is one destination port and how it went.
type FlowPort struct {
	Port            uint16
	Protocol        string
	Allowed, Denied int
}

// NamespaceFlow is the same traffic folded to the coarser axis.
type NamespaceFlow struct {
	Key             string
	Source          string
	Peer            string
	Allowed, Denied int
}

// maxFlows bounds the number of distinct workload-to-peer pairs kept.
//
// A cluster has a bounded number of these. A port scan does not: every refused
// address is a new peer, and the view that exists to show an operator an attack
// must not be the thing that exhausts the node's memory during one. Past the
// cap new pairs are counted and dropped, and the status line says how many,
// exactly as the event ring reports what rolled off.
const maxFlows = 512

// maxPortsPerFlow bounds the per-pair port list for the same reason. A
// workload talking to one peer on four hundred ports is a scan, not a
// baseline, and the count is the finding rather than the list.
const maxPortsPerFlow = 24

// foldFlow folds one network event into both axes.
//
// Unlike the event ring this is not frozen by pause: pausing freezes the list
// a person is reading a line of, and returning to a view that pretended the
// intervening minute did not happen would be a lie about the cluster.
func (m *Model) foldFlow(e export.Event) {
	n := e.Network
	if n == nil {
		return
	}

	src, srcNS := flowSource(e)
	peer, peerKind, peerNS := flowPeer(n)
	key := src + " → " + peer

	f, ok := m.flows[key]
	if !ok {
		if len(m.flows) >= maxFlows {
			m.flowsDropped++
			return
		}
		f = &Flow{
			Key: key, Source: src, SourceNamespace: srcNS,
			Peer: peer, PeerKind: peerKind, PeerNamespace: peerNS,
		}
		m.flows[key] = f
		m.flowOrder = append(m.flowOrder, key)
		sort.Strings(m.flowOrder)
	}
	denied := e.Denied()
	if denied {
		f.Denied++
	} else {
		f.Allowed++
	}
	f.addPort(n.DestinationPort, n.Protocol, denied)
	f.LastSeen = e.Timestamp.Time()

	m.foldNamespaceFlow(srcNS, peerNS, peerKind, denied)
}

// addPort records one port, or the fact that there were too many to record.
func (f *Flow) addPort(port uint16, protocol string, denied bool) {
	proto := strings.ToLower(protocol)
	for i := range f.Ports {
		if f.Ports[i].Port == port && f.Ports[i].Protocol == proto {
			if denied {
				f.Ports[i].Denied++
			} else {
				f.Ports[i].Allowed++
			}
			return
		}
	}
	if len(f.Ports) >= maxPortsPerFlow {
		return
	}
	p := FlowPort{Port: port, Protocol: proto}
	if denied {
		p.Denied = 1
	} else {
		p.Allowed = 1
	}
	f.Ports = append(f.Ports, p)
	sort.Slice(f.Ports, func(i, j int) bool {
		if f.Ports[i].Port != f.Ports[j].Port {
			return f.Ports[i].Port < f.Ports[j].Port
		}
		return f.Ports[i].Protocol < f.Ports[j].Protocol
	})
}

func (m *Model) foldNamespaceFlow(srcNS, peerNS, peerKind string, denied bool) {
	src := orUnattributed(srcNS)
	dst := peerNS
	if dst == "" {
		// A destination with no namespace is not in the cluster. Calling it
		// "unattributed" like an unknown source would merge two different
		// things: traffic Pahlevan could not attribute, and traffic that
		// genuinely left.
		dst = "(outside the cluster)"
		if peerKind == "node" {
			dst = "(nodes)"
		}
	}
	key := src + " → " + dst
	f, ok := m.nsFlows[key]
	if !ok {
		// No cap of its own. A namespace pair only appears here by way of a
		// flow that was accepted, and a flow's key contains its source
		// namespace, so this map can never hold more entries than the flow
		// table does. A second cap would be a second thing to keep in step
		// with the first, guarding nothing.
		f = &NamespaceFlow{Key: key, Source: src, Peer: dst}
		m.nsFlows[key] = f
		m.nsFlowOrder = append(m.nsFlowOrder, key)
		sort.Strings(m.nsFlowOrder)
	}
	if denied {
		f.Denied++
	} else {
		f.Allowed++
	}
}

// flowSource names the workload an event came from, and its namespace.
func flowSource(e export.Event) (string, string) {
	k := e.Kubernetes
	if k == nil {
		return workloadKey(e), ""
	}
	return eventWorkload(e), k.Namespace
}

// flowPeer names the destination. The agents resolve addresses to identities
// and put the answer on the event, so this reads it rather than guessing: an
// address the cluster could not name stays an address, which is the finding.
func flowPeer(n *export.NetworkInfo) (peer, kind, namespace string) {
	kind = strings.ToLower(n.DestinationKind)
	peer = n.DestinationName
	if peer == "" {
		return n.DestinationIP, kind, ""
	}
	if i := strings.IndexByte(peer, '/'); i > 0 {
		namespace = peer[:i]
	}
	return peer, kind, namespace
}

func orUnattributed(ns string) string {
	if ns == "" {
		return "(unattributed)"
	}
	return ns
}

// filteredFlows returns the flows matching the filter, in a stable order.
//
// Stable rather than sorted by denial count: a list that reorders itself as
// events arrive moves rows out from under the cursor, and the cursor is how
// somebody reads a detail pane.
func (m *Model) filteredFlows() []*Flow {
	needle := strings.ToLower(m.filterText())
	out := make([]*Flow, 0, len(m.flowOrder))
	for _, k := range m.flowOrder {
		f := m.flows[k]
		if needle != "" && !strings.Contains(strings.ToLower(flowHaystack(f)), needle) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// flowHaystack is what the filter matches: the identities and the ports, so
// "/5432" finds every workload talking to a database.
func flowHaystack(f *Flow) string {
	var b strings.Builder
	b.WriteString(f.Key)
	b.WriteByte(' ')
	b.WriteString(f.PeerKind)
	for _, p := range f.Ports {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(int(p.Port)))
		b.WriteByte(' ')
		b.WriteString(p.Protocol)
	}
	return b.String()
}

// ------------------------------------------------------------------- panes

func (m *Model) flowsBody(w, h int) string {
	specs := []colSpec{
		{title: "SOURCE", min: 12, max: 34, weight: 3, prio: 0},
		{title: "PEER", min: 12, max: 34, weight: 3, prio: 1},
		{title: "KIND", min: 4, weight: 0, prio: 4},
		{title: "PORTS", min: 5, weight: 1, prio: 2},
		{title: "CONNS", min: 5, weight: 0, prio: 5},
		{title: "DENIED", min: 6, weight: 0, prio: 3},
	}
	rows := func(start, end int) []table.Row {
		items := m.filteredFlows()
		out := make([]table.Row, 0, end-start)
		for _, f := range items[start:end] {
			out = append(out, table.Row{
				f.Source, f.Peer, orDash(f.PeerKind), portsCell(f.Ports),
				strconv.Itoa(f.Allowed + f.Denied), deniedCell(f.Denied),
			})
		}
		return out
	}
	return m.splitBody("flows", specs, rows, "no network events yet",
		"flow", m.flowDetail, w, h)
}

// portsCell renders a flow's ports for a column that may be narrow. The cell
// is plain text because bubbles' table truncates by byte and would cut a
// colour escape in half.
func portsCell(ports []FlowPort) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(int(p.Port)))
	}
	return strings.Join(parts, ",")
}

// deniedCell marks a refused flow in the list. The glyph carries it rather
// than colour, for the same truncation reason, and it is the same mark the
// events view uses for a denial.
func deniedCell(n int) string {
	if n == 0 {
		return "-"
	}
	return "✖ " + strconv.Itoa(n)
}

func (m *Model) selectedFlow() *Flow {
	items := m.filteredFlows()
	i := m.cursor()
	if i < 0 || i >= len(items) {
		return nil
	}
	return items[i]
}

func (m *Model) flowDetail(w int) string {
	f := m.selectedFlow()
	if f == nil {
		if m.flowsDropped > 0 {
			return styleDim.Render("no flow selected")
		}
		return styleDim.Render("no network events yet")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", styleHeader.Render(truncate(f.Source, w)))
	b.WriteString(styleDim.Render(truncate("  → "+f.Peer, w)) + "\n")
	b.WriteString(kv("peer kind", peerKindNote(f.PeerKind), w))
	if !f.LastSeen.IsZero() {
		b.WriteString(kv("last seen", f.LastSeen.Format("15:04:05"), w))
	}

	b.WriteString("\n" + styleDim.Render("PORTS") + "\n")
	for _, p := range f.Ports {
		line := fmt.Sprintf("  %-6d %-4s %d allowed", p.Port, orDash(p.Protocol), p.Allowed)
		if p.Denied > 0 {
			b.WriteString(truncate(line, max(1, w-2)) + " " + styleDeny.Render(strconv.Itoa(p.Denied)+" denied") + "\n")
			continue
		}
		b.WriteString(truncate(line, max(1, w)) + "\n")
	}
	if len(f.Ports) >= maxPortsPerFlow {
		b.WriteString("  " + styleWarn.Render(fmt.Sprintf(
			"%d ports is the per-flow limit; more were seen and are not listed", maxPortsPerFlow)) + "\n")
	}

	b.WriteByte('\n')
	if f.Denied == 0 {
		b.WriteString(styleAllow.Render(fmt.Sprintf("%d connections, none refused", f.Allowed)) + "\n")
	} else {
		b.WriteString(styleDeny.Render(fmt.Sprintf("%d of %d connections refused in-kernel",
			f.Denied, f.Allowed+f.Denied)) + "\n")
	}

	b.WriteString("\n" + styleDim.Render("NAMESPACE TO NAMESPACE") + "\n")
	for _, line := range m.namespaceLines(w) {
		b.WriteString(line + "\n")
	}
	if m.flowsDropped > 0 {
		b.WriteString("\n" + styleWarn.Render(wrap(fmt.Sprintf(
			"%d further destinations were seen and are not tracked: past %d distinct pairs this view stops "+
				"growing, because a port scan would otherwise make it unbounded.",
			m.flowsDropped, maxFlows), w)) + "\n")
	}
	return b.String()
}

// nsLineLimit bounds the namespace rollup drawn in the detail pane.
//
// The pane is twenty-odd rows and the frame is rebuilt on every arriving
// event, so rendering five hundred pairs to show twenty of them is the whole
// cost of the view. A real cluster has fewer pairs than this; one that has
// more is being scanned, and the count is the finding rather than the list.
const nsLineLimit = 24

// namespaceLines renders the coarse axis: which namespace talks to which, and
// how much of it was refused.
func (m *Model) namespaceLines(w int) []string {
	if len(m.nsFlowOrder) == 0 {
		return []string{"  " + styleDim.Render("nothing folded yet")}
	}
	shown := m.nsFlowOrder
	if len(shown) > nsLineLimit {
		shown = shown[:nsLineLimit]
	}
	out := make([]string, 0, len(shown)+1)
	for _, k := range shown {
		f := m.nsFlows[k]
		line := fmt.Sprintf("  %s  %d", f.Key, f.Allowed+f.Denied)
		if f.Denied > 0 {
			out = append(out, truncate(line, max(1, w-10))+" "+styleDeny.Render("✖ "+strconv.Itoa(f.Denied)))
			continue
		}
		out = append(out, truncate(line, max(1, w)))
	}
	if rest := len(m.nsFlowOrder) - len(shown); rest > 0 {
		out = append(out, "  "+styleDim.Render(fmt.Sprintf("and %d more namespace pair(s)", rest)))
	}
	return out
}

// peerKindNote spells out what the agent decided the destination was. The
// distinction that matters is the last one: a connection to an address the
// cluster cannot name is the shape exfiltration takes.
func peerKindNote(kind string) string {
	switch kind {
	case "service":
		return "Service"
	case "pod":
		return "Pod"
	case "node":
		return "a node of this cluster"
	case "loopback":
		return "loopback"
	case "external":
		return "external - outside this cluster"
	case "":
		return "unresolved - the cluster could not name it"
	default:
		return kind
	}
}
