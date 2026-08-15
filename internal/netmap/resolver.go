// Package netmap answers the question a raw network event cannot: what is
// 10.104.22.9?
//
// The kernel reports an address, because an address is what connect(2) was
// given. An operator reading a denial does not think in addresses. "Denied
// connect to 10.104.22.9:5432" is a line somebody has to go and look up before
// they can decide whether it matters; "denied connect to
// prod/postgres-primary:5432" is a line they can act on immediately, and the
// difference between those two is whether the alert gets investigated at 3am or
// muted.
//
// It is also the difference between two very different findings that look
// identical as addresses. A workload dialing an address inside the cluster
// that happens to be a Service it has no business using, and a workload
// dialing an address outside the cluster entirely, are not the same incident.
// Only the second is exfiltration. Without a map, both are "an IP".
//
// The map is built from what the agent already watches. Services carry their
// ClusterIP, pods carry their PodIP, nodes carry their addresses; none of this
// needs a DNS lookup, a PTR record, or a round trip to anything. That matters
// on the denial path: resolving a destination must not cost a network call, or
// a burst of denials becomes a burst of DNS traffic at exactly the wrong
// moment.
package netmap

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// Kind is what an address turned out to be.
type Kind string

const (
	// KindService is a Service ClusterIP, ExternalIP or LoadBalancer ingress.
	KindService Kind = "service"
	// KindPod is a pod address, reached directly rather than through a Service.
	// Worth distinguishing: a workload bypassing the Service is either a mesh
	// sidecar or something doing its own discovery, and both are notable.
	KindPod Kind = "pod"
	// KindNode is a node address. A pod dialing its own node is usually the
	// kubelet read-only port or a hostPort, both of which are worth seeing.
	KindNode Kind = "node"
	// KindLoopback is 127.0.0.0/8 or ::1 - a sidecar, or the workload talking
	// to itself.
	KindLoopback Kind = "loopback"
	// KindExternal is an address the cluster does not know. This is the one
	// that matters: a denied connect to an external address is the shape
	// exfiltration takes.
	KindExternal Kind = "external"
)

// Destination is what an address resolved to.
type Destination struct {
	Kind      Kind
	Namespace string
	Name      string
	// PortName is the Service port's name when the destination port matched
	// one. "postgres" reads better than 5432 and survives a port change.
	PortName string
}

// String renders the destination the way it should appear in an event.
func (d Destination) String() string {
	switch {
	case d.Name == "":
		return string(d.Kind)
	case d.Namespace == "":
		return d.Name
	default:
		return d.Namespace + "/" + d.Name
	}
}

// entry is one address the map knows about.
type entry struct {
	kind      Kind
	namespace string
	name      string
	// ports maps a port number to its Service port name, when the Service
	// named one.
	ports map[uint16]string
}

// Resolver maps addresses to what the cluster says they are.
//
// It is a snapshot rather than a live index into an informer cache: the lookup
// happens on the event path, where taking a lock another goroutine holds while
// walking a cache would put back pressure on the ring-buffer reader. Rebuilding
// wholesale and swapping the map costs one allocation per refresh and makes the
// read path a plain map lookup under a read lock.
type Resolver struct {
	mu sync.RWMutex
	// byAddr is keyed by the parsed address rather than by its string form, so
	// a lookup does not allocate and "10.0.0.1" and "10.0.0.001" cannot
	// disagree.
	byAddr map[netip.Addr]entry
}

// New returns an empty resolver. Everything is external until it is populated,
// which is the safe default: an unknown address reported as external is
// accurate, while one reported as a Service would be a lie.
func New() *Resolver {
	return &Resolver{byAddr: map[netip.Addr]entry{}}
}

// Lookup resolves one destination.
//
// The bool reports whether the address was known. A caller that wants to
// annotate an event should use the Destination either way: an unknown address
// resolves to KindExternal, which is itself the most interesting answer.
func (r *Resolver) Lookup(ip net.IP, port uint16) (Destination, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Destination{Kind: KindExternal}, false
	}
	// An IPv4 address arriving as a 16-byte slice is the same address; without
	// unmapping, every v4 lookup through a v6-shaped slice would miss.
	addr = addr.Unmap()

	if addr.IsLoopback() {
		return Destination{Kind: KindLoopback}, true
	}

	r.mu.RLock()
	e, found := r.byAddr[addr]
	r.mu.RUnlock()
	if !found {
		return Destination{Kind: KindExternal}, false
	}

	d := Destination{Kind: e.kind, Namespace: e.namespace, Name: e.name}
	if name, ok := e.ports[port]; ok {
		d.PortName = name
	}
	return d, true
}

// Snapshot is the cluster state a refresh is built from. Taking it as plain
// slices rather than as a client keeps this package testable without a fake API
// server, and keeps the informer wiring in the one place that already has it.
type Snapshot struct {
	Services []corev1.Service
	Pods     []corev1.Pod
	Nodes    []corev1.Node
}

// Refresh rebuilds the map.
//
// Ordering matters and is deliberate: nodes first, then pods, then services.
// A Service ClusterIP never collides with a pod address, but a hostNetwork pod
// carries its node's address, and reporting that as the pod is more useful than
// reporting it as the node - the pod is what is running. Services last for the
// same reason: an ExternalIP that is also a node address is more meaningfully
// the Service.
func (r *Resolver) Refresh(s Snapshot) {
	next := make(map[netip.Addr]entry,
		len(s.Services)+len(s.Pods)+len(s.Nodes))

	add := func(raw string, e entry) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !addr.IsValid() {
			return
		}
		next[addr.Unmap()] = e
	}

	for i := range s.Nodes {
		n := &s.Nodes[i]
		for _, a := range n.Status.Addresses {
			switch a.Type {
			case corev1.NodeInternalIP, corev1.NodeExternalIP:
				add(a.Address, entry{kind: KindNode, name: n.Name})
			}
		}
	}

	for i := range s.Pods {
		p := &s.Pods[i]
		e := entry{kind: KindPod, namespace: p.Namespace, name: p.Name}
		add(p.Status.PodIP, e)
		for _, ip := range p.Status.PodIPs {
			add(ip.IP, e)
		}
	}

	for i := range s.Services {
		svc := &s.Services[i]
		e := entry{
			kind:      KindService,
			namespace: svc.Namespace,
			name:      svc.Name,
			ports:     servicePortNames(svc),
		}
		for _, ip := range svc.Spec.ClusterIPs {
			// "None" is a headless Service. It has no address of its own, and
			// treating the literal string as one would put a junk key in the
			// map. Its pods are indexed above, which is the right answer for a
			// headless Service anyway.
			if ip == "" || ip == corev1.ClusterIPNone {
				continue
			}
			add(ip, e)
		}
		if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
			add(svc.Spec.ClusterIP, e)
		}
		for _, ip := range svc.Spec.ExternalIPs {
			add(ip, e)
		}
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.IP != "" {
				add(ing.IP, e)
			}
		}
	}

	r.mu.Lock()
	r.byAddr = next
	r.mu.Unlock()
}

// servicePortNames indexes a Service's named ports by number.
//
// Only named ports are indexed. An unnamed port has nothing better to report
// than the number the caller already has.
func servicePortNames(svc *corev1.Service) map[uint16]string {
	var out map[uint16]string
	for _, p := range svc.Spec.Ports {
		if p.Name == "" || p.Port <= 0 || p.Port > 65535 {
			continue
		}
		if out == nil {
			out = make(map[uint16]string, len(svc.Spec.Ports))
		}
		out[uint16(p.Port)] = p.Name
	}
	return out
}

// Size reports how many addresses are known, for the agent's log line and for
// a metric. A map that is unexpectedly empty is the failure this catches: the
// informers not being synced yet looks exactly like a cluster where every
// destination is external.
func (r *Resolver) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byAddr)
}

// Addresses returns the known addresses in sorted order. For `pahlevan debug`,
// where the question is "why is this destination being reported as external".
func (r *Resolver) Addresses() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.byAddr))
	for a := range r.byAddr {
		out = append(out, a.String())
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}
