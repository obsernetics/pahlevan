// Package netpol turns an observed network baseline into a Kubernetes
// NetworkPolicy, and refuses to write down more than was observed.
//
// A learned baseline is a list of addresses a workload was seen talking to.
// A NetworkPolicy is a list of label selectors. Getting from one to the other
// is not a rendering step: it is an inference, and every place the inference
// can go wrong makes the policy either broader than the evidence, which is a
// security claim nobody checked, or narrower than reality, which takes the
// workload down.
//
// The three ways it goes wrong, and what this package does about each:
//
//   - An address that resolves to nothing cannot become a selector. It becomes
//     an ipBlock, or it is reported. It never becomes a namespaceSelector
//     inferred from a subnet, because a subnet is not an identity.
//   - A label set derived from the pods that were observed will, in a real
//     namespace, often also select pods that were not. A rule built on it
//     permits traffic nobody watched. Selector refuses to emit such a set and
//     names the pods that made it unsafe.
//   - A baseline only contains what happened during the learning window. A
//     policy generated from it denies everything rarer than that window is
//     long. Generate carries pkg/cycle's verdict per subject so the report can
//     say which workloads have a period nobody waited for.
//
// Nothing here talks to a cluster. The inputs are plain structs, which is what
// makes the inference testable against the cases that matter.
package netpol

import "sort"

// PeerKind names what a destination address turned out to be.
//
// It mirrors pkg/netidentity's own PeerKind. The duplication is deliberate:
// this package has to be usable, and testable, without an IP-to-identity index
// and the informers one needs, so it declares the contract it depends on
// rather than importing an implementation of it.
type PeerKind string

const (
	// PeerPod is a pod address, which is the only kind that can become a
	// podSelector naming a workload.
	PeerPod PeerKind = "Pod"
	// PeerService is a Service address. A NetworkPolicy cannot name a
	// Service, so this becomes a selector over the pods behind it.
	PeerService PeerKind = "Service"
	// PeerNode is a node address. NetworkPolicy has no node selector, so this
	// can only ever be an ipBlock.
	PeerNode PeerKind = "Node"
	// PeerExternal is an address the cluster does not know. It becomes an
	// ipBlock or it is reported; it never becomes a selector.
	PeerExternal PeerKind = "External"
)

// Peer is a destination address resolved to a Kubernetes identity. The fields
// match pkg/netidentity.Peer exactly.
type Peer struct {
	Kind      PeerKind
	Namespace string
	Name      string
	Workload  string
	Labels    map[string]string
}

// Resolver maps a destination IP to a Kubernetes identity.
//
// This is the whole of what this package needs from an identity index, stated
// as an interface so the generator can be driven from a fake and so
// pkg/netidentity can satisfy it with a small adapter rather than this package
// taking a dependency on informers.
type Resolver interface {
	// Lookup reports the identity of an address. The boolean is false when
	// the address resolved to nothing at all, which is a different answer
	// from PeerExternal: external means the index looked and decided the
	// address is outside the cluster, false means it does not know. Both end
	// up as an ipBlock, and only one of them is a finding worth reading.
	Lookup(ip string) (Peer, bool)
}

// Pod is one pod of the cluster, as the roster sees it.
type Pod struct {
	Namespace string
	Name      string
	// IP is the pod address, used only by RosterResolver.
	IP string
	// Workload is the owning controller, spelled "Deployment/web". Two pods
	// of the same workload are interchangeable to a policy: traffic to one
	// replica is traffic to the workload, and a selector naming a single
	// replica would be wrong the moment it was rescheduled.
	Workload string
	Labels   map[string]string
}

// Key identifies a pod within its namespace.
func (p Pod) Key() string { return p.Namespace + "/" + p.Name }

// Roster is every pod the generator is allowed to reason about.
//
// It is the evidence for the one question that makes a generated selector
// honest: which pods would this label set select that were never observed? A
// generator handed no roster cannot answer it, so it emits no selector at all
// rather than guessing - see Generate.
type Roster []Pod

// InNamespace returns the roster's pods in one namespace, in name order.
func (r Roster) InNamespace(ns string) []Pod {
	out := make([]Pod, 0, len(r))
	for _, p := range r {
		if p.Namespace == ns {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// WorkloadPods returns every pod of one workload, which is the unit a peer
// selector is allowed to name. An empty workload matches nothing: a pod whose
// owner could not be determined is not evidence about any workload.
func (r Roster) WorkloadPods(ns, workload string) []Pod {
	if workload == "" {
		return nil
	}
	out := make([]Pod, 0, 8)
	for _, p := range r.InNamespace(ns) {
		if p.Workload == workload {
			out = append(out, p)
		}
	}
	return out
}

// Named returns one pod by namespace and name.
func (r Roster) Named(ns, name string) (Pod, bool) {
	for _, p := range r {
		if p.Namespace == ns && p.Name == name {
			return p, true
		}
	}
	return Pod{}, false
}

// rosterIndex is the roster with its three lookups precomputed.
//
// Generate asks the roster the same questions once per subject and once per
// peer, and each of Roster's methods walks and sorts the whole listing. On a
// cluster of a few hundred pods that turned the generator into a sort
// benchmark: the index is built once and every question after that is a map
// lookup.
type rosterIndex struct {
	byNS       map[string][]Pod
	byWorkload map[string][]Pod
	byName     map[string]Pod
	// cache memoises workloadSelector. Every subject that talks to the same
	// workload asks the same question about it, and the answer costs a scan of
	// the whole namespace.
	cache map[string]resolvedWorkload
}

// resolvedWorkload is a workload's pods and the checked selector naming them.
type resolvedWorkload struct {
	pods []Pod
	sel  Selector
}

func newRosterIndex(r Roster) *rosterIndex {
	x := &rosterIndex{
		byNS:       make(map[string][]Pod),
		byWorkload: make(map[string][]Pod),
		byName:     make(map[string]Pod, len(r)),
		cache:      make(map[string]resolvedWorkload),
	}
	for _, ns := range namespacesOf(r) {
		pods := r.InNamespace(ns)
		x.byNS[ns] = pods
		for _, p := range pods {
			x.byName[p.Key()] = p
			if p.Workload != "" {
				key := ns + "/" + p.Workload
				x.byWorkload[key] = append(x.byWorkload[key], p)
			}
		}
	}
	return x
}

func namespacesOf(r Roster) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r {
		if !seen[p.Namespace] {
			seen[p.Namespace] = true
			out = append(out, p.Namespace)
		}
	}
	sort.Strings(out)
	return out
}

func (x *rosterIndex) inNamespace(ns string) []Pod { return x.byNS[ns] }

func (x *rosterIndex) workloadPods(ns, workload string) []Pod {
	if workload == "" {
		return nil
	}
	return x.byWorkload[ns+"/"+workload]
}

func (x *rosterIndex) named(ns, name string) (Pod, bool) {
	p, ok := x.byName[ns+"/"+name]
	return p, ok
}

// workloadSelector names one workload's pods and derives a selector checked
// against the rest of the namespace. An empty pod list means the roster has
// never heard of the workload, and the Selector is then unusable by
// construction.
func (x *rosterIndex) workloadSelector(ns, workload string) ([]Pod, Selector) {
	key := ns + "/" + workload
	if r, ok := x.cache[key]; ok {
		return r.pods, r.sel
	}
	r := resolvedWorkload{pods: x.workloadPods(ns, workload)}
	if len(r.pods) > 0 {
		r.sel = selectorFor(r.pods, x.inNamespace(ns))
	}
	x.cache[key] = r
	return r.pods, r.sel
}

// RosterResolver resolves pod addresses from a pod listing.
//
// It is deliberately the least capable Resolver that is still true: it knows
// only what a pod listing already said, so it resolves pod addresses and
// nothing else. A Service ClusterIP, a node address and an internet address
// all come back unresolved, which is the honest answer from this input and
// which the generator turns into an ipBlock plus a finding rather than into a
// selector it cannot justify.
//
// pkg/netidentity is the real index. This exists so the command is useful
// before that lands, and afterwards as the fallback when the index is cold.
type RosterResolver struct {
	byIP map[string]Peer
}

// NewRosterResolver indexes a roster by pod IP.
func NewRosterResolver(r Roster) *RosterResolver {
	byIP := make(map[string]Peer, len(r))
	for _, p := range r {
		if p.IP == "" {
			continue
		}
		// First writer wins. Two pods reported with the same address means the
		// listing is stale - a terminated pod's address already reassigned -
		// and taking the later one would attribute traffic to whichever pod
		// the API server happened to return second.
		if _, seen := byIP[p.IP]; seen {
			continue
		}
		byIP[p.IP] = Peer{
			Kind:      PeerPod,
			Namespace: p.Namespace,
			Name:      p.Name,
			Workload:  p.Workload,
			Labels:    p.Labels,
		}
	}
	return &RosterResolver{byIP: byIP}
}

// Lookup satisfies Resolver.
func (r *RosterResolver) Lookup(ip string) (Peer, bool) {
	if r == nil {
		return Peer{}, false
	}
	p, ok := r.byIP[ip]
	return p, ok
}
