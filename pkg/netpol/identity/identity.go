// Package identity resolves a learned destination address to the Kubernetes
// identity behind it, in the form pkg/netpol takes.
//
// pkg/netpol states what it needs from an identity index as an interface and
// deliberately imports no implementation of one, so the generator can be
// tested against a table rather than against informers. pkg/netidentity is the
// index. This package is the join, and it exists because three decisions
// belong to neither side alone.
//
//   - A Service's rule is written from its spec.Selector, never from the
//     Service's own labels. pkg/netidentity carries a Service's metadata
//     labels, because that is what identifies the Service; pkg/netpol writes a
//     peer's labels straight into a podSelector. The two sets are not the same
//     set and are not even the same kind of thing, so passing the labels
//     through would emit a podSelector over whatever pods happen to carry the
//     Service's labels - not the pods behind the Service, and bounded by
//     nothing the traffic showed. A Service with no selector resolves with no
//     labels, which is what makes pkg/netpol refuse it rather than guess.
//
//   - A pod peer's workload is spelled the way the roster spells it, and is
//     taken from the roster rather than derived a second time.
//     pkg/netidentity records a workload by name, because that is what a
//     learned peer is reported as; pkg/netpol looks a workload up in the
//     roster, where it is "Deployment/web". A peer whose workload the roster
//     cannot find falls back to the single pod the address resolved to, and a
//     selector derived from one replica of a workload also selects its
//     siblings - which the generator correctly refuses, dropping a flow that
//     was observed. Resolving and the roster have to agree, so they agree by
//     construction.
//
//   - A node peer carries no labels at all. Node labels are real and a
//     NetworkPolicy has nowhere to put them: there is no node selector, so the
//     only honest rule is a literal address. Handing the labels over would
//     invite a podSelector built from a node's labels, which would select
//     whatever pods share them.
//
//   - An address the index does not hold is reported as external only when its
//     place in the address space says it cannot be a cluster address: a
//     globally routable address, or a cloud metadata endpoint. A private
//     address, a CGNAT address or a link-local one may well be a pod the
//     listing did not cover, so it stays unresolved. Both answers end up as an
//     ipBlock and neither widens the policy; the difference is whether the
//     report tells the reviewer something true.
//
// Nothing here widens what pkg/netpol emits. A peer that becomes resolvable
// either turns a literal address into a selector over the pods that address
// routed to, or keeps the literal address and gains a finding that names it.
package identity

import (
	"net/netip"

	corev1 "k8s.io/api/core/v1"

	"github.com/obsernetics/pahlevan/pkg/netidentity"
	"github.com/obsernetics/pahlevan/pkg/netname"
	"github.com/obsernetics/pahlevan/pkg/netpol"
)

// Resolver adapts a pkg/netidentity index to pkg/netpol's Resolver.
type Resolver struct {
	idx netidentity.Index
	// selectors is each Service's spec.Selector, keyed "namespace/name". A
	// Service absent from it has no selector, which is a different answer from
	// an empty one and is the answer pkg/netpol refuses on.
	selectors map[string]map[string]string
	// workloads is each roster pod's owning workload, keyed "namespace/name"
	// and spelled the way the roster spells it.
	workloads map[string]string
}

var _ netpol.Resolver = (*Resolver)(nil)

// New builds a Resolver over a snapshot of cluster state and the roster the
// generator will be run with.
//
// A snapshot rather than a watch-fed index, because the caller is a CLI that
// lists once and prints: there is no window in which an address could be
// rebound under it. The agent's live Store is the other shape this adapter
// could take and has no use for one - it learns identities on the event path,
// where a snapshot would be exactly the staleness pkg/netidentity exists to
// avoid.
//
// The roster is not a second opinion about the pods. It is the only opinion
// that matters, because it is what the generator checks a selector against: a
// pod resolved here that the roster does not hold produces no rule at all, so
// an index reaching further than the roster would turn rules that were literal
// addresses into nothing, which is narrower than the evidence. Pass the pods
// the roster was built from.
func New(snap netidentity.Snapshot, roster netpol.Roster) *Resolver {
	store := netidentity.New(netidentity.Options{})
	store.Sync(snap)
	r := &Resolver{
		idx:       store,
		selectors: make(map[string]map[string]string, len(snap.Services)),
		workloads: make(map[string]string, len(roster)),
	}
	for i := range snap.Services {
		svc := &snap.Services[i]
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		r.selectors[svc.Namespace+"/"+svc.Name] = copyLabels(svc.Spec.Selector)
	}
	for _, p := range roster {
		if p.Workload == "" {
			continue
		}
		r.workloads[p.Key()] = p.Workload
	}
	return r
}

// Snapshot pairs a pod, Service and node listing for New.
//
// It is here rather than at the call site because the pairing it names is this
// package's rule and not the caller's: the pods handed to the index are the
// pods the roster is built from.
func Snapshot(pods []corev1.Pod, services []corev1.Service, nodes []corev1.Node) netidentity.Snapshot {
	return netidentity.Snapshot{Pods: pods, Services: services, Nodes: nodes}
}

// Lookup satisfies netpol.Resolver.
//
// The bool keeps pkg/netpol's distinction: false means this resolver does not
// know what the address is, which is not the same statement as "the address is
// outside the cluster" and does not read the same way in a report.
func (r *Resolver) Lookup(ip string) (netpol.Peer, bool) {
	if r == nil || r.idx == nil {
		return netpol.Peer{}, false
	}
	addr, ok := netidentity.ParseAddr(ip)
	if !ok {
		// An address that does not parse is not an address. Classifying it
		// anyway would put a finding in the report about a destination nothing
		// can have been observed reaching.
		return netpol.Peer{}, false
	}
	if p, known := r.idx.Lookup(addr); known {
		return r.indexed(p), true
	}
	return unindexed(addr)
}

// indexed converts an identity the index holds.
func (r *Resolver) indexed(p netidentity.Peer) netpol.Peer {
	out := netpol.Peer{Namespace: p.Namespace, Name: p.Name}
	switch p.Kind {
	case netidentity.PeerPod:
		// The workload as the roster spells it, not as the index records it.
		// The labels are the pod's own: pkg/netpol does not build a peer
		// selector out of them - it derives one from the roster and checks it
		// against the rest of the namespace - so they are carried for
		// faithfulness rather than used.
		out.Kind = netpol.PeerPod
		out.Workload = r.workloads[p.Namespace+"/"+p.Name]
		out.Labels = copyLabels(p.Labels)
	case netidentity.PeerService:
		// The Service's selector, or nothing. See the package comment. Copied,
		// because the caller writes a peer's labels into a manifest and must
		// not be handed the table this resolver answers every lookup from.
		out.Kind = netpol.PeerService
		out.Labels = copyLabels(r.selectors[p.Namespace+"/"+p.Name])
	case netidentity.PeerNode:
		out.Kind = netpol.PeerNode
	default:
		// Including PeerExternal, and including a kind this package has never
		// heard of: anything unrecognized becomes the kind that can only be an
		// ipBlock, never one that can become a selector.
		out.Kind = netpol.PeerExternal
	}
	return out
}

// unindexed answers for an address no indexed object holds.
//
// Only two classes are external on this evidence. A globally routable address
// is not a pod, Service or node address in a cluster that works - those come
// out of private space, and a node's own public address is indexed as the
// node. A metadata endpoint is a fixed address belonging to the cloud provider
// and is the single most valuable destination in a baseline to see named.
//
// Everything else is left unresolved on purpose. A private or CGNAT address
// may be a pod in a namespace the listing did not cover, and reporting that as
// "outside the cluster" would be a false statement in the report for the exact
// case an operator is most likely to be reading. Loopback, multicast,
// broadcast and the unspecified address are not peers at all.
func unindexed(addr netip.Addr) (netpol.Peer, bool) {
	switch class := netname.Classify(addr); class {
	case netname.ClassPublic:
		// No name: "public 203.0.113.7" tells a reader nothing the address
		// does not, and pkg/netpol words an unnamed external peer for itself.
		return netpol.Peer{Kind: netpol.PeerExternal}, true
	case netname.ClassMetadata:
		return netpol.Peer{Kind: netpol.PeerExternal, Name: class.Label()}, true
	default:
		return netpol.Peer{}, false
	}
}

func copyLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
