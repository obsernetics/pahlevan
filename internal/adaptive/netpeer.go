package adaptive

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/netidentity"
	"github.com/obsernetics/pahlevan/pkg/netname"
)

// Learning egress in identity terms.
//
// A learned baseline of raw addresses is a baseline with a shelf life. A pod
// address is leased, not owned: the CNI hands it back seconds after the pod
// dies and gives it to whatever is scheduled next. So a baseline of addresses
// gets two things wrong, in opposite directions.
//
// It breaks a baseline that should still hold. The workload's database is
// rescheduled, comes back on a different address, and a peer the container has
// talked to for a week is suddenly absent from its learned set.
//
// And it holds a baseline that should have broken. The address the database
// used to have is given to something else - another team's namespace, an
// attacker's scratch pod - and a profile that says "this container talks to
// 10.244.3.17" now reads as though that is still fine.
//
// The fix is to learn what the peer is rather than where it was: a namespace,
// a workload and a port survive rescheduling and do not transfer to whoever
// inherits the address. Raw addresses are still recorded, because they are
// literally what the kernel allow-set holds and an operator auditing a profile
// has to be able to see them, but they are no longer the only record.
//
// External destinations keep exactly the behavior they had. They have no
// Kubernetes identity to learn, pkg/netname already names them on the export
// path, and duplicating that here would mean two answers for one address.
// What netname is used for here is its classifier, which is a pure prefix
// comparison: it keeps a loopback or unspecified address out of the peer list,
// where it is not a peer at all, and it names the handful of address ranges
// that are worth recording as a class - the cloud metadata endpoint above all.

// PeerIndex resolves a destination address to the Kubernetes identity behind
// it. *netidentity.Store implements it. Nil leaves the controller learning
// addresses only, which is what an agent whose index has not been wired does.
type PeerIndex = netidentity.Index

// eventAddr extracts the destination address from a network event for either
// address family.
//
// The AF_INET6 case is not optional. NetworkEvent carries the v4 address in a
// uint32 and the v6 address in a separate 16-byte field, and code that reads
// only the uint32 sees 0.0.0.0 for every IPv6 destination. This repository has
// shipped that bug once already, on the export path.
func eventAddr(e *ebpf.NetworkEvent) (netip.Addr, bool) {
	if e == nil {
		return netip.Addr{}, false
	}
	if e.Family == familyINet6 {
		// Unmapped, so a v4-mapped v6 destination is the same address as the
		// v4 one and does not learn twice.
		return netip.AddrFrom16(e.DstIP6).Unmap(), true
	}
	var b [4]byte
	// DstIP holds sin_addr.s_addr: the address already in network byte order,
	// decoded from the wire little-endian. Writing it back out the same way
	// restores the original byte order. Treating it as a host-order number and
	// shifting produces the address backwards, which is how 127.0.0.1 once
	// became 1.0.0.127.
	putUint32LE(b[:], e.DstIP)
	return netip.AddrFrom4(b), true
}

// familyINet6 is AF_INET6, hardcoded rather than taken from syscall so the
// value cannot drift by GOOS.
const familyINet6 = 10

func putUint32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// destID is one learned destination in address terms.
//
// A comparable struct rather than a string because this is a map key on the
// per-event path: building "10.244.1.5:5432" only to find out it is already in
// the set allocates twice per event, and a busy node delivers tens of
// thousands of them a second. The string form is produced once, when the
// profile is written.
type destID struct {
	addr netip.Addr
	port uint16
}

// String renders a learned destination the way it is reported: dotted quad for
// IPv4 and bracketed for IPv6, which is what net.SplitHostPort can read back
// and what every other destination string in the agent already uses.
//
// It replaces a key that formatted the raw uint32 as a decimal number, so a
// profile's learnedNetworkDestinations read "184549386:443" instead of
// "10.0.0.11:443", and every IPv6 destination collapsed onto "0:<port>"
// because that field is zero for AF_INET6.
func (d destID) String() string {
	return net.JoinHostPort(d.addr.String(), strconv.Itoa(int(d.port)))
}

// destKey is destID.String for an address and port.
func destKey(a netip.Addr, port uint16) string {
	return destID{addr: a, port: port}.String()
}

// peerID is one learned destination in identity terms. Comparable, and
// allocation-free to build, for the same reason destID is.
//
// A pod is recorded by its workload rather than by its name wherever the
// workload is known, because the pod name is the part that does not survive a
// rescheduling, and recording it would put the baseline right back where it
// started.
type peerID struct {
	kind      netidentity.PeerKind
	namespace string
	name      string
	port      uint16
}

func (p peerID) String() string {
	peer := netidentity.Peer{Kind: p.kind, Namespace: p.namespace, Name: p.name}
	return peer.String() + ":" + strconv.Itoa(int(p.port))
}

// peerIDOf folds a resolved peer and port into a key.
func peerIDOf(p netidentity.Peer, port uint16) peerID {
	name := p.Name
	if p.Kind == netidentity.PeerPod && p.Workload != "" {
		name = p.Workload
	}
	return peerID{kind: p.Kind, namespace: p.Namespace, name: name, port: port}
}

// classPeerID names an unresolved destination by the class of address it is,
// for the classes where that is a fact worth keeping.
//
// The false return means the address does not belong in the peer list: it is
// either not a peer (loopback, unspecified, multicast, broadcast, malformed)
// or it is an ordinary public address, which is already recorded raw and named
// by pkg/netname on the export path. Keeping public addresses out also keeps
// the list bounded: an outbound scan touches thousands of distinct addresses,
// and a learned set an attacker can grow at will is a liability in a CR.
func classPeerID(a netip.Addr, port uint16) (peerID, bool) {
	class := netname.Classify(a)
	switch class {
	case netname.ClassInvalid, netname.ClassLoopback, netname.ClassUnspecified,
		netname.ClassMulticast, netname.ClassBroadcast:
		return peerID{}, false
	}
	label := class.Label()
	if label == "" {
		return peerID{}, false
	}
	return peerID{kind: netidentity.PeerExternal, name: label, port: port}, true
}

// learnDestination records one observed egress destination, in both address
// and identity terms. Callers must hold c.mu.
func (c *Controller) learnDestination(st *cgState, e *ebpf.NetworkEvent) {
	a, ok := eventAddr(e)
	if !ok || !a.IsValid() {
		return
	}
	st.dests[destID{addr: a, port: e.DstPort}] = struct{}{}

	if c.Peers == nil {
		return
	}
	if peer, known := c.Peers.Lookup(a); known {
		st.peers[peerIDOf(peer, e.DstPort)] = struct{}{}
		return
	}
	if id, ok := classPeerID(a, e.DstPort); ok {
		st.peers[id] = struct{}{}
	}
}

// destString renders a Destination for a log line.
func destString(d Destination) string {
	return net.JoinHostPort(d.IP.String(), fmt.Sprint(d.Port))
}

// destinationKey identifies a Destination for set arithmetic, and is the same
// key the learned set uses so the two can be compared. The address is
// normalized through netip so an IPv4 address held as a 16-byte slice and the
// same address held as 4 bytes are one key rather than two.
func destinationKey(d Destination) destID {
	if a, ok := netip.AddrFromSlice(d.IP); ok {
		return destID{addr: a.Unmap(), port: d.Port}
	}
	return destID{port: d.Port}
}

// diffDestinations returns what is in next and not in prev, and what is in
// prev and not in next.
func diffDestinations(prev, next []Destination) (added, removed []Destination) {
	prevSet := make(map[destID]Destination, len(prev))
	for _, d := range prev {
		prevSet[destinationKey(d)] = d
	}
	nextSet := make(map[destID]Destination, len(next))
	for _, d := range next {
		k := destinationKey(d)
		nextSet[k] = d
		if _, had := prevSet[k]; !had {
			added = append(added, d)
		}
	}
	for k, d := range prevSet {
		if _, still := nextSet[k]; !still {
			removed = append(removed, d)
		}
	}
	return added, removed
}

// refreshSelectorPeers re-derives the selector-derived allow-set entries for an
// enforcing container and writes only the difference into the kernel.
//
// This is what makes a selector peer mean what it says. A selector names a set
// of workloads, and the set moves: pods are rescheduled onto new addresses,
// relabelled out of the selector, or deleted. Seeding it once at the enforce
// transition would mean "whatever matched the first time", which permits an
// address long after the pod that justified it is gone - and that address goes
// to somebody else.
//
// A withdrawal is skipped when the destination is still permitted for another
// reason: an ipBlock that also covers it, or the container having been
// observed using it during learning. The kernel allow-set has one kind of
// entry and no provenance, so revoking one that a learned fact also justifies
// would break the workload.
//
// Callers must hold c.mu.
func (c *Controller) refreshSelectorPeers(id uint64, st *cgState) {
	if st.phase != PhaseEnforcing {
		return
	}
	d, ok := c.policies.Resolve(id, st.ref)
	if !ok || !d.Blocking() {
		return
	}
	added, removed := diffDestinations(
		st.overrides.SelectorDestinations, d.Overrides.SelectorDestinations)
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	keep := make(map[destID]struct{}, len(d.Overrides.AllowedDestinations))
	for _, dest := range d.Overrides.AllowedDestinations {
		keep[destinationKey(dest)] = struct{}{}
	}

	seeded, revoked, failed := 0, 0, 0
	for _, dest := range added {
		if err := c.enforcer.AllowNetworkDestination(id, dest.IP, dest.Port, true); err != nil {
			failed++
			c.log.V(1).Info("could not seed a selector peer",
				"cgroup", id, "destination", destString(dest), "error", err.Error())
			continue
		}
		seeded++
	}
	for _, dest := range removed {
		key := destinationKey(dest)
		if _, still := keep[key]; still {
			continue
		}
		if _, learned := st.dests[key]; learned {
			continue
		}
		if err := c.enforcer.AllowNetworkDestination(id, dest.IP, dest.Port, false); err != nil {
			failed++
			c.log.V(1).Info("could not withdraw a selector peer",
				"cgroup", id, "destination", destString(dest), "error", err.Error())
			continue
		}
		revoked++
	}

	st.overrides = d.Overrides
	c.log.Info("selector peers re-resolved",
		"cgroup", id, "pod", st.ref.PodUID, "policy", d.PolicyName,
		"seeded", seeded, "revoked", revoked, "failed", failed)
}
