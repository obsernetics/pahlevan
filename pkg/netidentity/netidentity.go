// Package netidentity answers "who is 10.244.3.17?" in Kubernetes terms, and
// keeps answering it correctly after that address has been handed to somebody
// else.
//
// internal/netmap already turns an address into a name for an operator to
// read. This package exists because enforcement needs something netmap
// deliberately does not provide. netmap is a presentation-only snapshot
// rebuilt on a ten-second tick; if a decision depended on it, then for up to
// ten seconds after a pod died every lookup of its address would return the
// dead pod's identity, and a pod that had just been given that address would
// inherit its trust. Ten seconds is not a rounding error here: a CNI reassigns
// a freed pod address within a second or two, which is exactly how long a
// rescheduled workload takes to come back.
//
// So this index is watch-fed and it is explicit about reuse:
//
//  1. Every binding is owned by an object UID. A delete only removes a binding
//     whose UID matches, so the delete for a dead pod that arrives after the
//     add for its successor cannot evict the successor. Out-of-order delivery
//     across two objects is normal, and the naive "delete by address" is wrong
//     precisely in the reuse case this package is for.
//
//  2. A delete removes the binding immediately and leaves a tombstone carrying
//     the deletion time. Until something else claims the address, Lookup
//     reports it as unknown rather than as the identity that just died. An
//     address with no answer is a true statement; a dead pod's name is not.
//
//  3. Every binding carries a monotonic generation. A caller that cached an
//     answer can tell it has been rebound rather than refreshed, and the
//     learned baselines in internal/adaptive key on the identity rather than
//     on the address, so a recycled address resolving to a new identity simply
//     does not match what was learned.
//
// Addresses are netip.Addr throughout, never strings. This repository has
// already shipped one bug where an IPv6 destination was exported as 0.0.0.0
// because the address was carried in a uint32; string and integer handling of
// addresses is how that happens, and netip.Addr is how it stops.
package netidentity

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// PeerKind is what an address turned out to be.
type PeerKind string

const (
	// PeerPod is a pod address, reached directly rather than through a Service.
	PeerPod PeerKind = "Pod"
	// PeerService is a Service ClusterIP.
	PeerService PeerKind = "Service"
	// PeerNode is a node address. A hostNetwork pod shares it; see Lookup.
	PeerNode PeerKind = "Node"
	// PeerExternal is an address the cluster does not know about. It is the
	// zero answer, so a caller that ignores the bool still gets a true
	// statement rather than a wrong identity.
	PeerExternal PeerKind = "External"
)

// Peer is the Kubernetes identity behind an address.
//
// Labels is shared, not copied: it is the map the informer handed us and is
// never mutated after the binding is built, which is what makes a lookup on
// the event path allocation-free. Callers must treat it as read only. Use
// Peer.Clone if you need to keep and modify one.
type Peer struct {
	Kind      PeerKind
	Namespace string
	Name      string
	// Workload is the owning Deployment/StatefulSet/DaemonSet where known. It
	// is the part of a pod's identity that survives rescheduling, which is why
	// baselines are learned against it rather than against Name.
	Workload string
	Labels   map[string]string
}

// Index is the read side. The event path depends on this and nothing more, so
// a consumer can be tested against a map.
type Index interface {
	Lookup(ip netip.Addr) (Peer, bool)
}

// String renders a peer the way it should appear in a profile or an event.
func (p Peer) String() string {
	name := p.Name
	if p.Kind == PeerPod && p.Workload != "" {
		name = p.Workload
	}
	switch {
	case name == "":
		return strings.ToLower(string(p.Kind))
	case p.Namespace == "":
		return strings.ToLower(string(p.Kind)) + ":" + name
	default:
		return strings.ToLower(string(p.Kind)) + ":" + p.Namespace + "/" + name
	}
}

// Clone deep-copies a peer, including its labels.
func (p Peer) Clone() Peer {
	out := p
	if p.Labels != nil {
		out.Labels = make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			out.Labels[k] = v
		}
	}
	return out
}

// Defaults for the reuse bookkeeping.
const (
	// DefaultTombstoneTTL is how long a released address is remembered as
	// released. It only has to outlive the window in which a stale cached
	// answer could still be in flight on the event path; past that the address
	// is simply unknown, which is the same answer.
	DefaultTombstoneTTL = 5 * time.Minute
	// DefaultMaxTombstones bounds the tombstone table. Pod churn is not
	// attacker controlled the way an external destination is, but a crash-loop
	// across a large node still churns addresses, and an unbounded map that
	// only ever grows is a leak.
	DefaultMaxTombstones = 4096
)

// binding is one identity's claim on one address.
type binding struct {
	peer Peer
	uid  types.UID
	gen  uint64
	// hostNetwork marks a pod that carries its node's address rather than one
	// of its own. Such a pod has no distinct address, so it can never be the
	// answer for that address on its own.
	hostNetwork bool
	// nodeName is the pod's spec.nodeName, used to name the node a
	// hostNetwork pod's address really belongs to when the Node object itself
	// is not indexed.
	nodeName string
}

// slot is every claim on one address, plus the resolved answer.
//
// More than one claim is normal for a node address, which every hostNetwork
// pod on that node also reports as its PodIP, and transiently possible for a
// pod address when a successor's add is delivered before its predecessor's
// delete. Both are resolved in resolve(), not papered over.
type slot struct {
	owners map[types.UID]binding
	answer Peer
	gen    uint64
}

// Store is the index. Safe for concurrent lookups while the informer writes.
type Store struct {
	mu    sync.RWMutex
	slots map[netip.Addr]*slot
	// nsLabels backs namespaceSelector resolution.
	nsLabels map[string]map[string]string
	// pods is every pod currently indexed, for selector resolution. Keyed by
	// UID because a name is only unique within a namespace and a namespace can
	// be deleted and recreated.
	pods map[types.UID]*podEntry
	// owned is the addresses each object currently holds, so an update can
	// withdraw exactly the claims that object made and Sync can tell which
	// objects have disappeared without a delete event.
	owned map[types.UID]*owner

	// tombs remembers released addresses. order is insertion order, for the
	// bound: a plain map with no eviction would grow with pod churn.
	tombs map[netip.Addr]time.Time
	order []netip.Addr

	gen       uint64
	conflicts uint64

	now      func() time.Time
	ttl      time.Duration
	maxTombs int
}

// owner is one object's current claims.
type owner struct {
	kind  PeerKind
	addrs []netip.Addr
}

// podEntry is what selector resolution needs about a pod. Held separately from
// the address slots because a selector matches pods, and a pod may have two
// addresses or none.
type podEntry struct {
	namespace   string
	labels      map[string]string
	addrs       []netip.Addr
	hostNetwork bool
}

// Options configures a Store. The zero value is usable.
type Options struct {
	// TombstoneTTL overrides DefaultTombstoneTTL.
	TombstoneTTL time.Duration
	// MaxTombstones overrides DefaultMaxTombstones.
	MaxTombstones int
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// New returns an empty store. Everything is external until it is populated,
// which is the safe default: an unknown address reported as external is
// accurate, while one reported as a workload would be a lie.
func New(opts Options) *Store {
	s := &Store{
		slots:    map[netip.Addr]*slot{},
		nsLabels: map[string]map[string]string{},
		pods:     map[types.UID]*podEntry{},
		owned:    map[types.UID]*owner{},
		tombs:    map[netip.Addr]time.Time{},
		now:      opts.Now,
		ttl:      opts.TombstoneTTL,
		maxTombs: opts.MaxTombstones,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.ttl <= 0 {
		s.ttl = DefaultTombstoneTTL
	}
	if s.maxTombs <= 0 {
		s.maxTombs = DefaultMaxTombstones
	}
	return s
}

var _ Index = (*Store)(nil)

// Lookup resolves one address.
//
// The bool reports whether the address is known. An unknown address, a
// released one, and an invalid one all come back as (Peer{Kind: PeerExternal},
// false): a caller that ignores the bool is still told something true.
//
// A node address shared with hostNetwork pods resolves to the node, never to
// one of the pods. The address belongs to the node and is reachable as every
// hostNetwork pod on it, so answering with one particular pod would let a rule
// written about that pod be read as a rule about the node - and about the
// kubelet, and about every other hostNetwork pod there. LookupAll exposes the
// full set for callers that want it.
func (s *Store) Lookup(ip netip.Addr) (Peer, bool) {
	if !ip.IsValid() {
		return Peer{Kind: PeerExternal}, false
	}
	key := ip.Unmap()
	s.mu.RLock()
	sl, ok := s.slots[key]
	if !ok {
		s.mu.RUnlock()
		return Peer{Kind: PeerExternal}, false
	}
	p := sl.answer
	s.mu.RUnlock()
	return p, true
}

// LookupGeneration is Lookup plus the generation of the binding that answered.
// The generation increases on every write, so a caller holding an earlier one
// knows the address has been rebound rather than merely re-observed.
func (s *Store) LookupGeneration(ip netip.Addr) (Peer, uint64, bool) {
	if !ip.IsValid() {
		return Peer{Kind: PeerExternal}, 0, false
	}
	key := ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	sl, ok := s.slots[key]
	if !ok {
		return Peer{Kind: PeerExternal}, 0, false
	}
	return sl.answer, sl.gen, true
}

// LookupAll returns every identity claiming an address, in a deterministic
// order. For a node address this is the node and every hostNetwork pod on it.
// The slice is freshly allocated, so this is not the hot path; Lookup is.
func (s *Store) LookupAll(ip netip.Addr) []Peer {
	if !ip.IsValid() {
		return nil
	}
	key := ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	sl, ok := s.slots[key]
	if !ok {
		return nil
	}
	out := make([]Peer, 0, len(sl.owners))
	for _, b := range sl.owners {
		out = append(out, b.peer)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Released reports when an address was last released by a deleted identity and
// not since rebound. It is how a caller distinguishes "never heard of this
// address" from "this address belonged to something that is gone", which are
// the same answer for enforcement and very different ones for an operator
// reading why a baseline stopped matching.
func (s *Store) Released(ip netip.Addr) (time.Time, bool) {
	if !ip.IsValid() {
		return time.Time{}, false
	}
	key := ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tombs[key]
	if !ok {
		return time.Time{}, false
	}
	if s.now().Sub(t) > s.ttl {
		return time.Time{}, false
	}
	return t, true
}

// Len is the number of addresses indexed.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.slots)
}

// Conflicts counts the times an address was claimed by more than one identity
// that was not a node/hostNetwork pair. It should be zero or near it; a
// climbing value means adds and deletes are arriving badly out of order, which
// is worth a metric rather than a silent tie-break.
func (s *Store) Conflicts() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conflicts
}

// ---------------------------------------------------------------------------
// Writes. All of these are driven by informer events; see Handler.
// ---------------------------------------------------------------------------

// UpsertPod indexes a pod's addresses.
func (s *Store) UpsertPod(p *corev1.Pod) {
	if p == nil {
		return
	}
	addrs := podAddrs(p)
	_, workload := OwnerWorkload(p)
	peer := Peer{
		Kind:      PeerPod,
		Namespace: p.Namespace,
		Name:      p.Name,
		Workload:  workload,
		Labels:    p.Labels,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := objectKey(PeerPod, p.Namespace, p.Name, p.UID)
	s.pods[key] = &podEntry{
		namespace:   p.Namespace,
		labels:      p.Labels,
		addrs:       addrs,
		hostNetwork: p.Spec.HostNetwork,
	}
	s.setOwnerLocked(key, addrs, binding{
		peer:        peer,
		uid:         key,
		hostNetwork: p.Spec.HostNetwork,
		nodeName:    p.Spec.NodeName,
	})
}

// DeletePod withdraws a pod's addresses and tombstones them.
//
// The addresses withdrawn are the ones this store bound, not the ones on the
// object handed to the delete. A delete can arrive with a stale or emptied
// status, and withdrawing by the object's current PodIP would leave the real
// binding in place - the dead pod would keep answering for its address, which
// is the failure this package exists to stop.
func (s *Store) DeletePod(p *corev1.Pod) {
	if p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := objectKey(PeerPod, p.Namespace, p.Name, p.UID)
	delete(s.pods, key)
	s.removeOwnerLocked(key, podAddrs(p))
}

// UpsertService indexes a Service's ClusterIPs.
//
// Only ClusterIPs. An ExternalIP or a LoadBalancer ingress address is not
// necessarily inside the cluster and is frequently shared with something the
// cluster does not own, so binding an identity to it would be a guess.
func (s *Store) UpsertService(svc *corev1.Service) {
	if svc == nil {
		return
	}
	peer := Peer{
		Kind:      PeerService,
		Namespace: svc.Namespace,
		Name:      svc.Name,
		Labels:    svc.Labels,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := objectKey(PeerService, svc.Namespace, svc.Name, svc.UID)
	s.setOwnerLocked(key, serviceAddrs(svc), binding{peer: peer, uid: key})
}

// DeleteService withdraws a Service's ClusterIPs.
func (s *Store) DeleteService(svc *corev1.Service) {
	if svc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeOwnerLocked(objectKey(PeerService, svc.Namespace, svc.Name, svc.UID), serviceAddrs(svc))
}

// UpsertNode indexes a node's internal and external addresses.
func (s *Store) UpsertNode(n *corev1.Node) {
	if n == nil {
		return
	}
	peer := Peer{Kind: PeerNode, Name: n.Name, Labels: n.Labels}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := objectKey(PeerNode, "", n.Name, n.UID)
	s.setOwnerLocked(key, nodeAddrs(n), binding{peer: peer, uid: key})
}

// DeleteNode withdraws a node's addresses.
func (s *Store) DeleteNode(n *corev1.Node) {
	if n == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeOwnerLocked(objectKey(PeerNode, "", n.Name, n.UID), nodeAddrs(n))
}

// UpsertNamespace records a namespace's labels, which back namespaceSelector
// resolution.
func (s *Store) UpsertNamespace(ns *corev1.Namespace) {
	if ns == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nsLabels[ns.Name] = ns.Labels
}

// DeleteNamespace forgets a namespace's labels. Pods in it are removed by
// their own delete events; a namespace whose labels are gone matches nothing,
// which fails closed.
func (s *Store) DeleteNamespace(ns *corev1.Namespace) {
	if ns == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nsLabels, ns.Name)
}

// setOwnerLocked makes addrs the complete set of claims held by b.uid.
// Callers must hold s.mu.
func (s *Store) setOwnerLocked(uid types.UID, addrs []netip.Addr, b binding) {
	if prev, ok := s.owned[uid]; ok {
		// keep = addrs: an address this object is re-binding in the same write
		// was never released, so it must not be tombstoned.
		s.unbindLocked(prev.addrs, uid, addrs)
	}
	if len(addrs) == 0 {
		delete(s.owned, uid)
		return
	}
	s.owned[uid] = &owner{kind: b.peer.Kind, addrs: addrs}
	for _, a := range addrs {
		s.bindLocked(a, b)
	}
}

// removeOwnerLocked withdraws every claim held by uid. fallback is used when
// the store has no record of the object, which happens when a delete is the
// first event ever seen for it. Callers must hold s.mu.
func (s *Store) removeOwnerLocked(uid types.UID, fallback []netip.Addr) {
	addrs := fallback
	if prev, ok := s.owned[uid]; ok {
		addrs = prev.addrs
	}
	delete(s.owned, uid)
	s.unbindLocked(addrs, uid, nil)
}

// bindLocked installs one claim on one address. Callers must hold s.mu.
func (s *Store) bindLocked(a netip.Addr, b binding) {
	s.gen++
	b.gen = s.gen
	sl, ok := s.slots[a]
	if !ok {
		sl = &slot{owners: map[types.UID]binding{}}
		s.slots[a] = sl
	}
	sl.owners[b.uid] = b
	// The address is live again, so it is no longer released.
	s.dropTombLocked(a)
	s.resolveLocked(sl)
}

// unbindLocked withdraws uid's claim on each address, tombstoning any address
// left with no owner. Addresses in keep are not tombstoned: they are being
// rebound by the same object in the same write, so they were never released.
// Callers must hold s.mu.
func (s *Store) unbindLocked(addrs []netip.Addr, uid types.UID, keep []netip.Addr) {
	for _, a := range addrs {
		sl, ok := s.slots[a]
		if !ok {
			continue
		}
		// UID match is the whole point. A delete for a pod that no longer owns
		// this address - because its successor already claimed it - must not
		// evict the successor.
		if _, mine := sl.owners[uid]; !mine {
			continue
		}
		delete(sl.owners, uid)
		if len(sl.owners) > 0 {
			s.resolveLocked(sl)
			continue
		}
		delete(s.slots, a)
		if !containsAddr(keep, a) {
			s.tombstoneLocked(a)
		}
	}
}

// resolveLocked recomputes the answer for an address. Callers must hold s.mu.
//
// One owner is the ordinary case. The two that are not:
//
// A hostNetwork pod reports its node's address as its PodIP, so that address
// is claimed by the node and by every hostNetwork pod on it. It resolves to
// the node, always - including when the Node object is not indexed, in which
// case the node is named from the pod's spec.nodeName. Answering with one
// particular hostNetwork pod would let a statement about that pod be read as a
// statement about the kubelet and about every other hostNetwork pod there,
// which is exactly the silent widening this package exists to prevent.
//
// Two ordinary pods claiming one address is a genuine conflict: a delete has
// not been delivered yet. The newest binding wins, because it is the claim the
// API server asserted most recently, and the conflict is counted rather than
// hidden.
func (s *Store) resolveLocked(sl *slot) {
	var best binding
	var node binding
	hasNode := false
	var hostNode binding
	hasHostNetwork := false
	distinct := 0
	for _, b := range sl.owners {
		switch {
		case b.peer.Kind == PeerNode:
			if !hasNode || b.gen > node.gen {
				node, hasNode = b, true
			}
		case b.hostNetwork:
			if !hasHostNetwork || b.gen > hostNode.gen {
				hostNode, hasHostNetwork = b, true
			}
		default:
			distinct++
			if b.gen > best.gen {
				best = b
			}
		}
	}
	switch {
	case hasNode:
		sl.answer, sl.gen = node.peer, node.gen
	case hasHostNetwork:
		sl.answer = Peer{Kind: PeerNode, Name: hostNode.nodeName}
		sl.gen = hostNode.gen
	default:
		if distinct > 1 {
			s.conflicts++
		}
		sl.answer, sl.gen = best.peer, best.gen
	}
}

// tombstoneLocked records that an address was released. Callers must hold s.mu.
func (s *Store) tombstoneLocked(a netip.Addr) {
	now := s.now()
	if _, exists := s.tombs[a]; !exists {
		s.order = append(s.order, a)
	}
	s.tombs[a] = now
	// Evict from the front until the bound holds. Entries whose address has
	// since been rebound are already gone from the map, so this skips them.
	for len(s.order) > s.maxTombs {
		victim := s.order[0]
		s.order = s.order[1:]
		delete(s.tombs, victim)
	}
	// Opportunistic expiry, so a store that stops churning does not hold
	// tombstones forever.
	for len(s.order) > 0 {
		head := s.order[0]
		t, ok := s.tombs[head]
		if ok && now.Sub(t) <= s.ttl {
			break
		}
		s.order = s.order[1:]
		delete(s.tombs, head)
	}
}

func (s *Store) dropTombLocked(a netip.Addr) {
	if _, ok := s.tombs[a]; !ok {
		return
	}
	delete(s.tombs, a)
	for i, x := range s.order {
		if x == a {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Address extraction
// ---------------------------------------------------------------------------

// ParseAddr parses an address the way this package stores them: IPv4-mapped
// IPv6 is unmapped, so "::ffff:10.0.0.1" and "10.0.0.1" are one address, and
// anything unparseable is invalid rather than zero.
func ParseAddr(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !a.IsValid() {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func podAddrs(p *corev1.Pod) []netip.Addr {
	var out []netip.Addr
	add := func(raw string) {
		a, ok := ParseAddr(raw)
		if !ok || containsAddr(out, a) {
			return
		}
		out = append(out, a)
	}
	add(p.Status.PodIP)
	for _, ip := range p.Status.PodIPs {
		add(ip.IP)
	}
	return out
}

func serviceAddrs(svc *corev1.Service) []netip.Addr {
	var out []netip.Addr
	add := func(raw string) {
		// "None" is a headless Service and is not an address.
		if raw == "" || raw == corev1.ClusterIPNone {
			return
		}
		a, ok := ParseAddr(raw)
		if !ok || containsAddr(out, a) {
			return
		}
		out = append(out, a)
	}
	add(svc.Spec.ClusterIP)
	for _, ip := range svc.Spec.ClusterIPs {
		add(ip)
	}
	return out
}

func nodeAddrs(n *corev1.Node) []netip.Addr {
	var out []netip.Addr
	for _, a := range n.Status.Addresses {
		switch a.Type {
		case corev1.NodeInternalIP, corev1.NodeExternalIP:
			addr, ok := ParseAddr(a.Address)
			if !ok || containsAddr(out, addr) {
				continue
			}
			out = append(out, addr)
		}
	}
	return out
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// objectKey is the identity a binding is owned by.
//
// The UID is the right key: it is what makes a delete for a dead pod unable to
// evict its successor at the same address, and it is what tells a recreated
// object from the one it replaced. An object with no UID is not something the
// API server produces, but it is something a client can hand us - a manually
// built object in a test, a partially decoded one - and falling back on the
// kind and name keeps those from all colliding on the empty key, which would
// have each one silently withdrawing the last one's addresses.
func objectKey(kind PeerKind, namespace, name string, uid types.UID) types.UID {
	if uid != "" {
		return uid
	}
	return types.UID(string(kind) + "/" + namespace + "/" + name)
}

// OwnerWorkload walks one level up from a pod's controller reference, and a
// second level for the ReplicaSet a Deployment owns, which is the only
// indirection worth unwinding: nobody thinks in ReplicaSets.
func OwnerWorkload(p *corev1.Pod) (kind, name string) {
	if p == nil {
		return "", ""
	}
	for i := range p.OwnerReferences {
		ref := &p.OwnerReferences[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			// A ReplicaSet is named <deployment>-<pod-template-hash>. Trimming
			// the hash is how kubectl presents it too.
			if idx := strings.LastIndex(ref.Name, "-"); idx > 0 {
				return "Deployment", ref.Name[:idx]
			}
		}
		return ref.Kind, ref.Name
	}
	return "", ""
}
