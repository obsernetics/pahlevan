package adaptive

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/netidentity"
)

// stubIndex is a netidentity.Index backed by a map, which is the whole reason
// the interface is one method.
type stubIndex map[netip.Addr]netidentity.Peer

func (s stubIndex) Lookup(ip netip.Addr) (netidentity.Peer, bool) {
	p, ok := s[ip]
	if !ok {
		return netidentity.Peer{Kind: netidentity.PeerExternal}, false
	}
	return p, true
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return a
}

// ipv4Event builds a network event the way the kernel reports one: DstIP holds
// sin_addr.s_addr, already in network byte order.
func ipv4Event(cgroup uint64, ip string, port uint16) *ebpf.NetworkEvent {
	a := netip.MustParseAddr(ip).As4()
	raw := uint32(a[0]) | uint32(a[1])<<8 | uint32(a[2])<<16 | uint32(a[3])<<24
	return &ebpf.NetworkEvent{CgroupID: cgroup, DstIP: raw, DstPort: port, Family: 2}
}

func ipv6Event(cgroup uint64, ip string, port uint16) *ebpf.NetworkEvent {
	e := &ebpf.NetworkEvent{CgroupID: cgroup, DstPort: port, Family: familyINet6}
	copy(e.DstIP6[:], netip.MustParseAddr(ip).AsSlice())
	return e
}

func TestEventAddrHandlesBothFamilies(t *testing.T) {
	a, ok := eventAddr(ipv4Event(1, "10.0.0.11", 443))
	require.True(t, ok)
	assert.Equal(t, "10.0.0.11", a.String())

	a, ok = eventAddr(ipv6Event(1, "fd00::5", 443))
	require.True(t, ok)
	assert.Equal(t, "fd00::5", a.String(),
		"an IPv6 destination lives in DstIP6; reading DstIP gives 0.0.0.0 for every one of them")

	_, ok = eventAddr(nil)
	assert.False(t, ok)

	// A v6 event whose address slice is unusable is reported as unusable
	// rather than as the zero address.
	bad := &ebpf.NetworkEvent{Family: familyINet6}
	a, ok = eventAddr(bad)
	require.True(t, ok)
	assert.True(t, a.IsUnspecified())
}

// The learned destination list used to hold the raw uint32 formatted as a
// decimal number, so a profile read "184549386:443" and every IPv6
// destination collapsed onto "0:<port>" because that field is zero for
// AF_INET6.
func TestLearnedDestinationsAreRealAddresses(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.0.0.11", 443))
	_ = c.HandleNetworkEvent(ipv6Event(7, "fd00::5", 443))
	_ = c.HandleNetworkEvent(ipv6Event(7, "fd00::6", 443))

	c.mu.Lock()
	dests := renderKeys(c.state[7].dests)
	c.mu.Unlock()

	assert.Contains(t, dests, "10.0.0.11:443")
	assert.Contains(t, dests, "[fd00::5]:443")
	assert.Contains(t, dests, "[fd00::6]:443")
	assert.Len(t, dests, 3, "two distinct IPv6 destinations must not collapse onto one key")
}

func TestLearnedPeersAreIdentities(t *testing.T) {
	idx := stubIndex{
		mustAddr(t, "10.96.0.12"): {Kind: netidentity.PeerService, Namespace: "prod", Name: "postgres"},
		mustAddr(t, "10.244.1.5"): {Kind: netidentity.PeerPod, Namespace: "prod", Name: "api-7d9f-xx", Workload: "api"},
		mustAddr(t, "fd00::5"):    {Kind: netidentity.PeerPod, Namespace: "prod", Name: "cache-0", Workload: "cache"},
	}
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = idx

	_ = c.HandleNetworkEvent(ipv4Event(7, "10.96.0.12", 5432))
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.244.1.5", 8080))
	_ = c.HandleNetworkEvent(ipv6Event(7, "fd00::5", 6379))
	_ = c.HandleNetworkEvent(ipv4Event(7, "169.254.169.254", 80))
	_ = c.HandleNetworkEvent(ipv4Event(7, "8.8.8.8", 443))
	_ = c.HandleNetworkEvent(ipv4Event(7, "127.0.0.1", 9000))

	c.mu.Lock()
	peers := renderKeys(c.state[7].peers)
	dests := renderKeys(c.state[7].dests)
	c.mu.Unlock()

	assert.Contains(t, peers, "service:prod/postgres:5432")
	assert.Contains(t, peers, "pod:prod/api:8080", "a pod is recorded by its workload, not its name")
	assert.Contains(t, peers, "pod:prod/cache:6379")
	assert.Contains(t, peers, "external:cloud-metadata:80",
		"a workload asking the cloud for the node's credentials is the entry worth having")
	assert.NotContains(t, peers, "external::443")
	assert.Len(t, peers, 4,
		"an ordinary public address and a loopback address are not identities")

	assert.Len(t, dests, 6, "every destination is still recorded by address")
}

// A rescheduled peer keeps its identity even though its address changed, which
// is the whole point: the baseline holds instead of showing a new entry every
// time the database moves.
func TestARescheduledPeerDoesNotGrowTheIdentityBaseline(t *testing.T) {
	idx := stubIndex{}
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = idx

	postgres := netidentity.Peer{Kind: netidentity.PeerPod, Namespace: "prod", Name: "postgres-0", Workload: "postgres"}
	idx[mustAddr(t, "10.244.3.17")] = postgres
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.244.3.17", 5432))

	// The pod is rescheduled onto a different address.
	delete(idx, mustAddr(t, "10.244.3.17"))
	idx[mustAddr(t, "10.244.9.42")] = postgres
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.244.9.42", 5432))

	c.mu.Lock()
	peers := renderKeys(c.state[7].peers)
	dests := renderKeys(c.state[7].dests)
	c.mu.Unlock()

	assert.Len(t, peers, 1, "one peer, two addresses")
	assert.Contains(t, peers, "pod:prod/postgres:5432")
	assert.Len(t, dests, 2)
}

// And the converse: a new workload that inherits the dead pod's address gets
// its own entry rather than walking into the old one.
func TestARecycledAddressDoesNotInheritTheOldIdentity(t *testing.T) {
	idx := stubIndex{}
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = idx

	idx[mustAddr(t, "10.244.3.17")] = netidentity.Peer{
		Kind: netidentity.PeerPod, Namespace: "prod", Name: "postgres-0", Workload: "postgres"}
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.244.3.17", 5432))

	idx[mustAddr(t, "10.244.3.17")] = netidentity.Peer{
		Kind: netidentity.PeerPod, Namespace: "attacker", Name: "scratch-1", Workload: "scratch"}
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.244.3.17", 5432))

	c.mu.Lock()
	peers := renderKeys(c.state[7].peers)
	dests := renderKeys(c.state[7].dests)
	c.mu.Unlock()

	assert.Contains(t, peers, "pod:prod/postgres:5432")
	assert.Contains(t, peers, "pod:attacker/scratch:5432")
	assert.Len(t, peers, 2, "the recycled address is a second identity, not the same one")
	assert.Len(t, dests, 1, "by address alone the two are indistinguishable, which is the bug")
}

func TestLearnDestinationWithoutAnIndexIsAddressOnly(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	_ = c.HandleNetworkEvent(ipv4Event(7, "10.0.0.11", 443))
	c.mu.Lock()
	defer c.mu.Unlock()
	assert.Len(t, c.state[7].dests, 1)
	assert.Empty(t, c.state[7].peers, "no index means no identities, not guessed ones")
}

// renderKeys turns a learned set into the strings a profile reports, which is
// the form worth asserting on: the map keys themselves are an implementation
// detail chosen to keep the event path allocation-free.
func renderKeys[K interface {
	comparable
	fmt.Stringer
}](set map[K]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(set))
	for k := range set {
		out[k.String()] = struct{}{}
	}
	return out
}

func TestClassKeyOnlyNamesWhatIsWorthNaming(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"169.254.169.254", "external:cloud-metadata:80"},
		{"10.1.2.3", "external:private-network:80"},
		{"100.64.0.1", "external:cgnat:80"},
		{"fe80::1", "external:link-local:80"},
		{"203.0.113.1", "external:documentation:80"},
		{"8.8.8.8", ""},
		{"127.0.0.1", ""},
		{"::1", ""},
		{"0.0.0.0", ""},
		{"224.0.0.1", ""},
		{"255.255.255.255", ""},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			id, ok := classPeerID(netip.MustParseAddr(tc.addr), 80)
			if tc.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.want, id.String())
		})
	}
	_, ok := classPeerID(netip.Addr{}, 80)
	assert.False(t, ok)
}

func TestDiffDestinations(t *testing.T) {
	d := func(ip string, port uint16) Destination {
		return Destination{IP: net.ParseIP(ip), Port: port}
	}
	added, removed := diffDestinations(
		[]Destination{d("10.0.0.1", 80), d("10.0.0.2", 80)},
		[]Destination{d("10.0.0.2", 80), d("10.0.0.3", 80)},
	)
	require.Len(t, added, 1)
	assert.Equal(t, "10.0.0.3", added[0].IP.String())
	require.Len(t, removed, 1)
	assert.Equal(t, "10.0.0.1", removed[0].IP.String())

	// net.ParseIP returns a 16-byte slice for an IPv4 address, so the same
	// address reached two ways must be one key rather than two.
	added, removed = diffDestinations(
		[]Destination{{IP: net.IPv4(10, 0, 0, 1), Port: 80}},
		[]Destination{{IP: net.IP{10, 0, 0, 1}, Port: 80}},
	)
	assert.Empty(t, added)
	assert.Empty(t, removed)

	assert.Equal(t, "10.0.0.1:80", destinationKey(d("10.0.0.1", 80)).String())
	assert.Equal(t, "[fd00::1]:80", destinationKey(d("fd00::1", 80)).String())
	assert.Equal(t, "10.0.0.11:443", destKey(netip.MustParseAddr("10.0.0.11"), 443))
	// A malformed address still yields a stable key rather than panicking.
	assert.NotPanics(t, func() { destinationKey(Destination{IP: net.IP{1, 2, 3}, Port: 80}) })
}

// movingPolicies returns a Decision whose selector peers are whatever the
// pointed-to slice currently holds, which is how a selector behaves as pods
// come and go.
type movingPolicies struct {
	selector *[]Destination
	blocking bool
}

func (m movingPolicies) Resolve(uint64, attribution.ContainerRef) (Decision, bool) {
	mode := ModeMonitoring
	if m.blocking {
		mode = ModeBlocking
	}
	sel := *m.selector
	return Decision{
		PolicyName: "test",
		Mode:       mode,
		Overrides: Overrides{
			AllowedDestinations:  append([]Destination(nil), sel...),
			SelectorDestinations: append([]Destination(nil), sel...),
		},
	}, true
}

func (m movingPolicies) PodMeta(string) (string, string, bool) { return "", "", false }

func TestSelectorPeersTrackRealityWhileEnforcing(t *testing.T) {
	d := func(ip string) Destination { return Destination{IP: net.ParseIP(ip), Port: 5432} }

	set := []Destination{d("10.244.1.1"), d("10.244.1.2")}
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, movingPolicies{selector: &set, blocking: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// Get the container to enforcing, which seeds the initial set.
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 1})
	c.Reconcile()
	require.True(t, enf.enforced[42], "the container should be enforcing")
	assert.True(t, enf.dests["10.244.1.1:5432"])
	assert.True(t, enf.dests["10.244.1.2:5432"])

	// A pod stops matching the selector and another starts.
	set = []Destination{d("10.244.1.2"), d("10.244.7.9")}
	c.Reconcile()

	assert.False(t, enf.dests["10.244.1.1:5432"],
		"a pod that stopped matching the selector must stop being allowed")
	assert.True(t, enf.dests["10.244.1.2:5432"], "a pod that still matches stays allowed")
	assert.True(t, enf.dests["10.244.7.9:5432"], "a pod that started matching becomes allowed")
}

func TestSelectorWithdrawalSpareslearnedAndOtherwisePermittedDestinations(t *testing.T) {
	d := func(ip string) Destination { return Destination{IP: net.ParseIP(ip), Port: 5432} }

	set := []Destination{d("10.244.1.1"), d("10.244.1.2")}
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, movingPolicies{selector: &set, blocking: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// The container is observed talking to 10.244.1.1 during learning, so that
	// destination is in its own baseline as well as in the selector's set.
	_ = c.HandleNetworkEvent(ipv4Event(42, "10.244.1.1", 5432))
	c.Reconcile()
	require.True(t, enf.enforced[42])

	set = []Destination{d("10.244.1.2")}
	c.Reconcile()

	assert.True(t, enf.dests["10.244.1.1:5432"],
		"a destination the container learned must not be revoked because a selector moved")
}

func TestRefreshSelectorPeersIsANoOpWhereItShouldBe(t *testing.T) {
	set := []Destination{{IP: net.ParseIP("10.0.0.1"), Port: 80}}
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, movingPolicies{selector: &set, blocking: true})

	// Learning: nothing is programmed until the container enforces.
	c.mu.Lock()
	st := c.track(42)
	c.refreshSelectorPeers(42, st)
	c.mu.Unlock()
	assert.Empty(t, enf.dests)

	// Enforcing with an unchanged set: no writes.
	c.mu.Lock()
	st.phase = PhaseEnforcing
	st.overrides = Overrides{SelectorDestinations: append([]Destination(nil), set...)}
	c.refreshSelectorPeers(42, st)
	c.mu.Unlock()
	assert.Empty(t, enf.dests, "an unchanged selector must not rewrite the kernel every ten seconds")

	// A policy that no longer resolves, or is not blocking, leaves the kernel
	// alone rather than withdrawing everything.
	c2 := NewController(logr.Discard(), enf, nil, fakePolicies{ok: false})
	c2.mu.Lock()
	st2 := c2.track(42)
	st2.phase = PhaseEnforcing
	st2.overrides = Overrides{SelectorDestinations: append([]Destination(nil), set...)}
	c2.refreshSelectorPeers(42, st2)
	c2.mu.Unlock()
	assert.Empty(t, enf.dests)
}

func TestRefreshSelectorPeersToleratesEnforcerFailures(t *testing.T) {
	set := []Destination{{IP: net.ParseIP("10.0.0.1"), Port: 80}}
	enf := &fakeEnforcer{}
	enf.err = assert.AnError
	c := NewController(logr.Discard(), enf, nil, movingPolicies{selector: &set, blocking: true})
	c.mu.Lock()
	st := c.track(42)
	st.phase = PhaseEnforcing
	st.overrides = Overrides{SelectorDestinations: []Destination{{IP: net.ParseIP("10.9.9.9"), Port: 80}}}
	c.refreshSelectorPeers(42, st)
	// The failure is counted and logged, not fatal, and the applied set is
	// still advanced: retrying the same write every tick forever would be a
	// log flood, and the next reconcile re-derives it anyway.
	assert.Equal(t, set, st.overrides.SelectorDestinations)
	c.mu.Unlock()
}

func TestLearnDestinationIgnoresAnUnusableEvent(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.mu.Lock()
	st := c.track(42)
	c.learnDestination(st, nil)
	c.mu.Unlock()
	assert.Empty(t, st.dests)
}

// splitPolicies resolves a decision whose allowed set is wider than its
// selector set, which is what an ipBlock peer alongside a selector peer in one
// rule produces.
type splitPolicies struct {
	allowed  []Destination
	selector []Destination
}

func (p splitPolicies) Resolve(uint64, attribution.ContainerRef) (Decision, bool) {
	return Decision{
		PolicyName: "test",
		Mode:       ModeBlocking,
		Overrides: Overrides{
			AllowedDestinations:  p.allowed,
			SelectorDestinations: p.selector,
		},
	}, true
}

func (p splitPolicies) PodMeta(string) (string, string, bool) { return "", "", false }

// A destination that leaves the selector but is still covered by an ipBlock in
// the same policy must not be withdrawn. The kernel allow-set has one kind of
// entry and no provenance, so revoking it would revoke the ipBlock with it.
func TestSelectorWithdrawalSparesADestinationAnIPBlockStillCovers(t *testing.T) {
	shared := Destination{IP: net.ParseIP("10.244.1.1"), Port: 5432}
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, splitPolicies{allowed: []Destination{shared}})
	c.mu.Lock()
	st := c.track(42)
	st.phase = PhaseEnforcing
	st.overrides = Overrides{SelectorDestinations: []Destination{shared}}
	c.refreshSelectorPeers(42, st)
	c.mu.Unlock()

	assert.Empty(t, enf.dests,
		"a destination an ipBlock still covers must not be revoked when the selector drops it")
}
