package adaptive

import (
	"net"
	"net/netip"
	"testing"

	"github.com/go-logr/logr"

	"github.com/obsernetics/pahlevan/pkg/netidentity"
)

// The learn path now pays for an identity lookup on every network event, and
// the ring buffer can deliver tens of thousands a second on a busy node. The
// no-index case is the control: the difference between the two is what
// learning identities costs.

func BenchmarkHandleNetworkEvent_NoIndex(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	e := ipv4Event(42, "10.244.1.5", 5432)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleNetworkEvent(e)
	}
}

func BenchmarkHandleNetworkEvent_WithIndex(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = stubIndex{
		netip.MustParseAddr("10.244.1.5"): {
			Kind: netidentity.PeerPod, Namespace: "prod", Name: "api-7d9f-xx", Workload: "api"},
	}
	e := ipv4Event(42, "10.244.1.5", 5432)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleNetworkEvent(e)
	}
}

// An external destination misses the index and falls through to the
// classifier, which is the path an outbound scan drives.
func BenchmarkHandleNetworkEvent_External(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = stubIndex{}
	e := ipv4Event(42, "8.8.8.8", 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleNetworkEvent(e)
	}
}

func BenchmarkHandleNetworkEvent_IPv6(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: true})
	c.Peers = stubIndex{
		netip.MustParseAddr("fd00::5"): {
			Kind: netidentity.PeerPod, Namespace: "prod", Name: "cache-0", Workload: "cache"},
	}
	e := ipv6Event(42, "fd00::5", 6379)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleNetworkEvent(e)
	}
}

// The selector refresh runs once per enforcing container per reconcile tick,
// so the unchanged case has to be cheap: that is what it does almost every
// time.
func BenchmarkRefreshSelectorPeers_Unchanged(b *testing.B) {
	set := benchSelectorSet(64)
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		movingPolicies{selector: &set, blocking: true})
	c.mu.Lock()
	st := c.track(42)
	st.phase = PhaseEnforcing
	st.overrides = Overrides{SelectorDestinations: set}
	c.mu.Unlock()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.mu.Lock()
		c.refreshSelectorPeers(42, st)
		c.mu.Unlock()
	}
}

func BenchmarkRefreshSelectorPeers_OnePodMoved(b *testing.B) {
	set := benchSelectorSet(64)
	moved := append([]Destination(nil), set...)
	moved[0] = Destination{IP: net.IPv4(10, 250, 0, 1), Port: 5432}

	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		movingPolicies{selector: &set, blocking: true})
	c.mu.Lock()
	st := c.track(42)
	st.phase = PhaseEnforcing
	c.mu.Unlock()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.mu.Lock()
		st.overrides = Overrides{SelectorDestinations: moved}
		c.refreshSelectorPeers(42, st)
		c.mu.Unlock()
	}
}

func benchSelectorSet(n int) []Destination {
	out := make([]Destination, n)
	for i := range out {
		out[i] = Destination{IP: net.IPv4(10, 244, byte(i/256), byte(i%256)), Port: 5432}
	}
	return out
}
