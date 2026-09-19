package netname

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingResolver is the resolver this package is designed to survive: one
// that never answers. Every test that asserts the event path does not stall
// uses it, because a resolver that is merely slow can pass by luck.
type blockingResolver struct {
	calls   atomic.Int64
	live    atomic.Int64
	maxLive atomic.Int64
	release chan struct{}
}

func newBlockingResolver() *blockingResolver {
	return &blockingResolver{release: make(chan struct{})}
}

func (r *blockingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	r.calls.Add(1)
	live := r.live.Add(1)
	for {
		old := r.maxLive.Load()
		if live <= old || r.maxLive.CompareAndSwap(old, live) {
			break
		}
	}
	defer r.live.Add(-1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.release:
		return nil, nil
	}
}

// answeringResolver returns a fixed name, for the enrichment path.
type answeringResolver struct {
	calls atomic.Int64
	names []string
	err   error
}

func (r *answeringResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.calls.Add(1)
	return r.names, r.err
}

// Active reverse DNS is opt-in, and a Namer handed a resolver but not the flag
// must never use it. A PTR query on an attacker's address tells the attacker
// their address was seen, so this default is a security property, not a
// preference: it has to be asserted, not assumed.
func TestReverseDNSIsOffByDefault(t *testing.T) {
	res := &answeringResolver{names: []string{"evil.example.com."}}
	n := New(Options{Resolver: res})
	defer n.Close()

	for i := 0; i < 10; i++ {
		if got := n.Lookup(netip.MustParseAddr("8.8.8.8")); got.Name != "" {
			t.Fatalf("Lookup name = %q, want empty with reverse DNS off", got.Name)
		}
	}
	// Give any goroutine that should not exist a chance to run.
	time.Sleep(20 * time.Millisecond)
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver called %d times, want 0: reverse DNS must be opt-in", got)
	}
}

// New(Options{}) is what a caller that has not configured anything gets, and it
// must not be able to send a packet at all.
func TestZeroOptionsDoesNoLookups(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	if n.reverse {
		t.Error("reverse DNS enabled with zero Options")
	}
	if n.resolver != nil {
		t.Error("a resolver was installed with zero Options")
	}
	if got := n.Lookup(netip.MustParseAddr("203.0.113.7")); got.Name != "documentation" {
		t.Errorf("Lookup name = %q, want the range label", got.Name)
	}
}

// The whole point of the design: the event path must return at once even when
// the resolver never will. If this test can hang, so can the exporter during an
// incident, which is exactly when the events matter most.
func TestLookupDoesNotWaitOnTheResolver(t *testing.T) {
	res := newBlockingResolver()
	n := New(Options{ReverseDNS: true, Resolver: res})
	t.Cleanup(func() {
		close(res.release)
		n.Close()
	})

	addr := netip.MustParseAddr("198.51.100.9")
	start := time.Now()
	got := n.Lookup(addr)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("Lookup took %v, want an immediate return", elapsed)
	}
	if got.Name != "documentation" {
		// 198.51.100.0/24 is documentation space, so the range answers before
		// any lookup is even considered. Asserted so that a regression in the
		// ordering - lookup first, label second - shows up here.
		t.Errorf("Lookup name = %q, want documentation", got.Name)
	}

	// And the same for an address with no label, where a lookup really is
	// scheduled.
	start = time.Now()
	got = n.Lookup(netip.MustParseAddr("8.8.4.4"))
	elapsed = time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Lookup of an unlabelled address took %v, want an immediate return", elapsed)
	}
	if got.Name != "" {
		t.Errorf("Lookup name = %q, want empty while the lookup is in flight", got.Name)
	}
}

// A lookup that does complete must reach the next event about that address.
// Naming is asynchronous, not absent.
func TestReverseLookupEnrichesLaterLookups(t *testing.T) {
	res := &answeringResolver{names: []string{"host-8-8-8-8.example.net."}}
	n := New(Options{ReverseDNS: true, Resolver: res})
	defer n.Close()

	addr := netip.MustParseAddr("8.8.8.8")
	if got := n.Lookup(addr).Name; got != "" {
		t.Fatalf("first Lookup name = %q, want empty", got)
	}

	var got Result
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got = n.Lookup(addr); got.Name != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got.Name != "host-8-8-8-8.example.net" {
		t.Fatalf("Lookup name = %q, want the resolved name with its trailing dot trimmed", got.Name)
	}
	if got.Source != SourceReverse {
		t.Errorf("Source = %q, want %q", got.Source, SourceReverse)
	}
}

// A resolver that says "no such record" must be asked once, not once per
// packet. Otherwise the naming feature becomes the outbound flood it was meant
// to describe.
func TestFailedLookupIsNotRetriedPerEvent(t *testing.T) {
	res := &answeringResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}
	n := New(Options{ReverseDNS: true, Resolver: res})
	defer n.Close()

	addr := netip.MustParseAddr("8.8.8.8")
	n.Lookup(addr)
	// Wait for the first lookup to be recorded as a failure.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && n.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if n.Len() == 0 {
		t.Fatal("the failed lookup was not remembered")
	}
	for i := 0; i < 500; i++ {
		if name := n.Lookup(addr).Name; name != "" {
			t.Fatalf("Lookup name = %q, want empty", name)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if got := res.calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times for one address, want 1", got)
	}
}

// In-flight lookups are capped. A scan of a thousand distinct destinations must
// not turn into a thousand concurrent DNS queries leaving the node.
func TestInFlightLookupsAreBounded(t *testing.T) {
	res := newBlockingResolver()
	n := New(Options{ReverseDNS: true, Resolver: res, MaxInFlight: 3})
	t.Cleanup(func() {
		close(res.release)
		n.Close()
	})

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				// 8.x.y.z, all public, all distinct.
				a := netip.AddrFrom4([4]byte{8, byte(worker), byte(i >> 8), byte(i)})
				n.Lookup(a)
			}
		}(w)
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	if got := res.maxLive.Load(); got > 3 {
		t.Fatalf("%d concurrent lookups, want at most 3", got)
	}
	if got := res.calls.Load(); got > 8 {
		t.Fatalf("%d lookups started for 2000 destinations, want a small bounded number", got)
	}
}

// An observed answer is a name the workload itself was given, so it beats the
// range label: "private-network" is true of 10.2.0.7, but the operator is
// looking for "grafana.internal".
func TestObservedNameBeatsTheRangeLabel(t *testing.T) {
	n := New(Options{})
	defer n.Close()

	addr := netip.MustParseAddr("10.2.0.7")
	if got := n.Lookup(addr).Name; got != "private-network" {
		t.Fatalf("Lookup name = %q, want private-network before observation", got)
	}
	n.Observe("Grafana.Internal.", []netip.Addr{addr}, time.Minute)
	got := n.Lookup(addr)
	if got.Name != "grafana.internal" {
		t.Errorf("Lookup name = %q, want grafana.internal", got.Name)
	}
	if got.Source != SourceObserved {
		t.Errorf("Source = %q, want %q", got.Source, SourceObserved)
	}
	if got.Class != ClassPrivate {
		t.Errorf("Class = %q, want %q: observing a name must not change what the address is", got.Class, ClassPrivate)
	}
}

// Observation works the same for IPv6, including an answer carrying both
// families for one name.
func TestObserveDualStack(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	v4 := netip.MustParseAddr("93.184.216.34")
	v6 := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
	n.Observe("example.com", []netip.Addr{v4, v6}, time.Minute)
	if got := n.Lookup(v4).Name; got != "example.com" {
		t.Errorf("v4 Lookup name = %q, want example.com", got)
	}
	if got := n.Lookup(v6).Name; got != "example.com" {
		t.Errorf("v6 Lookup name = %q, want example.com", got)
	}
}

// A name lives in JSON events, webhook payloads and a terminal, and the far end
// chooses its text. Anything that could forge a log line or rewrite a terminal
// is dropped along with the name rather than sanitised into something
// plausible.
func TestObserveRejectsHostileNames(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"newline forges a log line", "evil\nlevel=info msg=allowed", ""},
		{"carriage return", "evil\rmsg=allowed", ""},
		{"terminal escape", "evil\x1b[2Kbenign.example.com", ""},
		{"nul", "evil\x00.example.com", ""},
		{"space", "two words", ""},
		{"empty", "", ""},
		{"root dot only", ".", ""},
		{"too long", string(make([]byte, 300)), ""},
		{"trailing dot trimmed", "api.github.com.", "api.github.com"},
		{"case folded", "API.GitHub.COM", "api.github.com"},
		{"underscore is allowed in practice", "_tcp.svc.local", "_tcp.svc.local"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeHost(tc.host); got != tc.want {
				t.Errorf("sanitizeHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}

	n := New(Options{})
	defer n.Close()
	addr := netip.MustParseAddr("8.8.8.8")
	n.Observe("evil\nlevel=info", []netip.Addr{addr}, time.Minute)
	if got := n.Lookup(addr).Name; got != "" {
		t.Errorf("Lookup name = %q, want empty: a hostile name must not be stored", got)
	}
}

// A hostile answer must not be able to pin a name in the cache forever, so a
// TTL longer than the configured maximum is clamped to it.
func TestObserveClampsTheTTL(t *testing.T) {
	now := time.Unix(0, 0)
	n := New(Options{TTL: time.Minute, Now: func() time.Time { return now }})
	defer n.Close()

	addr := netip.MustParseAddr("8.8.8.8")
	n.Observe("forever.example.com", []netip.Addr{addr}, 10*365*24*time.Hour)
	if got := n.Lookup(addr).Name; got != "forever.example.com" {
		t.Fatalf("Lookup name = %q, want the observed name", got)
	}
	now = now.Add(2 * time.Minute)
	if got := n.Lookup(addr).Name; got != "" {
		t.Fatalf("Lookup name = %q after the clamped TTL expired, want empty", got)
	}
}

// An address in the cluster's own CIDRs that the Service and pod map did not
// know is a pod the informers have not caught up with. Reporting it as though
// it had left the cluster is a false exfiltration alert.
func TestClusterCIDRBeatsPrivate(t *testing.T) {
	n := New(Options{ClusterCIDRs: []netip.Prefix{
		netip.MustParsePrefix("10.244.0.0/16"),
		netip.MustParsePrefix("fd12:3456::/64"),
	}})
	defer n.Close()

	for _, tc := range []struct {
		addr string
		want string
	}{
		{"10.244.1.5", "cluster-network"},
		{"fd12:3456::9", "cluster-network"},
		{"10.99.1.5", "private-network"},
		// A cluster CIDR must not override a metadata address, which is never
		// inside one and is the more important finding regardless.
		{"169.254.169.254", "cloud-metadata"},
	} {
		if got := n.Lookup(netip.MustParseAddr(tc.addr)).Name; got != tc.want {
			t.Errorf("Lookup(%s) name = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// Name is the signature the export path calls, taking a net.IP so the caller
// does not convert twice.
func TestNameFromNetIP(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	if got := n.Name(net.ParseIP("169.254.169.254")); got != "cloud-metadata" {
		t.Errorf("Name = %q, want cloud-metadata", got)
	}
	// net.ParseIP returns a 16 byte slice for a v4 address, so this also covers
	// the unmapping the classifier depends on.
	if got := n.Name(net.ParseIP("10.0.0.1")); got != "private-network" {
		t.Errorf("Name = %q, want private-network", got)
	}
	if got := n.Name(nil); got != "" {
		t.Errorf("Name(nil) = %q, want empty", got)
	}
	if got := n.Name(net.IP{1, 2, 3}); got != "" {
		t.Errorf("Name(malformed) = %q, want empty", got)
	}
}

// Close must be safe on a Namer that never resolved anything, and must not
// leave a goroutine behind when it did.
func TestCloseIsSafe(t *testing.T) {
	n := New(Options{})
	n.Close()
	n.Close()

	res := newBlockingResolver()
	m := New(Options{ReverseDNS: true, Resolver: res})
	m.Lookup(netip.MustParseAddr("8.8.8.8"))
	done := make(chan struct{})
	go func() {
		m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: an in-flight lookup was not cancelled")
	}
	// A lookup scheduled after Close must not start a goroutine.
	before := res.calls.Load()
	m.Lookup(netip.MustParseAddr("8.8.4.4"))
	time.Sleep(20 * time.Millisecond)
	if got := res.calls.Load(); got != before {
		t.Errorf("resolver called after Close: %d, want %d", got, before)
	}
}

// Concurrent use is the normal case: one Namer serves every ring buffer reader.
func TestConcurrentUse(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				a := netip.AddrFrom4([4]byte{10, byte(worker), byte(i >> 8), byte(i)})
				n.Observe("svc.example.com", []netip.Addr{a}, time.Minute)
				n.Lookup(a)
				n.Lookup(netip.MustParseAddr("169.254.169.254"))
			}
		}(w)
	}
	wg.Wait()
}

// Turning reverse DNS on without naming a resolver must use the process
// resolver rather than silently doing nothing, which would look identical to
// the feature working and finding no names.
func TestReverseDNSDefaultsToTheProcessResolver(t *testing.T) {
	n := New(Options{ReverseDNS: true})
	defer n.Close()
	if n.resolver != net.DefaultResolver {
		t.Errorf("resolver = %#v, want net.DefaultResolver", n.resolver)
	}
}

// Defaults are applied rather than left at zero, since a zero cache size or a
// zero in-flight cap would mean no caching and no lookups at all.
func TestDefaultsAreApplied(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	if n.cache.max != DefaultCacheSize {
		t.Errorf("cache max = %d, want %d", n.cache.max, DefaultCacheSize)
	}
	if n.maxInFlight != DefaultMaxInFlight {
		t.Errorf("maxInFlight = %d, want %d", n.maxInFlight, DefaultMaxInFlight)
	}
	if n.timeout != DefaultLookupTimeout || n.ttl != DefaultTTL || n.negativeTTL != DefaultNegativeTTL {
		t.Errorf("timeouts = %v/%v/%v, want the documented defaults", n.timeout, n.ttl, n.negativeTTL)
	}
}

// Junk in must not become a name out. A zero address is a decoding bug
// upstream, and labelling it would hide it.
func TestInvalidAddressesAreNotNamed(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	if got := n.Lookup(netip.Addr{}); got != (Result{}) {
		t.Errorf("Lookup(zero) = %+v, want the zero Result", got)
	}
	// An answer carrying a junk address must not poison the cache with it.
	good := netip.MustParseAddr("8.8.8.8")
	n.Observe("mixed.example.com", []netip.Addr{{}, good}, time.Minute)
	if got := n.Len(); got != 1 {
		t.Errorf("cache holds %d entries, want 1: the invalid address was stored", got)
	}
	if got := n.Lookup(good).Name; got != "mixed.example.com" {
		t.Errorf("Lookup name = %q, want mixed.example.com", got)
	}
}

// An observation with nothing to observe is a no-op rather than an empty entry.
func TestObserveIgnoresEmptyInput(t *testing.T) {
	n := New(Options{})
	defer n.Close()
	n.Observe("example.com", nil, time.Minute)
	n.Observe("", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, time.Minute)
	if got := n.Len(); got != 0 {
		t.Errorf("cache holds %d entries, want 0", got)
	}
}
