package netname

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Classification is what runs on every network event, so it has to be free.
// Allocating here would allocate once per connect(2) the node sees.
func BenchmarkClassify(b *testing.B) {
	addrs := []netip.Addr{
		netip.MustParseAddr("10.244.1.7"),
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("fd00:1234::1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Classify(addrs[i%len(addrs)])
	}
}

// The hot path proper: classify, then serve the name from cache.
func BenchmarkLookupCacheHit(b *testing.B) {
	n := New(Options{})
	defer n.Close()
	addr := netip.MustParseAddr("93.184.216.34")
	n.Observe("example.com", []netip.Addr{addr}, time.Hour)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n.Lookup(addr).Name == "" {
			b.Fatal("cache miss")
		}
	}
}

// The commonest answer of all: an address that a range names outright, with no
// cache entry and no lookup.
func BenchmarkLookupRangeLabel(b *testing.B) {
	n := New(Options{})
	defer n.Close()
	addr := netip.MustParseAddr("169.254.169.254")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n.Lookup(addr).Name == "" {
			b.Fatal("unnamed")
		}
	}
}

// What the export path actually calls, including the net.IP conversion.
func BenchmarkName(b *testing.B) {
	n := New(Options{})
	defer n.Close()
	ip := net.ParseIP("10.244.1.7")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.Name(ip)
	}
}

// An unnamed public address with reverse DNS off, which is the default: it must
// cost a classification and a cache probe, and nothing else.
func BenchmarkLookupMiss(b *testing.B) {
	n := New(Options{})
	defer n.Close()
	addr := netip.MustParseAddr("8.8.8.8")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.Lookup(addr)
	}
}

func BenchmarkObserve(b *testing.B) {
	n := New(Options{})
	defer n.Close()
	addrs := []netip.Addr{netip.MustParseAddr("93.184.216.34")}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Observe("example.com", addrs, time.Hour)
	}
}
