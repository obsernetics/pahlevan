package netname

import (
	"net/netip"
	"testing"
)

// The classification table is the part of this package that runs on every
// event, so it is the part that has to be right for every address family. IPv6
// cases sit alongside their IPv4 equivalents rather than in a section of their
// own: a dual stack cluster gets the v6 address, and a classifier that only
// knew v4 would silently report every one of them as public.
func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		want  Class
		label string
	}{
		// The one that matters most: a workload asking the cloud provider for
		// the node's credentials.
		{"aws gcp azure metadata", "169.254.169.254", ClassMetadata, "cloud-metadata"},
		{"ecs task metadata", "169.254.170.2", ClassMetadata, "cloud-metadata"},
		{"eks pod identity", "169.254.170.23", ClassMetadata, "cloud-metadata"},
		{"alibaba metadata", "100.100.100.200", ClassMetadata, "cloud-metadata"},
		{"ec2 metadata over ipv6", "fd00:ec2::254", ClassMetadata, "cloud-metadata"},

		// Metadata addresses are carved out of link-local and CGNAT space, so
		// the neighbours must not be swept up with them.
		{"link-local neighbour of metadata", "169.254.169.253", ClassLinkLocal, "link-local"},
		{"cgnat neighbour of alibaba metadata", "100.100.100.201", ClassCGNAT, "cgnat"},

		{"rfc1918 ten", "10.42.0.9", ClassPrivate, "private-network"},
		{"rfc1918 172.16", "172.16.5.1", ClassPrivate, "private-network"},
		{"rfc1918 172.31 upper edge", "172.31.255.255", ClassPrivate, "private-network"},
		{"just outside rfc1918 172.32", "172.32.0.1", ClassPublic, ""},
		{"rfc1918 192.168", "192.168.1.1", ClassPrivate, "private-network"},
		{"ipv6 unique local", "fd00:1234::1", ClassPrivate, "private-network"},
		{"ipv6 ula lower edge", "fc00::1", ClassPrivate, "private-network"},

		{"cgnat lower edge", "100.64.0.0", ClassCGNAT, "cgnat"},
		{"cgnat upper edge", "100.127.255.255", ClassCGNAT, "cgnat"},
		{"just below cgnat", "100.63.255.255", ClassPublic, ""},
		{"just above cgnat", "100.128.0.0", ClassPublic, ""},

		{"ipv4 loopback", "127.0.0.1", ClassLoopback, "loopback"},
		{"ipv4 loopback elsewhere in 127/8", "127.3.2.1", ClassLoopback, "loopback"},
		{"ipv6 loopback", "::1", ClassLoopback, "loopback"},

		{"ipv4 link-local", "169.254.3.4", ClassLinkLocal, "link-local"},
		{"ipv6 link-local", "fe80::1", ClassLinkLocal, "link-local"},

		{"ipv4 multicast", "224.0.0.251", ClassMulticast, "multicast"},
		{"ipv6 multicast", "ff02::fb", ClassMulticast, "multicast"},

		{"ipv4 broadcast", "255.255.255.255", ClassBroadcast, "broadcast"},
		{"ipv4 unspecified", "0.0.0.0", ClassUnspecified, "unspecified"},
		{"ipv6 unspecified", "::", ClassUnspecified, "unspecified"},

		{"rfc5737 test-net-1", "192.0.2.1", ClassDocumentation, "documentation"},
		{"rfc5737 test-net-2", "198.51.100.7", ClassDocumentation, "documentation"},
		{"rfc5737 test-net-3", "203.0.113.7", ClassDocumentation, "documentation"},
		{"rfc3849 ipv6 documentation", "2001:db8::4444", ClassDocumentation, "documentation"},

		{"rfc2544 benchmark", "198.18.0.1", ClassBenchmark, "benchmark"},
		{"rfc5180 ipv6 benchmark", "2001:2::1", ClassBenchmark, "benchmark"},

		{"reserved 240/4", "240.0.0.1", ClassReserved, "reserved"},

		// Ordinary public addresses carry no label, because "public" adds
		// nothing to an address the reader can already see.
		{"public ipv4", "8.8.8.8", ClassPublic, ""},
		{"public ipv6", "2606:4700:4700::1111", ClassPublic, ""},

		// A v4 address that arrived through a v6 socket is the same address and
		// must classify the same way.
		{"ipv4-mapped private", "::ffff:10.1.2.3", ClassPrivate, "private-network"},
		{"ipv4-mapped metadata", "::ffff:169.254.169.254", ClassMetadata, "cloud-metadata"},
		{"ipv4-mapped public", "::ffff:8.8.8.8", ClassPublic, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tc.addr, err)
			}
			if got := Classify(addr); got != tc.want {
				t.Errorf("Classify(%s) = %q, want %q", tc.addr, got, tc.want)
			}
			if got := Classify(addr).Label(); got != tc.label {
				t.Errorf("Classify(%s).Label() = %q, want %q", tc.addr, got, tc.label)
			}
		})
	}
}

// An address that did not parse is reported as invalid rather than guessed at:
// a malformed address in an event is a decoding bug, and labelling it would
// hide it.
func TestClassifyInvalidAddress(t *testing.T) {
	if got := Classify(netip.Addr{}); got != ClassInvalid {
		t.Errorf("Classify(zero) = %q, want %q", got, ClassInvalid)
	}
	if got := ClassInvalid.Label(); got != "" {
		t.Errorf("ClassInvalid.Label() = %q, want empty", got)
	}
}
