package netname

import "net/netip"

// Class is what an address is by virtue of where it sits in the address space,
// decided without asking anybody. Classification is a handful of prefix
// comparisons, so it costs nothing on the event path and cannot fail, stall or
// leak - which is why it is the first thing tried and, for most of the
// destinations that turn up in an incident, the only thing needed.
type Class string

const (
	// ClassInvalid is an address that did not parse. Reported rather than
	// guessed at: a malformed address in an event is a decoding bug worth
	// seeing, not something to paper over with a label.
	ClassInvalid Class = ""
	// ClassPublic is a globally routable address. It is the only class with no
	// label of its own - "public" tells an operator nothing they cannot see
	// from the address - so it is the class that falls through to a name.
	ClassPublic Class = "public"
	// ClassMetadata is a cloud instance metadata endpoint. This is the highest
	// value name in the package: a workload reaching 169.254.169.254 is asking
	// the cloud provider for the node's credentials, and that one line is the
	// difference between an operator recognising an SSRF-to-IMDS chain and
	// scrolling past a link-local address.
	ClassMetadata Class = "metadata"
	// ClassCluster is inside an operator-declared cluster CIDR but not in the
	// Service, pod or node map - a pod the informers have not caught up with
	// yet. Naming it beats reporting a pod address as though it left the
	// cluster, which is the false exfiltration alert this avoids.
	ClassCluster Class = "cluster"
	// ClassPrivate is RFC1918 or an IPv6 unique local address: off-cluster but
	// still inside somebody's network, so not the same finding as a connection
	// to the open internet.
	ClassPrivate Class = "private"
	// ClassCGNAT is RFC6598 100.64.0.0/10, the carrier grade NAT range. It also
	// turns up as the address space of several overlay VPNs, so it is worth
	// distinguishing from ordinary RFC1918.
	ClassCGNAT Class = "cgnat"
	// ClassLoopback is 127.0.0.0/8 or ::1 - a sidecar, or the workload talking
	// to itself.
	ClassLoopback Class = "loopback"
	// ClassLinkLocal is 169.254.0.0/16 or fe80::/10, excluding the metadata
	// addresses carved out of it above.
	ClassLinkLocal Class = "link-local"
	// ClassMulticast covers IPv4 224.0.0.0/4 and IPv6 ff00::/8.
	ClassMulticast Class = "multicast"
	// ClassBroadcast is the IPv4 limited broadcast address.
	ClassBroadcast Class = "broadcast"
	// ClassUnspecified is 0.0.0.0 or ::.
	ClassUnspecified Class = "unspecified"
	// ClassDocumentation is a range reserved for documentation and examples
	// (RFC5737, RFC3849). Real traffic to one of these is nearly always a
	// misconfiguration or a copied example, and saying so saves the lookup that
	// would have returned nothing.
	ClassDocumentation Class = "documentation"
	// ClassBenchmark is RFC2544 / RFC5180 benchmarking space.
	ClassBenchmark Class = "benchmark"
	// ClassReserved is IPv4 240.0.0.0/4.
	ClassReserved Class = "reserved"
)

// Label is how the class should appear in an event, or "" when the class adds
// nothing an operator cannot already read off the address. Public addresses
// have no label on purpose: "public 203.0.113.7" is noise, while an empty name
// keeps the existing "external" reading honest until a real name is known.
func (c Class) Label() string {
	switch c {
	case ClassMetadata:
		return "cloud-metadata"
	case ClassCluster:
		return "cluster-network"
	case ClassPrivate:
		return "private-network"
	case ClassCGNAT:
		return "cgnat"
	case ClassLoopback:
		return "loopback"
	case ClassLinkLocal:
		return "link-local"
	case ClassMulticast:
		return "multicast"
	case ClassBroadcast:
		return "broadcast"
	case ClassUnspecified:
		return "unspecified"
	case ClassDocumentation:
		return "documentation"
	case ClassBenchmark:
		return "benchmark"
	case ClassReserved:
		return "reserved"
	default:
		return ""
	}
}

// Metadata endpoints, by exact address rather than by prefix.
//
// Each of these is a single well known address that hands out instance
// credentials, so an exact comparison is both cheaper and more honest than a
// prefix: 169.254.169.254 is the metadata service, while the rest of
// 169.254.0.0/16 is ordinary link-local traffic and should not be reported as
// though a workload had gone looking for credentials.
var metadataAddrs = [...]netip.Addr{
	// AWS, GCP, Azure, OpenStack, DigitalOcean and Oracle all answer here.
	netip.MustParseAddr("169.254.169.254"),
	// ECS task metadata, which hands out the task role credentials.
	netip.MustParseAddr("169.254.170.2"),
	// EKS Pod Identity agent, same credentials by a different door.
	netip.MustParseAddr("169.254.170.23"),
	// Alibaba Cloud.
	netip.MustParseAddr("100.100.100.200"),
	// The IPv6 form of the EC2 instance metadata service. Left out of an
	// IPv4-only check, an IPv6 cluster loses exactly the signal that matters
	// most here, so it is in the same table rather than an afterthought.
	netip.MustParseAddr("fd00:ec2::254"),
}

var (
	cgnat4 = netip.MustParsePrefix("100.64.0.0/10")

	// RFC5737 and RFC3849 documentation space.
	doc4a = netip.MustParsePrefix("192.0.2.0/24")
	doc4b = netip.MustParsePrefix("198.51.100.0/24")
	doc4c = netip.MustParsePrefix("203.0.113.0/24")
	doc6  = netip.MustParsePrefix("2001:db8::/32")

	// RFC2544 and RFC5180 benchmarking space.
	bench4 = netip.MustParsePrefix("198.18.0.0/15")
	bench6 = netip.MustParsePrefix("2001:2::/48")

	reserved4  = netip.MustParsePrefix("240.0.0.0/4")
	broadcast4 = netip.MustParseAddr("255.255.255.255")
)

// Classify places an address in the address space. It never allocates, never
// blocks and never consults anything outside this file, so it is safe to call
// from the ring buffer reader on every event.
//
// Order is deliberate. Metadata addresses are checked before link-local and
// before CGNAT because they are carved out of those ranges and are the more
// specific - and far more interesting - answer.
func Classify(addr netip.Addr) Class {
	if !addr.IsValid() {
		return ClassInvalid
	}
	// An IPv4 address arriving as a 16 byte slice is the same address. Without
	// unmapping, every v4 destination that reached us through a v6 socket would
	// classify as public and lose its label.
	a := addr.Unmap()

	for _, m := range metadataAddrs {
		if a == m {
			return ClassMetadata
		}
	}

	switch {
	case a.IsLoopback():
		return ClassLoopback
	case a.IsUnspecified():
		return ClassUnspecified
	case a.IsMulticast():
		// Before the link-local test: 224.0.0.0/24 is link-local multicast, and
		// "multicast" is the more useful of the two readings.
		return ClassMulticast
	case a.IsLinkLocalUnicast():
		return ClassLinkLocal
	case a == broadcast4:
		// Checked before the reserved test, which would otherwise swallow it.
		return ClassBroadcast
	case a.IsPrivate():
		// netip.IsPrivate covers RFC1918 for v4 and fc00::/7 for v6, so IPv6
		// unique local addresses land here without a second table.
		return ClassPrivate
	case cgnat4.Contains(a):
		return ClassCGNAT
	case doc4a.Contains(a), doc4b.Contains(a), doc4c.Contains(a), doc6.Contains(a):
		return ClassDocumentation
	case bench4.Contains(a), bench6.Contains(a):
		return ClassBenchmark
	case reserved4.Contains(a):
		return ClassReserved
	default:
		return ClassPublic
	}
}
