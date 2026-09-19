package export

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/netname"
)

// (*netname.Namer).Name is meant to be handed straight to the pipeline, so the
// signatures have to stay compatible. A compile time check is cheaper than
// discovering the drift when somebody wires an agent.
var _ ExternalNameFunc = netname.New(netname.Options{}).Name

func netEvent4(ip string, port uint16) *ebpf.NetworkEvent {
	return &ebpf.NetworkEvent{
		DstIP:   binary.LittleEndian.Uint32(net.ParseIP(ip).To4()),
		DstPort: port, Protocol: 6, Family: 2, Comm: "curl", CgroupID: 1,
	}
}

func netEvent6(ip string, port uint16) *ebpf.NetworkEvent {
	e := &ebpf.NetworkEvent{DstPort: port, Protocol: 6, Family: 10, Comm: "curl", CgroupID: 1}
	copy(e.DstIP6[:], net.ParseIP(ip).To16())
	return e
}

func onlyEvent(t *testing.T, sink *captureSink) *Event {
	t.Helper()
	all := sink.all()
	if len(all) != 1 {
		t.Fatalf("got %d events, want 1", len(all))
	}
	if all[0].Network == nil {
		t.Fatal("no network detail")
	}
	return all[0]
}

// The gap this closes: a destination the cluster map does not know used to
// reach the operator as a bare address at the exact moment they were trying to
// understand an incident.
func TestHandlerNamesExternalDestinations(t *testing.T) {
	namer := netname.New(netname.Options{})
	defer namer.Close()

	tests := []struct {
		name  string
		event *ebpf.NetworkEvent
		want  string
	}{
		{"cloud metadata", netEvent4("169.254.169.254", 80), "cloud-metadata"},
		{"ec2 metadata over ipv6", netEvent6("fd00:ec2::254", 80), "cloud-metadata"},
		{"off-cluster private network", netEvent4("172.20.9.9", 443), "private-network"},
		{"carrier grade nat", netEvent4("100.64.3.4", 443), "cgnat"},
		{"ipv6 unique local", netEvent6("fd12::5", 443), "private-network"},
		// An ordinary public address is left alone: "public" would tell the
		// reader nothing the address does not, so the event keeps saying
		// external.
		{"public address keeps the external reading", netEvent4("8.8.8.8", 4444), "external"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureSink{}
			h := NewHandler(sink, HandlerOptions{
				Destination: func(net.IP, uint16) (string, string, string) {
					return "external", "external", ""
				},
				External: namer.Name,
			})
			if err := h.HandleNetworkEvent(tc.event); err != nil {
				t.Fatalf("HandleNetworkEvent: %v", err)
			}
			n := onlyEvent(t, sink).Network
			if n.DestinationName != tc.want {
				t.Errorf("DestinationName = %q, want %q", n.DestinationName, tc.want)
			}
			if n.DestinationKind != "external" {
				t.Errorf("DestinationKind = %q, want external: naming is presentation only and must not restate the kind alerts are written against", n.DestinationKind)
			}
		})
	}
}

// The cluster map wins. A Service name is a stronger statement than anything an
// address range can say, and an external namer that overwrote it would turn
// "prod/postgres" back into a label.
func TestExternalNamingDoesNotOverrideTheClusterMap(t *testing.T) {
	namer := netname.New(netname.Options{})
	defer namer.Close()

	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{
		Destination: func(net.IP, uint16) (string, string, string) {
			return "prod/postgres", "service", "postgres"
		},
		External: namer.Name,
	})
	// An RFC1918 address, which the namer would happily call private-network.
	if err := h.HandleNetworkEvent(netEvent4("10.104.22.9", 5432)); err != nil {
		t.Fatalf("HandleNetworkEvent: %v", err)
	}
	n := onlyEvent(t, sink).Network
	if n.DestinationName != "prod/postgres" {
		t.Errorf("DestinationName = %q, want prod/postgres", n.DestinationName)
	}
	if n.DestinationKind != "service" {
		t.Errorf("DestinationKind = %q, want service", n.DestinationKind)
	}
	if n.DestinationPortName != "postgres" {
		t.Errorf("DestinationPortName = %q, want postgres", n.DestinationPortName)
	}
}

// Without a cluster map at all the name still lands, and the kind stays empty:
// claiming "external" with nothing to check against would be inventing the
// field an alert is written on.
func TestExternalNamingWithoutAClusterMap(t *testing.T) {
	namer := netname.New(netname.Options{})
	defer namer.Close()

	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{External: namer.Name})
	if err := h.HandleNetworkEvent(netEvent4("169.254.169.254", 80)); err != nil {
		t.Fatalf("HandleNetworkEvent: %v", err)
	}
	n := onlyEvent(t, sink).Network
	if n.DestinationName != "cloud-metadata" {
		t.Errorf("DestinationName = %q, want cloud-metadata", n.DestinationName)
	}
	if n.DestinationKind != "" {
		t.Errorf("DestinationKind = %q, want empty", n.DestinationKind)
	}
}

// stalledResolver never answers, which is what a resolver does during the kind
// of incident this feature exists for.
type stalledResolver struct{ release chan struct{} }

func (r stalledResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.release:
		return nil, nil
	}
}

// The event must leave the handler whether or not anything can be named. An
// exporter stalled on a resolver drops exactly the events the incident is made
// of, which is strictly worse than printing an address.
func TestHandlerDoesNotBlockOnNaming(t *testing.T) {
	res := stalledResolver{release: make(chan struct{})}
	namer := netname.New(netname.Options{ReverseDNS: true, Resolver: res})
	t.Cleanup(func() {
		close(res.release)
		namer.Close()
	})

	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{
		Destination: func(net.IP, uint16) (string, string, string) {
			return "external", "external", ""
		},
		External: namer.Name,
	})

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := 0; i < 100; i++ {
			// All distinct and all public, so every one of them is a candidate
			// for the resolver that is never going to answer.
			_ = h.HandleNetworkEvent(netEvent4(netip.AddrFrom4([4]byte{8, 8, byte(i), 1}).String(), 4444))
		}
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		if elapsed > time.Second {
			t.Fatalf("100 events took %v with a resolver that never answers", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handler blocked on the resolver")
	}

	if got := len(sink.all()); got != 100 {
		t.Fatalf("got %d events, want 100: naming must never cost an event", got)
	}
	for _, ev := range sink.all() {
		if ev.Network.DestinationName != "external" {
			t.Fatalf("DestinationName = %q, want the unchanged external reading", ev.Network.DestinationName)
		}
	}
}

// The pipeline has to carry the hook through, or nothing above ever reaches a
// real agent.
func TestPipelineCarriesTheExternalNamer(t *testing.T) {
	namer := netname.New(netname.Options{})
	defer namer.Close()

	p, err := New(Config{
		Stdout:   false,
		FilePath: t.TempDir() + "/events.jsonl",
		External: namer.Name,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("no pipeline built")
	}
	defer func() { _ = p.Close() }()
	if p.Handler.ext == nil {
		t.Fatal("the external namer did not reach the handler")
	}
}

// Regression: an AF_INET6 event carries its address in DstIP6, and the
// conversion used to read DstIP regardless. Every IPv6 destination therefore
// left the agent as "0.0.0.0" - nothing to name, nothing to search for, and
// every v6 destination on the node indistinguishable from every other.
func TestIPv6DestinationIsRendered(t *testing.T) {
	tests := []struct {
		name  string
		event *ebpf.NetworkEvent
		want  string
	}{
		{"global unicast", netEvent6("2606:4700:4700::1111", 443), "2606:4700:4700::1111"},
		{"unique local", netEvent6("fd12::5", 443), "fd12::5"},
		{"link local", netEvent6("fe80::1", 443), "fe80::1"},
		// A v4 destination that arrived through a v6 socket reads as the v4
		// address it is, so it matches the cluster map.
		{"v4-mapped", netEvent6("::ffff:10.0.0.1", 443), "10.0.0.1"},
		{"ipv4 event is unchanged", netEvent4("10.0.0.1", 443), "10.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureSink{}
			h := NewHandler(sink, HandlerOptions{})
			if err := h.HandleNetworkEvent(tc.event); err != nil {
				t.Fatalf("HandleNetworkEvent: %v", err)
			}
			if got := onlyEvent(t, sink).Network.DestinationIP; got != tc.want {
				t.Errorf("DestinationIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// Naming sits on the ring buffer reader's path, so its cost has to be visible.
func BenchmarkHandleNetworkEventWithNaming(b *testing.B) {
	namer := netname.New(netname.Options{})
	defer namer.Close()

	h := NewHandler(&captureSink{}, HandlerOptions{
		Destination: func(net.IP, uint16) (string, string, string) {
			return "external", "external", ""
		},
		External: namer.Name,
	})
	ev := netEvent4("169.254.169.254", 80)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleNetworkEvent(ev)
	}
}

// The same path without naming, as the baseline the number above is read
// against.
func BenchmarkHandleNetworkEventWithoutNaming(b *testing.B) {
	h := NewHandler(&captureSink{}, HandlerOptions{
		Destination: func(net.IP, uint16) (string, string, string) {
			return "external", "external", ""
		},
	})
	ev := netEvent4("169.254.169.254", 80)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleNetworkEvent(ev)
	}
}
