package grpcapi

import (
	"testing"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// A gRPC subscriber must see the named destination too. Without it, every
// consumer would have to rebuild the address map itself from data the agent
// already has.
func TestToProtoCarriesTheNamedDestination(t *testing.T) {
	got := ToProto(&export.Event{
		Type: export.EventTypeNetwork, Action: export.ActionDeny,
		Network: &export.NetworkInfo{
			DestinationIP: "10.104.22.9", DestinationPort: 5432, Protocol: "TCP",
			DestinationName: "prod/postgres", DestinationKind: "service",
			DestinationPortName: "postgres",
		},
	})
	n := got.GetNetwork()
	if n == nil {
		t.Fatal("no network detail")
	}
	if n.GetDestinationName() != "prod/postgres" {
		t.Errorf("DestinationName = %q", n.GetDestinationName())
	}
	if n.GetDestinationKind() != "service" {
		t.Errorf("DestinationKind = %q", n.GetDestinationKind())
	}
	if n.GetDestinationPortName() != "postgres" {
		t.Errorf("DestinationPortName = %q", n.GetDestinationPortName())
	}
}
