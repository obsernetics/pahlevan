package policy

import (
	"fmt"
	"net"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/netidentity"
)

// Selector peers.
//
// A peer written as `namespaceSelector: {matchLabels: {team: payments}}` used
// to translate to a warning and nothing else: the CRD accepted it, the agent
// logged once that it could not be represented, and the operator was left with
// a policy they believed restricted cross-namespace egress while the kernel
// allow-set had never heard of it. A rule that is accepted and enforces
// nothing is worse than one that is rejected, because nobody goes looking.
//
// The allow-set is a hash of an exact (address, port) pair, so a selector
// genuinely has no representation in it. What it does have is an expansion:
// the addresses of the pods matching it right now. That is what is programmed,
// and because the set moves, it is re-expanded on every reconcile and the
// difference is written into the kernel (see Controller.refreshSelectorPeers).

// PeerIndex expands a selector peer into the addresses matching it now.
// *netidentity.Store implements it; the interface is here so the translation
// can be tested against a fake and so an agent with no index degrades to the
// previous warn-and-drop behavior rather than failing.
type PeerIndex interface {
	MatchPeers(sel netidentity.PeerSelector) netidentity.Match
}

// Context is the cluster state a translation may consult. The zero value is a
// translation with no cluster state, which is what the operator and the unit
// tests use.
type Context struct {
	// Namespace is the PahlevanPolicy's own namespace. A peer with no
	// namespaceSelector is scoped to it, exactly as in a NetworkPolicy.
	Namespace string
	// Peers is the identity index. Nil means selector peers cannot be
	// expanded and are reported as unrepresentable, as before.
	Peers PeerIndex
}

// resolveSelectorPeer expands one selector peer into destinations for the
// given ports, plus the warnings the operator needs to see.
//
// Two warnings matter more than the rest. An expansion that matched no pods is
// reported, because "my policy allows nothing" and "my selector has a typo"
// look identical from the outside. And a matched hostNetwork pod is reported,
// because its address is its node's: programming it would permit the node, the
// kubelet and every other hostNetwork pod on it, which is a much larger grant
// than the selector asked for, so it is skipped and said out loud.
func (ctx Context) resolveSelectorPeer(
	field string,
	peer policyv1alpha1.NetworkPeer,
	ports []uint16,
) ([]adaptive.Destination, []string) {
	if ctx.Peers == nil {
		return nil, []string{field + " selects peers by label, which this agent cannot " +
			"resolve to addresses; use an ipBlock"}
	}

	sel := netidentity.PeerSelector{
		Namespace:       toIdentitySelector(peer.NamespaceSelector),
		Pod:             toIdentitySelector(peer.PodSelector),
		PolicyNamespace: ctx.Namespace,
	}
	m := ctx.Peers.MatchPeers(sel)

	var warnings []string
	if m.SkippedHostNetwork > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s matches %d hostNetwork pod(s), whose address is their node's; they are not "+
				"permitted, because permitting that address would permit the node and every "+
				"other hostNetwork pod on it", field, m.SkippedHostNetwork))
	}
	if m.SkippedNoAddress > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s matches %d pod(s) with no address yet; they are permitted once they get one",
			field, m.SkippedNoAddress))
	}
	if len(m.IPs) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s currently matches no pod addresses, so it permits nothing", field))
		return nil, warnings
	}

	dests := make([]adaptive.Destination, 0, len(m.IPs)*len(ports))
	for _, a := range m.IPs {
		ip := net.IP(a.AsSlice())
		for _, p := range ports {
			dests = append(dests, adaptive.Destination{IP: ip, Port: p})
		}
	}
	return dests, warnings
}

// toIdentitySelector converts a policy label selector into the neutral one the
// index matches against. A nil selector stays nil, because nil and empty mean
// different things to a peer: nil is "not specified" and empty is "everything".
func toIdentitySelector(in *policyv1alpha1.LabelSelector) *netidentity.Selector {
	if in == nil {
		return nil
	}
	out := &netidentity.Selector{}
	if len(in.MatchLabels) > 0 {
		out.MatchLabels = make(map[string]string, len(in.MatchLabels))
		for k, v := range in.MatchLabels {
			out.MatchLabels[k] = v
		}
	}
	for _, req := range in.MatchExpressions {
		out.MatchExpressions = append(out.MatchExpressions, netidentity.Requirement{
			Key:      req.Key,
			Operator: string(req.Operator),
			Values:   append([]string(nil), req.Values...),
		})
	}
	return out
}
