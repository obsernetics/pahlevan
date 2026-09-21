package netidentity

import (
	"net/netip"
	"sort"
)

// Selector matching, which is what turns a policy peer written as
// "namespaceSelector: {team: payments}" into addresses the kernel can hold.
//
// The allow-set is a hash of an exact (address, port) pair, so a selector has
// no representation in it at all. The only way a selector can enforce anything
// is to be expanded into the set of addresses matching it right now, and
// re-expanded whenever that set changes. Everything here exists to make that
// expansion exact and to make it fail closed when it cannot be.

// Requirement is one matchExpressions entry, in the form the Kubernetes label
// selector uses. Declared here rather than taken from the policy API so this
// package stays below it and can be tested without one.
type Requirement struct {
	Key      string
	Operator string
	Values   []string
}

// Selector is matchLabels plus matchExpressions. An empty selector matches
// everything, which is what an explicitly-written `{}` means in Kubernetes; a
// nil *Selector means "not specified" and is interpreted by the caller.
type Selector struct {
	MatchLabels      map[string]string
	MatchExpressions []Requirement
}

// Empty reports whether the selector constrains nothing.
func (s *Selector) Empty() bool {
	return s == nil || (len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0)
}

// Matches evaluates the selector against a label set. A nil selector matches
// everything; it is the caller that decides whether nil means "everything" or
// "unspecified".
func (s *Selector) Matches(labels map[string]string) bool {
	if s == nil {
		return true
	}
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, req := range s.MatchExpressions {
		if !req.Matches(labels) {
			return false
		}
	}
	return true
}

// Matches evaluates one requirement. An unrecognized operator matches nothing:
// a selector nobody can interpret must not widen what is permitted.
func (r Requirement) Matches(labels map[string]string) bool {
	val, has := labels[r.Key]
	switch r.Operator {
	case "In":
		if !has {
			return false
		}
		return containsString(r.Values, val)
	case "NotIn":
		if !has {
			return true
		}
		return !containsString(r.Values, val)
	case "Exists":
		return has
	case "DoesNotExist":
		return !has
	default:
		return false
	}
}

func containsString(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// PeerSelector is a policy peer written as selectors rather than as a CIDR.
type PeerSelector struct {
	// Namespace selects namespaces by their labels. Nil means "not specified",
	// which - following NetworkPolicy - scopes the peer to PolicyNamespace.
	Namespace *Selector
	// Pod selects pods by their labels within the selected namespaces. Nil
	// means every pod there.
	Pod *Selector
	// PolicyNamespace is the namespace of the PahlevanPolicy the peer came
	// from. PahlevanPolicy is namespaced, and a peer with no namespaceSelector
	// means the policy's own namespace, exactly as it does in a NetworkPolicy.
	PolicyNamespace string
}

// Empty reports whether the peer names neither selector.
func (p PeerSelector) Empty() bool { return p.Namespace == nil && p.Pod == nil }

// Match is the expansion of one PeerSelector against the index right now.
type Match struct {
	// IPs are the addresses to program, sorted so a re-resolution that found
	// the same set produces the same slice and the caller's diff is stable.
	IPs []netip.Addr
	// Pods is how many pods matched, including ones with no usable address.
	Pods int
	// SkippedHostNetwork counts matched pods whose address is their node's
	// address. They are deliberately not expanded: permitting a hostNetwork
	// pod by address means permitting the node, the kubelet and every other
	// hostNetwork pod on it, which is not what the selector said. The count is
	// surfaced so the operator is told rather than left to wonder why their
	// selector produced fewer addresses than pods.
	SkippedHostNetwork int
	// SkippedNoAddress counts matched pods with no address yet - pending, or
	// between sandboxes. They resolve on a later re-resolution.
	SkippedNoAddress int
}

// MatchPeers expands a selector peer into the addresses matching it now.
//
// It fails closed in every direction it can. A peer with no selectors at all
// expands to nothing rather than to the whole cluster. A peer with no
// namespaceSelector and no policy namespace to fall back on expands to
// nothing. A namespace whose labels the index has never seen does not match a
// namespaceSelector, so an index that has not synced yet permits nothing
// rather than everything.
func (s *Store) MatchPeers(sel PeerSelector) Match {
	var m Match
	if sel.Empty() {
		return m
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	namespaces := s.selectNamespacesLocked(sel)
	if len(namespaces) == 0 {
		return m
	}

	seen := make(map[netip.Addr]struct{})
	for _, pod := range s.pods {
		if _, ok := namespaces[pod.namespace]; !ok {
			continue
		}
		if !sel.Pod.Matches(pod.labels) {
			continue
		}
		m.Pods++
		if pod.hostNetwork {
			m.SkippedHostNetwork++
			continue
		}
		if len(pod.addrs) == 0 {
			m.SkippedNoAddress++
			continue
		}
		for _, a := range pod.addrs {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			m.IPs = append(m.IPs, a)
		}
	}
	sort.Slice(m.IPs, func(i, j int) bool { return m.IPs[i].Less(m.IPs[j]) })
	return m
}

// selectNamespacesLocked resolves the namespace half of a peer. Callers must
// hold s.mu.
func (s *Store) selectNamespacesLocked(sel PeerSelector) map[string]struct{} {
	out := map[string]struct{}{}
	if sel.Namespace == nil {
		if sel.PolicyNamespace == "" {
			return out
		}
		out[sel.PolicyNamespace] = struct{}{}
		return out
	}
	for name, labels := range s.nsLabels {
		if sel.Namespace.Matches(labels) {
			out[name] = struct{}{}
		}
	}
	return out
}

// Namespaces is how many namespaces the index has labels for. A resolver that
// reports zero has not synced, and every namespaceSelector will match nothing
// until it has.
func (s *Store) Namespaces() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nsLabels)
}

// Pods is how many pods the index holds, across all namespaces.
func (s *Store) Pods() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pods)
}
