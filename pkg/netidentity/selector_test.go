package netidentity

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func strs(t *testing.T, addrs []netip.Addr) []string {
	t.Helper()
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func seeded(t *testing.T) *Store {
	t.Helper()
	s := New(Options{})
	s.UpsertNamespace(ns("prod", map[string]string{"team": "payments", "kubernetes.io/metadata.name": "prod"}))
	s.UpsertNamespace(ns("staging", map[string]string{"team": "payments", "kubernetes.io/metadata.name": "staging"}))
	s.UpsertNamespace(ns("other", map[string]string{"team": "web", "kubernetes.io/metadata.name": "other"}))

	s.UpsertPod(pod("p1", "prod", "ledger-1", "10.244.1.1", withLabels(map[string]string{"app": "ledger"})))
	s.UpsertPod(pod("p2", "prod", "web-1", "10.244.1.2", withLabels(map[string]string{"app": "web"})))
	s.UpsertPod(pod("p3", "staging", "ledger-2", "10.244.2.1", withLabels(map[string]string{"app": "ledger"})))
	s.UpsertPod(pod("p4", "other", "web-2", "10.244.3.1", withLabels(map[string]string{"app": "web"})))
	return s
}

func TestMatchPeersByNamespaceSelector(t *testing.T) {
	s := seeded(t)
	m := s.MatchPeers(PeerSelector{
		Namespace: &Selector{MatchLabels: map[string]string{"team": "payments"}},
	})
	assert.Equal(t, []string{"10.244.1.1", "10.244.1.2", "10.244.2.1"}, strs(t, m.IPs))
	assert.Equal(t, 3, m.Pods)
}

func TestMatchPeersByPodSelectorScopedToThePolicyNamespace(t *testing.T) {
	s := seeded(t)
	m := s.MatchPeers(PeerSelector{
		Pod:             &Selector{MatchLabels: map[string]string{"app": "ledger"}},
		PolicyNamespace: "prod",
	})
	assert.Equal(t, []string{"10.244.1.1"}, strs(t, m.IPs),
		"a pod selector with no namespace selector stays in the policy's namespace")
}

func TestMatchPeersIntersectsBothSelectors(t *testing.T) {
	s := seeded(t)
	m := s.MatchPeers(PeerSelector{
		Namespace: &Selector{MatchLabels: map[string]string{"team": "payments"}},
		Pod:       &Selector{MatchLabels: map[string]string{"app": "ledger"}},
	})
	assert.Equal(t, []string{"10.244.1.1", "10.244.2.1"}, strs(t, m.IPs))
}

func TestMatchPeersEmptyNamespaceSelectorMeansEveryNamespace(t *testing.T) {
	s := seeded(t)
	m := s.MatchPeers(PeerSelector{
		Namespace: &Selector{},
		Pod:       &Selector{MatchLabels: map[string]string{"app": "web"}},
	})
	assert.Equal(t, []string{"10.244.1.2", "10.244.3.1"}, strs(t, m.IPs),
		"an explicitly empty namespaceSelector is the whole cluster, as in a NetworkPolicy")
}

// Every way this can fail must fail closed. A selector that resolves to
// nothing permits nothing, which is the same outcome the operator had before
// selectors were enforceable at all. A selector that resolved to "everything"
// because the index had not synced would be strictly worse than the bug this
// change fixes.
func TestMatchPeersFailsClosed(t *testing.T) {
	s := seeded(t)

	t.Run("no selectors at all", func(t *testing.T) {
		m := s.MatchPeers(PeerSelector{PolicyNamespace: "prod"})
		assert.Empty(t, m.IPs)
		assert.Zero(t, m.Pods)
	})
	t.Run("pod selector with no namespace to fall back on", func(t *testing.T) {
		m := s.MatchPeers(PeerSelector{Pod: &Selector{}})
		assert.Empty(t, m.IPs)
	})
	t.Run("namespace the index has never seen", func(t *testing.T) {
		empty := New(Options{})
		empty.UpsertPod(pod("p1", "prod", "ledger-1", "10.244.1.1"))
		m := empty.MatchPeers(PeerSelector{Namespace: &Selector{MatchLabels: map[string]string{"team": "payments"}}})
		assert.Empty(t, m.IPs, "an unsynced namespace index must match nothing")
	})
	t.Run("unknown operator", func(t *testing.T) {
		m := s.MatchPeers(PeerSelector{
			Namespace: &Selector{},
			Pod:       &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "Sorta", Values: []string{"web"}}}},
		})
		assert.Empty(t, m.IPs, "an operator nobody can interpret must not widen the allowed set")
	})
}

func TestMatchPeersTracksSelectorChanges(t *testing.T) {
	s := seeded(t)
	sel := PeerSelector{
		Namespace: &Selector{},
		Pod:       &Selector{MatchLabels: map[string]string{"app": "ledger"}},
	}
	require.Equal(t, []string{"10.244.1.1", "10.244.2.1"}, strs(t, s.MatchPeers(sel).IPs))

	// A pod that stops matching stops being in the set. Relabelling is the
	// cheapest way for a workload to leave a selector, and a set that did not
	// notice would keep permitting it.
	s.UpsertPod(pod("p1", "prod", "ledger-1", "10.244.1.1", withLabels(map[string]string{"app": "retired"})))
	assert.Equal(t, []string{"10.244.2.1"}, strs(t, s.MatchPeers(sel).IPs))

	// A deleted pod leaves the set too.
	s.DeletePod(pod("p3", "staging", "ledger-2", "10.244.2.1"))
	assert.Empty(t, s.MatchPeers(sel).IPs)

	// And a new matching pod joins it.
	s.UpsertPod(pod("p9", "prod", "ledger-3", "10.244.1.9", withLabels(map[string]string{"app": "ledger"})))
	assert.Equal(t, []string{"10.244.1.9"}, strs(t, s.MatchPeers(sel).IPs))
}

func TestMatchPeersSkipsHostNetworkPodsExplicitly(t *testing.T) {
	s := New(Options{})
	s.UpsertNamespace(ns("prod", map[string]string{"team": "payments"}))
	s.UpsertPod(pod("p1", "prod", "normal", "10.244.1.1", withLabels(map[string]string{"app": "x"})))
	s.UpsertPod(pod("p2", "prod", "hostnet", "192.168.7.3",
		withLabels(map[string]string{"app": "x"}), withHostNetwork("worker-1")))
	s.UpsertPod(pod("p3", "prod", "pending", "", withLabels(map[string]string{"app": "x"})))

	m := s.MatchPeers(PeerSelector{
		Namespace: &Selector{},
		Pod:       &Selector{MatchLabels: map[string]string{"app": "x"}},
	})
	assert.Equal(t, []string{"10.244.1.1"}, strs(t, m.IPs),
		"a hostNetwork pod's address is its node's, so permitting it would permit the node")
	assert.Equal(t, 3, m.Pods)
	assert.Equal(t, 1, m.SkippedHostNetwork)
	assert.Equal(t, 1, m.SkippedNoAddress)
}

func TestMatchPeersDualStackPodContributesBothAddresses(t *testing.T) {
	s := New(Options{})
	s.UpsertNamespace(ns("prod", nil))
	s.UpsertPod(pod("p1", "prod", "api", "", withIPs("10.244.1.1", "fd00::1"), withLabels(map[string]string{"app": "api"})))

	m := s.MatchPeers(PeerSelector{Namespace: &Selector{}, Pod: &Selector{}})
	assert.Equal(t, []string{"10.244.1.1", "fd00::1"}, strs(t, m.IPs),
		"an IPv6 peer must be programmable, not dropped")
}

func TestSelectorMatching(t *testing.T) {
	labels := map[string]string{"app": "api", "tier": "backend"}
	cases := []struct {
		name string
		sel  *Selector
		want bool
	}{
		{"nil matches", nil, true},
		{"empty matches", &Selector{}, true},
		{"matchLabels hit", &Selector{MatchLabels: map[string]string{"app": "api"}}, true},
		{"matchLabels miss", &Selector{MatchLabels: map[string]string{"app": "web"}}, false},
		{"In hit", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "In", Values: []string{"api", "web"}}}}, true},
		{"In miss", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "In", Values: []string{"web"}}}}, false},
		{"In on absent key", &Selector{MatchExpressions: []Requirement{{Key: "zone", Operator: "In", Values: []string{"a"}}}}, false},
		{"NotIn hit", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "NotIn", Values: []string{"web"}}}}, true},
		{"NotIn miss", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "NotIn", Values: []string{"api"}}}}, false},
		{"NotIn on absent key", &Selector{MatchExpressions: []Requirement{{Key: "zone", Operator: "NotIn", Values: []string{"a"}}}}, true},
		{"Exists", &Selector{MatchExpressions: []Requirement{{Key: "tier", Operator: "Exists"}}}, true},
		{"Exists miss", &Selector{MatchExpressions: []Requirement{{Key: "zone", Operator: "Exists"}}}, false},
		{"DoesNotExist", &Selector{MatchExpressions: []Requirement{{Key: "zone", Operator: "DoesNotExist"}}}, true},
		{"DoesNotExist miss", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "DoesNotExist"}}}, false},
		{"unknown operator", &Selector{MatchExpressions: []Requirement{{Key: "app", Operator: "??"}}}, false},
		{"all requirements must hold", &Selector{
			MatchLabels:      map[string]string{"app": "api"},
			MatchExpressions: []Requirement{{Key: "zone", Operator: "Exists"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.sel.Matches(labels))
		})
	}
}

func TestSelectorEmptyAndPeerSelectorEmpty(t *testing.T) {
	var nilSel *Selector
	assert.True(t, nilSel.Empty())
	assert.True(t, (&Selector{}).Empty())
	assert.False(t, (&Selector{MatchLabels: map[string]string{"a": "b"}}).Empty())
	assert.False(t, (&Selector{MatchExpressions: []Requirement{{Key: "a", Operator: "Exists"}}}).Empty())

	assert.True(t, PeerSelector{}.Empty())
	assert.False(t, PeerSelector{Pod: &Selector{}}.Empty())
	assert.False(t, PeerSelector{Namespace: &Selector{}}.Empty())
}

func TestNamespaceDeletionRemovesItsLabels(t *testing.T) {
	s := seeded(t)
	s.DeleteNamespace(ns("prod", nil))
	m := s.MatchPeers(PeerSelector{Namespace: &Selector{MatchLabels: map[string]string{"team": "payments"}}})
	assert.Equal(t, []string{"10.244.2.1"}, strs(t, m.IPs),
		"a namespace whose labels are gone matches nothing")
	assert.Equal(t, 2, s.Namespaces())
}
