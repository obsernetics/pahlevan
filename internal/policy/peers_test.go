package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
	"github.com/obsernetics/pahlevan/pkg/netidentity"
)

func peerIndex(t *testing.T) *netidentity.Store {
	t.Helper()
	s := netidentity.New(netidentity.Options{})
	s.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "prod", Labels: map[string]string{"team": "payments"}}})
	s.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "other", Labels: map[string]string{"team": "web"}}})
	s.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p1", Namespace: "prod", Name: "db-0",
			Labels: map[string]string{"app": "db"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.1"},
	})
	s.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p2", Namespace: "prod", Name: "web-0",
			Labels: map[string]string{"app": "web"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.2"},
	})
	s.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p3", Namespace: "other", Name: "db-1",
			Labels: map[string]string{"app": "db"}},
		Status: corev1.PodStatus{PodIP: "10.244.2.1"},
	})
	return s
}

func selectorPolicy(peer policyv1alpha1.NetworkPeer, port int32) policyv1alpha1.PahlevanPolicySpec {
	return policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{{
				Ports: []policyv1alpha1.NetworkPort{{Port: &port}},
				Peers: []policyv1alpha1.NetworkPeer{peer},
			}},
		},
	}
}

// A namespaceSelector peer used to be accepted by the CRD, warned about once
// in the agent log, and enforce nothing at all. The operator believed
// cross-namespace egress was restricted and the kernel had never heard of the
// rule.
func TestNamespaceSelectorPeerNowEnforces(t *testing.T) {
	idx := peerIndex(t)
	d, warnings := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		NamespaceSelector: &policyv1alpha1.LabelSelector{
			MatchLabels: map[string]string{"team": "payments"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.ElementsMatch(t,
		[]string{"10.244.1.1:5432", "10.244.1.2:5432"},
		destStrings(d.Overrides.AllowedDestinations))
	assert.ElementsMatch(t,
		[]string{"10.244.1.1:5432", "10.244.1.2:5432"},
		destStrings(d.Overrides.SelectorDestinations),
		"selector-derived entries are tracked so they can be withdrawn later")
	assert.False(t, hasWarning(warnings, "cannot resolve"))
}

func TestPodSelectorPeerIsScopedToThePolicyNamespace(t *testing.T) {
	idx := peerIndex(t)
	d, _ := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.Equal(t, []string{"10.244.1.1:5432"}, destStrings(d.Overrides.AllowedDestinations),
		"the db pod in another namespace is not selected by a bare podSelector")
}

func TestSelectorAndIPBlockPeersCoexistInOneRule(t *testing.T) {
	idx := peerIndex(t)
	port := int32(5432)
	spec := policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{{
				Ports: []policyv1alpha1.NetworkPort{{Port: &port}},
				Peers: []policyv1alpha1.NetworkPeer{
					{IPBlock: &policyv1alpha1.IPBlock{CIDR: "192.0.2.7/32"}},
					{PodSelector: &policyv1alpha1.LabelSelector{
						MatchLabels: map[string]string{"app": "db"}}},
				},
			}},
		},
	}
	d, _ := TranslateIn("p", spec, time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.ElementsMatch(t, []string{"192.0.2.7:5432", "10.244.1.1:5432"},
		destStrings(d.Overrides.AllowedDestinations))
	assert.Equal(t, []string{"10.244.1.1:5432"}, destStrings(d.Overrides.SelectorDestinations),
		"an ipBlock is fixed and is not re-resolved as pods move")
}

func TestSelectorPeerExpandsBothAddressesOfADualStackPod(t *testing.T) {
	idx := netidentity.New(netidentity.Options{})
	idx.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}})
	idx.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p1", Namespace: "prod", Name: "db-0",
			Labels: map[string]string{"app": "db"}},
		Status: corev1.PodStatus{
			PodIP:  "10.244.1.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.1.1"}, {IP: "fd00::1"}},
		},
	})
	d, _ := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.ElementsMatch(t, []string{"10.244.1.1:5432", "[fd00::1]:5432"},
		destStrings(d.Overrides.AllowedDestinations),
		"an IPv6 peer must be programmed, not dropped")
}

func TestSelectorPeerWarnsWhenItMatchesNothing(t *testing.T) {
	idx := peerIndex(t)
	d, warnings := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "nope"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.Empty(t, d.Overrides.AllowedDestinations)
	assert.True(t, hasWarning(warnings, "matches no pod addresses"),
		"a selector with a typo and a selector that is genuinely empty look identical without this: %v",
		warnings)
}

func TestSelectorPeerWarnsAboutHostNetworkPodsRatherThanPermittingTheNode(t *testing.T) {
	idx := netidentity.New(netidentity.Options{})
	idx.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}})
	idx.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p1", Namespace: "prod", Name: "agent",
			Labels: map[string]string{"app": "agent"}},
		Spec:   corev1.PodSpec{HostNetwork: true, NodeName: "worker-1"},
		Status: corev1.PodStatus{PodIP: "192.168.7.3"},
	})
	d, warnings := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.Empty(t, d.Overrides.AllowedDestinations,
		"permitting a hostNetwork pod's address permits the node and every other hostNetwork pod on it")
	assert.True(t, hasWarning(warnings, "hostNetwork"), "warnings were %v", warnings)
}

func TestSelectorPeerWarnsAboutPodsWithNoAddressYet(t *testing.T) {
	idx := netidentity.New(netidentity.Options{})
	idx.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}})
	idx.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p1", Namespace: "prod", Name: "pending",
			Labels: map[string]string{"app": "db"}},
	})
	_, warnings := TranslateIn("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
	}, 5432), time.Now(), Context{Namespace: "prod", Peers: idx})
	assert.True(t, hasWarning(warnings, "no address yet"), "warnings were %v", warnings)
}

// A deny rule written with a selector denies the addresses matching it now,
// but is not tracked for withdrawal: un-denying an address as a pod stops
// matching would turn a rule's removal into a grant.
func TestSelectorDenyRuleIsNotTrackedForWithdrawal(t *testing.T) {
	idx := peerIndex(t)
	port := int32(5432)
	spec := policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{{
				Action: policyv1alpha1.PolicyActionDeny,
				Ports:  []policyv1alpha1.NetworkPort{{Port: &port}},
				Peers: []policyv1alpha1.NetworkPeer{{
					PodSelector: &policyv1alpha1.LabelSelector{
						MatchLabels: map[string]string{"app": "db"}}}},
			}},
		},
	}
	d, _ := TranslateIn("p", spec, time.Now(), Context{Namespace: "prod", Peers: idx})
	assert.Equal(t, []string{"10.244.1.1:5432"}, destStrings(d.Overrides.DeniedDestinations))
	assert.Empty(t, d.Overrides.SelectorDestinations)
	assert.Empty(t, d.Overrides.AllowedDestinations)
}

func TestSelectorPeerWithNoIndexKeepsTheOldWarning(t *testing.T) {
	d, warnings := Translate("p", selectorPolicy(policyv1alpha1.NetworkPeer{
		NamespaceSelector: &policyv1alpha1.LabelSelector{},
	}, 5432), time.Now())
	assert.Empty(t, d.Overrides.AllowedDestinations)
	assert.True(t, hasWarning(warnings, "this agent cannot resolve to addresses"),
		"warnings were %v", warnings)
}

func TestTranslateSpecInReachesTheIndex(t *testing.T) {
	idx := peerIndex(t)
	d, _, _ := TranslateSpecIn("p", policyv1beta1.PahlevanPolicySpec{
		EnforcementConfig: policyv1beta1.EnforcementConfig{
			Mode: policyv1beta1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1beta1.NetworkPolicy{
			EgressRules: []policyv1beta1.NetworkRule{{
				Ports: []policyv1beta1.NetworkPort{{Port: ptrInt32(5432)}},
				Peers: []policyv1beta1.NetworkPeer{{
					NamespaceSelector: &policyv1beta1.LabelSelector{
						MatchExpressions: []policyv1beta1.LabelSelectorRequirement{{
							Key: "team", Operator: "In", Values: []string{"payments"}}}}}},
			}},
		},
	}, time.Now(), Context{Namespace: "prod", Peers: idx})

	assert.ElementsMatch(t, []string{"10.244.1.1:5432", "10.244.1.2:5432"},
		destStrings(d.Overrides.AllowedDestinations),
		"the v1beta1 entry point must carry the selector through the conversion to v1alpha1")
}

func ptrInt32(v int32) *int32 { return &v }

func TestToIdentitySelector(t *testing.T) {
	assert.Nil(t, toIdentitySelector(nil), "nil and empty mean different things to a peer")

	out := toIdentitySelector(&policyv1alpha1.LabelSelector{})
	require.NotNil(t, out)
	assert.True(t, out.Empty())

	out = toIdentitySelector(&policyv1alpha1.LabelSelector{
		MatchLabels: map[string]string{"app": "db"},
		MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{
			Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"backend"}}},
	})
	assert.Equal(t, map[string]string{"app": "db"}, out.MatchLabels)
	require.Len(t, out.MatchExpressions, 1)
	assert.Equal(t, "In", out.MatchExpressions[0].Operator)
	assert.Equal(t, []string{"backend"}, out.MatchExpressions[0].Values)
}

// A selector is re-expanded on every resolve, so a pod that leaves it leaves
// the allowed set, and one that joins it joins.
func TestSelectorExpansionTracksTheIndex(t *testing.T) {
	idx := peerIndex(t)
	peer := policyv1alpha1.NetworkPeer{
		PodSelector: &policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
	}
	resolve := func() []string {
		d, _ := TranslateIn("p", selectorPolicy(peer, 5432), time.Now(),
			Context{Namespace: "prod", Peers: idx})
		return destStrings(d.Overrides.SelectorDestinations)
	}
	require.Equal(t, []string{"10.244.1.1:5432"}, resolve())

	idx.DeletePod(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		UID: types.UID("p1"), Namespace: "prod", Name: "db-0"}})
	assert.Empty(t, resolve(), "a deleted pod leaves the allowed set")

	idx.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "p9", Namespace: "prod", Name: "db-9",
			Labels: map[string]string{"app": "db"}},
		Status: corev1.PodStatus{PodIP: "10.244.1.9"},
	})
	assert.Equal(t, []string{"10.244.1.9:5432"}, resolve(), "a new matching pod joins it")
}

func TestPeerIndexInterfaceIsSatisfiedByTheStore(t *testing.T) {
	var _ PeerIndex = netidentity.New(netidentity.Options{})
	// And by anything else that answers the one question.
	var _ PeerIndex = stubPeerIndex{}
}

type stubPeerIndex struct{}

func (stubPeerIndex) MatchPeers(netidentity.PeerSelector) netidentity.Match {
	return netidentity.Match{IPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
}
