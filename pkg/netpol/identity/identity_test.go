package identity

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/obsernetics/pahlevan/pkg/netidentity"
	"github.com/obsernetics/pahlevan/pkg/netpol"
)

// ---------------------------------------------------------------- fixtures

// pod builds a pod whose controller is spelled "Kind/Name", the way a roster
// spells a workload. Replicas of one workload share it, which is the case that
// matters: a selector derived from one replica also selects its siblings.
func pod(ns, name, ip, workload string, labels map[string]string) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(ns + "/" + name), Labels: labels,
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
	if kind, owner, ok := strings.Cut(workload, "/"); ok {
		yes := true
		p.OwnerReferences = []metav1.OwnerReference{{
			Kind: kind, Name: owner, Controller: &yes,
		}}
	}
	return p
}

// service carries a selector and a different set of its own labels, which is
// the whole point: the two must never be confused for one another.
func service(ns, name, clusterIP string, selector, labels map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("svc/" + ns + "/" + name), Labels: labels,
		},
		Spec: corev1.ServiceSpec{ClusterIP: clusterIP, Selector: selector},
	}
}

func node(name, ip string, labels map[string]string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("node/" + name), Labels: labels},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: ip},
		}},
	}
}

// cluster is the fixture every test resolves against: one web pod, a postgres
// Service in front of two postgres pods, and a node.
func cluster() netidentity.Snapshot {
	return Snapshot(
		[]corev1.Pod{
			pod("prod", "web-1", "10.244.0.1", "Deployment/web", map[string]string{"app": "web"}),
			pod("db", "pg-0", "10.244.2.1", "StatefulSet/pg", map[string]string{"app": "postgres"}),
			pod("db", "pg-1", "10.244.2.2", "StatefulSet/pg", map[string]string{"app": "postgres"}),
		},
		[]corev1.Service{
			service("db", "postgres", "10.96.0.5",
				map[string]string{"app": "postgres"},
				map[string]string{"app": "postgres-chart", "team": "data"}),
		},
		[]corev1.Node{node("worker-1", "192.168.1.10", map[string]string{"app": "kubelet"})},
	)
}

// ------------------------------------------------------------------ lookup

func TestAPodResolvesToItsWorkload(t *testing.T) {
	r := New(cluster(), roster(cluster()))

	p, ok := r.Lookup("10.244.2.1")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerPod, p.Kind)
	assert.Equal(t, "db", p.Namespace)
	assert.Equal(t, "pg-0", p.Name)
	assert.Equal(t, "StatefulSet/pg", p.Workload,
		"the workload is what a policy can name, spelled the way the roster spells it")
}

func TestAPodWithNoControllerHasNoWorkload(t *testing.T) {
	// A bare pod is its own unit, and it is also one that never comes back
	// under that name. pkg/netpol groups it by name and says so in the report;
	// claiming a workload for it would attach a policy to something that does
	// not exist.
	snap := Snapshot([]corev1.Pod{
		pod("prod", "loose", "10.244.0.9", "", map[string]string{"app": "loose"}),
	}, nil, nil)

	p, ok := New(snap, roster(snap)).Lookup("10.244.0.9")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerPod, p.Kind)
	assert.Equal(t, "loose", p.Name)
	assert.Empty(t, p.Workload)
}

func TestAServiceResolvesToItsSelectorAndNotToItsOwnLabels(t *testing.T) {
	// The trap this adapter exists for. pkg/netidentity carries a Service's
	// metadata labels, because that is what identifies the Service.
	// pkg/netpol writes a peer's labels straight into a podSelector. Passing
	// the labels through would emit a podSelector over whatever pods happen to
	// carry app=postgres-chart - which is not the set behind the Service, and
	// is bounded by nothing the traffic showed.
	r := New(cluster(), roster(cluster()))

	p, ok := r.Lookup("10.96.0.5")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerService, p.Kind)
	assert.Equal(t, map[string]string{"app": "postgres"}, p.Labels)
	assert.NotContains(t, p.Labels, "team", "the Service's own labels are not a pod selector")
}

func TestAServiceWithNoSelectorResolvesWithNoLabels(t *testing.T) {
	// An ExternalName Service, or one whose endpoints are managed by hand. The
	// pods behind it cannot be named, and pkg/netpol refuses a peer it cannot
	// name rather than inventing a selector - so the honest answer here is no
	// labels, not a guess.
	snap := Snapshot(nil, []corev1.Service{
		service("db", "external", "10.96.0.9", nil, map[string]string{"app": "db"}),
	}, nil)

	p, ok := New(snap, roster(snap)).Lookup("10.96.0.9")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerService, p.Kind)
	assert.Empty(t, p.Labels)
}

func TestANodeCarriesNoLabels(t *testing.T) {
	// A NetworkPolicy has no node selector, so a node can only ever be a
	// literal address. Handing its labels over would invite a podSelector
	// built from them - this node's app=kubelet would select every pod that
	// shares it.
	p, ok := New(cluster(), roster(cluster())).Lookup("192.168.1.10")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerNode, p.Kind)
	assert.Equal(t, "worker-1", p.Name)
	assert.Empty(t, p.Labels)
}

func TestAHostNetworkPodResolvesToItsNodeRatherThanToItself(t *testing.T) {
	// A hostNetwork pod reports its node's address as its PodIP. Answering
	// with the pod would let a rule written about that pod be read as a rule
	// about the node, the kubelet, and every other hostNetwork pod there.
	hostPod := pod("kube-system", "proxy-1", "192.168.1.10", "DaemonSet/kube-proxy",
		map[string]string{"app": "kube-proxy"})
	hostPod.Spec.HostNetwork = true
	snap := Snapshot([]corev1.Pod{hostPod}, nil,
		[]corev1.Node{node("worker-1", "192.168.1.10", nil)})

	p, ok := New(snap, roster(snap)).Lookup("192.168.1.10")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerNode, p.Kind)
	assert.Empty(t, p.Labels, "a node peer has no selector to be built from")
}

func TestAPublicAddressIsExternalWithNoName(t *testing.T) {
	p, ok := New(cluster(), roster(cluster())).Lookup("93.184.216.34")
	require.True(t, ok, "a globally routable address no cluster object holds is outside the cluster")
	assert.Equal(t, netpol.PeerExternal, p.Kind)
	assert.Empty(t, p.Name, `"public 93.184.216.34" tells a reader nothing the address does not`)
}

func TestTheMetadataEndpointIsNamed(t *testing.T) {
	// The highest-value name in a baseline: a workload reaching here is asking
	// the cloud provider for the node's credentials.
	p, ok := New(cluster(), roster(cluster())).Lookup("169.254.169.254")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerExternal, p.Kind)
	assert.Equal(t, "cloud-metadata", p.Name)
}

func TestAnUnindexedPrivateAddressStaysUnresolved(t *testing.T) {
	// It may well be a pod in a namespace this listing did not cover. Calling
	// it external would put a false statement in the report for exactly the
	// case an operator is most likely to be reading.
	for _, ip := range []string{
		"10.244.9.9",      // RFC1918: an unlisted pod, for all this knows
		"100.64.0.1",      // CGNAT, which several overlay VPNs use
		"169.254.1.1",     // link-local, but not a metadata endpoint
		"fd00:1234::1",    // IPv6 unique local
		"127.0.0.1",       // a sidecar, not a peer
		"::",              // unspecified
		"224.0.0.1",       // multicast
		"255.255.255.255", // broadcast
	} {
		_, ok := New(cluster(), roster(cluster())).Lookup(ip)
		assert.False(t, ok, "%s must not be reported as outside the cluster", ip)
	}
}

func TestAnUnparseableAddressResolvesToNothing(t *testing.T) {
	r := New(cluster(), roster(cluster()))
	for _, ip := range []string{"", "not-an-address", "10.0.0.256", "10.0.0.1:80"} {
		_, ok := r.Lookup(ip)
		assert.False(t, ok, "%q", ip)
	}
}

func TestAnIPv4MappedAddressIsTheSameAddress(t *testing.T) {
	p, ok := New(cluster(), roster(cluster())).Lookup("::ffff:10.244.2.1")
	require.True(t, ok, "a v4 destination that arrived over a v6 socket is the same pod")
	assert.Equal(t, "pg-0", p.Name)
}

func TestANilResolverResolvesNothing(t *testing.T) {
	var r *Resolver
	_, ok := r.Lookup("10.244.0.1")
	assert.False(t, ok)

	_, ok = (&Resolver{}).Lookup("10.244.0.1")
	assert.False(t, ok, "a Resolver with no index must not claim to know anything")
}

// indexOf is an index that answers with one peer, including a kind this
// package has never heard of.
type indexOf netidentity.Peer

func (i indexOf) Lookup(_ netip.Addr) (netidentity.Peer, bool) { return netidentity.Peer(i), true }

func TestAnUnrecognizedKindCanOnlyBeAnAddress(t *testing.T) {
	// A kind this package does not know must fall to the one that becomes an
	// ipBlock, never to the one that becomes a selector.
	r := &Resolver{idx: indexOf(netidentity.Peer{
		Kind:   netidentity.PeerKind("Gateway"),
		Name:   "edge",
		Labels: map[string]string{"app": "edge"},
	})}

	p, ok := r.Lookup("10.244.0.1")
	require.True(t, ok)
	assert.Equal(t, netpol.PeerExternal, p.Kind)
	assert.Empty(t, p.Labels, "an unknown kind must not hand a label set to a podSelector")
}

func TestLabelsHandedOutAreCopies(t *testing.T) {
	// pkg/netidentity shares the informer's label map and documents it as read
	// only. A caller that mutated what it was given would corrupt the index.
	snap := cluster()
	r := New(snap, roster(snap))

	p, ok := r.Lookup("10.244.2.1")
	require.True(t, ok)
	p.Labels["app"] = "mutated"

	again, _ := r.Lookup("10.244.2.1")
	assert.Equal(t, "postgres", again.Labels["app"])
	assert.Equal(t, "postgres", snap.Pods[1].Labels["app"])

	svc, _ := r.Lookup("10.96.0.5")
	svc.Labels["app"] = "mutated"
	svcAgain, _ := r.Lookup("10.96.0.5")
	assert.Equal(t, "postgres", svcAgain.Labels["app"])
}

// ------------------------------------------------------- against pkg/netpol

// observation is one web pod's learned egress, which every generator case
// below starts from.
func observation(dests ...netpol.Destination) []netpol.Observation {
	return []netpol.Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1"},
		Destinations: dests,
	}}
}

// roster is the generator's view of the same fixture. It is derived from the
// same pods the index holds, which is the pairing New's comment requires.
func roster(snap netidentity.Snapshot) netpol.Roster {
	out := make(netpol.Roster, 0, len(snap.Pods))
	for i := range snap.Pods {
		p := &snap.Pods[i]
		workload := ""
		if len(p.OwnerReferences) > 0 {
			workload = p.OwnerReferences[0].Kind + "/" + p.OwnerReferences[0].Name
		}
		out = append(out, netpol.Pod{
			Namespace: p.Namespace, Name: p.Name, Workload: workload, Labels: p.Labels,
		})
	}
	return out
}

func dest(ip string, port int32) netpol.Destination {
	return netpol.Destination{IP: ip, Port: port, Protocol: corev1.ProtocolTCP}
}

func findingsText(s netpol.Subject) string {
	var b []byte
	for _, f := range s.Findings {
		b = append(b, f.Message...)
		b = append(b, '\n')
	}
	return string(b)
}

func TestAServiceBecomesTheSelectorOverThePodsBehindIt(t *testing.T) {
	snap := cluster()
	res := netpol.Generate(observation(dest("10.96.0.5", 5432), dest("10.96.0.5", 53)),
		netpol.Options{Roster: roster(snap), Resolver: New(snap, roster(snap)), Egress: true})

	require.Len(t, res.Policies, 1)
	to := res.Policies[0].Spec.Egress[0].To[0]
	require.NotNil(t, to.PodSelector)
	assert.Equal(t, map[string]string{"app": "postgres"}, to.PodSelector.MatchLabels)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "db"},
		to.NamespaceSelector.MatchLabels)
	assert.Nil(t, to.IPBlock, "a ClusterIP is not the address the traffic ends up at")
	assert.Contains(t, findingsText(res.Subjects[0]), "2 pod(s) behind it")
}

func TestANodeStaysALiteralAddress(t *testing.T) {
	snap := cluster()
	res := netpol.Generate(observation(dest("192.168.1.10", 10250), dest("10.96.0.5", 53)),
		netpol.Options{Roster: roster(snap), Resolver: New(snap, roster(snap)), Egress: true})

	require.Len(t, res.Policies, 1)
	var node *networkingv1.NetworkPolicyPeer
	for i, rule := range res.Policies[0].Spec.Egress {
		if rule.To[0].IPBlock != nil {
			node = &res.Policies[0].Spec.Egress[i].To[0]
		}
	}
	require.NotNil(t, node, "a node has no selector a NetworkPolicy can write")
	assert.Equal(t, "192.168.1.10/32", node.IPBlock.CIDR)
	assert.Nil(t, node.PodSelector)
	assert.Contains(t, findingsText(res.Subjects[0]), "no node selector")
}

func TestAnExternalAddressIsReportedAsOutsideTheCluster(t *testing.T) {
	snap := cluster()
	res := netpol.Generate(observation(dest("169.254.169.254", 80), dest("10.96.0.5", 53)),
		netpol.Options{Roster: roster(snap), Resolver: New(snap, roster(snap)), Egress: true})

	require.Len(t, res.Policies, 1)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "cloud-metadata")
	assert.Contains(t, text, "outside the cluster")
	assert.NotContains(t, text, "could not be resolved to any identity")
}

// TestResolvingAPeerNeverLoosensThePolicy is the guard on the whole change.
//
// Wiring a real index in resolves peers that used to resolve to nothing, and
// the one way that can go wrong is for a rule to end up permitting more than
// the evidence supports. So the same baseline is generated twice - once
// against a resolver that knows nothing, once against the index - and the
// second result is held to the first: the subject is selected by the same
// labels, every rule is still scoped to one namespace by name, no selector is
// empty (an empty selector means every pod), and no address was widened past
// the single host that was observed.
func TestResolvingAPeerNeverLoosensThePolicy(t *testing.T) {
	snap := cluster()
	obs := observation(
		dest("10.96.0.5", 5432),     // a Service: unresolved before, a selector now
		dest("192.168.1.10", 10250), // a node: unresolved before, named now
		dest("93.184.216.34", 443),  // off cluster: unresolved before, external now
		dest("10.244.2.1", 53),      // a pod, resolved either way
	)
	opt := netpol.Options{Roster: roster(snap), Egress: true}

	blind := netpol.Generate(obs, opt)
	opt.Resolver = New(snap, roster(snap))
	seeing := netpol.Generate(obs, opt)

	require.Len(t, blind.Policies, 1)
	require.Len(t, seeing.Policies, 1)

	assert.Equal(t, blind.Policies[0].Spec.PodSelector, seeing.Policies[0].Spec.PodSelector,
		"resolving a destination says nothing about which pods the policy applies to")
	assert.Equal(t, blind.Policies[0].Spec.PolicyTypes, seeing.Policies[0].Spec.PolicyTypes)

	for i, rule := range seeing.Policies[0].Spec.Egress {
		require.Len(t, rule.To, 1, "rule %d: a rule's to and ports are a cross product", i)
		to := rule.To[0]
		switch {
		case to.IPBlock != nil:
			assert.Nil(t, to.PodSelector, "rule %d: an address is not also a selector", i)
			assert.Empty(t, to.IPBlock.Except)
			assert.True(t,
				strings.HasSuffix(to.IPBlock.CIDR, "/32") || strings.HasSuffix(to.IPBlock.CIDR, "/128"),
				"rule %d: %s is wider than the one host that was observed", i, to.IPBlock.CIDR)
		default:
			require.NotNil(t, to.PodSelector, "rule %d: a peer is a selector or an address", i)
			assert.NotEmpty(t, to.PodSelector.MatchLabels,
				"rule %d: an empty podSelector selects every pod in the namespace", i)
			require.NotNil(t, to.NamespaceSelector,
				"rule %d: a peer with no namespaceSelector means the policy's own namespace", i)
			assert.Len(t, to.NamespaceSelector.MatchLabels, 1,
				"rule %d: a peer is scoped to exactly one namespace, by name", i)
			assert.Contains(t, to.NamespaceSelector.MatchLabels, "kubernetes.io/metadata.name")
		}
	}

	// And the point of resolving at all: more of the baseline is written down,
	// not less.
	assert.GreaterOrEqual(t, seeing.Subjects[0].Expressed, blind.Subjects[0].Expressed,
		"resolving a peer must not drop a destination that used to be expressed")
}
