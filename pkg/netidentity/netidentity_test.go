package netidentity

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, ok := ParseAddr(s)
	require.True(t, ok, "parse %q", s)
	return a
}

func pod(uid, ns, name, ip string, opts ...func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Namespace: ns, Name: name},
		Status:     corev1.PodStatus{PodIP: ip},
	}
	if ip != "" {
		p.Status.PodIPs = []corev1.PodIP{{IP: ip}}
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withLabels(l map[string]string) func(*corev1.Pod) {
	return func(p *corev1.Pod) { p.Labels = l }
}

func withOwner(kind, name string) func(*corev1.Pod) {
	yes := true
	return func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
	}
}

func withHostNetwork(node string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
		p.Spec.NodeName = node
	}
}

func withIPs(ips ...string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Status.PodIP = ips[0]
		p.Status.PodIPs = nil
		for _, ip := range ips {
			p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: ip})
		}
	}
}

func TestLookupUnknownAddressIsExternal(t *testing.T) {
	s := New(Options{})
	p, ok := s.Lookup(addr(t, "8.8.8.8"))
	assert.False(t, ok)
	assert.Equal(t, PeerExternal, p.Kind)

	p, ok = s.Lookup(netip.Addr{})
	assert.False(t, ok)
	assert.Equal(t, PeerExternal, p.Kind)
}

func TestLookupPodServiceAndNode(t *testing.T) {
	s := New(Options{})
	s.UpsertPod(pod("pod-a", "prod", "api-7d9f-xx", "10.244.1.5",
		withOwner("ReplicaSet", "api-7d9f"), withLabels(map[string]string{"app": "api"})))
	s.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{UID: "svc-a", Namespace: "prod", Name: "postgres"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.12", ClusterIPs: []string{"10.96.0.12"}},
	})
	s.UpsertNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{UID: "node-a", Name: "worker-1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "192.168.7.3"},
			{Type: corev1.NodeHostName, Address: "worker-1"},
		}},
	})

	p, ok := s.Lookup(addr(t, "10.244.1.5"))
	require.True(t, ok)
	assert.Equal(t, PeerPod, p.Kind)
	assert.Equal(t, "prod", p.Namespace)
	assert.Equal(t, "api-7d9f-xx", p.Name)
	assert.Equal(t, "api", p.Workload, "a ReplicaSet owner must unwind to its Deployment")
	assert.Equal(t, "pod:prod/api", p.String())

	p, ok = s.Lookup(addr(t, "10.96.0.12"))
	require.True(t, ok)
	assert.Equal(t, PeerService, p.Kind)
	assert.Equal(t, "service:prod/postgres", p.String())

	p, ok = s.Lookup(addr(t, "192.168.7.3"))
	require.True(t, ok)
	assert.Equal(t, PeerNode, p.Kind)
	assert.Equal(t, "node:worker-1", p.String())

	_, ok = s.Lookup(addr(t, "1.1.1.1"))
	assert.False(t, ok, "a hostname address is not an address and must not be indexed")
}

// TestDeletedPodDoesNotAnswerForRecycledAddress is the headline guard.
//
// A CNI hands a freed pod address to the next pod within seconds. If the index
// keeps answering with the dead pod, a brand new workload in a different
// namespace inherits whatever trust the dead one had.
func TestDeletedPodDoesNotAnswerForRecycledAddress(t *testing.T) {
	s := New(Options{})
	ip := "10.244.3.17"
	old := pod("old-uid", "payments", "ledger-abc", ip, withOwner("StatefulSet", "ledger"))
	s.UpsertPod(old)

	p, ok := s.Lookup(addr(t, ip))
	require.True(t, ok)
	require.Equal(t, "payments", p.Namespace)

	s.DeletePod(old)

	p, ok = s.Lookup(addr(t, ip))
	assert.False(t, ok, "a deleted pod must not keep answering for its address")
	assert.Equal(t, PeerExternal, p.Kind)
	assert.NotEqual(t, "payments", p.Namespace)

	when, released := s.Released(addr(t, ip))
	assert.True(t, released, "a released address must be recorded as released")
	assert.False(t, when.IsZero())

	// The address is handed to a different workload in a different namespace.
	fresh := pod("new-uid", "attacker", "scratch-xyz", ip, withOwner("ReplicaSet", "scratch-9ab"))
	s.UpsertPod(fresh)

	p, ok = s.Lookup(addr(t, ip))
	require.True(t, ok)
	assert.Equal(t, "attacker", p.Namespace, "the recycled address must resolve to its new owner")
	assert.Equal(t, "scratch-xyz", p.Name)
	assert.Equal(t, "scratch", p.Workload)

	_, released = s.Released(addr(t, ip))
	assert.False(t, released, "a rebound address is no longer released")
}

// A delete for the dead pod can be delivered after the add for its successor.
// Withdrawing by address alone would evict the live pod and leave the address
// unresolved, so the withdrawal is matched on the owning UID.
func TestLateDeleteDoesNotEvictTheSuccessor(t *testing.T) {
	s := New(Options{})
	ip := "10.244.3.17"
	old := pod("old-uid", "payments", "ledger-abc", ip)
	fresh := pod("new-uid", "web", "front-def", ip)

	s.UpsertPod(old)
	s.UpsertPod(fresh) // successor's add arrives first
	s.DeletePod(old)   // predecessor's delete arrives late

	p, ok := s.Lookup(addr(t, ip))
	require.True(t, ok, "the live pod must keep its address when a late delete arrives")
	assert.Equal(t, "web", p.Namespace)
	assert.Equal(t, "front-def", p.Name)
	assert.Equal(t, uint64(1), s.Conflicts(), "the overlap must be counted, not hidden")
}

// A delete can arrive with an emptied status. Withdrawing by the object's own
// PodIP would then withdraw nothing and the dead pod would keep answering.
func TestDeleteWithEmptiedStatusStillWithdraws(t *testing.T) {
	s := New(Options{})
	ip := "10.244.9.9"
	live := pod("uid-1", "prod", "api", ip)
	s.UpsertPod(live)

	stripped := pod("uid-1", "prod", "api", "")
	s.DeletePod(stripped)

	_, ok := s.Lookup(addr(t, ip))
	assert.False(t, ok, "a delete with no status must still withdraw the bound address")
}

// A pod that changes address must not keep answering on the old one.
func TestPodAddressChangeWithdrawsTheOldAddress(t *testing.T) {
	s := New(Options{})
	s.UpsertPod(pod("uid-1", "prod", "api", "10.244.0.1"))
	s.UpsertPod(pod("uid-1", "prod", "api", "10.244.0.2"))

	_, ok := s.Lookup(addr(t, "10.244.0.1"))
	assert.False(t, ok)
	p, ok := s.Lookup(addr(t, "10.244.0.2"))
	require.True(t, ok)
	assert.Equal(t, "api", p.Name)
}

// Re-observing the same pod at the same address is not a release, so it must
// not leave a tombstone behind.
func TestReobservingAPodDoesNotTombstoneItsAddress(t *testing.T) {
	s := New(Options{})
	p := pod("uid-1", "prod", "api", "10.244.0.1")
	s.UpsertPod(p)
	s.UpsertPod(p)

	_, released := s.Released(addr(t, "10.244.0.1"))
	assert.False(t, released)
	_, ok := s.Lookup(addr(t, "10.244.0.1"))
	assert.True(t, ok)
}

func TestGenerationDistinguishesRebindingFromRefresh(t *testing.T) {
	s := New(Options{})
	ip := addr(t, "10.244.5.5")
	s.UpsertPod(pod("uid-1", "prod", "api", "10.244.5.5"))
	_, gen1, ok := s.LookupGeneration(ip)
	require.True(t, ok)

	s.UpsertPod(pod("uid-1", "prod", "api", "10.244.5.5"))
	_, gen2, _ := s.LookupGeneration(ip)
	assert.Greater(t, gen2, gen1, "every write advances the generation")

	s.DeletePod(pod("uid-1", "prod", "api", "10.244.5.5"))
	s.UpsertPod(pod("uid-2", "other", "worker", "10.244.5.5"))
	p, gen3, ok := s.LookupGeneration(ip)
	require.True(t, ok)
	assert.Greater(t, gen3, gen2)
	assert.Equal(t, "other", p.Namespace)

	_, _, ok = s.LookupGeneration(addr(t, "203.0.113.1"))
	assert.False(t, ok)
	_, _, ok = s.LookupGeneration(netip.Addr{})
	assert.False(t, ok)
}

func TestHostNetworkPodResolvesToItsNodeNotToThePod(t *testing.T) {
	nodeIP := "192.168.7.3"
	t.Run("with the node indexed", func(t *testing.T) {
		s := New(Options{})
		s.UpsertNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{UID: "node-a", Name: "worker-1"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: nodeIP}}},
		})
		s.UpsertPod(pod("hp-1", "kube-system", "kube-proxy-aaa", nodeIP, withHostNetwork("worker-1")))
		s.UpsertPod(pod("hp-2", "monitoring", "node-exporter-bbb", nodeIP, withHostNetwork("worker-1")))

		p, ok := s.Lookup(addr(t, nodeIP))
		require.True(t, ok)
		assert.Equal(t, PeerNode, p.Kind, "a shared node address must never resolve to one hostNetwork pod")
		assert.Equal(t, "worker-1", p.Name)

		all := s.LookupAll(addr(t, nodeIP))
		assert.Len(t, all, 3, "every claim on the address stays visible")
		assert.Zero(t, s.Conflicts(), "a node sharing with hostNetwork pods is not a conflict")
	})

	t.Run("without the node indexed", func(t *testing.T) {
		s := New(Options{})
		s.UpsertPod(pod("hp-1", "kube-system", "kube-proxy-aaa", nodeIP, withHostNetwork("worker-1")))
		p, ok := s.Lookup(addr(t, nodeIP))
		require.True(t, ok)
		assert.Equal(t, PeerNode, p.Kind)
		assert.Equal(t, "worker-1", p.Name, "the node is named from spec.nodeName")
	})
}

func TestLookupAllIsDeterministicAndEmptyForUnknown(t *testing.T) {
	s := New(Options{})
	assert.Nil(t, s.LookupAll(addr(t, "10.0.0.1")))
	assert.Nil(t, s.LookupAll(netip.Addr{}))

	ip := "10.10.10.10"
	s.UpsertPod(pod("a", "zeta", "p1", ip, withHostNetwork("n1")))
	s.UpsertPod(pod("b", "alpha", "p2", ip, withHostNetwork("n1")))
	first := s.LookupAll(addr(t, ip))
	second := s.LookupAll(addr(t, ip))
	assert.Equal(t, first, second)
	require.Len(t, first, 2)
	assert.Equal(t, "alpha", first[0].Namespace, "sorted by namespace within a kind")
}

func TestIPv6IsIndexedAndUnmappedConsistently(t *testing.T) {
	s := New(Options{})
	s.UpsertPod(pod("uid-1", "prod", "api", "", withIPs("fd00::5", "10.244.0.9")))

	p, ok := s.Lookup(addr(t, "fd00::5"))
	require.True(t, ok, "an IPv6 pod address must be indexed")
	assert.Equal(t, "api", p.Name)

	p, ok = s.Lookup(addr(t, "10.244.0.9"))
	require.True(t, ok, "a dual-stack pod answers on both addresses")
	assert.Equal(t, "api", p.Name)

	// An IPv4-mapped IPv6 address is the same address.
	mapped := netip.MustParseAddr("::ffff:10.244.0.9")
	_, ok = s.Lookup(mapped)
	assert.True(t, ok, "IPv4-mapped IPv6 must resolve to the same binding")

	// And the two families are never confused for one another.
	_, ok = s.Lookup(addr(t, "fd00::9"))
	assert.False(t, ok)
}

func TestIPv6PodDeletionClearsBothAddresses(t *testing.T) {
	s := New(Options{})
	p := pod("uid-1", "prod", "api", "", withIPs("fd00::5", "10.244.0.9"))
	s.UpsertPod(p)
	s.DeletePod(p)
	_, ok := s.Lookup(addr(t, "fd00::5"))
	assert.False(t, ok)
	_, ok = s.Lookup(addr(t, "10.244.0.9"))
	assert.False(t, ok)
	assert.Zero(t, s.Len())
}

func TestServiceHeadlessAndInvalidAddressesAreIgnored(t *testing.T) {
	s := New(Options{})
	s.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{UID: "svc", Namespace: "prod", Name: "headless"},
		Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, ClusterIPs: []string{"None", "not-an-ip", ""}},
	})
	assert.Zero(t, s.Len())
}

func TestNilObjectsAreIgnored(t *testing.T) {
	s := New(Options{})
	s.UpsertPod(nil)
	s.DeletePod(nil)
	s.UpsertService(nil)
	s.DeleteService(nil)
	s.UpsertNode(nil)
	s.DeleteNode(nil)
	s.UpsertNamespace(nil)
	s.DeleteNamespace(nil)
	assert.Zero(t, s.Len())
	assert.Zero(t, s.Pods())
	assert.Zero(t, s.Namespaces())
	kind, name := OwnerWorkload(nil)
	assert.Equal(t, "", kind)
	assert.Equal(t, "", name)
}

func TestOwnerWorkload(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name       string
		refs       []metav1.OwnerReference
		kind, want string
	}{
		{"no owner", nil, "", ""},
		{"non-controller owner is ignored",
			[]metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-abc", Controller: &no}}, "", ""},
		{"replicaset unwinds to its deployment",
			[]metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-7d9f", Controller: &yes}}, "Deployment", "api"},
		{"replicaset with no hash keeps its name",
			[]metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api", Controller: &yes}}, "ReplicaSet", "api"},
		{"statefulset is used directly",
			[]metav1.OwnerReference{{Kind: "StatefulSet", Name: "ledger", Controller: &yes}}, "StatefulSet", "ledger"},
		{"daemonset is used directly",
			[]metav1.OwnerReference{{Kind: "DaemonSet", Name: "fluentd", Controller: &yes}}, "DaemonSet", "fluentd"},
		{"nil controller flag is ignored",
			[]metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-abc"}}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: tc.refs}}
			kind, name := OwnerWorkload(p)
			assert.Equal(t, tc.kind, kind)
			assert.Equal(t, tc.want, name)
		})
	}
}

func TestPeerStringAndClone(t *testing.T) {
	assert.Equal(t, "external", Peer{Kind: PeerExternal}.String())
	assert.Equal(t, "node:worker-1", Peer{Kind: PeerNode, Name: "worker-1"}.String())
	assert.Equal(t, "pod:prod/api", Peer{Kind: PeerPod, Namespace: "prod", Name: "api-x", Workload: "api"}.String())
	assert.Equal(t, "pod:prod/api-x", Peer{Kind: PeerPod, Namespace: "prod", Name: "api-x"}.String())

	src := Peer{Kind: PeerPod, Labels: map[string]string{"app": "api"}}
	clone := src.Clone()
	clone.Labels["app"] = "changed"
	assert.Equal(t, "api", src.Labels["app"], "Clone must not share the label map")
	assert.Nil(t, Peer{}.Clone().Labels)
}

func TestTombstonesExpireAndAreBounded(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(Options{
		TombstoneTTL:  time.Minute,
		MaxTombstones: 2,
		Now:           func() time.Time { return now },
	})

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		p := pod("uid-"+ip, "ns", "p", ip)
		s.UpsertPod(p)
		s.DeletePod(p)
	}
	_, ok := s.Released(addr(t, "10.0.0.1"))
	assert.False(t, ok, "the oldest tombstone is evicted once the bound is reached")
	_, ok = s.Released(addr(t, "10.0.0.3"))
	assert.True(t, ok)

	now = now.Add(2 * time.Minute)
	_, ok = s.Released(addr(t, "10.0.0.3"))
	assert.False(t, ok, "a tombstone past its TTL is not a release any more")

	// A later tombstone sweeps the expired ones out of the table.
	p := pod("uid-late", "ns", "late", "10.0.0.9")
	s.UpsertPod(p)
	s.DeletePod(p)
	assert.LessOrEqual(t, len(s.tombs), 2)
}

func TestReleasedIgnoresInvalidAndUnknownAddresses(t *testing.T) {
	s := New(Options{})
	_, ok := s.Released(netip.Addr{})
	assert.False(t, ok)
	_, ok = s.Released(addr(t, "10.0.0.1"))
	assert.False(t, ok)
}

func TestHandlerDispatchesEveryKind(t *testing.T) {
	s := New(Options{})
	h := s.Handler()

	p := pod("uid-1", "prod", "api", "10.244.0.1")
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{UID: "svc", Namespace: "prod", Name: "db"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.1"},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{UID: "node", Name: "w1"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"tier": "prod"}}}

	h.OnAdd(p, false)
	h.OnAdd(svc, false)
	h.OnAdd(node, false)
	h.OnAdd(ns, false)
	h.OnUpdate(p, pod("uid-1", "prod", "api", "10.244.0.2"))
	assert.Equal(t, 1, s.Namespaces())

	_, ok := s.Lookup(addr(t, "10.244.0.2"))
	assert.True(t, ok)

	// Unknown types and the missed-delete wrapper.
	h.OnAdd(&corev1.ConfigMap{}, false)
	h.OnDelete(&corev1.ConfigMap{})
	h.OnDelete(toolscache.DeletedFinalStateUnknown{Key: "prod/api", Obj: pod("uid-1", "prod", "api", "10.244.0.2")})
	_, ok = s.Lookup(addr(t, "10.244.0.2"))
	assert.False(t, ok, "a DeletedFinalStateUnknown is exactly the missed delete that leaves a stale identity")

	h.OnDelete(svc)
	h.OnDelete(node)
	h.OnDelete(ns)
	assert.Zero(t, s.Len())
	assert.Zero(t, s.Namespaces())
}

func TestSyncReapsWhatTheListingDoesNotMention(t *testing.T) {
	s := New(Options{})
	s.Sync(Snapshot{
		Pods:       []corev1.Pod{*pod("uid-1", "prod", "api", "10.244.0.1"), *pod("uid-2", "prod", "web", "10.244.0.2")},
		Services:   []corev1.Service{{ObjectMeta: metav1.ObjectMeta{UID: "svc-1", Namespace: "prod", Name: "db"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.1"}}},
		Nodes:      []corev1.Node{{ObjectMeta: metav1.ObjectMeta{UID: "n-1", Name: "w1"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}}}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}, {ObjectMeta: metav1.ObjectMeta{Name: "stale"}}},
	})
	assert.Equal(t, 4, s.Len())
	assert.Equal(t, 2, s.Namespaces())

	// A relist that drops everything but one pod withdraws the rest. This is
	// the path that repairs a delete the watch never delivered.
	s.Sync(Snapshot{
		Pods:       []corev1.Pod{*pod("uid-1", "prod", "api", "10.244.0.1")},
		Services:   []corev1.Service{},
		Nodes:      []corev1.Node{},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}},
	})
	assert.Equal(t, 1, s.Len())
	assert.Equal(t, 1, s.Pods())
	assert.Equal(t, 1, s.Namespaces())
	_, ok := s.Lookup(addr(t, "10.244.0.2"))
	assert.False(t, ok)
	_, released := s.Released(addr(t, "10.244.0.2"))
	assert.True(t, released, "a reaped pod's address is released, not merely forgotten")
}

func TestSyncSkipsKindsTheCallerCouldNotList(t *testing.T) {
	s := New(Options{})
	s.Sync(Snapshot{
		Pods:  []corev1.Pod{*pod("uid-1", "prod", "api", "10.244.0.1")},
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{UID: "n-1", Name: "w1"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}}}},
	})
	require.Equal(t, 2, s.Len())

	// A refresh whose pod List failed passes a nil slice, and must not be read
	// as "there are no pods any more".
	s.Sync(Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{UID: "n-1", Name: "w1"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}}}}})
	_, ok := s.Lookup(addr(t, "10.244.0.1"))
	assert.True(t, ok, "a nil slice means the kind was not listed, not that it is empty")
}

func TestSyncReapsAPodThatNeverHadAnAddress(t *testing.T) {
	s := New(Options{})
	s.Sync(Snapshot{Pods: []corev1.Pod{*pod("uid-1", "prod", "pending", "")}})
	assert.Equal(t, 1, s.Pods())
	s.Sync(Snapshot{Pods: []corev1.Pod{}})
	assert.Zero(t, s.Pods())
}

// Lookups run on the eBPF event path while the informer writes. Run with
// -race; a data race here is a crash in the agent's hot loop.
func TestConcurrentLookupsAndWrites(t *testing.T) {
	s := New(Options{})
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := netip.AddrFrom4([4]byte{10, 244, byte(w), byte(i % 251)})
				p := pod(ip.String(), "prod", "api", ip.String())
				s.UpsertPod(p)
				if i%3 == 0 {
					s.DeletePod(p)
				}
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for i := 0; i < 251; i++ {
					peer, _ := s.Lookup(netip.AddrFrom4([4]byte{10, 244, 1, byte(i)}))
					_ = peer.Namespace
					_ = peer.Labels["app"]
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// Objects with no UID must not all collide on one key. The API server always
// sets a UID, but a hand-built object does not, and a store that keyed every
// one of them on the empty string had each upsert silently withdraw the
// previous object's addresses - so an index built from such a listing held
// exactly one entry, whatever it was given.
func TestObjectsWithNoUIDDoNotCollide(t *testing.T) {
	s := New(Options{})
	s.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.6"},
	})
	s.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.5"},
	})
	s.UpsertNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}},
	})
	assert.Equal(t, 3, s.Len())

	// Two pods with the same name in different namespaces are still distinct.
	s.UpsertPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "staging", Name: "web"},
		Status:     corev1.PodStatus{PodIP: "10.0.1.6"},
	})
	assert.Equal(t, 4, s.Len())

	p, ok := s.Lookup(addr(t, "10.0.0.6"))
	require.True(t, ok)
	assert.Equal(t, "prod", p.Namespace)
}
