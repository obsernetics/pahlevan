package netidentity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A delete for an object the index never bound is a no-op, not a panic and not
// a tombstone. It happens on every restart: the informer replays deletes for
// objects that were gone before this agent started.
func TestDeletingSomethingNeverIndexedIsANoOp(t *testing.T) {
	s := New(Options{})
	s.DeletePod(pod("uid-ghost", "prod", "ghost", "10.0.0.1"))
	s.DeleteService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{UID: "svc-ghost", Namespace: "prod", Name: "ghost"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.1"},
	})
	s.DeleteNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{UID: "n-ghost", Name: "ghost"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.1"}}},
	})
	assert.Zero(t, s.Len())
	_, released := s.Released(addr(t, "10.0.0.1"))
	assert.False(t, released, "an address that was never bound was never released")
}

func TestNodeAddressesAreDeduplicatedAndValidated(t *testing.T) {
	s := New(Options{})
	s.UpsertNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{UID: "n-1", Name: "worker-1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "192.168.0.1"},
			{Type: corev1.NodeExternalIP, Address: "192.168.0.1"},
			{Type: corev1.NodeExternalIP, Address: "not-an-address"},
			{Type: corev1.NodeHostName, Address: "worker-1"},
			{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
		}},
	})
	assert.Equal(t, 2, s.Len(), "one address twice is one binding; a hostname is not an address")
	p, ok := s.Lookup(addr(t, "2001:db8::1"))
	require.True(t, ok, "a node's IPv6 address must be indexed too")
	assert.Equal(t, PeerNode, p.Kind)
}

// Two pods claiming one address sort deterministically even when they share a
// namespace, so a caller diffing LookupAll output is not chasing map order.
func TestLookupAllTieBreaksOnName(t *testing.T) {
	s := New(Options{})
	ip := "10.10.10.10"
	s.UpsertPod(pod("a", "prod", "zeta", ip, withHostNetwork("n1")))
	s.UpsertPod(pod("b", "prod", "alpha", ip, withHostNetwork("n1")))
	all := s.LookupAll(addr(t, ip))
	require.Len(t, all, 2)
	assert.Equal(t, "alpha", all[0].Name)
	assert.Equal(t, "zeta", all[1].Name)
}

// Two matched pods sharing an address contribute it once, so the caller does
// not program the same allow-set entry twice.
func TestMatchPeersDeduplicatesSharedAddresses(t *testing.T) {
	s := New(Options{})
	s.UpsertNamespace(ns("prod", nil))
	labels := map[string]string{"app": "x"}
	s.UpsertPod(pod("a", "prod", "one", "", withIPs("10.0.0.1", "10.0.0.2"), withLabels(labels)))
	s.UpsertPod(pod("b", "prod", "two", "", withIPs("10.0.0.2", "10.0.0.3"), withLabels(labels)))

	m := s.MatchPeers(PeerSelector{Namespace: &Selector{}, Pod: &Selector{}})
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, strs(t, m.IPs))
	assert.Equal(t, 2, m.Pods)
}

// A Service that loses its ClusterIP - or is recreated headless - stops
// answering rather than keeping the old address.
func TestServiceLosingItsClusterIPIsWithdrawn(t *testing.T) {
	s := New(Options{})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{UID: "svc", Namespace: "prod", Name: "db"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.1"},
	}
	s.UpsertService(svc)
	require.Equal(t, 1, s.Len())

	svc.Spec.ClusterIP = corev1.ClusterIPNone
	s.UpsertService(svc)
	assert.Zero(t, s.Len())
	_, released := s.Released(addr(t, "10.96.0.1"))
	assert.True(t, released)
}

// A duplicate delete for a pod whose binding is already gone must not touch
// the address, because by then it belongs to somebody else.
//
// This is the same UID guard as the late-delete case, reached the other way:
// the periodic Sync reaped the dead pod first, the CNI handed its address to a
// new pod, and only then did the watch deliver the delete. Withdrawing by
// address would take the live pod's binding with it and leave the address
// unresolved, which is how a peer becomes invisible to enforcement.
func TestDuplicateDeleteDoesNotTouchTheNewOwner(t *testing.T) {
	s := New(Options{})
	ip := "10.244.3.17"
	old := pod("old-uid", "payments", "ledger-abc", ip)
	s.UpsertPod(old)

	// A relist without the dead pod reaps it.
	s.Sync(Snapshot{Pods: []corev1.Pod{}})
	require.Zero(t, s.Len())

	// The address is handed on.
	fresh := pod("new-uid", "web", "front-def", ip)
	s.UpsertPod(fresh)

	// And only now does the watch deliver the delete for the dead pod.
	s.DeletePod(old)

	p, ok := s.Lookup(addr(t, ip))
	require.True(t, ok, "a duplicate delete must not withdraw the live pod's address")
	assert.Equal(t, "web", p.Namespace)
	assert.Equal(t, "front-def", p.Name)
}
