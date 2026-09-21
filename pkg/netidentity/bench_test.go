package netidentity

import (
	"fmt"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The lookup is on the per-event path: the eBPF ring buffer can deliver tens of
// thousands of network events a second on a busy node, and every one of them
// pays for this. These benchmarks exist so that a change which turns the
// lookup into an allocation is noticed here rather than as back pressure on
// the ring-buffer reader.

func benchStore(pods, services, nodes int) *Store {
	s := New(Options{})
	for i := 0; i < nodes; i++ {
		s.UpsertNode(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("n-%d", i)), Name: fmt.Sprintf("worker-%d", i)},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}).String()},
			}},
		})
	}
	for i := 0; i < services; i++ {
		s.UpsertService(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("s-%d", i)), Namespace: "prod", Name: fmt.Sprintf("svc-%d", i)},
			Spec:       corev1.ServiceSpec{ClusterIP: netip.AddrFrom4([4]byte{10, 96, byte(i / 256), byte(i % 256)}).String()},
		})
	}
	yes := true
	for i := 0; i < pods; i++ {
		s.UpsertPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID:       types.UID(fmt.Sprintf("p-%d", i)),
				Namespace: fmt.Sprintf("ns-%d", i%16),
				Name:      fmt.Sprintf("pod-%d", i),
				Labels:    map[string]string{"app": fmt.Sprintf("app-%d", i%32), "tier": "backend"},
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: fmt.Sprintf("app-%d-7d9f", i%32), Controller: &yes},
				},
			},
			Status: corev1.PodStatus{PodIP: podBenchAddr(i).String()},
		})
	}
	for i := 0; i < 16; i++ {
		s.UpsertNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("ns-%d", i),
			Labels: map[string]string{"team": fmt.Sprintf("team-%d", i%4)},
		}})
	}
	return s
}

func podBenchAddr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 244, byte(i / 256), byte(i % 256)})
}

func BenchmarkLookupHit(b *testing.B) {
	s := benchStore(2000, 200, 50)
	addrs := make([]netip.Addr, 256)
	for i := range addrs {
		addrs[i] = podBenchAddr(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup(addrs[i%len(addrs)]); !ok {
			b.Fatal("expected a hit")
		}
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	s := benchStore(2000, 200, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Lookup(netip.AddrFrom4([4]byte{203, 0, byte(i / 256), byte(i % 256)}))
	}
}

func BenchmarkLookupIPv6(b *testing.B) {
	s := New(Options{})
	addrs := make([]netip.Addr, 256)
	for i := range addrs {
		a := netip.MustParseAddr(fmt.Sprintf("fd00::%x", i+1))
		addrs[i] = a
		s.UpsertPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("p6-%d", i)), Namespace: "prod", Name: fmt.Sprintf("pod-%d", i)},
			Status:     corev1.PodStatus{PodIP: a.String()},
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup(addrs[i%len(addrs)]); !ok {
			b.Fatal("expected a hit")
		}
	}
}

// Lookups run while the informer writes, which is the shape the agent actually
// has: one writer goroutine and the event path reading.
func BenchmarkLookupParallelWithWrites(b *testing.B) {
	s := benchStore(2000, 200, 50)
	stop := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.UpsertPod(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("churn-%d", i%64)), Namespace: "prod", Name: "churn"},
				Status:     corev1.PodStatus{PodIP: netip.AddrFrom4([4]byte{10, 250, byte(i / 256), byte(i % 256)}).String()},
			})
			i++
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			s.Lookup(podBenchAddr(i % 256))
			i++
		}
	})
	b.StopTimer()
	close(stop)
}

func BenchmarkUpsertPod(b *testing.B) {
	s := benchStore(2000, 200, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.UpsertPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("p-%d", i%2000)), Namespace: "prod", Name: "p"},
			Status:     corev1.PodStatus{PodIP: podBenchAddr(i % 2000).String()},
		})
	}
}

func BenchmarkMatchPeers(b *testing.B) {
	s := benchStore(2000, 200, 50)
	sel := PeerSelector{
		Namespace: &Selector{MatchLabels: map[string]string{"team": "team-1"}},
		Pod:       &Selector{MatchLabels: map[string]string{"tier": "backend"}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(s.MatchPeers(sel).IPs) == 0 {
			b.Fatal("expected matches")
		}
	}
}

func BenchmarkSync(b *testing.B) {
	s := benchStore(0, 0, 0)
	snap := Snapshot{Pods: make([]corev1.Pod, 2000)}
	for i := range snap.Pods {
		snap.Pods[i] = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("p-%d", i)), Namespace: "prod", Name: "p"},
			Status:     corev1.PodStatus{PodIP: podBenchAddr(i).String()},
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Sync(snap)
	}
}
