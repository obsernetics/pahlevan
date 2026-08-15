package netmap

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svc(ns, name, clusterIP string, ports ...corev1.ServicePort) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ServiceSpec{ClusterIP: clusterIP, Ports: ports},
	}
}

func pod(ns, name, ip string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     corev1.PodStatus{PodIP: ip},
	}
}

func node(name, ip string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: ip},
		}},
	}
}

func populated() *Resolver {
	r := New()
	r.Refresh(Snapshot{
		Services: []corev1.Service{
			svc("prod", "postgres", "10.104.22.9",
				corev1.ServicePort{Name: "postgres", Port: 5432},
				corev1.ServicePort{Port: 9187}), // unnamed metrics port
			svc("kube-system", "kube-dns", "10.96.0.10",
				corev1.ServicePort{Name: "dns", Port: 53}),
		},
		Pods:  []corev1.Pod{pod("prod", "api-7d9", "10.244.1.15")},
		Nodes: []corev1.Node{node("node-3", "192.168.1.30")},
	})
	return r
}

// The whole point of the package: an address becomes something an operator can
// act on without going and looking it up.
func TestLookupNamesAClusterService(t *testing.T) {
	d, known := populated().Lookup(net.ParseIP("10.104.22.9"), 5432)
	require.True(t, known)
	assert.Equal(t, KindService, d.Kind)
	assert.Equal(t, "prod", d.Namespace)
	assert.Equal(t, "postgres", d.Name)
	assert.Equal(t, "postgres", d.PortName, "a named service port reads better than 5432")
	assert.Equal(t, "prod/postgres", d.String())
}

// An unnamed port has nothing better to report than the number the caller
// already has, so PortName stays empty rather than being invented.
func TestUnnamedServicePortHasNoPortName(t *testing.T) {
	d, known := populated().Lookup(net.ParseIP("10.104.22.9"), 9187)
	require.True(t, known)
	assert.Equal(t, "prod/postgres", d.String())
	assert.Empty(t, d.PortName)
}

// A workload reaching a pod directly rather than through its Service is either
// a mesh sidecar or something doing its own discovery. Both are worth seeing as
// distinct from a Service hit.
func TestLookupDistinguishesPodsFromServices(t *testing.T) {
	d, known := populated().Lookup(net.ParseIP("10.244.1.15"), 8080)
	require.True(t, known)
	assert.Equal(t, KindPod, d.Kind)
	assert.Equal(t, "prod/api-7d9", d.String())
}

func TestLookupNamesNodes(t *testing.T) {
	d, known := populated().Lookup(net.ParseIP("192.168.1.30"), 10250)
	require.True(t, known)
	assert.Equal(t, KindNode, d.Kind)
	assert.Equal(t, "node-3", d.String())
}

// The answer that matters. A denied connect to an address the cluster does not
// know is the shape exfiltration takes, and it must be distinguishable from a
// denied connect to a Service the workload simply is not allowed to use.
func TestUnknownAddressIsExternal(t *testing.T) {
	d, known := populated().Lookup(net.ParseIP("203.0.113.7"), 4444)
	assert.False(t, known)
	assert.Equal(t, KindExternal, d.Kind)
	assert.Equal(t, "external", d.String())
}

func TestLoopbackIsRecognisedWithoutTheMap(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		d, known := New().Lookup(net.ParseIP(ip), 8080)
		assert.True(t, known, ip)
		assert.Equal(t, KindLoopback, d.Kind, ip)
	}
}

// An IPv4 address arriving as a 16-byte slice is the same address. Without
// unmapping, every v4 lookup through a v6-shaped slice would miss and every
// in-cluster destination would be reported as external.
func TestIPv4MappedAddressesResolve(t *testing.T) {
	r := populated()
	v4 := net.ParseIP("10.104.22.9").To4()
	v16 := net.ParseIP("10.104.22.9").To16()
	require.Len(t, v4, 4)
	require.Len(t, v16, 16)

	a, ok1 := r.Lookup(v4, 5432)
	b, ok2 := r.Lookup(v16, 5432)
	assert.True(t, ok1)
	assert.True(t, ok2)
	assert.Equal(t, a, b, "the same address in two shapes must resolve identically")
}

func TestIPv6ServiceResolves(t *testing.T) {
	r := New()
	s := svc("prod", "api", "")
	s.Spec.ClusterIPs = []string{"fd00::1"}
	r.Refresh(Snapshot{Services: []corev1.Service{s}})

	d, known := r.Lookup(net.ParseIP("fd00::1"), 443)
	require.True(t, known)
	assert.Equal(t, "prod/api", d.String())
}

// A headless Service has no address of its own. Indexing the literal "None"
// would put a junk key in the map, and reporting a pod as the headless Service
// would be wrong anyway - the pod is what answered.
func TestHeadlessServiceIsNotIndexed(t *testing.T) {
	r := New()
	r.Refresh(Snapshot{
		Services: []corev1.Service{svc("prod", "headless", corev1.ClusterIPNone)},
		Pods:     []corev1.Pod{pod("prod", "member-0", "10.244.2.1")},
	})
	assert.Equal(t, 1, r.Size(), "only the pod should be indexed")

	d, known := r.Lookup(net.ParseIP("10.244.2.1"), 5432)
	require.True(t, known)
	assert.Equal(t, KindPod, d.Kind)
}

// ExternalIPs and LoadBalancer ingress addresses are how a Service is reached
// from outside, and a workload dialing one is dialing that Service.
func TestExternalIPsAndLoadBalancerIngressResolve(t *testing.T) {
	r := New()
	s := svc("prod", "edge", "10.96.1.1")
	s.Spec.ExternalIPs = []string{"198.51.100.4"}
	s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "198.51.100.5"}}
	r.Refresh(Snapshot{Services: []corev1.Service{s}})

	for _, ip := range []string{"10.96.1.1", "198.51.100.4", "198.51.100.5"} {
		d, known := r.Lookup(net.ParseIP(ip), 443)
		assert.True(t, known, ip)
		assert.Equal(t, "prod/edge", d.String(), ip)
	}
}

// A hostNetwork pod carries its node's address. Reporting the pod is more
// useful than reporting the node - the pod is what is running - which is why
// pods are indexed after nodes.
func TestHostNetworkPodWinsOverItsNode(t *testing.T) {
	r := New()
	r.Refresh(Snapshot{
		Nodes: []corev1.Node{node("node-3", "192.168.1.30")},
		Pods:  []corev1.Pod{pod("kube-system", "kube-proxy-abc", "192.168.1.30")},
	})
	d, known := r.Lookup(net.ParseIP("192.168.1.30"), 10256)
	require.True(t, known)
	assert.Equal(t, KindPod, d.Kind)
	assert.Equal(t, "kube-system/kube-proxy-abc", d.String())
}

// A refresh replaces the map wholesale. A pod that has gone away must stop
// resolving, or a denial gets attributed to a workload that no longer exists.
func TestRefreshReplacesRatherThanAccumulates(t *testing.T) {
	r := New()
	r.Refresh(Snapshot{Pods: []corev1.Pod{pod("prod", "old", "10.244.1.1")}})
	_, known := r.Lookup(net.ParseIP("10.244.1.1"), 80)
	require.True(t, known)

	r.Refresh(Snapshot{Pods: []corev1.Pod{pod("prod", "new", "10.244.1.2")}})
	_, known = r.Lookup(net.ParseIP("10.244.1.1"), 80)
	assert.False(t, known, "a departed pod must stop resolving")
	_, known = r.Lookup(net.ParseIP("10.244.1.2"), 80)
	assert.True(t, known)
}

// Before the informers sync, everything is external. That is the safe answer -
// accurate rather than invented - but it looks identical to a cluster where
// every destination really is external, which is why Size() exists.
func TestEmptyResolverReportsEverythingExternal(t *testing.T) {
	r := New()
	assert.Equal(t, 0, r.Size())
	d, known := r.Lookup(net.ParseIP("10.104.22.9"), 5432)
	assert.False(t, known)
	assert.Equal(t, KindExternal, d.Kind)
}

// Malformed input from a pod status field must be skipped, not indexed as a
// key nothing can ever match.
func TestGarbageAddressesAreSkipped(t *testing.T) {
	r := New()
	r.Refresh(Snapshot{
		Pods: []corev1.Pod{
			pod("prod", "no-ip", ""),
			pod("prod", "junk", "not-an-address"),
			pod("prod", "good", "10.244.1.9"),
		},
	})
	assert.Equal(t, 1, r.Size())
}

func TestLookupOfANilAddress(t *testing.T) {
	d, known := populated().Lookup(nil, 80)
	assert.False(t, known)
	assert.Equal(t, KindExternal, d.Kind)
}

func TestAddressesIsSorted(t *testing.T) {
	got := populated().Addresses()
	require.Len(t, got, 4)
	assert.Equal(t, []string{"10.104.22.9", "10.244.1.15", "10.96.0.10", "192.168.1.30"}, got)
}

// The lookup runs on the event path while a refresh runs on a timer. A race
// there would corrupt the map under exactly the load that makes it matter.
func TestConcurrentLookupAndRefresh(t *testing.T) {
	r := populated()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.Refresh(Snapshot{Pods: []corev1.Pod{
				pod("prod", fmt.Sprintf("p-%d", i), "10.244.1.15"),
			}})
		}
	}()

	for i := 0; i < 2000; i++ {
		_, _ = r.Lookup(net.ParseIP("10.244.1.15"), 8080)
		_, _ = r.Lookup(net.ParseIP("203.0.113.7"), 4444)
	}
	close(stop)
	wg.Wait()
}

func BenchmarkLookupHit(b *testing.B) {
	r := populated()
	ip := net.ParseIP("10.104.22.9")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Lookup(ip, 5432)
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	r := populated()
	ip := net.ParseIP("203.0.113.7")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Lookup(ip, 4444)
	}
}

func BenchmarkRefreshLargeCluster(b *testing.B) {
	var s Snapshot
	for i := 0; i < 500; i++ {
		s.Services = append(s.Services,
			svc("ns", fmt.Sprintf("svc-%d", i), fmt.Sprintf("10.96.%d.%d", i/256, i%256),
				corev1.ServicePort{Name: "http", Port: 80}))
	}
	for i := 0; i < 5000; i++ {
		s.Pods = append(s.Pods,
			pod("ns", fmt.Sprintf("pod-%d", i), fmt.Sprintf("10.244.%d.%d", i/256, i%256)))
	}
	r := New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Refresh(s)
	}
}
