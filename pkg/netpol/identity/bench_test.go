package identity

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/obsernetics/pahlevan/pkg/netidentity"
	"github.com/obsernetics/pahlevan/pkg/netpol"
)

// The generator asks this one question per learned destination, and a cluster's
// worth of baselines is tens of thousands of them in a CLI a person is waiting
// on. Building the index is paid once; a lookup is paid per destination and has
// to stay a map probe.

// benchSnapshot builds pods x replicas pods, one Service per workload, and a
// node per 50 pods.
func benchSnapshot(workloads, replicas int) (netidentity.Snapshot, netpol.Roster) {
	var pods []corev1.Pod
	var services []corev1.Service
	var nodes []corev1.Node
	for w := 0; w < workloads; w++ {
		app := fmt.Sprintf("w%d", w)
		for r := 0; r < replicas; r++ {
			pods = append(pods, pod("prod",
				fmt.Sprintf("%s-%d", app, r),
				fmt.Sprintf("10.244.%d.%d", w%250, r+1),
				"Deployment/"+app,
				map[string]string{"app": app}))
		}
		services = append(services, service("prod", app,
			fmt.Sprintf("10.96.%d.%d", w/250, w%250),
			map[string]string{"app": app},
			map[string]string{"app": app + "-chart"}))
	}
	for n := 0; n*50 < workloads*replicas; n++ {
		nodes = append(nodes, node(fmt.Sprintf("worker-%d", n),
			fmt.Sprintf("192.168.1.%d", n+1), nil))
	}
	snap := Snapshot(pods, services, nodes)
	return snap, roster(snap)
}

func BenchmarkNew(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if New(snap, r) == nil {
			b.Fatal("nil resolver")
		}
	}
}

func BenchmarkLookupPod(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := res.Lookup("10.244.63.1"); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkLookupService(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, ok := res.Lookup("10.96.0.63")
		if !ok || len(p.Labels) == 0 {
			b.Fatal("a Service peer with no selector is the refusal path")
		}
	}
}

func BenchmarkLookupNode(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := res.Lookup("192.168.1.1"); !ok {
			b.Fatal("miss")
		}
	}
}

// The classification path: an address the index does not hold, which is every
// destination outside the cluster and so the commonest answer of all in a
// baseline with any internet egress in it.
func BenchmarkLookupExternal(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := res.Lookup("93.184.216.34"); !ok {
			b.Fatal("a public address is outside the cluster")
		}
	}
}

func BenchmarkLookupUnresolved(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := res.Lookup("172.16.4.4"); ok {
			b.Fatal("an unindexed private address is not known to be anything")
		}
	}
}

// Generate driven through the real adapter rather than a table, which is what
// the command runs.
func BenchmarkGenerateThroughTheIndex(b *testing.B) {
	snap, r := benchSnapshot(64, 3)
	res := New(snap, r)
	obs := make([]netpol.Observation, 0, 64)
	for w := 0; w < 64; w++ {
		app := fmt.Sprintf("w%d", w)
		o := netpol.Observation{
			Namespace: "prod",
			Workload:  "Deployment/" + app,
			Pods:      []string{app + "-0", app + "-1", app + "-2"},
			Window:    3000000000,
		}
		for p := 0; p < 4; p++ {
			target := (w + p + 1) % 64
			o.Destinations = append(o.Destinations,
				dest(fmt.Sprintf("10.96.%d.%d", target/250, target%250), int32(8000+p)))
		}
		obs = append(obs, o)
	}
	opt := netpol.Options{Roster: r, Resolver: res, Egress: true}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := netpol.Generate(obs, opt); len(got.Policies) == 0 {
			b.Fatal("the fixture produced no policies, so this benchmark measures nothing")
		}
	}
}
