package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/export"
	"github.com/obsernetics/pahlevan/pkg/grpcapi"
)

// The hot paths are event aggregation and rendering. Everything else happens
// once per page load and is dominated by the API server round trip; these two
// run per event and per diagram, and an allocation here is an allocation on a
// node's whole syscall rate.

// BenchmarkStoreAdd measures folding one event into the aggregate: the
// workload lookup, the counters, and the process tree walk.
func BenchmarkStoreAdd(b *testing.B) {
	store := NewStore(StoreOptions{})
	event := fileEventForBench(visibleNS, "api", "/usr/share/nginx/html/index.html", false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Add(event)
	}
}

// BenchmarkStoreAddDenial is the burst case. Denials arrive in bursts by
// definition - something is attacking, or a profile is wrong - so the denial
// ring is on the path exactly when the node is busiest.
func BenchmarkStoreAddDenial(b *testing.B) {
	store := NewStore(StoreOptions{})
	event := fileEventForBench(visibleNS, "api", "/etc/shadow", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Add(event)
	}
}

// BenchmarkStoreAddExecAncestry walks and extends the process tree, which is
// the deepest work any event causes.
func BenchmarkStoreAddExecAncestry(b *testing.B) {
	store := NewStore(StoreOptions{})
	event := execDenialForBench(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh", "bash"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Add(event)
	}
}

// BenchmarkStoreAddAcrossWorkloads is the cluster shape: many workloads, each
// producing events, which is where the map lookup and the eviction scan live.
func BenchmarkStoreAddAcrossWorkloads(b *testing.B) {
	const workloads = 64
	store := NewStore(StoreOptions{})
	events := make([]*export.Event, workloads)
	for i := range events {
		events[i] = fileEventForBench(visibleNS, "api-"+strconv.Itoa(i), "/etc/passwd", i%4 == 0)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Add(events[i%workloads])
	}
}

// BenchmarkStoreSnapshot measures what every page load costs: a deep copy of
// every workload's aggregate, which is what keeps a handler from reading a
// tree the event pipeline is rewriting.
func BenchmarkStoreSnapshot(b *testing.B) {
	store := NewStore(StoreOptions{})
	for i := 0; i < 64; i++ {
		name := "api-" + strconv.Itoa(i)
		store.Add(execDenialForBench(visibleNS, name, "/usr/bin/curl", []string{"nginx", "sh"}))
		for j := 0; j < 16; j++ {
			store.Add(fileEventForBench(visibleNS, name, "/etc/passwd", j%3 == 0))
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Snapshot()
	}
}

func BenchmarkFlowSVG(b *testing.B) {
	stages := []FlowStage{
		{Name: "Selected", State: StateDone, Detail: "12 containers matched by the policy selector"},
		{Name: "Learning", State: StateDone, Detail: "213 syscalls, 488 paths, 9 destinations learned"},
		{Name: "Transition", State: StateFailed, Detail: "2 rollbacks out of 3 attempts: denial rate exceeded the rollback threshold"},
		{Name: "Enforcing", State: StateActive, Detail: "12 containers enforcing, 41 denials since"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FlowSVG(stages)
	}
}

func BenchmarkSurfaceSVG(b *testing.B) {
	surface := Surface{
		SyscallCount: 213, FileCount: 488, NetworkCount: 9,
		ExecutableCount: 6, CapabilityCount: 3,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SurfaceSVG(surface)
	}
}

// BenchmarkProcessTreeSVG renders a tree at the size the ceiling allows, which
// is the worst case a real workload can produce.
func BenchmarkProcessTreeSVG(b *testing.B) {
	tree := benchTree(4, 3)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ProcessTreeSVG(tree, false)
	}
}

// BenchmarkOverviewHandler is the whole read path for the busiest page: token
// review, one access review per namespace, three CRD lists and the JSON
// encode. The fake clientset stands in for the API server, so what is measured
// is this package's own cost rather than the network.
func BenchmarkOverviewHandler(b *testing.B) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(b, auth, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET /api/overview = %d", rec.Code)
		}
	}
}

// BenchmarkWorkloadDetailHandler covers the per-workload page: the surface
// merge, the flow, and the store lookup behind it.
func BenchmarkWorkloadDetailHandler(b *testing.B) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	store := NewStore(StoreOptions{})
	store.Add(execDenialForBench(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))
	server := newTestServer(b, auth, store)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/workloads/"+visibleNS+"/Deployment/api", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET the workload detail = %d", rec.Code)
		}
	}
}

func BenchmarkEventFromProtoAndStore(b *testing.B) {
	// The live path end to end: one wire event converted and folded in.
	store := NewStore(StoreOptions{})
	msg := grpcapi.ToProto(execDenialForBench(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := EventFromProto(msg)
		store.Add(&event)
	}
}

func benchTree(breadth, depth int) []*ProcessNode {
	if depth == 0 {
		return nil
	}
	out := make([]*ProcessNode, 0, breadth)
	for i := 0; i < breadth; i++ {
		out = append(out, &ProcessNode{
			Comm:     "proc-" + strconv.Itoa(depth) + "-" + strconv.Itoa(i),
			Count:    depth * (i + 1),
			Denied:   i % 2,
			Children: benchTree(breadth, depth-1),
		})
	}
	return out
}

// The benchmark fixtures duplicate the test builders because those take
// *testing.T, and a benchmark that calls t.Fatalf does not compile.

func k8sRefForBench(ns, workload string) *export.KubernetesRef {
	return &export.KubernetesRef{
		Namespace: ns, Pod: workload + "-0", Container: workload, Node: "node-1",
		WorkloadKind: "Deployment", WorkloadName: workload, Image: "example.test/" + workload + ":1",
	}
}

func fileEventForBench(ns, workload, path string, denied bool) *export.Event {
	action := export.ActionObserve
	if denied {
		action = export.ActionDeny
	}
	return &export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
		Type:       export.EventTypeFile,
		Action:     action,
		Process:    export.ProcessInfo{PID: 7, Comm: "nginx", ParentComm: "pause"},
		Kubernetes: k8sRefForBench(ns, workload),
		File:       &export.FileInfo{Path: path, SyscallName: "read"},
	}
}

func execDenialForBench(ns, workload, binary string, ancestry []string) *export.Event {
	e := &export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
		Type:       export.EventTypeProcess,
		Action:     export.ActionDeny,
		Process:    export.ProcessInfo{PID: 4242, Comm: "curl"},
		Kubernetes: k8sRefForBench(ns, workload),
		Exec:       &export.ExecInfo{Binary: binary},
	}
	for i := len(ancestry) - 1; i >= 0; i-- {
		e.Exec.Ancestry = append(e.Exec.Ancestry, export.AncestorInfo{PID: uint32(100 + i), Comm: ancestry[i]})
	}
	return e
}
