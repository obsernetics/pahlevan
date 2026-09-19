package cycle

import (
	"context"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Interval runs on the reconcile path, once per policy per schedule change, so
// it is nowhere near a hot loop. It is benchmarked because the cost is entirely
// decided by sampleFirings: if the sample ever has to grow, this is the number
// that says what growing it buys and what it costs.
func BenchmarkIntervalEveryFiveMinutes(b *testing.B) {
	benchmarkInterval(b, "*/5 * * * *")
}

func BenchmarkIntervalNightly(b *testing.B) {
	benchmarkInterval(b, "0 3 * * *")
}

// The worst case in practice: a day-of-month schedule makes the parser step
// month by month, 63 times over, across more than five years.
func BenchmarkIntervalMonthly(b *testing.B) {
	benchmarkInterval(b, "0 0 1 * *")
}

func BenchmarkIntervalDayOfWeek(b *testing.B) {
	benchmarkInterval(b, "0 3 * * 1")
}

func benchmarkInterval(b *testing.B, expr string) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Interval(expr); err != nil {
			b.Fatalf("Interval(%q): %v", expr, err)
		}
	}
}

// Discovery is the part that runs per reconcile, and a cached client is what it
// runs against in the operator: every Get below is served from an informer's
// local store, with no API round trip. The fake client has the same shape - an
// in-memory tracker behind the client.Client interface - so this measures the
// walk itself, which is what the reconcile pays.
func BenchmarkFindPodToCronJob(b *testing.B) {
	p := pod("nightly-29081600-abcde", ownedBy("batch/v1", "Job", "nightly-29081600"))
	c := clientWith(b,
		p,
		job("nightly-29081600", ownedBy("batch/v1", "CronJob", "nightly")),
		cronJob("nightly", "0 3 * * *"),
	)
	benchmarkFind(b, c, p)
}

// The common case by a wide margin: a Deployment pod, two hops to the answer
// "no cycle". This is the cost the walk imposes on every workload that has no
// periodicity at all, which is most of them.
func BenchmarkFindDeploymentPod(b *testing.B) {
	p := pod("web-7d9f4-xyz", ownedBy("apps/v1", "ReplicaSet", "web-7d9f4"))
	c := clientWith(b,
		p,
		replicaSet("web-7d9f4", ownedBy("apps/v1", "Deployment", "web")),
		deployment("web"),
	)
	benchmarkFind(b, c, p)
}

// A pod with no owner at all: the floor, showing what the walk costs when there
// is nothing to walk.
func BenchmarkFindUnownedPod(b *testing.B) {
	p := pod("static-pod")
	benchmarkFind(b, clientWith(b, p), p)
}

func benchmarkFind(b *testing.B, c client.Client, obj client.Object) {
	b.Helper()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Find(ctx, c, obj); err != nil {
			b.Fatalf("Find: %v", err)
		}
	}
}

// The whole resolution a controller performs: walk the owner chain, then work
// out the window.
func BenchmarkFindRequired(b *testing.B) {
	p := pod("nightly-29081600-abcde", ownedBy("batch/v1", "Job", "nightly-29081600"))
	c := clientWith(b,
		p,
		job("nightly-29081600", ownedBy("batch/v1", "CronJob", "nightly")),
		cronJob("nightly", "0 3 * * *"),
	)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := FindRequired(ctx, c, p, 50*time.Minute); err != nil {
			b.Fatalf("FindRequired: %v", err)
		}
	}
}
