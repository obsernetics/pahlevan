package discovery

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Start runs discovery from two goroutines: the pod watch reaches
// discoverExistingContainers through startWatch, and the periodic refresh
// reaches it on every tick. Both end up in updateContainer, which takes the
// write lock - so the map itself was safe. The count logged at the end of
// discovery was not read under any lock, and that was a genuine data race
// between the two.
//
// It reproduced on a CI runner and not on a workstation, at 150 runs of the
// test that caught it, which is the usual way a timing-dependent race behaves
// and a bad thing to rely on a scheduler to find again. Calling discovery
// concurrently on purpose exercises the same two accesses deterministically:
// with the read unguarded, -race reports it every time.
func TestConcurrentDiscoveryIsFreeOfRaces(t *testing.T) {
	objs := make([]client.Object, 0, 24)
	for i := 0; i < 24; i++ {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("web-%d", i),
				Namespace: "default",
				UID:       k8stypes.UID(fmt.Sprintf("uid-%d", i)),
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}},
			},
		})
	}
	tracker := newTestTracker(t, objs...)

	ctx := context.Background()
	const goroutines = 8

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < 20; n++ {
				if err := tracker.discoverExistingContainers(ctx); err != nil {
					t.Errorf("discovery failed: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	// Every pod contributes two containers, and discovery is idempotent: the
	// same keys are rewritten rather than accumulated. A count that drifts
	// with the number of goroutines would mean the key is not stable.
	got := tracker.GetContainers(nil)
	require.Len(t, got, len(objs)*2,
		"discovery is not idempotent; running it concurrently changed the tracked set")
}

// Readers must be safe against a concurrent discovery too - the operator calls
// these from its reconcile loop while the tracker's own goroutines are writing.
func TestReadersAreSafeDuringDiscovery(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default", UID: k8stypes.UID("uid-1")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx"}}},
	}
	tracker := newTestTracker(t, pod)

	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = tracker.discoverExistingContainers(ctx)
			}
		}
	}()

	for i := 0; i < 200; i++ {
		_ = tracker.GetContainers(nil)
		_, _ = tracker.GetContainer("nginx")
		_ = tracker.GetContainersByPod("default", "web-1")
		_ = tracker.GetStats()
	}
	close(stop)
	wg.Wait()
}

func BenchmarkDiscoverExistingContainers(b *testing.B) {
	tracker := newBenchTracker(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := tracker.discoverExistingContainers(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
