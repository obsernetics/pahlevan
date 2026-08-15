package export

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

type capturingSink struct{ events []*Event }

func (c *capturingSink) Enqueue(e *Event) bool {
	c.events = append(c.events, e)
	return true
}

func denialEvent(cgroup uint64) *ebpf.FileEvent {
	return &ebpf.FileEvent{CgroupID: cgroup, Path: "/etc/shadow", Flags: ebpf.DeniedFlag}
}

// Events start flowing the moment the eBPF programs attach, which is before the
// node's pod cache has been populated. The first lookup therefore fails, and
// caching that failure meant every later event for the container went out with
// an empty namespace and pod: the denials an operator most needs to attribute
// were exactly the ones that could not be.
func TestAttributionIsRetriedUntilItResolves(t *testing.T) {
	var calls int64
	var warm atomic.Bool

	sink := &capturingSink{}
	h := NewHandler(sink, HandlerOptions{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		Attribution: func(id uint64) (KubernetesRef, bool) {
			atomic.AddInt64(&calls, 1)
			if !warm.Load() {
				// The pod cache has not caught up yet.
				return KubernetesRef{}, false
			}
			return KubernetesRef{Namespace: "prod", Pod: "nginx-7c9b4", PodUID: "uid-1"}, true
		},
	})

	require.NoError(t, h.HandleFileEvent(denialEvent(42)))
	require.Len(t, sink.events, 1)
	assert.Nil(t, sink.events[0].Kubernetes, "nothing to attribute yet")

	warm.Store(true)
	require.NoError(t, h.HandleFileEvent(denialEvent(42)))
	require.Len(t, sink.events, 2)
	require.NotNil(t, sink.events[1].Kubernetes,
		"the second event must be attributed once the pod cache is warm")
	assert.Equal(t, "prod", sink.events[1].Kubernetes.Namespace)
	assert.Equal(t, "nginx-7c9b4", sink.events[1].Kubernetes.Pod)
}

// A reference carrying only a pod UID is worth emitting but must not be
// memoised, or a container attributed once at startup stays half-attributed.
func TestPartialAttributionIsNotMemoised(t *testing.T) {
	var complete atomic.Bool
	sink := &capturingSink{}
	h := NewHandler(sink, HandlerOptions{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		Attribution: func(id uint64) (KubernetesRef, bool) {
			if !complete.Load() {
				// A cgroup id resolves to a UID immediately; the namespace and
				// name need the pod cache.
				return KubernetesRef{PodUID: "uid-1"}, true
			}
			return KubernetesRef{Namespace: "prod", Pod: "nginx-7c9b4", PodUID: "uid-1"}, true
		},
	})

	require.NoError(t, h.HandleFileEvent(denialEvent(42)))
	require.NotNil(t, sink.events[0].Kubernetes)
	assert.Equal(t, "uid-1", sink.events[0].Kubernetes.PodUID)
	assert.Empty(t, sink.events[0].Kubernetes.Namespace)

	complete.Store(true)
	require.NoError(t, h.HandleFileEvent(denialEvent(42)))
	require.NotNil(t, sink.events[1].Kubernetes)
	assert.Equal(t, "prod", sink.events[1].Kubernetes.Namespace,
		"a partial reference must not be cached over a complete one")
}

// Once complete, the answer is memoised and the resolver is not consulted again.
func TestCompleteAttributionIsMemoised(t *testing.T) {
	var calls int64
	sink := &capturingSink{}
	h := NewHandler(sink, HandlerOptions{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		Attribution: func(id uint64) (KubernetesRef, bool) {
			atomic.AddInt64(&calls, 1)
			return KubernetesRef{Namespace: "prod", Pod: "nginx", PodUID: "uid-1"}, true
		},
	})

	for i := 0; i < 5; i++ {
		require.NoError(t, h.HandleFileEvent(denialEvent(42)))
	}
	assert.Equal(t, int64(1), atomic.LoadInt64(&calls),
		"a complete reference should be resolved once and reused")
	for _, ev := range sink.events {
		require.NotNil(t, ev.Kubernetes)
		assert.Equal(t, "prod", ev.Kubernetes.Namespace)
	}
}

func TestKubernetesRefComplete(t *testing.T) {
	var nilRef *KubernetesRef
	assert.False(t, nilRef.Complete())
	assert.False(t, (&KubernetesRef{}).Complete())
	assert.False(t, (&KubernetesRef{PodUID: "u"}).Complete())
	assert.False(t, (&KubernetesRef{Namespace: "ns"}).Complete())
	assert.False(t, (&KubernetesRef{Pod: "p"}).Complete())
	assert.True(t, (&KubernetesRef{Namespace: "ns", Pod: "p"}).Complete())
}

func BenchmarkHandleFileEventAttributed(b *testing.B) {
	h := NewHandler(&capturingSink{}, HandlerOptions{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		Attribution: func(uint64) (KubernetesRef, bool) {
			return KubernetesRef{Namespace: "prod", Pod: "nginx", PodUID: "uid-1"}, true
		},
	})
	ev := denialEvent(42)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleFileEvent(ev)
	}
}

// The unresolved path costs a resolver call per event until the pod cache
// warms; this measures that cost.
func BenchmarkHandleFileEventUnattributed(b *testing.B) {
	h := NewHandler(&capturingSink{}, HandlerOptions{
		Now:         func() time.Time { return time.Unix(1700000000, 0) },
		Attribution: func(uint64) (KubernetesRef, bool) { return KubernetesRef{}, false },
	})
	ev := denialEvent(42)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleFileEvent(ev)
	}
}
