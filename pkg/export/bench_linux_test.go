package export

import (
	"context"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// discardExporter accepts everything and does no work, so a benchmark measures
// the conversion and queueing cost rather than the sink.
type discardExporter struct{}

func (discardExporter) Name() string                           { return "discard" }
func (discardExporter) Export(context.Context, []*Event) error { return nil }
func (discardExporter) Close() error                           { return nil }

// BenchmarkConvertAndEnqueue measures the hot path the eBPF ring buffer
// readers run on: convert a raw event into the envelope, apply the filter,
// resolve attribution and hand it to the bounded queue.
func BenchmarkConvertAndEnqueue(b *testing.B) {
	q := NewQueue(discardExporter{}, QueueOptions{
		Capacity:      1 << 16,
		BatchSize:     512,
		FlushInterval: time.Millisecond,
	})
	defer func() { _ = q.Close() }()

	h := NewHandler(q, HandlerOptions{
		Attribution: func(uint64) (KubernetesRef, bool) {
			return KubernetesRef{Namespace: "prod", Pod: "api-0", Container: "api"}, true
		},
	})

	file := &ebpf.FileEvent{
		PID:       4242,
		UID:       0,
		Flags:     DeniedFlag,
		SyscallNr: 257,
		Comm:      "curl",
		CgroupID:  99,
		Path:      "/etc/shadow",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleFileEvent(file)
	}
}

// BenchmarkConvertOnly isolates the envelope conversion.
func BenchmarkConvertOnly(b *testing.B) {
	ev := &ebpf.SyscallEvent{PID: 1, SyscallNr: 59, Comm: "sh", CgroupID: 7}
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromSyscallEvent(ev, now)
	}
}

// BenchmarkEnqueueWhenFull measures the drop path, which must stay cheap: a
// saturated queue is exactly when the data plane cannot afford to wait.
func BenchmarkEnqueueWhenFull(b *testing.B) {
	q := &Queue{
		opts:   QueueOptions{Capacity: 1}.withDefaults(),
		ch:     make(chan *Event, 1),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	q.ch <- testEventFor(EventTypeFile)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Enqueue(testEventFor(EventTypeFile))
	}
}

func testEventFor(t EventType) *Event {
	return &Event{Version: SchemaVersion, Type: t, Action: ActionObserve}
}
