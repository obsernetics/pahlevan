package export

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExporter records the batches it receives and can be made to fail or to
// block, which is how the queue's non-blocking guarantee is exercised.
type fakeExporter struct {
	name string

	mu      sync.Mutex
	batches [][]*Event
	closed  int

	err     error
	release chan struct{}
}

func newFakeExporter(name string) *fakeExporter { return &fakeExporter{name: name} }

func (f *fakeExporter) Name() string { return f.name }

func (f *fakeExporter) Export(ctx context.Context, events []*Event) error {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	batch := make([]*Event, len(events))
	copy(batch, events)
	f.batches = append(f.batches, batch)
	return nil
}

func (f *fakeExporter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeExporter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func (f *fakeExporter) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func testEvent(t EventType) *Event {
	return &Event{Version: SchemaVersion, Timestamp: Timestamp(testNow), Type: t, Action: ActionObserve}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within the timeout")
}

func TestMultiFansOut(t *testing.T) {
	a, b := newFakeExporter("a"), newFakeExporter("b")
	m := NewMulti(a, nil, b)

	if got := len(m.Exporters()); got != 2 {
		t.Fatalf("nil sinks should be skipped, got %d", got)
	}
	if m.Name() != "multi" {
		t.Errorf("name = %q", m.Name())
	}
	if err := m.Export(context.Background(), nil); err != nil {
		t.Errorf("empty batch: %v", err)
	}
	if err := m.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if a.count() != 1 || b.count() != 1 {
		t.Fatalf("counts = %d/%d", a.count(), b.count())
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if a.closeCount() != 1 || b.closeCount() != 1 {
		t.Errorf("close counts = %d/%d", a.closeCount(), b.closeCount())
	}
}

func TestMultiJoinsErrors(t *testing.T) {
	bad := newFakeExporter("bad")
	bad.err = errors.New("boom")
	good := newFakeExporter("good")

	m := NewMulti(bad, good)
	err := m.Export(context.Background(), []*Event{testEvent(EventTypeSyscall)})
	if err == nil || !strings.Contains(err.Error(), "bad: boom") {
		t.Fatalf("err = %v", err)
	}
	if good.count() != 1 {
		t.Error("a failing sink must not stop the others")
	}
}

func TestQueueDeliversBatches(t *testing.T) {
	sink := newFakeExporter("sink")
	q := NewQueue(sink, QueueOptions{Capacity: 16, BatchSize: 2, FlushInterval: 5 * time.Millisecond})
	defer func() { _ = q.Close() }()

	for i := 0; i < 5; i++ {
		if !q.Enqueue(testEvent(EventTypeSyscall)) {
			t.Fatalf("enqueue %d was dropped", i)
		}
	}
	if q.Enqueue(nil) {
		t.Error("a nil event must not be accepted")
	}
	waitFor(t, func() bool { return sink.count() == 5 })
	if q.Dropped() != 0 {
		t.Errorf("dropped = %d", q.Dropped())
	}
	waitFor(t, func() bool { return q.Sent() == 5 })
	if q.Capacity() != 16 {
		t.Errorf("capacity = %d", q.Capacity())
	}
}

func TestQueueDropsWhenFullInsteadOfBlocking(t *testing.T) {
	sink := newFakeExporter("slow")
	sink.release = make(chan struct{})

	q := NewQueue(sink, QueueOptions{Capacity: 4, BatchSize: 1, FlushInterval: time.Millisecond})

	// The drain goroutine parks inside Export, so the buffer fills and every
	// further Enqueue must return immediately with false.
	accepted, dropped := 0, 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if q.Enqueue(testEvent(EventTypeNetwork)) {
				accepted++
			} else {
				dropped++
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue blocked while the sink was stuck")
	}

	if dropped == 0 {
		t.Fatalf("expected drops, accepted %d dropped %d", accepted, dropped)
	}
	if accepted > 6 {
		t.Errorf("accepted %d events with a capacity of 4", accepted)
	}
	if q.Dropped() != uint64(dropped) {
		t.Errorf("Dropped() = %d, counted %d", q.Dropped(), dropped)
	}

	close(sink.release)
	_ = q.Close()
}

func TestQueueCountsSinkFailuresAsDrops(t *testing.T) {
	sink := newFakeExporter("failing")
	sink.err = errors.New("collector down")

	var gotErr error
	var mu sync.Mutex
	q := NewQueue(sink, QueueOptions{
		Capacity:      8,
		BatchSize:     2,
		FlushInterval: time.Millisecond,
		ExportTimeout: time.Second,
		OnError: func(err error) {
			mu.Lock()
			gotErr = err
			mu.Unlock()
		},
	})

	for i := 0; i < 2; i++ {
		q.Enqueue(testEvent(EventTypeProcess))
	}
	waitFor(t, func() bool { return q.Dropped() == 2 })
	mu.Lock()
	err := gotErr
	mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "collector down") {
		t.Fatalf("OnError got %v", err)
	}
	if q.Sent() != 0 {
		t.Errorf("sent = %d", q.Sent())
	}
	_ = q.Close()
}

func TestQueueFlushesOnClose(t *testing.T) {
	sink := newFakeExporter("sink")
	q := NewQueue(sink, QueueOptions{Capacity: 64, BatchSize: 1000, FlushInterval: time.Hour})

	for i := 0; i < 10; i++ {
		q.Enqueue(testEvent(EventTypeFile))
	}
	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if sink.count() != 10 {
		t.Fatalf("close should flush the buffer, got %d events", sink.count())
	}
	// Close is idempotent and a closed queue rejects new events.
	if err := q.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if sink.closeCount() != 1 {
		t.Errorf("sink closed %d times", sink.closeCount())
	}
	if q.Enqueue(testEvent(EventTypeFile)) {
		t.Error("a closed queue must reject events")
	}
	if q.Dropped() != 1 {
		t.Errorf("dropped = %d", q.Dropped())
	}
}

func TestQueueFlushWaitsForDrain(t *testing.T) {
	sink := newFakeExporter("sink")
	q := NewQueue(sink, QueueOptions{Capacity: 8, BatchSize: 1, FlushInterval: time.Millisecond})
	defer func() { _ = q.Close() }()

	q.Enqueue(testEvent(EventTypeSyscall))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := q.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if q.Len() != 0 {
		t.Errorf("len = %d", q.Len())
	}
}

func TestQueueFlushRespectsContext(t *testing.T) {
	sink := newFakeExporter("stuck")
	sink.release = make(chan struct{})
	q := NewQueue(sink, QueueOptions{Capacity: 8, BatchSize: 1, FlushInterval: time.Millisecond})

	for i := 0; i < 4; i++ {
		q.Enqueue(testEvent(EventTypeSyscall))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := q.Flush(ctx); err == nil {
		t.Fatal("expected the flush to time out")
	}
	close(sink.release)
	_ = q.Close()
}

func TestQueueDefaults(t *testing.T) {
	sink := newFakeExporter("sink")
	q := NewQueue(sink, QueueOptions{})
	defer func() { _ = q.Close() }()
	if q.Capacity() != DefaultQueueCapacity {
		t.Errorf("capacity = %d", q.Capacity())
	}
	if q.opts.BatchSize != DefaultBatchSize || q.opts.FlushInterval != DefaultFlushInterval {
		t.Errorf("options = %+v", q.opts)
	}
}
