package export

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Exporter is a sink that ships a batch of envelopes somewhere outside the
// process. Implementations must be safe for concurrent use and must return
// promptly; the Queue in front of them is what keeps the eBPF readers free of
// back pressure, but a sink that blocks forever still stalls the drain loop.
type Exporter interface {
	// Name identifies the sink in logs and metrics.
	Name() string
	// Export ships a batch. A nil or empty batch is a no-op.
	Export(ctx context.Context, events []*Event) error
	// Close flushes and releases the sink. Close must be idempotent.
	Close() error
}

// ErrClosed is returned by a sink used after Close.
var ErrClosed = errors.New("export: sink is closed")

// Multi fans a batch out to several sinks. A failing sink does not prevent the
// others from receiving the batch; all errors are joined.
type Multi struct {
	exporters []Exporter
}

// NewMulti returns a Multi over the given sinks. Nil sinks are skipped, so
// callers can build the list conditionally.
func NewMulti(exporters ...Exporter) *Multi {
	m := &Multi{}
	for _, e := range exporters {
		if e != nil {
			m.exporters = append(m.exporters, e)
		}
	}
	return m
}

func (m *Multi) Name() string { return "multi" }

// Exporters returns the sinks in the fan-out, in registration order.
func (m *Multi) Exporters() []Exporter {
	out := make([]Exporter, len(m.exporters))
	copy(out, m.exporters)
	return out
}

func (m *Multi) Export(ctx context.Context, events []*Event) error {
	if len(events) == 0 || len(m.exporters) == 0 {
		return nil
	}
	var errs []error
	for _, e := range m.exporters {
		if err := e.Export(ctx, events); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (m *Multi) Close() error {
	var errs []error
	for _, e := range m.exporters {
		if err := e.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Enqueuer accepts a single envelope without blocking. Queue is the production
// implementation; tests and callers that want synchronous delivery can supply
// their own.
type Enqueuer interface {
	// Enqueue returns false when the event was dropped.
	Enqueue(event *Event) bool
}

// Queue defaults.
const (
	DefaultQueueCapacity = 8192
	DefaultBatchSize     = 256
	DefaultFlushInterval = time.Second
)

// QueueOptions configures the bounded queue that decouples the eBPF ring
// buffer readers from the sinks.
type QueueOptions struct {
	// Capacity is the number of events buffered before Enqueue starts
	// dropping. Zero uses DefaultQueueCapacity.
	Capacity int
	// BatchSize caps how many events are handed to the sink at once. Zero uses
	// DefaultBatchSize.
	BatchSize int
	// FlushInterval bounds how long a partial batch waits. Zero uses
	// DefaultFlushInterval.
	FlushInterval time.Duration
	// ExportTimeout bounds a single Export call. Zero means no timeout beyond
	// whatever the sink applies itself.
	ExportTimeout time.Duration
	// OnError, when set, is called for every failed Export. It must not block.
	OnError func(err error)
}

func (o QueueOptions) withDefaults() QueueOptions {
	if o.Capacity <= 0 {
		o.Capacity = DefaultQueueCapacity
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = DefaultFlushInterval
	}
	return o
}

// Queue is a bounded, non-blocking buffer in front of an Exporter. Enqueue
// never blocks: when the buffer is full the event is dropped and counted in
// pahlevan_export_dropped_total{reason="queue_full"}. A single background
// goroutine drains the buffer into batches.
type Queue struct {
	exporter Exporter
	opts     QueueOptions

	ch   chan *Event
	done chan struct{}
	wg   sync.WaitGroup

	closeOnce sync.Once
	closed    chan struct{}

	mu      sync.Mutex
	dropped uint64
	sent    uint64
}

// NewQueue starts the drain goroutine for exporter. Call Close to flush and
// stop it.
func NewQueue(exporter Exporter, opts QueueOptions) *Queue {
	RegisterMetrics()
	opts = opts.withDefaults()
	q := &Queue{
		exporter: exporter,
		opts:     opts,
		ch:       make(chan *Event, opts.Capacity),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
	}
	q.wg.Add(1)
	go q.run()
	return q
}

// Enqueue offers an event to the queue. It returns false when the event was
// dropped because the buffer is full or the queue is closed. It never blocks.
func (q *Queue) Enqueue(event *Event) bool {
	if event == nil {
		return false
	}
	select {
	case <-q.closed:
		q.drop(dropReasonClosed)
		return false
	default:
	}
	select {
	case q.ch <- event:
		countExported(event.Type)
		return true
	default:
		q.drop(dropReasonQueueFull)
		return false
	}
}

func (q *Queue) drop(reason string) {
	q.mu.Lock()
	q.dropped++
	q.mu.Unlock()
	countDropped(reason, 1)
}

// Dropped returns the number of events discarded so far.
func (q *Queue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// Sent returns the number of events handed to the sink successfully.
func (q *Queue) Sent() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sent
}

// Len returns the number of events currently buffered.
func (q *Queue) Len() int { return len(q.ch) }

// Capacity returns the configured buffer size.
func (q *Queue) Capacity() int { return q.opts.Capacity }

func (q *Queue) run() {
	defer q.wg.Done()
	ticker := time.NewTicker(q.opts.FlushInterval)
	defer ticker.Stop()

	batch := make([]*Event, 0, q.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		q.export(batch)
		batch = make([]*Event, 0, q.opts.BatchSize)
	}

	for {
		select {
		case ev := <-q.ch:
			batch = append(batch, ev)
			if len(batch) >= q.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-q.done:
			// Drain whatever is still buffered before returning.
			for {
				select {
				case ev := <-q.ch:
					batch = append(batch, ev)
					if len(batch) >= q.opts.BatchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func (q *Queue) export(batch []*Event) {
	ctx := context.Background()
	if q.opts.ExportTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, q.opts.ExportTimeout)
		defer cancel()
	}
	err := q.exporter.Export(ctx, batch)
	if err != nil {
		countDropped(dropReasonSinkError, len(batch))
		q.mu.Lock()
		q.dropped += uint64(len(batch))
		q.mu.Unlock()
		if q.opts.OnError != nil {
			q.opts.OnError(err)
		}
		return
	}
	q.mu.Lock()
	q.sent += uint64(len(batch))
	q.mu.Unlock()
}

// Flush blocks until the currently buffered events have been handed to the
// sink, or until the context is done. It is intended for tests and for a
// graceful shutdown that wants a deadline.
func (q *Queue) Flush(ctx context.Context) error {
	for {
		if len(q.ch) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// Close stops the drain goroutine after flushing what is buffered, then closes
// the underlying sink. It is idempotent.
func (q *Queue) Close() error {
	var err error
	q.closeOnce.Do(func() {
		close(q.closed)
		close(q.done)
		q.wg.Wait()
		err = q.exporter.Close()
	})
	return err
}
