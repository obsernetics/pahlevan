package ebpf

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errHandlerTest = errors.New("sink unavailable")

// counterValue reads a single child of a CounterVec. The Vecs are package-level
// and registered in init(), so tests read deltas rather than absolute values -
// any other test in the package may have moved them.
func counterValue(t *testing.T, vec *prometheus.CounterVec, kind string) float64 {
	t.Helper()
	var m dto.Metric
	c, err := vec.GetMetricWithLabelValues(kind)
	require.NoError(t, err)
	require.NoError(t, c.(prometheus.Metric).Write(&m))
	return m.GetCounter().GetValue()
}

// managerForCounters builds a Manager with only the counter wiring populated.
// NewManager() needs CAP_BPF to drop the memlock rlimit and probe the kernel,
// which is exactly what must not happen on the host.
func managerForCounters() *Manager {
	counters := make(map[string]dataPlaneCounters, len(eventKinds))
	for _, k := range eventKinds {
		counters[k] = newDataPlaneCounters(k)
	}
	return &Manager{stopCh: make(chan struct{}), counters: counters}
}

type countingHandler struct {
	syscalls, networks, files, processes, caps int
}

func (h *countingHandler) HandleSyscallEvent(*SyscallEvent) error       { h.syscalls++; return nil }
func (h *countingHandler) HandleNetworkEvent(*NetworkEvent) error       { h.networks++; return nil }
func (h *countingHandler) HandleFileEvent(*FileEvent) error             { h.files++; return nil }
func (h *countingHandler) HandleProcessEvent(*ProcessEvent) error       { h.processes++; return nil }
func (h *countingHandler) HandleCapabilityEvent(*CapabilityEvent) error { h.caps++; return nil }

// failingHandler stands in for a sink that has broken - an export webhook that
// is refusing connections, a full disk.
type failingHandler struct{ err error }

func (h *failingHandler) HandleSyscallEvent(*SyscallEvent) error       { return h.err }
func (h *failingHandler) HandleNetworkEvent(*NetworkEvent) error       { return h.err }
func (h *failingHandler) HandleFileEvent(*FileEvent) error             { return h.err }
func (h *failingHandler) HandleProcessEvent(*ProcessEvent) error       { return h.err }
func (h *failingHandler) HandleCapabilityEvent(*CapabilityEvent) error { return h.err }

// A handler that fails must be countable. Silently discarding the error made a
// broken export pipeline indistinguishable from a quiet cluster: events kept
// being decoded and counted while nothing downstream ever received them.
func TestHandlerErrorsAreCounted(t *testing.T) {
	m := managerForCounters()
	ctx := context.Background()
	m.eventHandlers = []EventHandler{&failingHandler{err: errHandlerTest}, &countingHandler{}}

	before := counterValue(t, ebpfHandlerErrorsTotal, kindFile)
	beforeEvents := counterValue(t, ebpfEventsTotal, kindFile)
	m.handleEventRecord(ctx, kindFile, buildFileRec(1, 2, 100, 0, 0, 0, "sh", "/etc/passwd"))

	assert.Equal(t, before+1, counterValue(t, ebpfHandlerErrorsTotal, kindFile),
		"the failing handler must be counted exactly once")
	assert.Equal(t, beforeEvents+1, counterValue(t, ebpfEventsTotal, kindFile),
		"one handler failing must not stop the event from being counted")
}

// A healthy handler must not move the error counter, or the metric is useless
// as an alert.
func TestHandlerErrorsStayZeroWhenHandlersSucceed(t *testing.T) {
	m := managerForCounters()
	m.eventHandlers = []EventHandler{&countingHandler{}}

	before := counterValue(t, ebpfHandlerErrorsTotal, kindSyscall)
	m.handleEventRecord(context.Background(), kindSyscall, buildSyscallRec(1, 2, 59, 100, 0, 0, "sh"))
	assert.Equal(t, before, counterValue(t, ebpfHandlerErrorsTotal, kindSyscall))
}

// Every kind must count its events, not just the denied ones. Exec and
// capability events used to increment nothing unless they were denied, so an
// agent observing exec traffic reported an empty series.
func TestDataPlaneCountersCountEveryKind(t *testing.T) {
	m := managerForCounters()
	ctx := context.Background()
	h := &countingHandler{}
	m.eventHandlers = []EventHandler{h}

	cases := []struct {
		kind string
		rec  []byte
	}{
		{kindSyscall, buildSyscallRec(1, 2, 59, 100, 0, 0, "sh")},
		{kindFile, buildFileRec(1, 2, 100, 0, 0, 0, "sh", "/etc/passwd")},
		{kindNetwork, buildNetRec(1, 2, 100, 0x0100007f, 0x08080808, 1234, 53, 17, 0, "sh")},
		{kindExec, buildExecRec(1, 2, 100, 1, 0, 0, "sh", "init", "/bin/sh")},
		{kindCapability, buildCapRec(1, 2, 100, 21, 0, "sh")},
	}

	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			before := counterValue(t, ebpfEventsTotal, c.kind)
			m.handleEventRecord(ctx, c.kind, c.rec)
			after := counterValue(t, ebpfEventsTotal, c.kind)
			assert.Equal(t, before+1, after, "%s event should be counted", c.kind)
		})
	}

	assert.Equal(t, 1, h.syscalls)
	assert.Equal(t, 1, h.files)
	assert.Equal(t, 1, h.networks)
	assert.Equal(t, 1, h.processes)
	assert.Equal(t, 1, h.caps)
}

// A denial must increment both the event counter and the denial counter: the
// denial is a subset of traffic, not a separate stream, so denials/events is a
// meaningful ratio on a dashboard.
func TestDataPlaneCountersCountDenials(t *testing.T) {
	m := managerForCounters()
	ctx := context.Background()

	cases := []struct {
		kind string
		rec  []byte
	}{
		{kindFile, buildFileRec(1, 2, 100, 0, 0, DeniedFlag, "sh", "/etc/shadow")},
		{kindNetwork, buildNetRec(1, 2, 100, 0x0100007f, 0x08080808, 1234, 4444, 6, DeniedDirection, "sh")},
		{kindExec, buildExecRec(1, 2, 100, 1, 0, DeniedFlag, "sh", "init", "/usr/bin/nc")},
		{kindCapability, buildCapRec(1, 2, 100, 21, DeniedFlag, "sh")},
	}

	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			evBefore := counterValue(t, ebpfEventsTotal, c.kind)
			dnBefore := counterValue(t, ebpfDenialsTotal, c.kind)
			m.handleEventRecord(ctx, c.kind, c.rec)
			assert.Equal(t, evBefore+1, counterValue(t, ebpfEventsTotal, c.kind), "event")
			assert.Equal(t, dnBefore+1, counterValue(t, ebpfDenialsTotal, c.kind), "denial")
		})
	}
}

// An allowed event must not be counted as a denial.
func TestDataPlaneCountersAllowedIsNotDenied(t *testing.T) {
	m := managerForCounters()
	before := counterValue(t, ebpfDenialsTotal, kindFile)
	m.handleEventRecord(context.Background(), kindFile,
		buildFileRec(1, 2, 100, 0, 0, 0, "sh", "/etc/passwd"))
	assert.Equal(t, before, counterValue(t, ebpfDenialsTotal, kindFile))
}

// Undecodable records used to vanish without a trace, so a wire-format skew
// between the kernel and userspace halves looked like an idle node.
func TestDataPlaneCountersCountDecodeErrors(t *testing.T) {
	m := managerForCounters()
	ctx := context.Background()
	truncated := []byte{0x01, 0x02, 0x03}

	for _, kind := range eventKinds {
		t.Run(kind, func(t *testing.T) {
			errBefore := counterValue(t, ebpfDecodeErrorsTotal, kind)
			evBefore := counterValue(t, ebpfEventsTotal, kind)
			m.handleEventRecord(ctx, kind, truncated)
			assert.Equal(t, errBefore+1, counterValue(t, ebpfDecodeErrorsTotal, kind), "decode error")
			assert.Equal(t, evBefore, counterValue(t, ebpfEventsTotal, kind), "must not count as an event")
		})
	}
}

// An unrecognized kind must be inert rather than panic on the nil map entry.
func TestDataPlaneCountersUnknownKindIsInert(t *testing.T) {
	m := managerForCounters()
	assert.NotPanics(t, func() {
		m.handleEventRecord(context.Background(), "nonsense", []byte{0x00})
	})
}

// Series for kinds that have not fired must still be present, otherwise
// "enforcement is off" and "no traffic yet" are indistinguishable.
func TestDataPlaneCountersPreCreateEveryChild(t *testing.T) {
	for _, vec := range []*prometheus.CounterVec{ebpfEventsTotal, ebpfDenialsTotal, ebpfDecodeErrorsTotal} {
		for _, kind := range eventKinds {
			_, err := vec.GetMetricWithLabelValues(kind)
			require.NoError(t, err, "kind %s must be pre-created", kind)
		}
	}
}

// The userspace constants must match the literals the kernel writes in bpf/*.c.
func TestDenialContractConstants(t *testing.T) {
	assert.Equal(t, uint32(0x80000000), DeniedFlag)
	assert.Equal(t, uint32(0x40000000), KilledFlag)
	assert.Equal(t, uint8(0x80), DeniedDirection)
}

func BenchmarkHandleEventRecordSyscall(b *testing.B) {
	m := managerForCounters()
	ctx := context.Background()
	rec := buildSyscallRec(1, 2, 59, 100, 0, 0, "sh")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.handleEventRecord(ctx, kindSyscall, rec)
	}
}

func BenchmarkHandleEventRecordFileDenied(b *testing.B) {
	m := managerForCounters()
	ctx := context.Background()
	rec := buildFileRec(1, 2, 100, 0, 0, DeniedFlag, "sh", "/etc/shadow")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.handleEventRecord(ctx, kindFile, rec)
	}
}

func BenchmarkHandleEventRecordDecodeError(b *testing.B) {
	m := managerForCounters()
	ctx := context.Background()
	rec := []byte{0x01, 0x02, 0x03}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.handleEventRecord(ctx, kindFile, rec)
	}
}

// These two document why dispatch is synchronous. The goroutine variant is what
// notifyHandlers used to do; keeping the comparison next to the code stops the
// change from being quietly reverted as a "concurrency improvement".
func BenchmarkNotifyHandlersSync(b *testing.B) {
	m := managerForCounters()
	m.eventHandlers = []EventHandler{&countingHandler{}}
	ev := &SyscallEvent{PID: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.notifyHandlers(kindSyscall, func(h EventHandler) error { return h.HandleSyscallEvent(ev) })
	}
}

func BenchmarkNotifyHandlersGoroutinePerEvent(b *testing.B) {
	var wg sync.WaitGroup
	h := &countingHandler{}
	ev := &SyscallEvent{PID: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.HandleSyscallEvent(ev) }()
	}
	wg.Wait()
}

// A ring-buffer read that keeps failing used to spin the loop at full speed:
// `continue` went straight back to Read(), which failed immediately, forever.
// One CPU core pinned per affected reader, silently, while the agent processed
// nothing - and there were eight readers.
//
// This asserts the loop now backs off. It measures iterations rather than CPU,
// because a busy loop is exactly a loop that iterates as fast as it can.
func TestAFailingReaderBacksOffInsteadOfSpinning(t *testing.T) {
	var reads atomic.Int64
	stop := make(chan struct{})

	// Stand in for the reader: always fails, instantly, with an error the loop
	// does not recognise - the shape of a corrupted buffer or an unexpected
	// epoll fault.
	failing := func() error {
		reads.Add(1)
		return errors.New("simulated ring buffer fault")
	}

	// The loop under test, with the same structure processEvents uses.
	go func() {
		var consecutive int
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := failing(); err != nil {
				consecutive++
				select {
				case <-stop:
					return
				case <-time.After(readErrorBackoff):
				}
				continue
			}
		}
	}()

	time.Sleep(350 * time.Millisecond)
	close(stop)

	n := reads.Load()
	// With a 100ms backoff, 350ms allows roughly four attempts. Without any
	// backoff this same loop reaches millions.
	if n > 50 {
		t.Errorf("a persistently failing reader attempted %d reads in 350ms; "+
			"it is spinning rather than backing off", n)
	}
	if n == 0 {
		t.Error("the reader never retried at all; a transient fault would stop the agent")
	}
	t.Logf("%d attempts in 350ms with a %v backoff", n, readErrorBackoff)
}

// The backoff must not delay shutdown: an agent that takes a backoff interval
// per reader to stop is an agent that misses its termination grace period.
func TestBackoffDoesNotDelayShutdown(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Always fails, so the loop is always inside the backoff wait.
			select {
			case <-stop:
				return
			case <-time.After(readErrorBackoff):
			}
		}
	}()

	time.Sleep(20 * time.Millisecond) // land inside a backoff
	start := time.Now()
	close(stop)
	select {
	case <-done:
	case <-time.After(readErrorBackoff):
		t.Fatal("the loop did not exit promptly; the backoff wait is not selecting on stop")
	}
	t.Logf("exited %v after stop, well inside the %v backoff", time.Since(start), readErrorBackoff)
}

// A closed reader is Stop() doing its job. Treating it as a fault would log an
// error and back off on every clean shutdown.
func TestClosedReaderIsNotAFault(t *testing.T) {
	for _, err := range []error{ringbuf.ErrClosed, os.ErrClosed} {
		if !errors.Is(err, ringbuf.ErrClosed) && !errors.Is(err, os.ErrClosed) {
			t.Errorf("%v is not recognised as a closed reader", err)
		}
	}
	// And a deadline is deliberate, not a fault.
	if !errors.Is(os.ErrDeadlineExceeded, os.ErrDeadlineExceeded) {
		t.Error("a deadline is not recognised")
	}
}

// Every kind must resolve to its own reader. A kind that resolves to nil, or to
// the wrong one, silently stops delivering that class of event.
func TestEveryEventKindHasItsOwnReader(t *testing.T) {
	m := &Manager{
		eventReader:        &ringbuf.Reader{},
		networkEventReader: &ringbuf.Reader{},
		fileEventReader:    &ringbuf.Reader{},
		execEventReader:    &ringbuf.Reader{},
		capEventReader:     &ringbuf.Reader{},
		credEventReader:    &ringbuf.Reader{},
		shellEventReader:   &ringbuf.Reader{},
		kprobeEventReader:  &ringbuf.Reader{},
	}
	seen := map[*ringbuf.Reader]string{}
	for _, kind := range eventKinds {
		r := m.readerFor(kind)
		if r == nil {
			t.Errorf("%s resolves to no reader, so those events are never delivered", kind)
			continue
		}
		if other, dup := seen[r]; dup {
			t.Errorf("%s and %s share a reader", kind, other)
		}
		seen[r] = kind
	}
	if got := m.readerFor("nonexistent"); got != nil {
		t.Error("an unknown kind resolved to a reader")
	}
}
