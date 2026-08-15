package ebpf

import (
	"context"
	"errors"
	"sync"
	"testing"

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
