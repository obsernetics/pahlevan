package ebpf

import (
	"context"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/obsernetics/pahlevan/pkg/observability"
)

// recordSpans installs an in-memory recorder as the process tracer for the
// duration of one test.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	observability.SetTracerProvider(tp)
	t.Cleanup(func() {
		observability.DisableTracing()
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

// TestHotEventPathProducesNoSpans is the mechanical form of the rule stated in
// the comment on processEvents: the per-event path must never start a span.
//
// It is a test rather than a convention because the temptation is real and the
// consequence is invisible in review: a span per event would cost an
// allocation and a queue slot on the busiest path in the agent, hundreds of
// thousands of times a second, and everything would still appear to work - it
// would just burn the CPU budget that the whole design is built to protect.
func TestHotEventPathProducesNoSpans(t *testing.T) {
	rec := recordSpans(t)

	m := managerForCounters()
	m.eventHandlers = []EventHandler{&countingHandler{}}
	ctx := context.Background()

	// Every decoded kind, several times over, plus an undecodable record and
	// an unknown kind, so no branch of handleEventRecord escapes the check.
	for i := 0; i < 50; i++ {
		m.handleEventRecord(ctx, kindSyscall, buildSyscallRec(1, 2, 59, 100, 0, 0, "sh"))
		m.handleEventRecord(ctx, kindFile, buildFileRec(1, 2, 100, 0, 0, 0, "sh", "/etc/passwd"))
		m.handleEventRecord(ctx, kindNetwork, buildNetRec(1, 2, 100, 0x01020304, 0x05060708, 1, 443, 6, 0, "sh"))
		m.handleEventRecord(ctx, kindExec, buildExecRec(1, 2, 100, 1, 0, 0, "sh", "bash", "/bin/sh"))
		m.handleEventRecord(ctx, kindCapability, buildCapRec(1, 2, 100, 21, 0, "sh"))
		m.handleEventRecord(ctx, kindSyscall, []byte{0x00, 0x01}) // undecodable
		m.handleEventRecord(ctx, "nonsense", []byte{0x00})
	}

	if n := len(rec.Ended()); n != 0 {
		// Distinct names only: a span per event produces thousands of
		// identical lines, and a failure message nobody can read is a failure
		// message nobody acts on.
		seen := map[string]bool{}
		var names []string
		for _, s := range rec.Ended() {
			if !seen[s.Name()] {
				seen[s.Name()] = true
				names = append(names, s.Name())
			}
		}
		t.Fatalf("the per-event hot path started %d spans (%s); it must start none - see the comment on processEvents",
			n, strings.Join(names, ", "))
	}
	// Started-but-unfinished spans would be just as expensive, so check those
	// too rather than only the ended ones.
	if n := len(rec.Started()); n != 0 {
		t.Fatalf("the per-event hot path started %d spans that were never ended", n)
	}
}

// TestEnforcementModeChangeIsTraced covers the span an operator reaches for
// first when a container starts being denied things.
func TestEnforcementModeChangeIsTraced(t *testing.T) {
	rec := recordSpans(t)

	// No collection is loaded, so the map write fails - which is the case
	// worth asserting: the control plane believes it switched the cgroup to
	// enforcing while the kernel is still in learn mode.
	m := &Manager{}
	if err := m.SetFileEnforcement(4026532567, true); err == nil {
		t.Fatal("expected an error from a manager with no file collection")
	}

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	span := ended[0]
	if span.Name() != observability.SpanEnforcementMode {
		t.Fatalf("span name = %q, want %q", span.Name(), observability.SpanEnforcementMode)
	}
	attrs := map[string]string{}
	for _, a := range span.Attributes() {
		attrs[string(a.Key)] = a.Value.Emit()
	}
	if attrs["pahlevan.enforcement.subsystem"] != "file" {
		t.Errorf("subsystem = %q", attrs["pahlevan.enforcement.subsystem"])
	}
	if attrs["pahlevan.enforcement.mode"] != "enforce" {
		t.Errorf("mode = %q", attrs["pahlevan.enforcement.mode"])
	}
	// Rendered as a string: a cgroup id with the top bit set would come back
	// as a negative number from an int64 attribute and match nothing.
	if attrs["pahlevan.cgroup.id"] != "4026532567" {
		t.Errorf("cgroup id = %q", attrs["pahlevan.cgroup.id"])
	}
	if span.Status().Code.String() != "Error" {
		t.Errorf("a failed map write must leave the span in error, got %v", span.Status().Code)
	}
}

func TestEnforcementModeSubsystemsAreDistinct(t *testing.T) {
	rec := recordSpans(t)
	m := &Manager{}
	_ = m.SetFileEnforcement(1, false)
	_ = m.SetNetworkEnforcement(1, true)
	_ = m.SetExecEnforcement(1, true)
	_ = m.SetCapabilityEnforcement(1, false)

	want := map[string]string{"file": "learn", "network": "enforce", "exec": "enforce", "capability": "learn"}
	got := map[string]string{}
	for _, s := range rec.Ended() {
		attrs := map[string]string{}
		for _, a := range s.Attributes() {
			attrs[string(a.Key)] = a.Value.Emit()
		}
		got[attrs["pahlevan.enforcement.subsystem"]] = attrs["pahlevan.enforcement.mode"]
	}
	if len(got) != len(want) {
		t.Fatalf("expected one span per subsystem, got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("subsystem %s mode = %q, want %q", k, got[k], v)
		}
	}
}

// TestEnforcementModeNotTracedWhenDisabled is the counterpart: with tracing
// off, the same call must produce nothing and behave identically.
func TestEnforcementModeNotTracedWhenDisabled(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	observability.SetTracerProvider(tp)
	observability.DisableTracing()

	m := &Manager{}
	if err := m.SetFileEnforcement(1, true); err == nil {
		t.Fatal("expected an error from a manager with no file collection")
	}
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("tracing is off but %d spans were recorded", n)
	}
}

// BenchmarkHandleEventRecord_TracingEnabled and _TracingDisabled are the proof
// that instrumenting the control plane left the data plane alone: the two
// figures must be the same, because there is no span on this path.
func BenchmarkHandleEventRecord_TracingDisabled(b *testing.B) {
	observability.DisableTracing()
	benchmarkHandleEventRecord(b)
}

func BenchmarkHandleEventRecord_TracingEnabled(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	observability.SetTracerProvider(tp)
	defer func() {
		observability.DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	benchmarkHandleEventRecord(b)
}

func benchmarkHandleEventRecord(b *testing.B) {
	b.Helper()
	m := managerForCounters()
	m.eventHandlers = []EventHandler{&countingHandler{}}
	ctx := context.Background()
	rec := buildSyscallRec(1, 2, 59, 100, 0, 0, "sh")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.handleEventRecord(ctx, kindSyscall, rec)
	}
}

// BenchmarkSetFileEnforcement_Tracing* measures a control-plane operation that
// IS instrumented, so the cost of a span is a number rather than a claim.
func BenchmarkSetFileEnforcement_TracingDisabled(b *testing.B) {
	observability.DisableTracing()
	benchmarkSetFileEnforcement(b)
}

func BenchmarkSetFileEnforcement_TracingEnabled(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	observability.SetTracerProvider(tp)
	defer func() {
		observability.DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	benchmarkSetFileEnforcement(b)
}

func benchmarkSetFileEnforcement(b *testing.B) {
	b.Helper()
	m := &Manager{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SetFileEnforcement(uint64(i), true)
	}
}

// TestLoadPrograms_FailureIsARedRootSpan covers the load span without loading
// anything into the kernel: the capability gate fails first, which is exactly
// what happens on a node that cannot run the agent at all.
//
// The per-program child spans need a real kernel to exercise and are covered
// by the VM suite rather than here - loading BPF on the build host is not
// something this test may do.
func TestLoadPrograms_FailureIsARedRootSpan(t *testing.T) {
	rec := recordSpans(t)

	m := &Manager{capabilities: &SystemCapabilities{HasEBPFSupport: false}}
	if err := m.LoadPrograms(); err == nil {
		t.Fatal("expected LoadPrograms to fail without eBPF support")
	}

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	if ended[0].Name() != observability.SpanEBPFLoad {
		t.Fatalf("span name = %q, want %q", ended[0].Name(), observability.SpanEBPFLoad)
	}
	if ended[0].Status().Code.String() != "Error" {
		t.Errorf("status = %v, want Error", ended[0].Status().Code)
	}
}

// TestLoadPrograms_MissingTracepointsIsRecorded covers the second gate: eBPF
// is present but the required syscall tracepoint is not, which leaves an agent
// that loads nothing while the pod still starts.
func TestLoadPrograms_MissingTracepointsIsRecorded(t *testing.T) {
	rec := recordSpans(t)

	m := &Manager{capabilities: &SystemCapabilities{HasEBPFSupport: true, HasTracepointSupport: false}}
	if err := m.LoadPrograms(); err == nil {
		t.Fatal("expected LoadPrograms to fail without tracepoint support")
	}
	ended := rec.Ended()
	if len(ended) != 1 || ended[0].Status().Code.String() != "Error" {
		t.Fatalf("expected one failed load span, got %d", len(ended))
	}
	if !strings.Contains(ended[0].Status().Description, "tracepoint") {
		t.Errorf("status description does not name the missing feature: %q",
			ended[0].Status().Description)
	}
}

// TestAttachPrograms_UnloadedIsARedRootSpan covers the attach root span for
// the misordered-startup case, where Start is called before LoadPrograms.
func TestAttachPrograms_UnloadedIsARedRootSpan(t *testing.T) {
	rec := recordSpans(t)

	m := &Manager{}
	if err := m.AttachPrograms(); err == nil {
		t.Fatal("expected AttachPrograms to fail with nothing loaded")
	}
	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	if ended[0].Name() != observability.SpanEBPFAttach {
		t.Fatalf("span name = %q, want %q", ended[0].Name(), observability.SpanEBPFAttach)
	}
	if ended[0].Status().Code.String() != "Error" {
		t.Errorf("status = %v, want Error", ended[0].Status().Code)
	}
}
