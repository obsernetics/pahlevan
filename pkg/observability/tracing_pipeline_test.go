package observability

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recordSpans installs an in-memory span recorder as the process tracer and
// removes it again when the test ends. Every assertion in this file is about
// the spans that actually came out the far end of the pipeline; asserting that
// a tracer exists is what let the previous implementation ship a provider with
// no span processors.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	SetTracerProvider(tp)
	t.Cleanup(func() {
		DisableTracing()
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

func attrsOf(t *testing.T, s sdktrace.ReadOnlySpan) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, a := range s.Attributes() {
		m[string(a.Key)] = a.Value.Emit()
	}
	return m
}

func TestStartSpan_RecordsNameAndAttributes(t *testing.T) {
	rec := recordSpans(t)

	_, span := StartSpan(context.Background(), SpanProfileGenerate,
		AttrNamespace.String("prod"),
		AttrWorkload.String("checkout"),
		AttrPolicy.String("checkout-policy"),
		AttrSyscalls.Int(41))
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	if ended[0].Name() != "pahlevan.profile.generate" {
		t.Errorf("span name = %q", ended[0].Name())
	}
	got := attrsOf(t, ended[0])
	for k, want := range map[string]string{
		"pahlevan.namespace":        "prod",
		"pahlevan.workload":         "checkout",
		"pahlevan.policy":           "checkout-policy",
		"pahlevan.profile.syscalls": "41",
	} {
		if got[k] != want {
			t.Errorf("attribute %s = %q, want %q", k, got[k], want)
		}
	}
	if ended[0].InstrumentationScope().Name != ScopeName {
		t.Errorf("scope = %q, want %q", ended[0].InstrumentationScope().Name, ScopeName)
	}
}

func TestStartSpan_ChildIsParentedCorrectly(t *testing.T) {
	rec := recordSpans(t)

	ctx, parent := StartSpan(context.Background(), SpanEBPFLoad)
	_, child := StartSpan(ctx, SpanEBPFProgramLoad, AttrProgram.String("file_monitor"))
	child.End()
	parent.End()

	ended := rec.Ended()
	if len(ended) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(ended))
	}
	childSpan, parentSpan := ended[0], ended[1]
	if childSpan.Name() != SpanEBPFProgramLoad || parentSpan.Name() != SpanEBPFLoad {
		t.Fatalf("unexpected order: %q then %q", childSpan.Name(), parentSpan.Name())
	}
	// Same trace is necessary but not sufficient: a sibling shares the trace
	// id too. The parent span id is what makes the waterfall nest.
	if childSpan.SpanContext().TraceID() != parentSpan.SpanContext().TraceID() {
		t.Error("child is in a different trace from its parent")
	}
	if childSpan.Parent().SpanID() != parentSpan.SpanContext().SpanID() {
		t.Errorf("child parent = %s, want %s",
			childSpan.Parent().SpanID(), parentSpan.SpanContext().SpanID())
	}
}

func TestRecordError_SetsErrorStatusAndException(t *testing.T) {
	rec := recordSpans(t)

	_, span := StartSpan(context.Background(), SpanEBPFProgramAttach,
		AttrProgram.String("file_monitor"),
		AttrHook.String("lsm/file_open"))
	want := errors.New("attach lsm/file_open: operation not supported")
	if got := RecordError(span, want); !errors.Is(got, want) {
		t.Fatalf("RecordError must return the error unchanged, got %v", got)
	}
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	// A recorded exception without an error status renders as a successful
	// span in most backends, which is how a failed attach stayed invisible.
	if ended[0].Status().Code != codes.Error {
		t.Errorf("status = %v, want Error", ended[0].Status().Code)
	}
	if ended[0].Status().Description != want.Error() {
		t.Errorf("status description = %q", ended[0].Status().Description)
	}
	var sawException bool
	for _, e := range ended[0].Events() {
		if e.Name == "exception" {
			sawException = true
		}
	}
	if !sawException {
		t.Error("RecordError did not record an exception event")
	}
}

func TestEndSpan_SuccessLeavesStatusUnset(t *testing.T) {
	rec := recordSpans(t)

	_, span := StartSpan(context.Background(), SpanPolicyApply)
	EndSpan(span, nil)

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	if ended[0].Status().Code == codes.Error {
		t.Error("a successful span must not carry an error status")
	}
}

func TestRecordPhaseTransition_IsAnEventOnTheSpan(t *testing.T) {
	rec := recordSpans(t)

	_, span := StartSpan(context.Background(), SpanPolicyReconcile,
		AttrNamespace.String("prod"), AttrPolicy.String("checkout-policy"))
	RecordPhaseTransition(span, "Learning", "Transition", "WindowElapsed")
	span.End()

	events := rec.Ended()[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Name != EventPhaseTransition {
		t.Fatalf("event name = %q", events[0].Name)
	}
	got := map[string]string{}
	for _, a := range events[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["pahlevan.phase.from"] != "Learning" || got["pahlevan.phase.to"] != "Transition" {
		t.Errorf("transition attributes = %v", got)
	}
	if got["pahlevan.reason"] != "WindowElapsed" {
		t.Errorf("reason = %q", got["pahlevan.reason"])
	}
}

func TestRecordMapSizing_OneAttributePerMapAndSkipsDefaults(t *testing.T) {
	rec := recordSpans(t)

	_, span := StartSpan(context.Background(), SpanEBPFProgramLoad)
	RecordMapSizing(span, map[string]uint32{
		"file_allowed": 65536,
		"file_events":  1 << 20,
		"unused":       0, // compiled default kept: must not appear
	})
	span.End()

	events := rec.Ended()[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := map[string]string{}
	for _, a := range events[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	// Both maps must survive: a shared key would have deduplicated them down
	// to whichever the map iteration happened to yield last.
	if got["pahlevan.ebpf.map.file_allowed"] != "65536" {
		t.Errorf("file_allowed = %q", got["pahlevan.ebpf.map.file_allowed"])
	}
	if got["pahlevan.ebpf.map.file_events"] != "1048576" {
		t.Errorf("file_events = %q", got["pahlevan.ebpf.map.file_events"])
	}
	if _, ok := got["pahlevan.ebpf.map.unused"]; ok {
		t.Error("a zero override means the compiled default was kept and must not be reported")
	}
}

func TestRecordMapSizing_AllDefaultsRecordsNoEvent(t *testing.T) {
	rec := recordSpans(t)
	_, span := StartSpan(context.Background(), SpanEBPFProgramLoad)
	RecordMapSizing(span, map[string]uint32{"a": 0, "b": 0})
	span.End()
	if n := len(rec.Ended()[0].Events()); n != 0 {
		t.Errorf("expected no event when nothing was overridden, got %d", n)
	}
}

// TestTracingDisabled_ProducesNoSpans is the other half of the contract: with
// tracing off, instrumentation must be inert. Code is instrumented
// unconditionally throughout the agent, so "off" has to mean nothing reaches a
// processor, not merely that nothing is exported.
func TestTracingDisabled_ProducesNoSpans(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	SetTracerProvider(tp)
	DisableTracing()

	if TracingActive() {
		t.Fatal("TracingActive must be false after DisableTracing")
	}
	ctx := context.Background()
	ctx2, span := StartSpan(ctx, SpanPolicyReconcile, AttrNamespace.String("prod"))
	RecordError(span, errors.New("boom"))
	RecordPhaseTransition(span, "Learning", "Enforcing", "test")
	AddEvent(span, "whatever")
	span.End()

	if len(rec.Ended()) != 0 {
		t.Fatalf("tracing is off but %d spans were recorded", len(rec.Ended()))
	}
	if span.IsRecording() {
		t.Error("the disabled span claims to be recording")
	}
	// The caller's context is handed back untouched, so nothing downstream
	// pays for a context level that carries a span nobody will ever export.
	if ctx2 != ctx {
		t.Error("StartSpan must return the caller's context when tracing is off")
	}
}

func TestSetTracerProviderNil_DisablesTracing(t *testing.T) {
	recordSpans(t)
	if !TracingActive() {
		t.Fatal("recorder should have enabled tracing")
	}
	SetTracerProvider(nil)
	if TracingActive() {
		t.Fatal("SetTracerProvider(nil) must disable tracing")
	}
}

// TestNoExportersMeansNoTracerProvider covers the removal of the pipeline half
// that implied a capability it did not have: a manager with no tracing
// exporter used to build a TracerProvider with zero span processors and report
// tracing as enabled.
func TestNoExportersMeansNoTracerProvider(t *testing.T) {
	DisableTracing()
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })

	if m.TracingEnabled() {
		t.Error("TracingEnabled must be false when no tracing exporter is configured")
	}
	if TracingActive() {
		t.Error("the process tracer must stay off when no tracing exporter is configured")
	}
	// And the manager's own StartSpan must stay usable and silent.
	_, span := m.StartSpan(context.Background(), "anything")
	if span.IsRecording() {
		t.Error("span is recording despite there being nothing to export it to")
	}
	span.End()
}

// TestConsoleExporterBuildsATracerProvider is the positive control for the
// test above: with an exporter configured, the provider is built and the
// process tracer is installed.
func TestConsoleExporterBuildsATracerProvider(t *testing.T) {
	DisableTracing()
	m, err := NewManager("console")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Shutdown()
		DisableTracing()
	})
	if !m.TracingEnabled() {
		t.Error("TracingEnabled must be true once a span exporter exists")
	}
	if !TracingActive() {
		t.Error("the process tracer must be installed once a span exporter exists")
	}
}

// BenchmarkStartSpan_Disabled and BenchmarkStartSpan_Enabled make the cost of
// instrumentation a number rather than a claim. Everything in the agent is
// instrumented unconditionally, so the disabled figure is what every operator
// who does not run a collector actually pays.
func BenchmarkStartSpan_Disabled(b *testing.B) {
	DisableTracing()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := StartSpan(ctx, SpanPolicyReconcile,
			AttrNamespace.String("prod"),
			AttrPolicy.String("checkout-policy"))
		span.End()
	}
}

func BenchmarkStartSpan_Enabled(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	SetTracerProvider(tp)
	defer func() {
		DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := StartSpan(ctx, SpanPolicyReconcile,
			AttrNamespace.String("prod"),
			AttrPolicy.String("checkout-policy"))
		span.End()
	}
}

// BenchmarkStartSpan_NeverSampled measures the middle case: tracing is
// configured but this trace was not sampled. A production agent at a 10%
// sample rate spends 90% of its reconciles on this path.
func BenchmarkStartSpan_NeverSampled(b *testing.B) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))
	SetTracerProvider(tp)
	defer func() {
		DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := StartSpan(ctx, SpanPolicyReconcile,
			AttrNamespace.String("prod"),
			AttrPolicy.String("checkout-policy"))
		span.End()
	}
}
