package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestStartSpanBeforeTracingConfigured guards the case that made tracing useless:
// a manager whose tracer was never set must still hand back a usable span rather
// than nil-panic, so callers can instrument unconditionally.
func TestStartSpanBeforeTracingConfigured(t *testing.T) {
	m := &Manager{}
	ctx, span := m.StartSpan(context.Background(), "unconfigured")
	if span == nil {
		t.Fatal("StartSpan returned a nil span")
	}
	if ctx == nil {
		t.Fatal("StartSpan returned a nil context")
	}
	span.End() // must not panic
	if m.TracingEnabled() {
		t.Error("TracingEnabled should be false with no provider")
	}
}

// TestStartSpanRecordsSpans proves spans actually reach an exporter. The previous
// implementation built a provider with zero span processors, so nothing was ever
// recorded even when tracing was "enabled".
func TestStartSpanRecordsSpans(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	m := &Manager{tracerProvider: tp, tracer: tp.Tracer("test")}
	if !m.TracingEnabled() {
		t.Fatal("TracingEnabled should be true once a provider is set")
	}

	_, span := m.StartSpan(context.Background(), "learn-to-enforce",
		attribute.String("pod", "nginx-1"), attribute.Int("syscalls", 42))
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected exactly 1 recorded span, got %d", len(ended))
	}
	got := ended[0]
	if got.Name() != "learn-to-enforce" {
		t.Errorf("span name = %q", got.Name())
	}
	attrs := map[string]string{}
	for _, a := range got.Attributes() {
		attrs[string(a.Key)] = a.Value.Emit()
	}
	if attrs["pod"] != "nginx-1" {
		t.Errorf("pod attribute = %q", attrs["pod"])
	}
	if attrs["syscalls"] != "42" {
		t.Errorf("syscalls attribute = %q", attrs["syscalls"])
	}
}

func TestStartSpanNested(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	m := &Manager{tracerProvider: tp, tracer: tp.Tracer("test")}

	ctx, parent := m.StartSpan(context.Background(), "parent")
	_, child := m.StartSpan(ctx, "child")
	child.End()
	parent.End()

	if n := len(rec.Ended()); n != 2 {
		t.Fatalf("expected 2 spans, got %d", n)
	}
	// The child must share the parent's trace id, which is what makes the span a
	// child rather than an unrelated root.
	var childSpan, parentSpan = rec.Ended()[0], rec.Ended()[1]
	if childSpan.SpanContext().TraceID() != parentSpan.SpanContext().TraceID() {
		t.Error("child span is not part of the parent trace")
	}
}

func BenchmarkStartSpan(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	m := &Manager{tracerProvider: tp, tracer: tp.Tracer("bench")}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, span := m.StartSpan(ctx, "op", attribute.Int("i", i))
		span.End()
	}
}
