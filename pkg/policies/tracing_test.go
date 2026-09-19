package policies

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/observability"
)

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

func tracedSpansByName(rec *tracetest.SpanRecorder) map[string]sdktrace.ReadOnlySpan {
	out := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range rec.Ended() {
		out[s.Name()] = s
	}
	return out
}

func tracedAttrs(s sdktrace.ReadOnlySpan) map[string]string {
	m := map[string]string{}
	for _, a := range s.Attributes() {
		m[string(a.Key)] = a.Value.Emit()
	}
	return m
}

// TestGeneratePolicy_IsTracedWithWorkloadIdentity asserts the span an operator
// reaches for when asking why a policy allows what it allows: the workload it
// belongs to, and the size and confidence of what came out.
func TestGeneratePolicy_IsTracedWithWorkloadIdentity(t *testing.T) {
	rec := recordSpans(t)

	sl := learner.NewSyscallLearner(10, 0.7, time.Minute, 5)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "checkout", Namespace: "prod"}
	require.NoError(t, sl.StartLearning(context.Background(), "c1", ref, &policyv1alpha1.PahlevanPolicy{}))
	_, err := sl.GenerateProfile("c1")
	require.NoError(t, err)

	ee := NewEnforcementEngine(nil, sl)
	require.NoError(t, ee.RegisterContainer("c1", ref, &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-policy", Namespace: "prod"},
	}))

	// The eBPF manager is nil, so the apply fails - which is the interesting
	// case: generation succeeded and installation did not, and only the child
	// span says so.
	_, gerr := ee.GeneratePolicy("c1")
	require.Error(t, gerr)

	byName := tracedSpansByName(rec)
	gen, ok := byName[observability.SpanProfileGenerate]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanProfileGenerate, tracedNames(rec))
	}
	attrs := tracedAttrs(gen)
	for k, want := range map[string]string{
		"pahlevan.namespace":     "prod",
		"pahlevan.workload":      "checkout",
		"pahlevan.workload.kind": "Deployment",
		"pahlevan.policy":        "checkout-policy",
		"pahlevan.container.id":  "c1",
	} {
		if attrs[k] != want {
			t.Errorf("attribute %s = %q, want %q", k, attrs[k], want)
		}
	}
	for _, k := range []string{
		"pahlevan.profile.syscalls",
		"pahlevan.profile.file_rules",
		"pahlevan.profile.network_rules",
		"pahlevan.profile.confidence",
		"pahlevan.profile.quality",
	} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("generated policy span is missing %s: %v", k, attrs)
		}
	}

	apply, ok := byName[observability.SpanPolicyApply]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanPolicyApply, tracedNames(rec))
	}
	if apply.Parent().SpanID() != gen.SpanContext().SpanID() {
		t.Error("the apply span is not a child of the generation span")
	}
	// Both must be red: the install failed, and the generation call failed
	// because of it.
	if apply.Status().Code.String() != "Error" {
		t.Errorf("apply span status = %v, want Error", apply.Status().Code)
	}
	if gen.Status().Code.String() != "Error" {
		t.Errorf("generate span status = %v, want Error", gen.Status().Code)
	}
}

// TestApplyPolicyToEBPF_FailureIsVisibleInTheTrace is the narrow version of
// the rule that a failed kernel write must be a red span and not only a log
// line.
func TestApplyPolicyToEBPF_FailureIsVisibleInTheTrace(t *testing.T) {
	rec := recordSpans(t)

	ee := NewEnforcementEngine(&ebpf.Manager{}, nil)
	err := ee.applyPolicyToEBPF(context.Background(), "c1", &GeneratedPolicy{
		Version:       1,
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}}},
	})
	require.Error(t, err)

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %v", tracedNames(rec))
	}
	if ended[0].Name() != observability.SpanPolicyApply {
		t.Fatalf("span name = %q", ended[0].Name())
	}
	if ended[0].Status().Code.String() != "Error" {
		t.Errorf("status = %v, want Error", ended[0].Status().Code)
	}
	if ended[0].Status().Description != err.Error() {
		t.Errorf("status description = %q, want %q", ended[0].Status().Description, err.Error())
	}
}

// TestUpdateLifecyclePhase_RecordsTheTransition covers the enforcement-mode
// side: the phase change carries both ends, so a container that moved phase
// without its policy being rebuilt is visible.
func TestUpdateLifecyclePhase_RecordsTheTransition(t *testing.T) {
	rec := recordSpans(t)

	ee := NewEnforcementEngine(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "checkout", Namespace: "prod"}
	require.NoError(t, ee.RegisterContainer("c1", ref, &policyv1alpha1.PahlevanPolicy{}))
	require.NoError(t, ee.UpdateLifecyclePhase("c1", PhaseRunning))

	span, ok := tracedSpansByName(rec)[observability.SpanLifecyclePhase]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanLifecyclePhase, tracedNames(rec))
	}
	attrs := tracedAttrs(span)
	if attrs["pahlevan.container.id"] != "c1" {
		t.Errorf("container id = %q", attrs["pahlevan.container.id"])
	}
	if attrs["pahlevan.namespace"] != "prod" || attrs["pahlevan.workload"] != "checkout" {
		t.Errorf("workload identity = %v", attrs)
	}
	var from, to string
	for _, e := range span.Events() {
		if e.Name != observability.EventPhaseTransition {
			continue
		}
		for _, a := range e.Attributes {
			switch string(a.Key) {
			case "pahlevan.phase.from":
				from = a.Value.Emit()
			case "pahlevan.phase.to":
				to = a.Value.Emit()
			}
		}
	}
	if from != string(PhaseInitializing) || to != string(PhaseRunning) {
		t.Errorf("transition = %q -> %q", from, to)
	}
}

func TestUpdateLifecyclePhase_UnknownContainerIsARedSpan(t *testing.T) {
	rec := recordSpans(t)
	ee := NewEnforcementEngine(nil, nil)
	require.Error(t, ee.UpdateLifecyclePhase("nope", PhaseRunning))

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %v", tracedNames(rec))
	}
	if ended[0].Status().Code.String() != "Error" {
		t.Errorf("status = %v, want Error", ended[0].Status().Code)
	}
}

func TestPolicies_NoSpansWhenTracingDisabled(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	observability.SetTracerProvider(tp)
	observability.DisableTracing()

	ee := NewEnforcementEngine(nil, nil)
	require.NoError(t, ee.RegisterContainer("c1", learner.WorkloadReference{}, &policyv1alpha1.PahlevanPolicy{}))
	require.NoError(t, ee.UpdateLifecyclePhase("c1", PhaseRunning))
	require.Error(t, ee.applyPolicyToEBPF(context.Background(), "c1", &GeneratedPolicy{}))

	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("tracing is off but %d spans were recorded", n)
	}
}

func tracedNames(rec *tracetest.SpanRecorder) []string {
	var names []string
	for _, s := range rec.Ended() {
		names = append(names, s.Name())
	}
	return names
}

// BenchmarkGeneratePolicy_Tracing* measures the cost of instrumenting policy
// generation - the heaviest control-plane operation in the engine - with and
// without tracing.
func BenchmarkUpdateLifecyclePhase_TracingDisabled(b *testing.B) {
	observability.DisableTracing()
	benchmarkUpdateLifecyclePhase(b)
}

func BenchmarkUpdateLifecyclePhase_TracingEnabled(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	observability.SetTracerProvider(tp)
	defer func() {
		observability.DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	benchmarkUpdateLifecyclePhase(b)
}

func benchmarkUpdateLifecyclePhase(b *testing.B) {
	b.Helper()
	ee := NewEnforcementEngine(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "checkout", Namespace: "prod"}
	if err := ee.RegisterContainer("c1", ref, &policyv1alpha1.PahlevanPolicy{}); err != nil {
		b.Fatalf("RegisterContainer: %v", err)
	}
	phases := []WorkloadLifecyclePhase{PhaseRunning, PhaseInitializing}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ee.UpdateLifecyclePhase("c1", phases[i%2]); err != nil {
			b.Fatalf("UpdateLifecyclePhase: %v", err)
		}
	}
}
