package controller

import (
	"context"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/observability"
)

// recordSpans installs an in-memory recorder as the process tracer for one
// test. Every assertion below is on the spans that came out of it: a reconcile
// that "has tracing" but emits nothing is exactly the state this work removed.
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

func spansByName(rec *tracetest.SpanRecorder) map[string]sdktrace.ReadOnlySpan {
	out := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range rec.Ended() {
		out[s.Name()] = s
	}
	return out
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[string]string {
	m := map[string]string{}
	for _, a := range s.Attributes() {
		m[string(a.Key)] = a.Value.Emit()
	}
	return m
}

// TestReconcile_EmitsRootSpanWithIdentity asserts the span every policy trace
// hangs off, including the identity attributes that make a trace findable:
// without namespace and policy name there is no way to go from "this policy is
// stuck" to its traces.
func TestReconcile_EmitsRootSpanWithIdentity(t *testing.T) {
	rec := recordSpans(t)

	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	byName := spansByName(rec)
	root, ok := byName[observability.SpanPolicyReconcile]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanPolicyReconcile, spanNames(rec))
	}
	attrs := spanAttrs(root)
	if attrs["pahlevan.namespace"] != "prod" || attrs["pahlevan.policy"] != "checkout-policy" {
		t.Errorf("root span identity attributes = %v", attrs)
	}
	if attrs["pahlevan.phase"] != string(policyv1alpha1.PolicyPhaseEnforcing) {
		t.Errorf("phase attribute = %q", attrs["pahlevan.phase"])
	}

	// The phase handler must be a child of the reconcile, or a waterfall
	// cannot separate reconcile overhead from handler work.
	phase, ok := byName[observability.SpanPolicyPhase]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanPolicyPhase, spanNames(rec))
	}
	if phase.Parent().SpanID() != root.SpanContext().SpanID() {
		t.Error("the phase span is not a child of the reconcile span")
	}
	// The enforcement phase rolls profiles up; that span must nest under the
	// phase span rather than float as its own root.
	if agg, ok := byName[observability.SpanProfileAggregate]; ok {
		if agg.Parent().SpanID() != phase.SpanContext().SpanID() {
			t.Error("the aggregate span is not a child of the phase span")
		}
	} else {
		t.Errorf("no %s span; got %v", observability.SpanProfileAggregate, spanNames(rec))
	}
}

// TestReconcile_PhaseTransitionIsAnEventOnTheSpan is the deliverable the
// roadmap asked for by name: the transition must be visible inside the
// reconcile that decided it.
func TestReconcile_PhaseTransitionIsAnEventOnTheSpan(t *testing.T) {
	rec := recordSpans(t)

	// A policy with no phase at all: the first reconcile initializes it.
	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	root, ok := spansByName(rec)[observability.SpanPolicyReconcile]
	if !ok {
		t.Fatalf("no reconcile span; got %v", spanNames(rec))
	}
	from, to, reason := phaseTransition(t, root)
	if from != "" || to != string(policyv1alpha1.PolicyPhaseInitializing) {
		t.Errorf("transition = %q -> %q", from, to)
	}
	if reason != "StatusEmpty" {
		t.Errorf("reason = %q", reason)
	}
}

// TestLearningWindowClose_IsTracedWithItsReason covers the learning window and
// its close, including which of the two conditions closed it - the usual root
// cause when a workload breaks minutes after a rollout.
func TestLearningWindowClose_IsTracedWithItsReason(t *testing.T) {
	rec := recordSpans(t)

	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	policy.Status.LearningStatus = &policyv1alpha1.LearningStatus{
		StartTime: &metav1.Time{Time: time.Now().Add(-2 * time.Hour)},
	}
	r := &PahlevanPolicyReconciler{
		Client:         newFakeClient(t, policy),
		Scheme:         testScheme(t),
		LearningWindow: time.Minute,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	window, ok := spansByName(rec)[observability.SpanLearningWindow]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanLearningWindow, spanNames(rec))
	}
	attrs := spanAttrs(window)
	if attrs["pahlevan.namespace"] != "prod" || attrs["pahlevan.policy"] != "checkout-policy" {
		t.Errorf("learning window identity attributes = %v", attrs)
	}
	if attrs["pahlevan.learning.window_seconds"] != "60" {
		t.Errorf("window_seconds = %q", attrs["pahlevan.learning.window_seconds"])
	}
	if attrs["pahlevan.learning.progress"] != "100" {
		t.Errorf("progress = %q", attrs["pahlevan.learning.progress"])
	}

	var sawClose bool
	for _, e := range window.Events() {
		if e.Name != observability.EventLearningWindowClosed {
			continue
		}
		sawClose = true
		for _, a := range e.Attributes {
			if string(a.Key) == "pahlevan.reason" && a.Value.Emit() != "WindowElapsed" {
				t.Errorf("close reason = %q, want WindowElapsed", a.Value.Emit())
			}
		}
	}
	if !sawClose {
		t.Error("the learning window closed without a window_closed event")
	}

	from, to, _ := phaseTransition(t, window)
	if from != string(policyv1alpha1.PolicyPhaseLearning) || to != string(policyv1alpha1.PolicyPhaseTransition) {
		t.Errorf("transition = %q -> %q", from, to)
	}
}

// TestLearningWindowClose_AutoTransitionReason distinguishes the early close
// from the elapsed one. Both move the policy to Transition; only the trace
// says which happened.
func TestLearningWindowClose_AutoTransitionReason(t *testing.T) {
	rec := recordSpans(t)

	// 90% of the way through a 100 second window: the window has not elapsed,
	// but the behaviour looked stable enough to transition early.
	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Spec.LearningConfig.AutoTransition = true
	policy.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	policy.Status.LearningStatus = &policyv1alpha1.LearningStatus{
		StartTime: &metav1.Time{Time: time.Now().Add(-90 * time.Second)},
	}
	r := &PahlevanPolicyReconciler{
		Client:         newFakeClient(t, policy),
		Scheme:         testScheme(t),
		LearningWindow: 100 * time.Second,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	window, ok := spansByName(rec)[observability.SpanLearningWindow]
	if !ok {
		t.Fatalf("no learning window span; got %v", spanNames(rec))
	}
	_, _, reason := phaseTransition(t, window)
	if reason != "AutoTransition" {
		t.Errorf("close reason = %q, want AutoTransition", reason)
	}
}

// TestInitialization_DiscoverySpanCarriesWorkloadCount separates "the selector
// matched nothing" from "the API server was slow", which look identical from
// outside the process.
func TestInitialization_DiscoverySpanCarriesWorkloadCount(t *testing.T) {
	rec := recordSpans(t)

	labels := map[string]string{"app": "checkout"}
	policy := samplePolicy("checkout-policy", "prod", labels)
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseInitializing
	dep := sampleDeployment("checkout", "prod", labels)
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy, dep), Scheme: testScheme(t)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	discover, ok := spansByName(rec)[observability.SpanWorkloadDiscovery]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanWorkloadDiscovery, spanNames(rec))
	}
	if got := spanAttrs(discover)["pahlevan.workloads"]; got != "1" {
		t.Errorf("workload count = %q, want 1", got)
	}
}

// TestReconcile_ProducesNoSpansWhenTracingDisabled keeps the "off means off"
// promise honest for the reconcile path, which is instrumented
// unconditionally.
func TestReconcile_ProducesNoSpansWhenTracingDisabled(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	observability.SetTracerProvider(tp)
	observability.DisableTracing()

	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("tracing is off but the reconcile recorded %d spans", n)
	}
}

func spanNames(rec *tracetest.SpanRecorder) []string {
	var names []string
	for _, s := range rec.Ended() {
		names = append(names, s.Name())
	}
	return names
}

func phaseTransition(t *testing.T, s sdktrace.ReadOnlySpan) (from, to, reason string) {
	t.Helper()
	for _, e := range s.Events() {
		if e.Name != observability.EventPhaseTransition {
			continue
		}
		for _, a := range e.Attributes {
			switch string(a.Key) {
			case "pahlevan.phase.from":
				from = a.Value.Emit()
			case "pahlevan.phase.to":
				to = a.Value.Emit()
			case "pahlevan.reason":
				reason = a.Value.Emit()
			}
		}
		return from, to, reason
	}
	t.Fatalf("span %q carries no %s event", s.Name(), observability.EventPhaseTransition)
	return "", "", ""
}

// BenchmarkReconcile_Tracing* turns the overhead of instrumenting the
// reconcile path into a measured number. The reconcile does real client work,
// so the span cost is reported against a realistic baseline rather than
// against an empty function.
func BenchmarkReconcile_TracingDisabled(b *testing.B) {
	observability.DisableTracing()
	benchmarkReconcile(b)
}

func BenchmarkReconcile_TracingEnabled(b *testing.B) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	observability.SetTracerProvider(tp)
	defer func() {
		observability.DisableTracing()
		_ = tp.Shutdown(context.Background())
	}()
	benchmarkReconcile(b)
}

func benchmarkReconcile(b *testing.B) {
	b.Helper()
	policy := samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	r := &PahlevanPolicyReconciler{Client: newFakeClient(b, policy), Scheme: testScheme(b)}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "checkout-policy", Namespace: "prod"}}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			b.Fatalf("Reconcile: %v", err)
		}
	}
}

// TestLearningStartAndStop_AreTracedPerContainer covers the two ends of a
// container's learning window. A start with no matching stop is what a
// container that vanished without the reconciler noticing looks like, and no
// counter can show that - only the pair of spans can.
func TestLearningStartAndStop_AreTracedPerContainer(t *testing.T) {
	rec := recordSpans(t)

	r := &ContainerLearnerReconciler{
		Client:            newFakeClient(t),
		Scheme:            testScheme(t),
		SyscallLearner:    learner.NewSyscallLearner(10, 0.5, time.Minute, 3),
		TrackedContainers: make(map[string]*ContainerTrackingInfo),
	}
	info := &ContainerTrackingInfo{
		ContainerID:  "c1",
		PodName:      "checkout-abc",
		PodNamespace: "prod",
		WorkloadName: "checkout",
		WorkloadKind: "Deployment",
	}
	policies := []*policyv1alpha1.PahlevanPolicy{
		samplePolicy("checkout-policy", "prod", map[string]string{"app": "checkout"}),
	}
	if err := r.startLearningForContainer(context.Background(), "c1", info, policies); err != nil {
		t.Fatalf("startLearningForContainer: %v", err)
	}
	if err := r.stopLearningForContainer(context.Background(), "c1"); err != nil {
		t.Fatalf("stopLearningForContainer: %v", err)
	}

	byName := spansByName(rec)
	start, ok := byName[observability.SpanLearningStart]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanLearningStart, spanNames(rec))
	}
	attrs := spanAttrs(start)
	for k, want := range map[string]string{
		"pahlevan.namespace":     "prod",
		"pahlevan.pod":           "checkout-abc",
		"pahlevan.container.id":  "c1",
		"pahlevan.workload":      "checkout",
		"pahlevan.workload.kind": "Deployment",
		"pahlevan.policies":      "1",
	} {
		if attrs[k] != want {
			t.Errorf("start span attribute %s = %q, want %q", k, attrs[k], want)
		}
	}

	stop, ok := byName[observability.SpanLearningStop]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanLearningStop, spanNames(rec))
	}
	if spanAttrs(stop)["pahlevan.container.id"] != "c1" {
		t.Errorf("stop span container id = %q", spanAttrs(stop)["pahlevan.container.id"])
	}
	if start.Status().Code.String() == "Error" || stop.Status().Code.String() == "Error" {
		t.Error("a clean start/stop pair must not be marked failed")
	}
}

// TestLearningStart_WithoutLearnerIsRecordedAsDegraded: a node whose learner
// never came up learns nothing while every pod looks healthy, so the span has
// to say so rather than succeed silently.
func TestLearningStart_WithoutLearnerIsRecordedAsDegraded(t *testing.T) {
	rec := recordSpans(t)

	r := &ContainerLearnerReconciler{Client: newFakeClient(t), Scheme: testScheme(t)}
	info := &ContainerTrackingInfo{ContainerID: "c1", PodName: "p", PodNamespace: "prod"}
	if err := r.startLearningForContainer(context.Background(), "c1", info, nil); err != nil {
		t.Fatalf("startLearningForContainer: %v", err)
	}

	start, ok := spansByName(rec)[observability.SpanLearningStart]
	if !ok {
		t.Fatalf("no %s span; got %v", observability.SpanLearningStart, spanNames(rec))
	}
	var degraded bool
	for _, e := range start.Events() {
		if e.Name == observability.EventDegraded {
			degraded = true
		}
	}
	if !degraded {
		t.Error("starting learning with no learner must be recorded as degraded")
	}
}
