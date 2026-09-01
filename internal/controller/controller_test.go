package controller

import (
	"context"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/visualization"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme(tb testing.TB) *runtime.Scheme {
	tb.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		tb.Fatalf("clientgoscheme.AddToScheme: %v", err)
	}
	if err := policyv1alpha1.AddToScheme(scheme); err != nil {
		tb.Fatalf("policyv1alpha1.AddToScheme: %v", err)
	}
	return scheme
}

func newFakeClient(tb testing.TB, objs ...client.Object) client.Client {
	tb.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(tb)).
		WithObjects(objs...).
		WithStatusSubresource(
			&policyv1alpha1.PahlevanPolicy{},
			&policyv1alpha1.AttackSurface{},
		).
		Build()
}

func samplePolicy(name, ns string, matchLabels map[string]string) *policyv1alpha1.PahlevanPolicy {
	return &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: policyv1alpha1.PahlevanPolicySpec{
			Selector: policyv1alpha1.LabelSelector{MatchLabels: matchLabels},
		},
	}
}

func sampleDeployment(name, ns string, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, UID: "dep-uid"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
		},
	}
}

// --------------------------------------------------------------------------
// PahlevanPolicyReconciler
// --------------------------------------------------------------------------

func TestPahlevanPolicy_Reconcile_NotFound(t *testing.T) {
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t), Scheme: testScheme(t)}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("expected no error for missing policy, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected empty result, got %+v", res)
	}
}

func TestPahlevanPolicy_Reconcile_AddsFinalizerThenInitializes(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t), LearningWindow: time.Minute}

	key := types.NamespacedName{Name: "p1", Namespace: "default"}

	// First reconcile adds the finalizer and requeues.
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue after adding finalizer, got %+v", res)
	}
	var got policyv1alpha1.PahlevanPolicy
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("expected finalizer to be added")
	}

	// Second reconcile initializes status -> Initializing.
	res, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue after init, got %+v", res)
	}
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != policyv1alpha1.PolicyPhaseInitializing {
		t.Fatalf("expected Initializing phase, got %s", got.Status.Phase)
	}
}

func TestPahlevanPolicy_HandleInitialization_NoWorkloads(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseInitializing
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	res, err := r.handleInitialization(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleInitialization: %v", err)
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue, got %+v", res)
	}
	// Phase stays Initializing when there are no targets.
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseInitializing {
		t.Fatalf("expected phase unchanged, got %s", policy.Status.Phase)
	}
}

func TestPahlevanPolicy_HandleInitialization_WithWorkload_NilEBPFManager(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseInitializing
	dep := sampleDeployment("web", "default", labels)

	c := newFakeClient(t, policy, dep)
	// EBPFManager intentionally nil: must not panic (robustness guard).
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t), LearningWindow: time.Minute}

	if _, err := r.handleInitialization(context.Background(), policy); err != nil {
		t.Fatalf("handleInitialization: %v", err)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseLearning {
		t.Fatalf("expected Learning phase, got %s", policy.Status.Phase)
	}
	if len(policy.Status.TargetWorkloads) != 1 {
		t.Fatalf("expected 1 target workload, got %d", len(policy.Status.TargetWorkloads))
	}
	if policy.Status.TargetWorkloads[0].Kind != "Deployment" {
		t.Fatalf("expected Deployment kind, got %s", policy.Status.TargetWorkloads[0].Kind)
	}
}

func TestPahlevanPolicy_HandleLearning_TransitionsWhenElapsed(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	start := metav1.Time{Time: time.Now().Add(-2 * time.Hour)}
	policy.Status.LearningStatus = &policyv1alpha1.LearningStatus{StartTime: &start}

	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t), LearningWindow: time.Minute}

	res, err := r.handleLearning(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleLearning: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue, got %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseTransition {
		t.Fatalf("expected Transition phase, got %s", policy.Status.Phase)
	}
	if policy.Status.LearningStatus.EndTime == nil {
		t.Fatal("expected learning EndTime to be set")
	}
}

func TestPahlevanPolicy_HandleLearning_StaysWhenNotElapsed(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	start := metav1.Time{Time: time.Now()}
	policy.Status.LearningStatus = &policyv1alpha1.LearningStatus{StartTime: &start}

	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t), LearningWindow: time.Hour}

	res, err := r.handleLearning(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleLearning: %v", err)
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue, got %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseLearning {
		t.Fatalf("expected phase unchanged, got %s", policy.Status.Phase)
	}
}

func TestPahlevanPolicy_HandleTransition_ToEnforcing(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseTransition
	dep := sampleDeployment("web", "default", labels)

	c := newFakeClient(t, policy, dep)
	r := &PahlevanPolicyReconciler{
		Client:           c,
		Scheme:           testScheme(t),
		LearningWindow:   time.Minute,
		EnforcementDelay: 0, // avoid sleeping in tests
	}

	res, err := r.handleTransition(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleTransition: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Fatalf("expected 1m requeue, got %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseEnforcing {
		t.Fatalf("expected Enforcing phase, got %s", policy.Status.Phase)
	}
	if policy.Status.EnforcementStatus == nil {
		t.Fatal("expected enforcement status")
	}
}

func TestPahlevanPolicy_HandleTransition_NoWorkloadError(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Status.Phase = policyv1alpha1.PolicyPhaseTransition
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	res, err := r.handleTransition(context.Background(), policy)
	if err == nil {
		t.Fatal("expected error when no workload matches")
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue on error, got %+v", res)
	}
}

// profileFor builds a ContainerProfile as a node agent would publish it.
func profileFor(name, ns, policyRef, phase string, files, network, execs, caps, rollbacks int32) *policyv1alpha1.ContainerProfile {
	return &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       policyv1alpha1.ContainerProfileSpec{PolicyRef: policyRef},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:              phase,
			DeniedFiles:        files,
			DeniedNetwork:      network,
			DeniedExecs:        execs,
			DeniedCapabilities: caps,
			DenialCount:        files + network + execs + caps,
			RollbackCount:      rollbacks,
		},
	}
}

// The policy's blocked* counters used to stay at zero forever while the printed
// column claimed to show blocked syscalls. They are rolled up from the
// ContainerProfiles the node agents publish.
func TestPahlevanPolicy_AggregatesContainerProfiles(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing

	c := newFakeClient(t, policy,
		profileFor("c1", "default", "p1", "Enforcing", 3, 2, 1, 0, 1),
		profileFor("c2", "default", "p1", "Learning", 1, 0, 0, 4, 0),
		// Governed by a different policy: must not be counted.
		profileFor("c3", "default", "other", "Enforcing", 100, 100, 100, 100, 9),
	)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	if err := r.aggregateProfiles(context.Background(), policy); err != nil {
		t.Fatalf("aggregateProfiles: %v", err)
	}
	st := policy.Status.EnforcementStatus
	if st == nil {
		t.Fatal("expected enforcement status")
	}
	if st.TotalContainers != 2 || st.EnforcingContainers != 1 {
		t.Errorf("containers = %d total / %d enforcing, want 2/1", st.TotalContainers, st.EnforcingContainers)
	}
	if st.BlockedFileAccess != 4 || st.BlockedNetworkConnections != 2 ||
		st.BlockedExecs != 1 || st.BlockedCapabilities != 4 {
		t.Errorf("per-kind wrong: %+v", st)
	}
	if st.BlockedTotal != 11 {
		t.Errorf("blockedTotal = %d, want 11", st.BlockedTotal)
	}
	if st.RollbackCount != 1 {
		t.Errorf("rollbackCount = %d, want 1", st.RollbackCount)
	}
	// Syscalls are confined by seccomp, whose denials this agent cannot see.
	if st.BlockedSyscalls != 0 {
		t.Errorf("blockedSyscalls = %d, want 0", st.BlockedSyscalls)
	}
}

// StartTime is set at the enforce transition and must survive a roll-up.
func TestPahlevanPolicy_AggregatePreservesStartTime(t *testing.T) {
	policy := samplePolicy("p1", "default", nil)
	start := metav1.NewTime(time.Unix(1700000000, 0))
	policy.Status.EnforcementStatus = &policyv1alpha1.EnforcementStatus{StartTime: &start}

	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}
	if err := r.aggregateProfiles(context.Background(), policy); err != nil {
		t.Fatalf("aggregateProfiles: %v", err)
	}
	if policy.Status.EnforcementStatus.StartTime == nil ||
		!policy.Status.EnforcementStatus.StartTime.Equal(&start) {
		t.Errorf("startTime lost: %+v", policy.Status.EnforcementStatus.StartTime)
	}
}

func TestPahlevanPolicy_HandleEnforcement_SelfHealing(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	policy.Spec.SelfHealing.Enabled = true

	// One container denying heavily: the roll-up puts it over the per-container
	// threshold, which is what the backstop reads.
	c := newFakeClient(t, policy,
		profileFor("c1", "default", "p1", "Enforcing", 2000, 0, 0, 0, 0))
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	res, err := r.handleEnforcement(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleEnforcement: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue, got %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseRollingBack {
		t.Fatalf("expected RollingBack, got %s", policy.Status.Phase)
	}
	if policy.Status.EnforcementStatus.BlockedTotal != 2000 {
		t.Errorf("blockedTotal = %d, want 2000", policy.Status.EnforcementStatus.BlockedTotal)
	}
}

// A healthy fleet must not be rolled back by the backstop.
func TestPahlevanPolicy_HandleEnforcement_HealthyIsLeftAlone(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	policy.Spec.SelfHealing.Enabled = true

	c := newFakeClient(t, policy,
		profileFor("c1", "default", "p1", "Enforcing", 2, 1, 0, 0, 0))
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	res, err := r.handleEnforcement(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleEnforcement: %v", err)
	}
	if res.RequeueAfter == requeueImmediately {
		t.Errorf("healthy policy should not requeue immediately: %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseEnforcing {
		t.Errorf("phase = %s, want Enforcing", policy.Status.Phase)
	}
}

func TestPahlevanPolicy_HandleEnforcement_Steady(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	res, err := r.handleEnforcement(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleEnforcement: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Fatalf("expected 1m requeue, got %+v", res)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseEnforcing {
		t.Fatalf("expected Enforcing unchanged, got %s", policy.Status.Phase)
	}
}

func TestPahlevanPolicy_HandleRollback(t *testing.T) {
	policy := samplePolicy("p1", "default", map[string]string{"app": "web"})
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.Phase = policyv1alpha1.PolicyPhaseRollingBack
	policy.Status.EnforcementStatus = &policyv1alpha1.EnforcementStatus{RollbackCount: 1}
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	if _, err := r.handleRollback(context.Background(), policy); err != nil {
		t.Fatalf("handleRollback: %v", err)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseEnforcing {
		t.Fatalf("expected Enforcing after rollback, got %s", policy.Status.Phase)
	}
	if policy.Status.EnforcementStatus.RollbackCount != 2 {
		t.Fatalf("expected RollbackCount incremented, got %d", policy.Status.EnforcementStatus.RollbackCount)
	}
}

func TestPahlevanPolicy_HandleFailure(t *testing.T) {
	policy := samplePolicy("p1", "default", nil)
	policy.Status.Phase = policyv1alpha1.PolicyPhaseFailed
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}
	res, err := r.handleFailure(context.Background(), policy)
	if err != nil {
		t.Fatalf("handleFailure: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("expected 5m requeue, got %+v", res)
	}
}

func TestPahlevanPolicy_ReconcilePolicy_UnknownPhase(t *testing.T) {
	policy := samplePolicy("p1", "default", nil)
	policy.Status.Phase = policyv1alpha1.PolicyPhase("Bogus")
	r := &PahlevanPolicyReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}
	res, err := r.reconcilePolicy(context.Background(), policy)
	if err != nil {
		t.Fatalf("reconcilePolicy: %v", err)
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue for unknown phase, got %+v", res)
	}
}

func TestPahlevanPolicy_HandleDeletion(t *testing.T) {
	policy := samplePolicy("p1", "default", nil)
	policy.Finalizers = []string{"pahlevan.io/finalizer"}
	policy.Status.TargetWorkloads = []policyv1alpha1.WorkloadReference{{Name: "web"}}
	c := newFakeClient(t, policy)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	if _, err := r.handleDeletion(context.Background(), policy); err != nil {
		t.Fatalf("handleDeletion: %v", err)
	}
	var got policyv1alpha1.PahlevanPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "p1", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("expected finalizer removed, got %+v", got.Finalizers)
	}
}

func TestPahlevanPolicy_MatchesSelector(t *testing.T) {
	r := &PahlevanPolicyReconciler{}

	cases := []struct {
		name     string
		labels   map[string]string
		selector policyv1alpha1.LabelSelector
		want     bool
	}{
		{"empty selector matches all", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{}, true},
		{"matchLabels hit", map[string]string{"app": "web"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{"matchLabels miss", map[string]string{"app": "db"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, false},
		{"In hit", map[string]string{"tier": "fe"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe", "be"}}}}, true},
		{"In miss missing key", map[string]string{"x": "y"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe"}}}}, false},
		{"In miss wrong value", map[string]string{"tier": "db"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe"}}}}, false},
		{"NotIn hit", map[string]string{"tier": "db"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"fe"}}}}, true},
		{"NotIn miss", map[string]string{"tier": "fe"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"fe"}}}}, false},
		{"Exists hit", map[string]string{"tier": "x"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists}}}, true},
		{"Exists miss", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists}}}, false},
		{"DoesNotExist hit", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpDoesNotExist}}}, true},
		{"DoesNotExist miss", map[string]string{"tier": "x"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpDoesNotExist}}}, false},
	}
	for _, tc := range cases {
		if got := r.matchesSelector(tc.labels, tc.selector); got != tc.want {
			t.Errorf("%s: matchesSelector=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestPahlevanPolicy_ShouldTransitionToEnforcement(t *testing.T) {
	r := &PahlevanPolicyReconciler{}

	// Nil learning status -> false (robustness guard).
	if r.shouldTransitionToEnforcement(samplePolicy("p", "default", nil)) {
		t.Fatal("expected false with nil learning status")
	}

	minSamples := int32(100)
	progress := int32(90)
	p := samplePolicy("p", "default", nil)
	p.Spec.LearningConfig.MinSamples = &minSamples
	p.Status.LearningStatus = &policyv1alpha1.LearningStatus{SamplesCollected: 50, Progress: &progress}
	if r.shouldTransitionToEnforcement(p) {
		t.Fatal("expected false when samples below min")
	}

	p.Status.LearningStatus.SamplesCollected = 200
	if !r.shouldTransitionToEnforcement(p) {
		t.Fatal("expected true when samples met and progress high")
	}

	low := int32(10)
	p.Status.LearningStatus.Progress = &low
	if r.shouldTransitionToEnforcement(p) {
		t.Fatal("expected false when progress low")
	}
}

func TestPahlevanPolicy_ShouldTriggerSelfHealing(t *testing.T) {
	r := &PahlevanPolicyReconciler{}
	p := samplePolicy("p", "default", nil)

	if r.shouldTriggerSelfHealing(p) {
		t.Fatal("expected false with nil enforcement status")
	}
	// The threshold is now an average per governed container, so a policy with
	// no containers cannot trip it however large the count.
	p.Status.EnforcementStatus = &policyv1alpha1.EnforcementStatus{BlockedTotal: 100000}
	if r.shouldTriggerSelfHealing(p) {
		t.Fatal("expected false with no governed containers")
	}

	p.Status.EnforcementStatus = &policyv1alpha1.EnforcementStatus{
		BlockedTotal: 10, TotalContainers: 1,
	}
	if r.shouldTriggerSelfHealing(p) {
		t.Fatal("expected false below threshold")
	}

	p.Status.EnforcementStatus.BlockedFileAccess = 5000
	p.Status.EnforcementStatus.BlockedTotal = 5010
	if !r.shouldTriggerSelfHealing(p) {
		t.Fatal("expected true above threshold")
	}

	// A large deployment must not trip the backstop simply by being large:
	// the same absolute count spread over many containers is normal.
	p.Status.EnforcementStatus.TotalContainers = 50
	if r.shouldTriggerSelfHealing(p) {
		t.Fatal("expected false when the same total is spread across 50 containers")
	}
}

func TestPahlevanPolicy_UpdateCondition(t *testing.T) {
	r := &PahlevanPolicyReconciler{}
	p := samplePolicy("p", "default", nil)

	r.updateCondition(p, policyv1alpha1.PolicyConditionReady, policyv1alpha1.ConditionFalse, "Init", "initializing")
	if len(p.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(p.Status.Conditions))
	}
	// Same type, same status -> no duplicate, no change.
	r.updateCondition(p, policyv1alpha1.PolicyConditionReady, policyv1alpha1.ConditionFalse, "Init2", "again")
	if len(p.Status.Conditions) != 1 || p.Status.Conditions[0].Reason != "Init" {
		t.Fatalf("expected no update on same status, got %+v", p.Status.Conditions)
	}
	// Same type, changed status -> updated in place.
	r.updateCondition(p, policyv1alpha1.PolicyConditionReady, policyv1alpha1.ConditionTrue, "Ready", "ok")
	if p.Status.Conditions[0].Status != policyv1alpha1.ConditionTrue {
		t.Fatalf("expected status updated, got %+v", p.Status.Conditions[0])
	}
	// New type -> appended.
	r.updateCondition(p, policyv1alpha1.PolicyConditionError, policyv1alpha1.ConditionTrue, "Err", "boom")
	if len(p.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(p.Status.Conditions))
	}
}

func TestPahlevanPolicy_GetWorkloadContainers(t *testing.T) {
	labels := map[string]string{"app": "web"}
	dep := sampleDeployment("web", "default", labels)
	runningPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default", Labels: labels},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://abc123"},
			},
		},
	}
	pendingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-2", Namespace: "default", Labels: labels},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	c := newFakeClient(t, dep, runningPod, pendingPod)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	ids, err := r.getWorkloadContainers(context.Background(), dep)
	if err != nil {
		t.Fatalf("getWorkloadContainers: %v", err)
	}
	if len(ids) != 1 || ids[0] != "containerd://abc123" {
		t.Fatalf("expected 1 running container id, got %+v", ids)
	}
}

func TestPahlevanPolicy_WorkloadsToReferences(t *testing.T) {
	r := &PahlevanPolicyReconciler{}
	dep := sampleDeployment("web", "default", nil)
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default"}}
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "default"}}

	refs := r.workloadsToReferences([]metav1.Object{dep, sts, ds})
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d", len(refs))
	}
	if refs[0].Kind != "Deployment" || refs[1].Kind != "StatefulSet" || refs[2].Kind != "DaemonSet" {
		t.Fatalf("unexpected kinds: %+v", refs)
	}
}

// The reconciler must not register an eBPF event handler.
//
// It used to add one per target workload on every reconcile that reached
// handleInitialization. Handlers are appended to a slice that is never pruned
// and is walked synchronously for every ring-buffer record, so each reconcile
// made the hottest path permanently slower - and the handler did nothing but
// increment a counter through a pointer to a policy from an earlier reconcile.
//
// A fake enforcer that counts registrations is the only way to assert the
// absence of a call that used to be there.
func TestPahlevanPolicyReconcilerRegistersNoEventHandler(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	policy.Status.Phase = policyv1alpha1.PolicyPhaseInitializing
	// A matching workload, so initialization gets past "no targets found" and
	// reaches the point where the handler used to be registered.
	c := newFakeClient(t, policy, sampleDeployment("web", "default", labels))
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t), LearningWindow: time.Minute}

	// A nil EBPFManager is what the old code guarded against; with the
	// registration gone, initialization must complete without one and without
	// reaching for it.
	if _, err := r.handleInitialization(context.Background(), policy); err != nil {
		t.Fatalf("handleInitialization: %v", err)
	}
	if policy.Status.Phase != policyv1alpha1.PolicyPhaseLearning {
		t.Errorf("phase = %s, want Learning", policy.Status.Phase)
	}
}

// --------------------------------------------------------------------------
// ContainerLearnerReconciler
// --------------------------------------------------------------------------

func newContainerLearner(t *testing.T, objs ...client.Object) *ContainerLearnerReconciler {
	t.Helper()
	return &ContainerLearnerReconciler{
		Client:            newFakeClient(t, objs...),
		Scheme:            testScheme(t),
		SyscallLearner:    learner.NewSyscallLearner(10, 0.5, time.Minute, 3),
		TrackedContainers: make(map[string]*ContainerTrackingInfo),
	}
}

func TestContainerLearner_Reconcile_NotFound(t *testing.T) {
	r := newContainerLearner(t)
	r.TrackedContainers["c1"] = &ContainerTrackingInfo{PodName: "gone", PodNamespace: "default"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gone", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %+v", res)
	}
	if _, ok := r.TrackedContainers["c1"]; ok {
		t.Fatal("expected tracking info cleaned up on deletion")
	}
}

func TestContainerLearner_Reconcile_Pending(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	r := newContainerLearner(t, pod)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 10*time.Second {
		t.Fatalf("expected 10s requeue, got %+v", res)
	}
}

func TestContainerLearner_Reconcile_RunningNoPolicies(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://x", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
		},
	}
	r := newContainerLearner(t, pod)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Fatalf("expected 1m requeue with no policies, got %+v", res)
	}
}

func TestContainerLearner_Reconcile_RunningStartsLearning(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc", Namespace: "default", Labels: labels,
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-12345"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://deadbeef", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}},
			},
		},
	}
	r := newContainerLearner(t, policy, pod)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "web-abc", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue, got %+v", res)
	}
	ti, ok := r.TrackedContainers["deadbeef"]
	if !ok {
		t.Fatal("expected container tracked")
	}
	if !ti.LearningStarted {
		t.Fatal("expected learning started")
	}
	if ti.WorkloadKind != "Deployment" || ti.WorkloadName != "web" {
		t.Fatalf("expected workload derived from replicaset, got %s/%s", ti.WorkloadKind, ti.WorkloadName)
	}
	// The learner should now know about this container.
	if _, err := r.SyscallLearner.GetLearningState("deadbeef"); err != nil {
		t.Fatalf("expected learning state for container: %v", err)
	}
}

func TestContainerLearner_Reconcile_RunningNilLearnerAndNilMap(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: "default", Labels: labels},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://feed", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			},
		},
	}
	// Nil SyscallLearner and nil TrackedContainers must not panic (robustness).
	r := &ContainerLearnerReconciler{Client: newFakeClient(t, policy, pod), Scheme: testScheme(t)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "web-abc", Namespace: "default"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := r.TrackedContainers["feed"]; !ok {
		t.Fatal("expected container tracked even with nil learner")
	}
}

func TestContainerLearner_Reconcile_Terminated(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase:             corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://abc"}},
		},
	}
	r := newContainerLearner(t, pod)
	// Pre-seed learner + tracking so termination has something to clean up.
	_ = r.SyscallLearner.StartLearning(context.Background(), "abc", learner.WorkloadReference{}, nil)
	r.TrackedContainers["abc"] = &ContainerTrackingInfo{ContainerID: "abc", PodName: "p", PodNamespace: "default"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p", Namespace: "default"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := r.TrackedContainers["abc"]; ok {
		t.Fatal("expected container removed from tracking after termination")
	}
}

func TestContainerLearner_ExtractContainerID(t *testing.T) {
	r := &ContainerLearnerReconciler{}
	if got := r.extractContainerID("docker://abc"); got != "abc" {
		t.Errorf("docker: got %s", got)
	}
	if got := r.extractContainerID("containerd://xyz"); got != "xyz" {
		t.Errorf("containerd: got %s", got)
	}
	if got := r.extractContainerID("malformed"); got != "" {
		t.Errorf("malformed: expected empty, got %s", got)
	}
}

func TestContainerLearner_GetWorkloadOwnerReference(t *testing.T) {
	r := &ContainerLearnerReconciler{}

	rsPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc123"}}}}
	ref := r.getWorkloadOwnerReference(rsPod)
	if ref == nil || ref.Kind != "Deployment" || ref.Name != "web" {
		t.Fatalf("expected Deployment/web, got %+v", ref)
	}

	stsPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db"}}}}
	ref = r.getWorkloadOwnerReference(stsPod)
	if ref == nil || ref.Kind != "StatefulSet" || ref.Name != "db" {
		t.Fatalf("expected StatefulSet/db, got %+v", ref)
	}

	orphan := &corev1.Pod{}
	if r.getWorkloadOwnerReference(orphan) != nil {
		t.Fatal("expected nil for pod without workload owner")
	}
}

func TestContainerLearner_GetDeploymentNameFromReplicaSet(t *testing.T) {
	r := &ContainerLearnerReconciler{}
	if got := r.getDeploymentNameFromReplicaSet("web-6d8f9c"); got != "web" {
		t.Errorf("got %s", got)
	}
	if got := r.getDeploymentNameFromReplicaSet("multi-part-name-abc"); got != "multi-part-name" {
		t.Errorf("got %s", got)
	}
	if got := r.getDeploymentNameFromReplicaSet("single"); got != "single" {
		t.Errorf("got %s", got)
	}
}

func TestContainerLearner_PoliciesToNamespacedNames(t *testing.T) {
	r := &ContainerLearnerReconciler{}
	names := r.policiesToNamespacedNames([]*policyv1alpha1.PahlevanPolicy{
		samplePolicy("a", "ns1", nil),
		samplePolicy("b", "ns2", nil),
	})
	if len(names) != 2 || names[0].Name != "a" || names[1].Namespace != "ns2" {
		t.Fatalf("unexpected names: %+v", names)
	}
}

func TestContainerLearner_HandlePodDeletion(t *testing.T) {
	r := newContainerLearner(t)
	_ = r.SyscallLearner.StartLearning(context.Background(), "c1", learner.WorkloadReference{}, nil)
	r.TrackedContainers["c1"] = &ContainerTrackingInfo{ContainerID: "c1", PodName: "p", PodNamespace: "default"}
	r.TrackedContainers["c2"] = &ContainerTrackingInfo{ContainerID: "c2", PodName: "other", PodNamespace: "default"}

	r.handlePodDeletion(types.NamespacedName{Name: "p", Namespace: "default"})
	if _, ok := r.TrackedContainers["c1"]; ok {
		t.Fatal("expected c1 removed")
	}
	if _, ok := r.TrackedContainers["c2"]; !ok {
		t.Fatal("expected c2 retained")
	}
}

// --------------------------------------------------------------------------
// AttackSurfaceAnalyzerReconciler
// --------------------------------------------------------------------------

func newAttackSurfaceReconciler(t *testing.T, objs ...client.Object) *AttackSurfaceAnalyzerReconciler {
	t.Helper()
	c := newFakeClient(t, objs...)
	return &AttackSurfaceAnalyzerReconciler{
		Client:                c,
		Scheme:                testScheme(t),
		AttackSurfaceAnalyzer: visualization.NewAttackSurfaceAnalyzer(c, nil, nil),
		AnalysisInterval:      time.Minute,
	}
}

func TestAttackSurface_Reconcile_TriggersAnalysis(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	dep := sampleDeployment("web", "default", labels)
	r := newAttackSurfaceReconciler(t, policy, dep)

	// LastFullAnalysis is zero -> time interval elapsed -> analysis runs.
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p1", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Fatalf("expected requeue at interval, got %+v", res)
	}
	if r.LastFullAnalysis.IsZero() {
		t.Fatal("expected LastFullAnalysis updated")
	}
}

func TestAttackSurface_PerformClusterAnalysis_NilAnalyzer(t *testing.T) {
	// Nil analyzer must be handled gracefully (robustness guard).
	r := &AttackSurfaceAnalyzerReconciler{Client: newFakeClient(t), Scheme: testScheme(t)}
	if err := r.performClusterAnalysis(context.Background()); err != nil {
		t.Fatalf("expected nil error with nil analyzer, got %v", err)
	}
}

func TestAttackSurface_GetTargetWorkloads(t *testing.T) {
	labels := map[string]string{"app": "web"}
	policy := samplePolicy("p1", "default", labels)
	dep := sampleDeployment("web", "default", labels)
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default", Labels: labels}}
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "default", Labels: labels}}
	other := sampleDeployment("nomatch", "default", map[string]string{"app": "other"})

	r := newAttackSurfaceReconciler(t, policy, dep, sts, ds, other)
	workloads, err := r.getTargetWorkloads(context.Background(), policy)
	if err != nil {
		t.Fatalf("getTargetWorkloads: %v", err)
	}
	if len(workloads) != 3 {
		t.Fatalf("expected 3 matching workloads, got %d", len(workloads))
	}
}

func TestAttackSurface_UpdatePolicyWithAttackSurface(t *testing.T) {
	r := &AttackSurfaceAnalyzerReconciler{}
	policy := samplePolicy("p1", "default", nil)

	surface := &visualization.WorkloadAttackSurface{
		Containers: map[string]*visualization.ContainerAttackSurface{
			"c1": {
				SyscallExposure:    &visualization.SyscallExposureAnalysis{RiskySyscalls: []string{"ptrace", "mount"}},
				FileSystemExposure: &visualization.FileSystemExposureAnalysis{WritablePaths: []string{"/etc"}},
				CapabilityAnalysis: &visualization.CapabilityAnalysis{Added: []string{"NET_ADMIN"}, Risky: []string{"SYS_ADMIN"}},
			},
		},
		ServiceExposure: &visualization.ServiceExposure{
			Ports: []visualization.ExposedPort{{Port: 80}, {Port: 443}},
		},
		OverallRiskScore: 7.0,
	}
	r.updatePolicyWithAttackSurface(policy, surface)

	as := policy.Status.AttackSurface
	if as == nil {
		t.Fatal("expected attack surface status")
	}
	if len(as.ExposedSyscalls) != 2 || len(as.ExposedPorts) != 2 {
		t.Fatalf("unexpected syscalls/ports: %+v", as)
	}
	if len(as.WritableFiles) != 1 || len(as.Capabilities) != 2 {
		t.Fatalf("unexpected files/caps: %+v", as)
	}
	if as.RiskScore == nil || *as.RiskScore != 7 {
		t.Fatalf("unexpected risk score: %+v", as.RiskScore)
	}
	if as.LastAnalysis == nil {
		t.Fatal("expected LastAnalysis set")
	}
}

func TestAttackSurface_UpsertAttackSurface(t *testing.T) {
	policy := samplePolicy("p1", "default", nil)
	risk := int32(5)
	policy.Status.AttackSurface = &policyv1alpha1.AttackSurfaceStatus{RiskScore: &risk}
	c := newFakeClient(t, policy)
	r := &AttackSurfaceAnalyzerReconciler{Client: c, Scheme: testScheme(t)}

	if err := r.upsertAttackSurface(context.Background(), policy); err != nil {
		t.Fatalf("upsertAttackSurface (create): %v", err)
	}
	var as policyv1alpha1.AttackSurface
	if err := c.Get(context.Background(), types.NamespacedName{Name: "p1", Namespace: "default"}, &as); err != nil {
		t.Fatalf("get AttackSurface: %v", err)
	}
	if as.Status.RiskScore == nil || *as.Status.RiskScore != 5 {
		t.Fatalf("unexpected mirrored risk score: %+v", as.Status.RiskScore)
	}

	// Second call updates the existing AttackSurface (AlreadyExists path).
	newRisk := int32(9)
	policy.Status.AttackSurface.RiskScore = &newRisk
	if err := r.upsertAttackSurface(context.Background(), policy); err != nil {
		t.Fatalf("upsertAttackSurface (update): %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "p1", Namespace: "default"}, &as); err != nil {
		t.Fatalf("get AttackSurface: %v", err)
	}
	if as.Status.RiskScore == nil || *as.Status.RiskScore != 9 {
		t.Fatalf("expected updated risk score 9, got %+v", as.Status.RiskScore)
	}
}

func TestAttackSurface_UpsertAttackSurface_NilStatus(t *testing.T) {
	policy := samplePolicy("p1", "default", nil) // no AttackSurface status
	r := &AttackSurfaceAnalyzerReconciler{Client: newFakeClient(t, policy), Scheme: testScheme(t)}
	if err := r.upsertAttackSurface(context.Background(), policy); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestAttackSurface_IsSignificantChange(t *testing.T) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"}}
	dep := sampleDeployment("dep", "default", nil)
	policy := samplePolicy("pol", "default", nil)

	r := newAttackSurfaceReconciler(t, svc, pod, dep, policy)

	if !r.isSignificantChange(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "svc", Namespace: "default"}}) {
		t.Error("service change should be significant")
	}
	if !r.isSignificantChange(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "dep", Namespace: "default"}}) {
		t.Error("deployment change should be significant")
	}
	if !r.isSignificantChange(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "pol", Namespace: "default"}}) {
		t.Error("policy change should be significant")
	}
	// Pod is found but is not, on its own, a significant change.
	if r.isSignificantChange(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "pod", Namespace: "default"}}) {
		t.Error("pod change should not be significant")
	}
	// Missing resource -> not significant.
	if r.isSignificantChange(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "ghost", Namespace: "default"}}) {
		t.Error("missing resource should not be significant")
	}
}

func TestAttackSurface_MatchesSelector(t *testing.T) {
	r := &AttackSurfaceAnalyzerReconciler{}
	if !r.matchesSelector(map[string]string{"app": "web"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}) {
		t.Error("expected match")
	}
	if r.matchesSelector(map[string]string{"app": "db"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}) {
		t.Error("expected no match")
	}
	if !r.matchesSelector(map[string]string{"x": "y"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "x", Operator: policyv1alpha1.LabelSelectorOpExists}}}) {
		t.Error("expected Exists match")
	}
}

// --------------------------------------------------------------------------
// Benchmarks
// --------------------------------------------------------------------------

func BenchmarkPahlevanPolicyReconcile(b *testing.B) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = policyv1alpha1.AddToScheme(scheme)

	labels := map[string]string{"app": "web"}
	policy := &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "p1", Namespace: "default",
			Finalizers: []string{"pahlevan.io/finalizer"},
		},
		Spec:   policyv1alpha1.PahlevanPolicySpec{Selector: policyv1alpha1.LabelSelector{MatchLabels: labels}},
		Status: policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseEnforcing},
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: labels}}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, dep).
		WithStatusSubresource(&policyv1alpha1.PahlevanPolicy{}).
		Build()
	r := &PahlevanPolicyReconciler{Client: c, Scheme: scheme, LearningWindow: time.Minute}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1", Namespace: "default"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			b.Fatalf("reconcile: %v", err)
		}
	}
}
