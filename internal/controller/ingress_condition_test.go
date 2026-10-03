package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	policytranslate "github.com/obsernetics/pahlevan/internal/policy"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func policyWithIngress(name, ns string, rules int) *policyv1alpha1.PahlevanPolicy {
	p := samplePolicy(name, ns, map[string]string{"app": "demo"})
	p.Spec.NetworkPolicy = &policyv1alpha1.NetworkPolicy{
		IngressRules: make([]policyv1alpha1.NetworkRule, rules),
	}
	return p
}

func conditionOf(
	t testing.TB,
	p *policyv1alpha1.PahlevanPolicy,
	kind policyv1alpha1.PolicyConditionType,
) (policyv1alpha1.PolicyCondition, bool) {
	t.Helper()
	for _, c := range p.Status.Conditions {
		if c.Type == kind {
			return c, true
		}
	}
	return policyv1alpha1.PolicyCondition{}, false
}

// The whole point of the change. A policy that asks for ingress enforcement
// must say on its own status that it is not getting any, with the same sentence
// the API server would have refused it with.
func TestIngressRulesRecordAFalseConditionWithTheRefusalMessage(t *testing.T) {
	p := policyWithIngress("demo", "prod", 1)

	require.True(t, setIngressCondition(p), "the condition has to be written")

	cond, ok := conditionOf(t, p, policyv1alpha1.PolicyConditionIngressEnforced)
	require.True(t, ok,
		"a policy with ingressRules carries no IngressEnforced condition, so the only record "+
			"that the rule does nothing is a log line on one node")
	assert.Equal(t, policyv1alpha1.ConditionFalse, cond.Status,
		"the condition must be False: ingress is never enforced, so True would be a lie")
	assert.Equal(t, policytranslate.IngressNotEnforcedReason, cond.Reason)
	assert.Equal(t, policytranslate.IngressNotEnforced, cond.Message,
		"the condition message is the shared refusal sentence, not a paraphrase")
	assert.False(t, cond.LastTransitionTime.IsZero())
}

// A policy that asks for nothing must not be decorated with a condition about
// a field it does not set. Every policy in the cluster carrying a network
// caveat would make the real ones invisible.
func TestNoIngressRulesLeavesNoCondition(t *testing.T) {
	tests := []struct {
		name   string
		policy *policyv1alpha1.PahlevanPolicy
	}{
		{"no network policy", samplePolicy("demo", "prod", map[string]string{"app": "demo"})},
		{"an empty ingress list", policyWithIngress("demo", "prod", 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, setIngressCondition(tc.policy),
				"nothing changed, so nothing should be written to the API server")
			_, ok := conditionOf(t, tc.policy, policyv1alpha1.PolicyConditionIngressEnforced)
			assert.False(t, ok)
		})
	}
}

// Reconciles are frequent and unconditional. A second pass over an unchanged
// policy must report no change, or every reconcile of every policy becomes a
// status write.
func TestIngressConditionIsIdempotent(t *testing.T) {
	p := policyWithIngress("demo", "prod", 1)
	require.True(t, setIngressCondition(p))
	assert.False(t, setIngressCondition(p), "a second pass over an unchanged policy must not write")
	assert.False(t, setIngressCondition(p))
	assert.Len(t, p.Status.Conditions, 1, "the condition must not be appended twice")
}

// When the operator removes the rules, the condition goes away. Flipping it to
// True would assert that ingress is enforced, which never happens here, and
// leaving it False would report a refusal that no longer applies - a condition
// the operator cannot clear by fixing the policy is its own false signal.
func TestRemovingIngressRulesRemovesTheCondition(t *testing.T) {
	p := policyWithIngress("demo", "prod", 2)
	require.True(t, setIngressCondition(p))
	require.Len(t, p.Status.Conditions, 1)

	p.Spec.NetworkPolicy.IngressRules = nil

	require.True(t, setIngressCondition(p), "the removal has to be written")
	_, ok := conditionOf(t, p, policyv1alpha1.PolicyConditionIngressEnforced)
	assert.False(t, ok, "the condition must be removed, not left False or flipped to True")
}

// The other conditions are the policy's lifecycle. Adding or removing this one
// must not disturb them or their order.
func TestIngressConditionLeavesOtherConditionsAlone(t *testing.T) {
	p := policyWithIngress("demo", "prod", 1)
	p.Status.Conditions = []policyv1alpha1.PolicyCondition{
		{Type: policyv1alpha1.PolicyConditionReady, Status: policyv1alpha1.ConditionTrue, Reason: "Initialized"},
		{Type: policyv1alpha1.PolicyConditionLearning, Status: policyv1alpha1.ConditionTrue, Reason: "LearningStarted"},
	}

	require.True(t, setIngressCondition(p))
	require.Len(t, p.Status.Conditions, 3)
	assert.Equal(t, policyv1alpha1.PolicyConditionReady, p.Status.Conditions[0].Type)
	assert.Equal(t, policyv1alpha1.PolicyConditionLearning, p.Status.Conditions[1].Type)

	p.Spec.NetworkPolicy = nil
	require.True(t, setIngressCondition(p))
	require.Len(t, p.Status.Conditions, 2)
	assert.Equal(t, policyv1alpha1.PolicyConditionReady, p.Status.Conditions[0].Type)
	assert.Equal(t, "Initialized", p.Status.Conditions[0].Reason)
	assert.Equal(t, policyv1alpha1.PolicyConditionLearning, p.Status.Conditions[1].Type)
}

// A stale message on a condition whose status did not change is the trap in
// updateCondition elsewhere in this file: it returns early when the status
// matches, so a corrected sentence never lands. This condition is almost
// entirely message, so it cannot inherit that.
func TestIngressConditionCorrectsAStaleMessageAndKeepsTheTimestamp(t *testing.T) {
	p := policyWithIngress("demo", "prod", 1)
	earlier := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	p.Status.Conditions = []policyv1alpha1.PolicyCondition{{
		Type:               policyv1alpha1.PolicyConditionIngressEnforced,
		Status:             policyv1alpha1.ConditionFalse,
		LastTransitionTime: earlier,
		Reason:             "SomethingOlder",
		Message:            "ingressRules are ignored",
	}}

	require.True(t, setIngressCondition(p), "a stale message has to be corrected")

	cond, ok := conditionOf(t, p, policyv1alpha1.PolicyConditionIngressEnforced)
	require.True(t, ok)
	assert.Equal(t, policytranslate.IngressNotEnforced, cond.Message)
	assert.Equal(t, policytranslate.IngressNotEnforcedReason, cond.Reason)
	assert.Equal(t, earlier, cond.LastTransitionTime,
		"the status did not transition, so the original timestamp stands")
}

// The condition reaches a real API server through the status subresource, and
// a reconcile of a policy without ingress rules must not write at all.
func TestReconcileIngressConditionPersistsAndIsQuietWhenClean(t *testing.T) {
	ctx := context.Background()

	withIngress := policyWithIngress("dirty", "prod", 1)
	clean := samplePolicy("clean", "prod", map[string]string{"app": "demo"})
	c := newFakeClient(t, withIngress, clean)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	require.NoError(t, r.reconcileIngressCondition(ctx, withIngress))

	var stored policyv1alpha1.PahlevanPolicy
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "dirty", Namespace: "prod"}, &stored))
	cond, ok := conditionOf(t, &stored, policyv1alpha1.PolicyConditionIngressEnforced)
	require.True(t, ok, "the condition did not survive the status write")
	assert.Equal(t, policyv1alpha1.ConditionFalse, cond.Status)
	assert.Equal(t, policytranslate.IngressNotEnforced, cond.Message)

	require.NoError(t, r.reconcileIngressCondition(ctx, clean))
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "clean", Namespace: "prod"}, &stored))
	assert.Empty(t, stored.Status.Conditions)
}

// Reconcile itself has to reach the condition. A helper nothing calls is the
// same no-op the defect was about, one level up.
func TestReconcileRecordsTheIngressConditionOnAPolicyItHandles(t *testing.T) {
	ctx := context.Background()
	p := policyWithIngress("demo", "prod", 1)
	p.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	c := newFakeClient(t, p)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(t)}

	// The finalizer is added on the first pass and the object is requeued, so
	// two reconciles are needed before the phase handlers run.
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo", Namespace: "prod"}}
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}

	var stored policyv1alpha1.PahlevanPolicy
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "demo", Namespace: "prod"}, &stored))
	cond, ok := conditionOf(t, &stored, policyv1alpha1.PolicyConditionIngressEnforced)
	require.True(t, ok,
		"Reconcile never recorded the ingress condition, so an applied policy still says nothing")
	assert.Equal(t, policyv1alpha1.ConditionFalse, cond.Status)
	assert.Equal(t, policytranslate.IngressNotEnforcedReason, cond.Reason)
}

// --------------------------------------------------------------------------
// Benchmarks
// --------------------------------------------------------------------------

// The steady state: a policy whose condition is already correct. This runs on
// every reconcile of every policy, so it has to decide "nothing changed"
// without allocating.
func BenchmarkSetIngressConditionUnchanged(b *testing.B) {
	p := policyWithIngress("demo", "prod", 1)
	setIngressCondition(p)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if setIngressCondition(p) {
			b.Fatal("the condition was already correct")
		}
	}
}

// The other steady state, and by far the common one: no ingress rules at all.
func BenchmarkSetIngressConditionClean(b *testing.B) {
	p := samplePolicy("demo", "prod", map[string]string{"app": "demo"})
	p.Status.Conditions = []policyv1alpha1.PolicyCondition{
		{Type: policyv1alpha1.PolicyConditionReady, Status: policyv1alpha1.ConditionTrue},
		{Type: policyv1alpha1.PolicyConditionLearning, Status: policyv1alpha1.ConditionTrue},
		{Type: policyv1alpha1.PolicyConditionEnforcing, Status: policyv1alpha1.ConditionTrue},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if setIngressCondition(p) {
			b.Fatal("a clean policy needs no condition")
		}
	}
}

// Adding then removing, which is what a policy being corrected looks like.
func BenchmarkSetIngressConditionToggling(b *testing.B) {
	p := policyWithIngress("demo", "prod", 1)
	rules := p.Spec.NetworkPolicy.IngressRules
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Spec.NetworkPolicy.IngressRules = rules
		setIngressCondition(p)
		p.Spec.NetworkPolicy.IngressRules = nil
		setIngressCondition(p)
	}
}
