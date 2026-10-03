package controller

import (
	"context"

	policytranslate "github.com/obsernetics/pahlevan/internal/policy"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reconcileIngressCondition keeps PolicyConditionIngressEnforced in step with
// the spec, and writes the status only when it changed.
//
// The CRD refuses networkPolicy.ingressRules outright, so in a current cluster
// this never fires. It is here for the two cases where the refusal does not
// reach the author: a policy stored before the validation shipped, and an API
// server that does not evaluate the CEL rule. In both, the policy is live, it
// asks for ingress enforcement, and nothing enforces it. Before this, the only
// trace of that was one line in one node agent's log, which is not somewhere an
// operator looks to find out whether their policy means what it says.
func (r *PahlevanPolicyReconciler) reconcileIngressCondition(
	ctx context.Context,
	policy *policyv1alpha1.PahlevanPolicy,
) error {
	if !setIngressCondition(policy) {
		return nil
	}
	return r.Status().Update(ctx, policy)
}

// setIngressCondition applies the condition in memory and reports whether
// anything changed.
//
// It is split from the write so the decision can be tested without an API
// server, and so the caller writes only on a change: a status update on every
// reconcile of every policy is write amplification the API server pays for.
//
// The condition is removed rather than flipped to True when the rules go away.
// True would assert that ingress is enforced, which is never the case here, and
// a stale False would report a refusal that no longer applies. Absence is the
// only honest third state.
func setIngressCondition(policy *policyv1alpha1.PahlevanPolicy) bool {
	idx := indexOfCondition(policy.Status.Conditions, policyv1alpha1.PolicyConditionIngressEnforced)

	if !policytranslate.DeclaresIngress(policy.Spec) {
		if idx < 0 {
			return false
		}
		policy.Status.Conditions = append(
			policy.Status.Conditions[:idx], policy.Status.Conditions[idx+1:]...)
		return true
	}

	want := policyv1alpha1.PolicyCondition{
		Type:               policyv1alpha1.PolicyConditionIngressEnforced,
		Status:             policyv1alpha1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             policytranslate.IngressNotEnforcedReason,
		Message:            policytranslate.IngressNotEnforced,
	}
	if idx < 0 {
		policy.Status.Conditions = append(policy.Status.Conditions, want)
		return true
	}

	existing := policy.Status.Conditions[idx]
	if existing.Status == want.Status &&
		existing.Reason == want.Reason &&
		existing.Message == want.Message {
		return false
	}
	// An unchanged Status means the condition did not transition, so the
	// original timestamp stands and only the corrected reason or message is
	// written. updateCondition elsewhere in this controller returns early when
	// the status matches, which leaves a stale message in place; this field is
	// the message, so it cannot afford that.
	if existing.Status == want.Status {
		want.LastTransitionTime = existing.LastTransitionTime
	}
	policy.Status.Conditions[idx] = want
	return true
}

// indexOfCondition returns the position of a condition type, or -1.
func indexOfCondition(
	conditions []policyv1alpha1.PolicyCondition,
	t policyv1alpha1.PolicyConditionType,
) int {
	for i := range conditions {
		if conditions[i].Type == t {
			return i
		}
	}
	return -1
}
