package admission

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// Derived admission.
//
// The static policy above rejects the things that are dangerous for any
// workload: privileged containers, privilege escalation, host namespaces. It is
// the same baseline any admission controller ships and it knows nothing about
// the workload it is guarding.
//
// These policies are different in kind. They are generated from what a workload
// was actually observed doing, so the rule for an nginx that only ever used
// NET_BIND_SERVICE is narrower than the rule for a workload that legitimately
// needs CAP_SYS_ADMIN, and neither had to be written by hand. That is the same
// idea as the runtime allow-set, moved to the point where a pod is admitted:
// a new revision asking for privilege the workload has never needed is
// rejected before it runs, rather than denied once it tries.
//
// The limits are worth stating. It can only constrain what a pod spec
// declares, so it catches a revision that asks for CAP_SYS_ADMIN and not one
// that exploits its way there at runtime, which is what the LSM hooks are for.
// And it is only as good as the learning window: a capability used on a code
// path that never ran is a capability the policy will reject.

// DerivedPolicyName is the object name for a policy's derived admission rules.
func DerivedPolicyName(policy string) string { return "pahlevan-derived-" + policy }

// DerivedBindingName is the object name for the matching binding.
func DerivedBindingName(policy string) string { return "pahlevan-derived-" + policy }

// Baseline is the learned behaviour a derived policy is built from, collapsed
// across every container the policy governs.
type Baseline struct {
	// Capabilities are the capability names observed, without the CAP_ prefix,
	// matching the spelling a pod spec uses.
	Capabilities []string
	// Containers is how many container profiles contributed. Zero means
	// nothing has been learned and no policy should be derived at all.
	Containers int
	// Enforcing is how many of those have reached enforcement.
	Enforcing int
}

// CollapseBaseline unions the learned behaviour of the profiles governed by one
// policy.
//
// The union, not the intersection: a capability one replica needed is a
// capability the workload needs, and intersecting would produce a policy that
// rejects the pod that taught it.
func CollapseBaseline(policy string, profiles []policyv1alpha1.ContainerProfile) Baseline {
	var b Baseline
	seen := map[string]struct{}{}
	for i := range profiles {
		p := &profiles[i]
		if p.Spec.PolicyRef != policy {
			continue
		}
		b.Containers++
		if p.Status.Phase == "Enforcing" {
			b.Enforcing++
		}
		for _, c := range p.Status.LearnedCapabilities {
			c = strings.TrimSpace(strings.TrimPrefix(c, "CAP_"))
			if c == "" {
				continue
			}
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			b.Capabilities = append(b.Capabilities, c)
		}
	}
	sort.Strings(b.Capabilities)
	return b
}

// Ready reports whether a baseline is worth deriving a policy from.
//
// A policy with no learned containers would reject every capability, including
// ones the workload has simply not exercised yet, so nothing is derived until
// at least one container has finished learning. Refusing to guess is the whole
// difference between this and a hand-written deny-list.
func (b Baseline) Ready() bool { return b.Containers > 0 && b.Enforcing > 0 }

// DerivedPolicy builds the ValidatingAdmissionPolicy for one PahlevanPolicy
// from its learned baseline. It returns nil when the baseline is not ready.
func DerivedPolicy(policy string, b Baseline) *admissionregistrationv1.ValidatingAdmissionPolicy {
	if !b.Ready() {
		return nil
	}
	fail := failClosed
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: DerivedPolicyName(policy),
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "pahlevan",
				"pahlevan.io/policy":        policy,
				"pahlevan.io/derived":       "true",
			},
			Annotations: map[string]string{
				// Says where the rule came from, so an operator who hits it can
				// tell a learned constraint from a hand-written one.
				"pahlevan.io/derived-from": fmt.Sprintf(
					"%d container profile(s), %d enforcing", b.Containers, b.Enforcing),
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &fail,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create, admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: capabilityExpression(b.Capabilities),
				Message: fmt.Sprintf(
					"Pahlevan admission: this workload was observed using only [%s]; "+
						"requesting another capability needs a policy exception",
					strings.Join(b.Capabilities, ", ")),
				Reason: reasonPtr(metav1.StatusReasonForbidden),
			}},
		},
	}
}

// capabilityExpression builds the CEL that holds requested capabilities to the
// learned set.
//
// Init and ephemeral containers are checked too: a capability requested by an
// init container is a capability the pod gets, and checking only the main
// containers would leave the obvious way around the rule wide open.
func capabilityExpression(allowed []string) string {
	// Sorted here rather than relying on the caller: stability is a property of
	// the generated expression, and a Baseline built by hand would otherwise
	// rewrite the object on every reconcile.
	sorted := append([]string(nil), allowed...)
	sort.Strings(sorted)
	list := celStringList(sorted)
	// A container that requests nothing passes trivially. The has() chain is
	// required because CEL on a pod spec errors rather than returning false
	// when an optional field is absent.
	const perContainer = `(!has(c.securityContext) || !has(c.securityContext.capabilities) || ` +
		`!has(c.securityContext.capabilities.add) || c.securityContext.capabilities.add.all(cap, cap in %s))`

	clauses := []string{
		"object.spec.containers.all(c, " + fmt.Sprintf(perContainer, list) + ")",
		"(!has(object.spec.initContainers) || object.spec.initContainers.all(c, " +
			fmt.Sprintf(perContainer, list) + "))",
		"(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, " +
			fmt.Sprintf(perContainer, list) + "))",
	}
	return strings.Join(clauses, " && ")
}

// celStringList renders a CEL list literal. Names are quoted and the list is
// sorted so the generated expression is stable: an unstable expression would
// rewrite the object on every reconcile and make a real change invisible in the
// noise.
func celStringList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, `'`+strings.ReplaceAll(s, `'`, `\'`)+`'`)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// DerivedBinding binds a derived policy to the namespaces that opted in.
//
// It uses the same opt-in label as the static policy. Deriving a rule from
// observed behaviour and applying it to a namespace that never asked for
// admission control would be a surprise, and the failure mode is a pod that
// will not start.
func DerivedBinding(policy string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicyBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: DerivedBindingName(policy),
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "pahlevan",
				"pahlevan.io/policy":        policy,
				"pahlevan.io/derived":       "true",
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: DerivedPolicyName(policy),
			ValidationActions: []admissionregistrationv1.ValidationAction{
				admissionregistrationv1.Deny,
			},
			MatchResources: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"pahlevan.io/admission": "enforce"},
				},
			},
		},
	}
}

// EnsureDerived reconciles the derived admission policies for every
// PahlevanPolicy that has a ready baseline.
//
// Policies whose containers are still learning get nothing, and a policy that
// loses its baseline has its derived objects removed rather than left behind
// enforcing a constraint nothing supports any more.
func EnsureDerived(ctx context.Context, c client.Client) (int, error) {
	if !supported(ctx, c) {
		return 0, ErrUnsupported
	}

	var policies policyv1alpha1.PahlevanPolicyList
	if err := c.List(ctx, &policies); err != nil {
		return 0, fmt.Errorf("listing policies: %w", err)
	}
	var profiles policyv1alpha1.ContainerProfileList
	if err := c.List(ctx, &profiles); err != nil {
		return 0, fmt.Errorf("listing container profiles: %w", err)
	}

	applied := 0
	var errs []string
	live := map[string]struct{}{}

	for i := range policies.Items {
		pol := &policies.Items[i]
		base := CollapseBaseline(pol.Name, profiles.Items)
		derived := DerivedPolicy(pol.Name, base)
		if derived == nil {
			continue
		}
		if err := upsert(ctx, c, derived); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", pol.Name, err))
			continue
		}
		if err := upsert(ctx, c, DerivedBinding(pol.Name)); err != nil {
			errs = append(errs, fmt.Sprintf("%s binding: %v", pol.Name, err))
			continue
		}
		live[DerivedPolicyName(pol.Name)] = struct{}{}
		applied++
	}

	if err := pruneDerived(ctx, c, live); err != nil {
		errs = append(errs, "prune: "+err.Error())
	}
	if len(errs) > 0 {
		return applied, fmt.Errorf("derived admission: %s", strings.Join(errs, "; "))
	}
	return applied, nil
}

// pruneDerived removes derived objects whose policy or baseline is gone.
//
// Leaving one behind would keep rejecting pods on the strength of a baseline
// nothing tracks any more, which is the worst kind of stale rule: it looks
// deliberate.
func pruneDerived(ctx context.Context, c client.Client, live map[string]struct{}) error {
	sel := client.MatchingLabels{"pahlevan.io/derived": "true"}

	var pols admissionregistrationv1.ValidatingAdmissionPolicyList
	if err := c.List(ctx, &pols, sel); err != nil {
		return err
	}
	for i := range pols.Items {
		p := &pols.Items[i]
		if _, keep := live[p.Name]; keep {
			continue
		}
		if err := c.Delete(ctx, p); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}

	var binds admissionregistrationv1.ValidatingAdmissionPolicyBindingList
	if err := c.List(ctx, &binds, sel); err != nil {
		return err
	}
	for i := range binds.Items {
		b := &binds.Items[i]
		if _, keep := live[b.Spec.PolicyName]; keep {
			continue
		}
		if err := c.Delete(ctx, b); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
