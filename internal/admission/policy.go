// Package admission manages Pahlevan's CEL-based admission control.
//
// Instead of a mutating/validating webhook (extra pods, certs, and a network hop
// in the request path), Pahlevan uses Kubernetes ValidatingAdmissionPolicy
// (CEL, in-process in the API server, GA in 1.30+). The operator ensures a
// hardening policy exists and binds it to namespaces opted in via the label
// pahlevan.io/admission=enforce. This complements the runtime data plane:
// admission blocks obviously-dangerous pod specs before they ever start.
package admission

import (
	"context"
	"errors"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const fieldOwner = client.FieldOwner("pahlevan-operator")

const (
	policyName  = "pahlevan-pod-hardening"
	bindingName = "pahlevan-pod-hardening-binding"
	optInLabel  = "pahlevan.io/admission"
	optInValue  = "enforce"
	failClosed  = admissionregistrationv1.Fail
)

// DesiredPolicy returns the ValidatingAdmissionPolicy Pahlevan enforces: it
// rejects privileged containers, privilege escalation, and host namespace
// sharing - the baseline that most runtime compromises rely on.
func DesiredPolicy() *admissionregistrationv1.ValidatingAdmissionPolicy {
	fail := failClosed
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   policyName,
			Labels: map[string]string{"app.kubernetes.io/part-of": "pahlevan"},
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
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: `object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)`,
					Message:    "Pahlevan admission: privileged containers are not allowed",
					Reason:     reasonPtr(metav1.StatusReasonForbidden),
				},
				{
					Expression: `object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.allowPrivilegeEscalation) || c.securityContext.allowPrivilegeEscalation == false)`,
					Message:    "Pahlevan admission: allowPrivilegeEscalation must be false",
					Reason:     reasonPtr(metav1.StatusReasonForbidden),
				},
				{
					Expression: `!has(object.spec.hostPID) || object.spec.hostPID == false`,
					Message:    "Pahlevan admission: hostPID is not allowed",
					Reason:     reasonPtr(metav1.StatusReasonForbidden),
				},
				{
					Expression: `!has(object.spec.hostNetwork) || object.spec.hostNetwork == false`,
					Message:    "Pahlevan admission: hostNetwork is not allowed",
					Reason:     reasonPtr(metav1.StatusReasonForbidden),
				},
			},
		},
	}
}

// DesiredBinding binds the policy to namespaces labeled pahlevan.io/admission=enforce.
func DesiredBinding() *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicyBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   bindingName,
			Labels: map[string]string{"app.kubernetes.io/part-of": "pahlevan"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: policyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{
				admissionregistrationv1.Deny,
			},
			MatchResources: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{optInLabel: optInValue},
				},
			},
		},
	}
}

// Ensure creates or updates the policy and binding. It is a no-op-safe upsert and
// tolerates clusters without the ValidatingAdmissionPolicy API (pre-1.30): such
// clusters return a NoKindMatch/NotFound on the GVK, which is reported as
// ErrUnsupported rather than a hard failure.
func Ensure(ctx context.Context, c client.Client) error {
	if !supported(c) {
		return ErrUnsupported
	}
	if err := upsert(ctx, c, DesiredPolicy()); err != nil {
		return err
	}
	return upsert(ctx, c, DesiredBinding())
}

// ErrUnsupported is returned when the cluster lacks the ValidatingAdmissionPolicy API.
var ErrUnsupported = errors.New("ValidatingAdmissionPolicy API not available (requires Kubernetes 1.30+)")

// supported takes no context: RESTMapper resolution is served from the
// client's cached mapper and never issues a request.
func supported(c client.Client) bool {
	gvk := schema.GroupVersionKind{
		Group:   admissionregistrationv1.SchemeGroupVersion.Group,
		Version: admissionregistrationv1.SchemeGroupVersion.Version,
		Kind:    "ValidatingAdmissionPolicy",
	}
	_, err := c.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

// upsert applies the object declaratively via server-side apply, so it creates
// or updates without needing a resourceVersion and converges to the desired spec.
func upsert(ctx context.Context, c client.Client, obj client.Object) error {
	return c.Patch(ctx, obj, client.Apply, fieldOwner, client.ForceOwnership)
}

func reasonPtr(r metav1.StatusReason) *metav1.StatusReason { return &r }
