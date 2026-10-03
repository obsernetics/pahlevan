package policy

import (
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// IngressNotEnforced is the single sentence every surface uses when a policy
// asks Pahlevan to enforce ingress.
//
// Pahlevan's network data plane is one LSM hook, socket_connect, which the
// kernel calls on the outbound connect() of the process being governed. It
// sees a destination the workload chose, not a peer that chose the workload,
// so it cannot decide an inbound connection at all. The LSM set has no usable
// inbound counterpart either: security_socket_accept runs before the pending
// connection is dequeued, so the socket it is handed carries no peer address
// to match a rule against, and security_socket_bind sees only the local
// address a server asked to listen on. An ingress rule therefore has nothing
// in this design that could carry it.
//
// What matters is that it says so where the operator is looking. The same
// sentence appears in three places: the CRD's CEL validation refuses the field
// at apply time, which is the only moment the author is certain to be watching;
// PolicyConditionIngressEnforced records it on the status of a policy that was
// stored before that validation shipped; and `pahlevan policy explain` prints
// it against a file before it is ever applied. The CRD copy lives in a
// kubebuilder marker and cannot reference this constant, so
// TestCRDIngressValidationMatchesMessage asserts the two have not drifted.
const IngressNotEnforced = "networkPolicy.ingressRules is not enforced and is refused rather " +
	"than silently ignored: Pahlevan enforces network policy at the socket_connect LSM hook, " +
	"which governs outbound connections only. Use a Kubernetes NetworkPolicy for ingress; " +
	"pahlevan netpol generate writes one from observed traffic."

// IngressNotEnforcedReason is the machine-readable Reason on
// PolicyConditionIngressEnforced. Operators match on Reason, not on prose, so
// it is a stable identifier rather than a summary of the message.
const IngressNotEnforcedReason = "IngressRulesRefused"

// DeclaresIngress reports whether a spec asks for ingress enforcement, which
// is the sole trigger for the condition. A nil networkPolicy and an empty
// ingressRules list both declare nothing: the operator asked for no ingress
// rule, so there is nothing to refuse and nothing to report.
func DeclaresIngress(spec policyv1alpha1.PahlevanPolicySpec) bool {
	return spec.NetworkPolicy != nil && len(spec.NetworkPolicy.IngressRules) > 0
}
