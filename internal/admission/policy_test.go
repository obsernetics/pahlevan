package admission

import (
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestDesiredPolicy(t *testing.T) {
	p := DesiredPolicy()
	if p.Name != policyName {
		t.Errorf("name = %q", p.Name)
	}
	if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Error("expected fail-closed failure policy")
	}
	if len(p.Spec.Validations) < 4 {
		t.Fatalf("expected >=4 validations, got %d", len(p.Spec.Validations))
	}
	joined := ""
	for _, v := range p.Spec.Validations {
		if v.Expression == "" || v.Message == "" {
			t.Error("validation missing expression/message")
		}
		joined += v.Expression + "\n"
	}
	for _, want := range []string{"privileged", "allowPrivilegeEscalation", "hostPID", "hostNetwork"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a validation guarding %q", want)
		}
	}
}

func TestDesiredBinding(t *testing.T) {
	b := DesiredBinding()
	if b.Spec.PolicyName != policyName {
		t.Errorf("binding policyName = %q", b.Spec.PolicyName)
	}
	if len(b.Spec.ValidationActions) == 0 || b.Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Error("expected Deny validation action")
	}
	if b.Spec.MatchResources == nil || b.Spec.MatchResources.NamespaceSelector == nil {
		t.Fatal("expected namespace selector")
	}
	if b.Spec.MatchResources.NamespaceSelector.MatchLabels[optInLabel] != optInValue {
		t.Errorf("expected opt-in label %s=%s", optInLabel, optInValue)
	}
}
