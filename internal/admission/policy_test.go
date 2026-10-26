package admission

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// A cluster below 1.30 must be told so rather than treated as a failed write:
// Ensure never even attempts a Patch in that case.
func TestEnsureUnsupportedCluster(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(derivedScheme(t)).Build()

	err := Ensure(context.Background(), c)

	assert.ErrorIs(t, err, ErrUnsupported)
	assert.Error(t, c.Get(context.Background(), client.ObjectKey{Name: policyName},
		&admissionregistrationv1.ValidatingAdmissionPolicy{}),
		"no policy should be written when the API is unsupported")
}

// The common path: a cluster that supports the API gets both objects, with
// the spec Ensure actually wants on the wire.
func TestEnsureCreatesPolicyAndBinding(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(derivedScheme(t)).
		WithRESTMapper(fakeMapperWithVAP(t)).
		Build()

	require.NoError(t, Ensure(context.Background(), c))

	var vap admissionregistrationv1.ValidatingAdmissionPolicy
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: policyName}, &vap))
	assert.Equal(t, admissionregistrationv1.Fail, *vap.Spec.FailurePolicy)

	var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: bindingName}, &binding))
	assert.Equal(t, policyName, binding.Spec.PolicyName)

	// Calling Ensure again against what it just wrote must stay a no-op
	// success: it is an upsert, run on every reconcile, not a one-shot create.
	require.NoError(t, Ensure(context.Background(), c))
}

// A Patch failure on the policy itself must stop before the binding is ever
// attempted: a binding pointing at a policy that was never written would
// bind nothing.
func TestEnsureReturnsErrorWhenPolicyPatchFails(t *testing.T) {
	wantErr := errors.New("apiserver unavailable")
	c := fake.NewClientBuilder().
		WithScheme(derivedScheme(t)).
		WithRESTMapper(fakeMapperWithVAP(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				if obj.GetName() == policyName {
					return wantErr
				}
				return cl.Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	err := Ensure(context.Background(), c)

	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Error(t, c.Get(context.Background(), client.ObjectKey{Name: bindingName},
		&admissionregistrationv1.ValidatingAdmissionPolicyBinding{}),
		"the binding must not be attempted once the policy upsert fails")
}

// A Patch failure on the binding, after the policy succeeded, must still
// surface as an error rather than a silent partial success.
func TestEnsureReturnsErrorWhenBindingPatchFails(t *testing.T) {
	wantErr := errors.New("conflict")
	c := fake.NewClientBuilder().
		WithScheme(derivedScheme(t)).
		WithRESTMapper(fakeMapperWithVAP(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				if obj.GetName() == bindingName {
					return wantErr
				}
				return cl.Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	err := Ensure(context.Background(), c)

	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Name: policyName},
		&admissionregistrationv1.ValidatingAdmissionPolicy{}),
		"the policy write that did succeed must not be rolled back")
}
