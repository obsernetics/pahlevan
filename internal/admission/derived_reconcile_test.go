package admission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func derivedScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, policyv1alpha1.AddToScheme(s))
	require.NoError(t, admissionregistrationv1.AddToScheme(s))
	return s
}

func pahlevanPolicy(name string) *policyv1alpha1.PahlevanPolicy {
	return &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod"},
	}
}

func derivedClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(derivedScheme(t)).
		WithObjects(objs...).
		WithRESTMapper(fakeMapperWithVAP(t)).
		Build()
}

func TestEnsureDerivedCreatesPolicyAndBinding(t *testing.T) {
	p := learnedProfile("cp-a", "nginx-security", "Enforcing", "NET_BIND_SERVICE")
	c := derivedClient(t, pahlevanPolicy("nginx-security"), &p)

	n, err := EnsureDerived(context.Background(), c)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	var vap admissionregistrationv1.ValidatingAdmissionPolicy
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Name: DerivedPolicyName("nginx-security")}, &vap))
	assert.Contains(t, vap.Spec.Validations[0].Expression, "'NET_BIND_SERVICE'")

	var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Name: DerivedBindingName("nginx-security")}, &binding))
	assert.Equal(t, DerivedPolicyName("nginx-security"), binding.Spec.PolicyName)
}

// A policy whose containers are still learning must derive nothing. Guessing
// would produce a rule that rejects capabilities the workload has simply not
// exercised yet.
func TestEnsureDerivedSkipsPoliciesStillLearning(t *testing.T) {
	p := learnedProfile("cp-a", "nginx-security", "Learning", "NET_BIND_SERVICE")
	c := derivedClient(t, pahlevanPolicy("nginx-security"), &p)

	n, err := EnsureDerived(context.Background(), c)
	require.NoError(t, err)
	assert.Zero(t, n)

	var vap admissionregistrationv1.ValidatingAdmissionPolicy
	err = c.Get(context.Background(), client.ObjectKey{Name: DerivedPolicyName("nginx-security")}, &vap)
	assert.Error(t, err, "nothing should be derived before a baseline exists")
}

// A rule outliving the evidence for it is the worst kind of stale: it looks
// deliberate. When the policy goes, the derived objects go with it.
func TestEnsureDerivedPrunesWhenThePolicyIsDeleted(t *testing.T) {
	p := learnedProfile("cp-a", "nginx-security", "Enforcing", "CHOWN")
	pol := pahlevanPolicy("nginx-security")
	c := derivedClient(t, pol, &p)

	_, err := EnsureDerived(context.Background(), c)
	require.NoError(t, err)
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Name: DerivedPolicyName("nginx-security")},
		&admissionregistrationv1.ValidatingAdmissionPolicy{}))

	require.NoError(t, c.Delete(context.Background(), pol))
	_, err = EnsureDerived(context.Background(), c)
	require.NoError(t, err)

	err = c.Get(context.Background(),
		client.ObjectKey{Name: DerivedPolicyName("nginx-security")},
		&admissionregistrationv1.ValidatingAdmissionPolicy{})
	assert.Error(t, err, "the derived policy must not outlive the policy it came from")

	err = c.Get(context.Background(),
		client.ObjectKey{Name: DerivedBindingName("nginx-security")},
		&admissionregistrationv1.ValidatingAdmissionPolicyBinding{})
	assert.Error(t, err, "the binding must go too")
}

// The static hardening policy is not derived and must survive the prune.
func TestEnsureDerivedLeavesTheStaticPolicyAlone(t *testing.T) {
	static := DesiredPolicy()
	c := derivedClient(t, static)

	_, err := EnsureDerived(context.Background(), c)
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKey{Name: static.Name},
		&admissionregistrationv1.ValidatingAdmissionPolicy{})
	assert.NoError(t, err, "the static policy carries no derived label and must be untouched")
}

// A new capability observed later must widen the rule, or the workload's own
// next rollout is rejected by a policy derived from its past.
func TestEnsureDerivedWidensWhenTheBaselineGrows(t *testing.T) {
	p := learnedProfile("cp-a", "nginx-security", "Enforcing", "CHOWN")
	c := derivedClient(t, pahlevanPolicy("nginx-security"), &p)

	_, err := EnsureDerived(context.Background(), c)
	require.NoError(t, err)

	var live policyv1alpha1.ContainerProfile
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Namespace: "prod", Name: "cp-a"}, &live))
	live.Status.LearnedCapabilities = []string{"CHOWN", "SETUID"}
	require.NoError(t, c.Update(context.Background(), &live))

	_, err = EnsureDerived(context.Background(), c)
	require.NoError(t, err)

	var vap admissionregistrationv1.ValidatingAdmissionPolicy
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Name: DerivedPolicyName("nginx-security")}, &vap))
	assert.Contains(t, vap.Spec.Validations[0].Expression, "'SETUID'")
}

// A cluster without the API must be told so rather than logged as a failure.
func TestEnsureDerivedUnsupportedCluster(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(derivedScheme(t)).Build()
	_, err := EnsureDerived(context.Background(), c)
	assert.ErrorIs(t, err, ErrUnsupported)
}

// fakeMapperWithVAP is a RESTMapper that knows about ValidatingAdmissionPolicy,
// which is how supported() decides the cluster is new enough. Without it every
// test would take the unsupported path and assert nothing.
func fakeMapperWithVAP(t *testing.T) meta.RESTMapper {
	t.Helper()
	gv := admissionregistrationv1.SchemeGroupVersion
	m := meta.NewDefaultRESTMapper([]schema.GroupVersion{gv})
	m.Add(gv.WithKind("ValidatingAdmissionPolicy"), meta.RESTScopeRoot)
	m.Add(gv.WithKind("ValidatingAdmissionPolicyBinding"), meta.RESTScopeRoot)
	return m
}
