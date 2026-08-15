package admission

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func learnedProfile(name, policyRef, phase string, caps ...string) policyv1alpha1.ContainerProfile {
	return policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod"},
		Spec:       policyv1alpha1.ContainerProfileSpec{PolicyRef: policyRef},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:               phase,
			LearnedCapabilities: caps,
		},
	}
}

// The union, not the intersection: a capability one replica needed is one the
// workload needs, and intersecting would produce a policy that rejects the
// very pod that taught it.
func TestCollapseBaselineUnionsAcrossReplicas(t *testing.T) {
	b := CollapseBaseline("p1", []policyv1alpha1.ContainerProfile{
		learnedProfile("a", "p1", "Enforcing", "NET_BIND_SERVICE"),
		learnedProfile("b", "p1", "Enforcing", "CHOWN", "NET_BIND_SERVICE"),
	})
	assert.Equal(t, []string{"CHOWN", "NET_BIND_SERVICE"}, b.Capabilities)
	assert.Equal(t, 2, b.Containers)
	assert.Equal(t, 2, b.Enforcing)
}

// A profile governed by a different policy must not widen this one.
func TestCollapseBaselineIgnoresOtherPolicies(t *testing.T) {
	b := CollapseBaseline("p1", []policyv1alpha1.ContainerProfile{
		learnedProfile("a", "p1", "Enforcing", "CHOWN"),
		learnedProfile("b", "other", "Enforcing", "SYS_ADMIN"),
	})
	assert.Equal(t, []string{"CHOWN"}, b.Capabilities)
	assert.Equal(t, 1, b.Containers)
}

// The agent reports names without the prefix, but a hand-edited status might
// carry it; both must collapse to one entry.
func TestCollapseBaselineNormalisesTheCapPrefix(t *testing.T) {
	b := CollapseBaseline("p1", []policyv1alpha1.ContainerProfile{
		learnedProfile("a", "p1", "Enforcing", "CAP_CHOWN"),
		learnedProfile("b", "p1", "Enforcing", "CHOWN", "  "),
	})
	assert.Equal(t, []string{"CHOWN"}, b.Capabilities)
}

// Nothing is derived until something has actually finished learning. A policy
// built from an empty baseline would reject every capability, including ones
// the workload simply has not exercised yet.
func TestBaselineNotReadyBeforeLearningCompletes(t *testing.T) {
	assert.False(t, Baseline{}.Ready(), "no containers means nothing observed")
	assert.False(t, Baseline{Containers: 3}.Ready(),
		"containers still learning have not finished telling us what they need")
	assert.True(t, Baseline{Containers: 3, Enforcing: 1}.Ready())

	assert.Nil(t, DerivedPolicy("p1", Baseline{Containers: 2}),
		"no policy may be derived from a baseline that is not ready")
}

func TestDerivedPolicyShape(t *testing.T) {
	b := Baseline{Capabilities: []string{"CHOWN", "NET_BIND_SERVICE"}, Containers: 2, Enforcing: 2}
	p := DerivedPolicy("nginx-security", b)
	require.NotNil(t, p)

	assert.Equal(t, "pahlevan-derived-nginx-security", p.Name)
	assert.Equal(t, "nginx-security", p.Labels["pahlevan.io/policy"])
	assert.Equal(t, "true", p.Labels["pahlevan.io/derived"])
	// An operator who hits the rule must be able to tell a learned constraint
	// from a hand-written one.
	assert.Contains(t, p.Annotations["pahlevan.io/derived-from"], "2 container profile(s)")

	require.NotNil(t, p.Spec.FailurePolicy)
	assert.Equal(t, failClosed, *p.Spec.FailurePolicy)
	require.Len(t, p.Spec.Validations, 1)

	msg := p.Spec.Validations[0].Message
	assert.Contains(t, msg, "CHOWN")
	assert.Contains(t, msg, "NET_BIND_SERVICE")
}

// Checking only the main containers would leave the obvious way around the
// rule wide open: a capability an init container requests is one the pod gets.
func TestDerivedPolicyCoversInitAndEphemeralContainers(t *testing.T) {
	p := DerivedPolicy("p1", Baseline{Capabilities: []string{"CHOWN"}, Containers: 1, Enforcing: 1})
	require.NotNil(t, p)
	expr := p.Spec.Validations[0].Expression

	assert.Contains(t, expr, "object.spec.containers.all")
	assert.Contains(t, expr, "object.spec.initContainers.all")
	assert.Contains(t, expr, "object.spec.ephemeralContainers.all")
	// The optional lists must be guarded, or CEL errors instead of passing when
	// a pod simply has no init containers.
	assert.Contains(t, expr, "!has(object.spec.initContainers)")
	assert.Contains(t, expr, "!has(object.spec.ephemeralContainers)")
}

// A container requesting nothing must pass. CEL errors rather than returning
// false on an absent optional field, so every level needs a has() guard.
func TestDerivedPolicyGuardsAbsentSecurityContext(t *testing.T) {
	p := DerivedPolicy("p1", Baseline{Capabilities: []string{"CHOWN"}, Containers: 1, Enforcing: 1})
	require.NotNil(t, p)
	expr := p.Spec.Validations[0].Expression

	for _, guard := range []string{
		"!has(c.securityContext)",
		"!has(c.securityContext.capabilities)",
		"!has(c.securityContext.capabilities.add)",
	} {
		assert.Contains(t, expr, guard, "an absent field must not error the expression")
	}
}

// An unstable expression would rewrite the object on every reconcile and bury
// a real change in the noise.
func TestDerivedPolicyExpressionIsStable(t *testing.T) {
	a := DerivedPolicy("p1", Baseline{
		Capabilities: []string{"NET_BIND_SERVICE", "CHOWN"}, Containers: 1, Enforcing: 1,
	})
	b := DerivedPolicy("p1", Baseline{
		Capabilities: []string{"CHOWN", "NET_BIND_SERVICE"}, Containers: 1, Enforcing: 1,
	})
	require.NotNil(t, a)
	require.NotNil(t, b)
	assert.Equal(t, a.Spec.Validations[0].Expression, b.Spec.Validations[0].Expression,
		"the same set in a different order must produce the same expression")
}

func TestCelStringList(t *testing.T) {
	assert.Equal(t, "[]", celStringList(nil))
	assert.Equal(t, "['CHOWN']", celStringList([]string{"CHOWN"}))
	assert.Equal(t, "['A', 'B']", celStringList([]string{"A", "B"}))
	// A quote in a capability name would otherwise break out of the literal.
	assert.Equal(t, `['a\'b']`, celStringList([]string{"a'b"}))
}

// A workload that used no capabilities gets a policy allowing none, which is
// the correct and strictest possible outcome rather than a degenerate one.
func TestDerivedPolicyWithNoLearnedCapabilities(t *testing.T) {
	p := DerivedPolicy("p1", Baseline{Containers: 1, Enforcing: 1})
	require.NotNil(t, p)
	assert.Contains(t, p.Spec.Validations[0].Expression, "cap in []")
}

// Deriving a rule from observed behaviour and applying it to a namespace that
// never opted in would be a surprise whose failure mode is a pod that will not
// start.
func TestDerivedBindingRequiresTheOptInLabel(t *testing.T) {
	b := DerivedBinding("nginx-security")
	require.NotNil(t, b)
	assert.Equal(t, "pahlevan-derived-nginx-security", b.Name)
	assert.Equal(t, "pahlevan-derived-nginx-security", b.Spec.PolicyName)
	require.NotNil(t, b.Spec.MatchResources)
	require.NotNil(t, b.Spec.MatchResources.NamespaceSelector)
	assert.Equal(t, "enforce",
		b.Spec.MatchResources.NamespaceSelector.MatchLabels["pahlevan.io/admission"])
}

// The derived objects must not collide with the static ones, or reconciling
// one would clobber the other.
func TestDerivedNamesDoNotCollideWithTheStaticPolicy(t *testing.T) {
	static := DesiredPolicy()
	assert.NotEqual(t, static.Name, DerivedPolicyName("p1"))
	assert.True(t, strings.HasPrefix(DerivedPolicyName("p1"), "pahlevan-derived-"))
	assert.NotEqual(t, DerivedPolicyName("a"), DerivedPolicyName("b"))
}

func BenchmarkCollapseBaseline(b *testing.B) {
	profiles := make([]policyv1alpha1.ContainerProfile, 0, 200)
	for i := 0; i < 200; i++ {
		profiles = append(profiles, learnedProfile("c", "p1", "Enforcing",
			"CHOWN", "NET_BIND_SERVICE", "SETUID"))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CollapseBaseline("p1", profiles)
	}
}

func BenchmarkDerivedPolicy(b *testing.B) {
	base := Baseline{Capabilities: []string{"CHOWN", "NET_BIND_SERVICE", "SETUID"}, Containers: 5, Enforcing: 5}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DerivedPolicy("p1", base)
	}
}
