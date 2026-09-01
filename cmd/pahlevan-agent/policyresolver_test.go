package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
)

func boolPtr(b bool) *bool { return &b }

func pod(name, ns, uid string, labels map[string]string, owners ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
			Labels: labels, OwnerReferences: owners,
		},
	}
}

func controllerRef(kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{Kind: kind, Name: name, Controller: boolPtr(true)}
}

// resolverWith builds a resolver with its caches populated directly, which is
// what Refresh would have produced.
func resolverWith(pods []*corev1.Pod, policies []policyv1alpha1.PahlevanPolicy, nsLabels map[string]map[string]string) *policyResolver {
	r := newPolicyResolver(nil, "node-1")
	for _, p := range pods {
		r.podsByUID[string(p.UID)] = p
	}
	r.policies = policies
	if nsLabels != nil {
		r.nsLabels = nsLabels
	}
	return r
}

func blockingPolicy(name string, sel policyv1alpha1.LabelSelector) policyv1alpha1.PahlevanPolicy {
	return policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: policyv1alpha1.PahlevanPolicySpec{
			Selector:       sel,
			LearningConfig: policyv1alpha1.LearningConfig{Duration: &metav1.Duration{Duration: time.Minute}},
			EnforcementConfig: policyv1alpha1.EnforcementConfig{
				Mode: policyv1alpha1.EnforcementModeBlocking,
			},
		},
	}
}

// A pod name is ephemeral; the workload is what an operator reasons about.
func TestOwnerWorkload(t *testing.T) {
	tests := []struct {
		name     string
		owners   []metav1.OwnerReference
		wantKind string
		wantName string
	}{
		{"no owner", nil, "", ""},
		{"daemonset", []metav1.OwnerReference{controllerRef("DaemonSet", "node-exporter")},
			"DaemonSet", "node-exporter"},
		{"statefulset", []metav1.OwnerReference{controllerRef("StatefulSet", "postgres")},
			"StatefulSet", "postgres"},
		{"job", []metav1.OwnerReference{controllerRef("Job", "migrate")}, "Job", "migrate"},
		// Nobody thinks in ReplicaSets, so the Deployment behind it is reported.
		{"replicaset unwinds to its deployment",
			[]metav1.OwnerReference{controllerRef("ReplicaSet", "nginx-6799fc88d8")},
			"Deployment", "nginx"},
		{"replicaset with a hyphenated deployment name",
			[]metav1.OwnerReference{controllerRef("ReplicaSet", "my-web-app-6799fc88d8")},
			"Deployment", "my-web-app"},
		// A ReplicaSet with no hash suffix is reported as itself rather than
		// guessed at.
		{"replicaset with no hash", []metav1.OwnerReference{controllerRef("ReplicaSet", "bare")},
			"ReplicaSet", "bare"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, name := ownerWorkload(pod("p", "ns", "uid", nil, tc.owners...))
			assert.Equal(t, tc.wantKind, kind)
			assert.Equal(t, tc.wantName, name)
		})
	}
}

// A non-controller owner reference is not the workload.
func TestOwnerWorkloadIgnoresNonControllerRefs(t *testing.T) {
	p := pod("p", "ns", "uid", nil, metav1.OwnerReference{Kind: "Deployment", Name: "x"})
	kind, name := ownerWorkload(p)
	assert.Empty(t, kind)
	assert.Empty(t, name)
}

func TestPodDetail(t *testing.T) {
	labels := map[string]string{"app": "nginx", "team": "platform"}
	r := resolverWith([]*corev1.Pod{
		pod("nginx-1", "prod", "uid-1", labels, controllerRef("ReplicaSet", "nginx-6799fc88d8")),
	}, nil, nil)

	d, ok := r.PodDetail("uid-1")
	require.True(t, ok)
	assert.Equal(t, "Deployment", d.WorkloadKind)
	assert.Equal(t, "nginx", d.WorkloadName)
	assert.Equal(t, labels, d.Labels)

	_, ok = r.PodDetail("missing")
	assert.False(t, ok)
}

// The labels are copied: the pod cache is replaced wholesale on every refresh,
// and an exported event outlives the pod object it came from.
func TestPodDetailCopiesLabels(t *testing.T) {
	labels := map[string]string{"app": "nginx"}
	r := resolverWith([]*corev1.Pod{pod("nginx-1", "prod", "uid-1", labels)}, nil, nil)

	d, ok := r.PodDetail("uid-1")
	require.True(t, ok)
	d.Labels["app"] = "tampered"
	assert.Equal(t, "nginx", labels["app"], "mutating the result must not reach the cache")
}

func TestResolveMatchesByLabel(t *testing.T) {
	r := resolverWith(
		[]*corev1.Pod{pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx"})},
		[]policyv1alpha1.PahlevanPolicy{blockingPolicy("p1", policyv1alpha1.LabelSelector{
			MatchLabels: map[string]string{"app": "nginx"},
		})}, nil)

	d, ok := r.Resolve(1, attribution.ContainerRef{PodUID: "uid-1"})
	require.True(t, ok)
	assert.Equal(t, "p1", d.PolicyName)
	assert.Equal(t, adaptive.ModeBlocking, d.Mode)
	assert.Equal(t, time.Minute, d.Window)
}

func TestResolveWithoutAPodUIDOrPod(t *testing.T) {
	r := resolverWith(nil, []policyv1alpha1.PahlevanPolicy{
		blockingPolicy("p1", policyv1alpha1.LabelSelector{}),
	}, nil)

	_, ok := r.Resolve(1, attribution.ContainerRef{})
	assert.False(t, ok, "no pod uid means nothing to govern")

	_, ok = r.Resolve(1, attribution.ContainerRef{PodUID: "unknown"})
	assert.False(t, ok, "a pod the node has never seen is not governed")
}

// namespaceSelector was accepted by the CRD and ignored, so a policy scoped to
// one namespace silently governed the whole cluster.
func TestNamespaceSelectorScopesThePolicy(t *testing.T) {
	pods := []*corev1.Pod{
		pod("nginx-prod", "prod", "uid-prod", map[string]string{"app": "nginx"}),
		pod("nginx-dev", "dev", "uid-dev", map[string]string{"app": "nginx"}),
	}
	policy := blockingPolicy("p1", policyv1alpha1.LabelSelector{
		MatchLabels: map[string]string{"app": "nginx"},
		NamespaceSelector: &policyv1alpha1.NamespaceSelector{
			MatchLabels: map[string]string{"env": "production"},
		},
	})
	r := resolverWith(pods, []policyv1alpha1.PahlevanPolicy{policy}, map[string]map[string]string{
		"prod": {"env": "production"},
		"dev":  {"env": "development"},
	})

	_, ok := r.Resolve(1, attribution.ContainerRef{PodUID: "uid-prod"})
	assert.True(t, ok, "the production pod is in scope")

	_, ok = r.Resolve(2, attribution.ContainerRef{PodUID: "uid-dev"})
	assert.False(t, ok, "the dev pod must not be governed by a production-scoped policy")
}

// Kubernetes stamps every namespace with kubernetes.io/metadata.name, so
// selecting by name works through the label selector.
func TestNamespaceSelectorByName(t *testing.T) {
	policy := blockingPolicy("p1", policyv1alpha1.LabelSelector{
		NamespaceSelector: &policyv1alpha1.NamespaceSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
	})
	r := resolverWith(
		[]*corev1.Pod{pod("nginx", "prod", "uid-1", nil)},
		[]policyv1alpha1.PahlevanPolicy{policy},
		map[string]map[string]string{"prod": {"kubernetes.io/metadata.name": "prod"}})

	_, ok := r.Resolve(1, attribution.ContainerRef{PodUID: "uid-1"})
	assert.True(t, ok)
}

// An unknown namespace must fail closed. Matching a scoped policy against a
// namespace the agent cannot see would widen it silently, which is the failure
// this field exists to prevent.
func TestNamespaceSelectorFailsClosedOnAnUnknownNamespace(t *testing.T) {
	policy := blockingPolicy("p1", policyv1alpha1.LabelSelector{
		NamespaceSelector: &policyv1alpha1.NamespaceSelector{
			MatchLabels: map[string]string{"env": "production"},
		},
	})
	// The namespace cache is empty, as it would be if listing namespaces was
	// denied by RBAC.
	r := resolverWith([]*corev1.Pod{pod("nginx", "prod", "uid-1", nil)},
		[]policyv1alpha1.PahlevanPolicy{policy}, nil)

	_, ok := r.Resolve(1, attribution.ContainerRef{PodUID: "uid-1"})
	assert.False(t, ok, "an unresolvable namespace must not match a scoped policy")
}

func TestNamespaceSelectorMatchExpressions(t *testing.T) {
	policy := blockingPolicy("p1", policyv1alpha1.LabelSelector{
		NamespaceSelector: &policyv1alpha1.NamespaceSelector{
			MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{
				Key: "env", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"production", "staging"},
			}},
		},
	})
	r := resolverWith(
		[]*corev1.Pod{
			pod("a", "prod", "uid-a", nil),
			pod("b", "dev", "uid-b", nil),
		},
		[]policyv1alpha1.PahlevanPolicy{policy},
		map[string]map[string]string{"prod": {"env": "production"}, "dev": {"env": "development"}})

	_, ok := r.Resolve(1, attribution.ContainerRef{PodUID: "uid-a"})
	assert.True(t, ok)
	_, ok = r.Resolve(2, attribution.ContainerRef{PodUID: "uid-b"})
	assert.False(t, ok)
}

func TestSelectorMatches(t *testing.T) {
	r := newPolicyResolver(nil, "node-1")
	p := pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx", "tier": "frontend"})

	assert.True(t, r.selectorMatches(policyv1alpha1.LabelSelector{}, p), "empty selector matches everything")

	assert.True(t, r.selectorMatches(policyv1alpha1.LabelSelector{
		MatchLabels: map[string]string{"app": "nginx"},
	}, p))
	assert.False(t, r.selectorMatches(policyv1alpha1.LabelSelector{
		MatchLabels: map[string]string{"app": "apache"},
	}, p), "a mismatched matchLabels value excludes the pod")

	assert.True(t, r.selectorMatches(policyv1alpha1.LabelSelector{
		MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
			{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"frontend"}},
		},
	}, p))
	assert.False(t, r.selectorMatches(policyv1alpha1.LabelSelector{
		MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
			{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"backend"}},
		},
	}, p), "a non-matching matchExpressions requirement excludes the pod")
}

func TestRequirementMatches(t *testing.T) {
	labels := map[string]string{"tier": "frontend"}
	req := func(op policyv1alpha1.LabelSelectorOperator, values ...string) policyv1alpha1.LabelSelectorRequirement {
		return policyv1alpha1.LabelSelectorRequirement{Key: "tier", Operator: op, Values: values}
	}
	assert.True(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpIn, "frontend"), labels))
	assert.False(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpIn, "backend"), labels))
	assert.False(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpNotIn, "frontend"), labels))
	assert.True(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpNotIn, "backend"), labels))
	assert.True(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpExists), labels))
	assert.False(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpDoesNotExist), labels))
	// An unrecognized operator must not match, rather than matching everything.
	assert.False(t, requirementMatches(req("Sideways", "frontend"), labels))

	// An absent key.
	assert.False(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpIn, "x"), nil))
	assert.True(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpNotIn, "x"), nil))
	assert.True(t, requirementMatches(req(policyv1alpha1.LabelSelectorOpDoesNotExist), nil))
}

// Translation warnings are logged once per distinct set, not on every reconcile,
// or an unrepresentable rule would bury the log it is trying to surface.
func TestWarningsAreDeduplicated(t *testing.T) {
	r := newPolicyResolver(nil, "node-1")
	warnings := []string{"first", "second"}

	r.noteWarnings("p1", warnings)
	r.noteWarnings("p1", warnings)

	count := 0
	r.warned.Range(func(any, any) bool { count++; return true })
	assert.Equal(t, 1, count, "the same warning set is remembered once")

	r.noteWarnings("p2", warnings)
	count = 0
	r.warned.Range(func(any, any) bool { count++; return true })
	assert.Equal(t, 2, count, "a different policy warns separately")

	// No warnings is a no-op.
	r.noteWarnings("p3", nil)
	count = 0
	r.warned.Range(func(any, any) bool { count++; return true })
	assert.Equal(t, 2, count)
}

func BenchmarkResolve(b *testing.B) {
	r := resolverWith(
		[]*corev1.Pod{pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx"},
			controllerRef("ReplicaSet", "nginx-6799fc88d8"))},
		[]policyv1alpha1.PahlevanPolicy{blockingPolicy("p1", policyv1alpha1.LabelSelector{
			MatchLabels: map[string]string{"app": "nginx"},
		})}, nil)
	ref := attribution.ContainerRef{PodUID: "uid-1"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Resolve(1, ref)
	}
}

func BenchmarkPodDetail(b *testing.B) {
	r := resolverWith([]*corev1.Pod{pod("nginx-1", "prod", "uid-1",
		map[string]string{"app": "nginx", "team": "platform", "tier": "frontend"},
		controllerRef("ReplicaSet", "nginx-6799fc88d8"))}, nil, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.PodDetail("uid-1")
	}
}
