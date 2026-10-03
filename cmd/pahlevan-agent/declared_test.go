package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
)

// declaringPolicy is a blocking policy that declares the operations a nightly
// job needs and the learning window will never see.
func declaringPolicy(name string, sel policyv1beta1.WorkloadSelector) policyv1beta1.PahlevanPolicy {
	p := blockingPolicy(name, sel)
	p.Spec.LearningConfig.ExpectedBehavior = &policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db", Write: true},
			{Path: "/etc/ssl/renewed.pem"},
		},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []string{"CAP_DAC_OVERRIDE"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
		},
	}
	return p
}

// The resolver is what joins the two halves of a declaration: the entries it
// seeds into the kernel allow-set, and the entries the profile reports as
// declared. Before this, the reporting half had no caller at all - the lists
// were rendered by a method nothing called, onto an API version the agent does
// not persist - so a declaration reached the kernel and nothing on a real
// cluster ever said so.
func TestDeclaredForReportsWhatWasSeededIntoTheKernel(t *testing.T) {
	r := resolverWith(
		[]*corev1.Pod{pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx"})},
		[]policyv1beta1.PahlevanPolicy{declaringPolicy("p1", policyv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "nginx"},
		})}, nil)

	ref := attribution.ContainerRef{PodUID: "uid-1", ContainerID: "fedcba9876543210"}
	d, ok := r.Resolve(1, ref)
	require.True(t, ok)

	// Seeded into the allow-set.
	assert.Contains(t, d.Overrides.AllowedFiles, "/var/lib/app/nightly.db")
	assert.Contains(t, d.Overrides.AllowedWriteFiles, "/var/lib/app/nightly.db")
	assert.Contains(t, d.Overrides.AllowedExecs, "/usr/bin/pg_dump")

	// And reported as declared, in the one rendering that produced them.
	declared, ok := r.DeclaredFor(ref.ContainerID)
	require.True(t, ok, "a container whose policy declared something must report it")
	assert.Equal(t, []string{
		"/etc/ssl/renewed.pem",
		"/var/lib/app/nightly.db (write)",
	}, declared.Files)
	assert.Equal(t, []string{"10.43.12.7:5432"}, declared.Destinations)
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, declared.Executables)
	assert.Equal(t, []string{"DAC_OVERRIDE"}, declared.Capabilities)
}

func TestDeclaredForSaysNothingAboutAContainerNothingDeclaredFor(t *testing.T) {
	r := resolverWith(
		[]*corev1.Pod{pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx"})},
		[]policyv1beta1.PahlevanPolicy{blockingPolicy("p1", policyv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "nginx"},
		})}, nil)

	ref := attribution.ContainerRef{PodUID: "uid-1", ContainerID: "0123456789abcdef"}
	_, ok := r.Resolve(1, ref)
	require.True(t, ok)

	declared, ok := r.DeclaredFor(ref.ContainerID)
	assert.False(t, ok, "a policy with no expectedBehavior declares nothing")
	assert.True(t, declared.Empty())

	_, ok = r.DeclaredFor("a-container-nobody-resolved")
	assert.False(t, ok)
}

// The agent resolver is the production DeclarationReporter. Asserting it here
// as well as in the source keeps the failure legible: a resolver that stops
// reporting is a cluster whose profiles silently lose the declared lists.
func TestTheAgentResolverIsADeclarationReporter(t *testing.T) {
	var reporter adaptive.DeclarationReporter = newPolicyResolver(nil, "node-1")
	declared, ok := reporter.DeclaredFor("nothing")
	assert.False(t, ok)
	assert.True(t, declared.Empty())
}

func BenchmarkDeclaredFor(b *testing.B) {
	r := resolverWith(
		[]*corev1.Pod{pod("nginx-1", "prod", "uid-1", map[string]string{"app": "nginx"})},
		[]policyv1beta1.PahlevanPolicy{declaringPolicy("p1", policyv1beta1.WorkloadSelector{
			MatchLabels: map[string]string{"app": "nginx"},
		})}, nil)
	ref := attribution.ContainerRef{PodUID: "uid-1", ContainerID: "fedcba9876543210"}
	if _, ok := r.Resolve(1, ref); !ok {
		b.Fatal("the fixture is not governed, so this benchmark measures the miss path")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := r.DeclaredFor(ref.ContainerID); !ok {
			b.Fatal("miss")
		}
	}
}
