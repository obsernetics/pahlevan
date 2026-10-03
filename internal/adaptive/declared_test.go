package adaptive

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// declaringPolicies is a PolicyResolver that also reports declarations, which
// is what the agent's resolver does. The declaration is keyed by container ID,
// the same way the real one keys it.
type declaringPolicies struct {
	fakePoliciesMeta
	byContainer map[string]Declared
	asked       []string
}

func (p *declaringPolicies) DeclaredFor(containerID string) (Declared, bool) {
	p.asked = append(p.asked, containerID)
	d, ok := p.byContainer[containerID]
	return d, ok
}

func sampleDeclared() Declared {
	return Declared{
		Files:        []string{"/etc/ssl/renewed.pem", "/var/lib/app/nightly.db (write)"},
		Destinations: []string{"10.43.12.7:5432"},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []string{"DAC_OVERRIDE"},
	}
}

func TestDeclaredIsEmptyUntilSomethingIsDeclared(t *testing.T) {
	assert.True(t, Declared{}.Empty())
	assert.False(t, Declared{Files: []string{"/x"}}.Empty())
	assert.False(t, Declared{Destinations: []string{"10.0.0.1:1"}}.Empty())
	assert.False(t, Declared{Executables: []string{"/x"}}.Empty())
	assert.False(t, Declared{Capabilities: []string{"CHOWN"}}.Empty())
}

func TestReportIntoWritesTheFourFieldsAndLeavesTheLearnedOnes(t *testing.T) {
	status := &policyv1alpha1.ContainerProfileStatus{
		LearnedFiles:               []string{"/etc/nginx/nginx.conf"},
		LearnedExecutables:         []string{"/usr/sbin/nginx"},
		LearnedCapabilities:        []string{"NET_BIND_SERVICE"},
		LearnedNetworkDestinations: []string{"10.0.0.1:443"},
	}
	sampleDeclared().ReportInto(status)

	assert.Equal(t, []string{"/etc/ssl/renewed.pem", "/var/lib/app/nightly.db (write)"},
		status.DeclaredFiles)
	assert.Equal(t, []string{"10.43.12.7:5432"}, status.DeclaredNetworkDestinations)
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, status.DeclaredExecutables)
	assert.Equal(t, []string{"DAC_OVERRIDE"}, status.DeclaredCapabilities)

	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, status.LearnedFiles,
		"an assertion must never be written into the record of what was observed")
	assert.Equal(t, []string{"/usr/sbin/nginx"}, status.LearnedExecutables)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, status.LearnedCapabilities)
	assert.Equal(t, []string{"10.0.0.1:443"}, status.LearnedNetworkDestinations)
}

func TestReportIntoClearsWhatAnEmptiedDeclarationNoLongerCovers(t *testing.T) {
	// A profile must not report an entry the policy no longer declares and the
	// kernel no longer has seeded.
	status := &policyv1alpha1.ContainerProfileStatus{
		DeclaredFiles:               []string{"/gone"},
		DeclaredNetworkDestinations: []string{"10.0.0.1:1"},
		DeclaredExecutables:         []string{"/gone"},
		DeclaredCapabilities:        []string{"CHOWN"},
		LearnedFiles:                []string{"/etc/nginx/nginx.conf"},
	}
	Declared{}.ReportInto(status)

	assert.Nil(t, status.DeclaredFiles)
	assert.Nil(t, status.DeclaredNetworkDestinations)
	assert.Nil(t, status.DeclaredExecutables)
	assert.Nil(t, status.DeclaredCapabilities)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, status.LearnedFiles,
		"clearing declarations must not touch what was learned")
}

func TestReportIntoIsIdempotent(t *testing.T) {
	// Otherwise every sync would be an API write and a profile's
	// resourceVersion would climb forever on a policy nobody touched.
	first := &policyv1alpha1.ContainerProfileStatus{}
	second := &policyv1alpha1.ContainerProfileStatus{}
	sampleDeclared().ReportInto(first)
	sampleDeclared().ReportInto(second)
	assert.Equal(t, first, second)
}

func TestReportIntoDoesNotShareItsSlices(t *testing.T) {
	// The declaration is held per container and reported on every sync. A
	// status that aliased it would let an API client's mutation reach back into
	// what the agent believes it declared.
	d := sampleDeclared()
	status := &policyv1alpha1.ContainerProfileStatus{}
	d.ReportInto(status)
	status.DeclaredFiles[0] = "/mutated"
	assert.Equal(t, "/etc/ssl/renewed.pem", d.Files[0])
}

func TestReportIntoToleratesANilStatus(t *testing.T) {
	assert.NotPanics(t, func() { sampleDeclared().ReportInto(nil) })
}

// TestPersistProfileReportsWhatThePolicyDeclared is the guard on the whole
// defect. The declared* fields were written by a method nothing called, onto a
// version the agent does not persist, so on a real cluster they were always
// empty while the API, its comments and its conversion notes all described
// them at length.
func TestPersistProfileReportsWhatThePolicyDeclared(t *testing.T) {
	cl := newTestScheme(t).Build()
	resolver := &declaringPolicies{
		fakePoliciesMeta: fakePoliciesMeta{blocking: true, ok: true, ns: "prod", name: "web-abc", metaOK: true},
		byContainer:      map[string]Declared{"fedcba9876543210": sampleDeclared()},
	}
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, resolver)
	c.Client = cl
	c.Node = "node-1"

	c.mu.Lock()
	st := c.track(92)
	st.ref.PodUID = "pod-uid-declared"
	st.ref.ContainerID = "fedcba9876543210"
	st.phase = PhaseEnforcing
	st.enforcingSince = time.Unix(1700000500, 0)
	st.files = map[string]struct{}{"/etc/nginx/nginx.conf": {}}
	c.mu.Unlock()

	c.persistProfile(st)

	cp := &policyv1alpha1.ContainerProfile{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: profileName(st.ref), Namespace: "prod"}, cp))

	assert.Equal(t, []string{"/etc/ssl/renewed.pem", "/var/lib/app/nightly.db (write)"},
		cp.Status.DeclaredFiles,
		"a declaration that reaches the kernel has to reach the profile too")
	assert.Equal(t, []string{"10.43.12.7:5432"}, cp.Status.DeclaredNetworkDestinations)
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, cp.Status.DeclaredExecutables)
	assert.Equal(t, []string{"DAC_OVERRIDE"}, cp.Status.DeclaredCapabilities)

	// And the learned list still says only what was observed.
	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, cp.Status.LearnedFiles)
	assert.Equal(t, []string{"fedcba9876543210"}, resolver.asked,
		"the declaration is looked up by container, because that is what a policy governs")
}

// A resolver that declares nothing for this container leaves the fields unset,
// rather than writing an empty array into every profile in the cluster.
func TestPersistProfileLeavesTheDeclaredFieldsUnsetWhenNothingIsDeclared(t *testing.T) {
	cl := newTestScheme(t).Build()
	resolver := &declaringPolicies{
		fakePoliciesMeta: fakePoliciesMeta{blocking: true, ok: true, ns: "prod", name: "web-abc", metaOK: true},
		byContainer:      map[string]Declared{"other-container": sampleDeclared()},
	}
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, resolver)
	c.Client = cl

	c.mu.Lock()
	st := c.track(93)
	st.ref.PodUID = "pod-uid-undeclared"
	st.ref.ContainerID = "0123456789abcdef"
	c.mu.Unlock()

	c.persistProfile(st)

	cp := &policyv1alpha1.ContainerProfile{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: profileName(st.ref), Namespace: "prod"}, cp))
	assert.Nil(t, cp.Status.DeclaredFiles)
	assert.Nil(t, cp.Status.DeclaredNetworkDestinations)
	assert.Nil(t, cp.Status.DeclaredExecutables)
	assert.Nil(t, cp.Status.DeclaredCapabilities)
}

// A resolver that cannot report declarations at all is the ordinary case for a
// fake and has to keep working, because DeclarationReporter is asserted for
// rather than required.
func TestPersistProfileWorksWithAResolverThatCannotReportDeclarations(t *testing.T) {
	cl := newTestScheme(t).Build()
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePoliciesMeta{ok: true, ns: "prod", name: "web-abc", metaOK: true})
	c.Client = cl

	c.mu.Lock()
	st := c.track(94)
	st.ref.PodUID = "pod-uid-no-reporter"
	st.ref.ContainerID = "abcdef0123456789"
	c.mu.Unlock()

	require.NotPanics(t, func() { c.persistProfile(st) })

	cp := &policyv1alpha1.ContainerProfile{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: profileName(st.ref), Namespace: "prod"}, cp))
	assert.Nil(t, cp.Status.DeclaredFiles)
}

// Reporting is on the status-sync path, which runs per container per interval,
// so it is worth knowing what the write costs on top of the rendering.
func BenchmarkDeclaredReportInto(b *testing.B) {
	d := sampleDeclared()
	status := &policyv1alpha1.ContainerProfileStatus{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReportInto(status)
	}
}

// The empty case is the common one: most containers are governed by a policy
// that declares nothing, and it must not allocate four slices to say so.
func BenchmarkDeclaredReportIntoEmpty(b *testing.B) {
	var d Declared
	status := &policyv1alpha1.ContainerProfileStatus{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReportInto(status)
	}
}

func BenchmarkDeclaredEmpty(b *testing.B) {
	d := sampleDeclared()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d.Empty() {
			b.Fatal("the fixture declares something")
		}
	}
}
