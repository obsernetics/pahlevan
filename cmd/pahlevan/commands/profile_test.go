package commands

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/obsernetics/pahlevan/pkg/cli"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func containerProfileWithSeccomp(name, ns string, ref *policyv1alpha1.SeccompProfileRef) *policyv1alpha1.ContainerProfile {
	return &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       policyv1alpha1.ContainerProfileSpec{PodName: "nginx-7c9b4", PolicyRef: "p1"},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:   "Enforcing",
			Seccomp: ref,
		},
	}
}

func fullSeccompRef() *policyv1alpha1.SeccompProfileRef {
	return &policyv1alpha1.SeccompProfileRef{
		LocalhostProfile: "pahlevan/pahlevan-uid-1.json",
		Path:             "/var/lib/kubelet/seccomp/pahlevan/pahlevan-uid-1.json",
		Node:             "node-1",
		AllowedSyscalls:  50,
		TotalSyscalls:    373,
	}
}

func TestProfileListShowsGeneratedProfiles(t *testing.T) {
	installFakeClients(t,
		containerProfileWithSeccomp("cp-1", "default", fullSeccompRef()),
		// No generated profile: must not appear.
		containerProfileWithSeccomp("cp-2", "default", nil),
	)

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "cp-1")
	assert.NotContains(t, got, "cp-2", "a container with no generated profile has nothing to list")
	assert.Contains(t, got, "node-1")
	assert.Contains(t, got, "50/373")
	// 1 - 50/373 = 86.6%
	assert.Contains(t, got, "86.6%", "the reduction is the number that justifies applying the profile")
	assert.Contains(t, got, "pahlevan/pahlevan-uid-1.json")
}

// An empty list must say why it is empty; "No resources found" sends people
// looking in the wrong place.
func TestProfileListExplainsAnEmptyResult(t *testing.T) {
	installFakeClients(t, containerProfileWithSeccomp("cp-2", "default", nil))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "No generated seccomp profiles")
	assert.Contains(t, got, "--seccomp-dir", "the message should name the flag that enables emission")
}

// A profile outside the kubelet's seccomp root cannot be referenced. Printing
// a blank column would read as "no profile"; it is labeled instead.
func TestProfileListLabelsAnUnreferenceableProfile(t *testing.T) {
	ref := fullSeccompRef()
	ref.LocalhostProfile = ""
	ref.Path = "/tmp/elsewhere/pahlevan-uid-1.json"
	installFakeClients(t, containerProfileWithSeccomp("cp-1", "default", ref))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "outside kubelet seccomp root")
}

func TestProfileGetOutputsTheReference(t *testing.T) {
	installFakeClients(t, containerProfileWithSeccomp("cp-1", "default", fullSeccompRef()))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"get", "cp-1", "-o", "json"})
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "pahlevan/pahlevan-uid-1.json")
	assert.Contains(t, got, "node-1")
}

func TestProfileGetFailsLoudlyWithoutAProfile(t *testing.T) {
	installFakeClients(t, containerProfileWithSeccomp("cp-2", "default", nil))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"get", "cp-2"})
	err := cmd.Execute()
	require.Error(t, err, "asking for a profile that does not exist must fail, not print nothing")
	assert.Contains(t, err.Error(), "--seccomp-dir")
}

// The patch is the point of the command: it must be the exact change a user
// applies, and it must be valid to apply.
func TestProfilePatchRendersAnApplicableChange(t *testing.T) {
	installFakeClients(t, containerProfileWithSeccomp("cp-1", "default", fullSeccompRef()))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"patch", "cp-1"})
	require.NoError(t, cmd.Execute())

	got := out.String()

	// The commentary an operator needs before applying it.
	assert.Contains(t, got, "node-1")
	assert.Contains(t, got, "50 of 373")
	assert.Contains(t, got, "copy it to every node")
	assert.Contains(t, got, "kubectl -n default patch deployment")

	// Strip the leading comments and parse what is left: the patch has to be
	// real YAML with the right shape, not a formatted string that looks right.
	var body []string
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			body = append(body, line)
		}
	}
	var patch map[string]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(strings.Join(body, "\n")), &patch))

	spec := patch["spec"].(map[string]interface{})
	tmpl := spec["template"].(map[string]interface{})
	podSpec := tmpl["spec"].(map[string]interface{})
	secCtx := podSpec["securityContext"].(map[string]interface{})
	seccompProfile := secCtx["seccompProfile"].(map[string]interface{})

	assert.Equal(t, "Localhost", seccompProfile["type"])
	assert.Equal(t, "pahlevan/pahlevan-uid-1.json", seccompProfile["localhostProfile"])
}

// A profile the kubelet could not resolve must refuse to render a patch rather
// than emit one that breaks the workload on rollout.
func TestProfilePatchRefusesAnUnreferenceableProfile(t *testing.T) {
	ref := fullSeccompRef()
	ref.LocalhostProfile = ""
	installFakeClients(t, containerProfileWithSeccomp("cp-1", "default", ref))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"patch", "cp-1"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside the kubelet")
	assert.Contains(t, err.Error(), "--seccomp-root", "the error should say how to fix it")
}

// A profile narrower than what was observed is worth saying out loud, because
// applying it will deny syscalls the workload actually made.
func TestProfilePatchWarnsAboutSkippedSyscalls(t *testing.T) {
	ref := fullSeccompRef()
	ref.SkippedUnknown = 3
	installFakeClients(t, containerProfileWithSeccomp("cp-1", "default", ref))

	cmd := NewProfileCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"patch", "cp-1"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "3 observed syscall numbers have no name")
}

func TestBuildSeccompPatch(t *testing.T) {
	p := BuildSeccompPatch("pahlevan/x.json")
	assert.Equal(t, "Localhost", p.Spec.Template.Spec.SecurityContext.SeccompProfile.Type)
	assert.Equal(t, "pahlevan/x.json", p.Spec.Template.Spec.SecurityContext.SeccompProfile.LocalhostProfile)
}

func BenchmarkCollectProfiles(b *testing.B) {
	scheme := cli.GetScheme()
	objs := make([]crclient.Object, 0, 500)
	for i := 0; i < 500; i++ {
		objs = append(objs, containerProfileWithSeccomp(
			fmt.Sprintf("cp-%03d", i), "default", fullSeccompRef()))
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := collectProfiles(ctx, fc, "default", false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildSeccompPatch(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildSeccompPatch("pahlevan/pahlevan-uid-1.json")
	}
}
