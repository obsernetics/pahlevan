package profilesync

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, policyv1alpha1.AddToScheme(s))
	return s
}

func profile(ns, name, podName, policyRef string, syscalls ...int64) *policyv1alpha1.ContainerProfile {
	return &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       policyv1alpha1.ContainerProfileSpec{PodName: podName, PolicyRef: policyRef},
		Status:     policyv1alpha1.ContainerProfileStatus{LearnedSyscalls: syscalls},
	}
}

func syncerWith(t *testing.T, objs ...client.Object) (*Syncer, string) {
	t.Helper()
	dir := t.TempDir()
	return &Syncer{
		Client: fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(objs...).Build(),
		Log:    logr.Discard(),
		Dir:    dir,
	}, dir
}

// knownSyscall returns a real number for this architecture, so the generated
// profile actually names something.
func knownSyscall(t *testing.T, name string) int64 {
	t.Helper()
	for nr, n := range seccomp.SyscallName {
		if n == name {
			return int64(nr)
		}
	}
	t.Fatalf("%s is not in this architecture's syscall table", name)
	return 0
}

// The whole point: a node that never ran the container still ends up with its
// profile, because a rollout can put the pod anywhere.
func TestSyncMaterialisesEveryProfile(t *testing.T) {
	openat := knownSyscall(t, "openat")
	s, dir := syncerWith(t,
		profile("prod", "cp-a", "nginx-1", "", openat),
		profile("dev", "cp-b", "api-1", "", openat),
	)

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, res.Written)
	assert.Zero(t, res.Errors)

	for _, want := range []string{"pahlevan-prod-nginx-1.json", "pahlevan-dev-api-1.json"} {
		data, err := os.ReadFile(filepath.Join(dir, want))
		require.NoError(t, err, "%s should have been written", want)

		var decoded struct {
			DefaultAction string `json:"defaultAction"`
			Syscalls      []struct {
				Names []string `json:"names"`
			} `json:"syscalls"`
		}
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, "SCMP_ACT_ERRNO", decoded.DefaultAction, "profiles must be default-deny")
		require.Len(t, decoded.Syscalls, 1)
		assert.Contains(t, decoded.Syscalls[0].Names, "openat")
	}
}

// A container that has learned nothing must not get a profile. An empty
// default-deny profile is one that kills the workload on the next rollout.
func TestSyncSkipsUnlearnedProfiles(t *testing.T) {
	s, dir := syncerWith(t, profile("prod", "cp-a", "nginx-1", ""))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Skipped)
	assert.Zero(t, res.Written)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing should be written for a container with no learned set")
}

// The policy's syscall lists are part of the enforced artifact, so a node
// regenerating remotely has to apply them too or it produces a different file
// from the one the owning node reported.
func TestSyncAppliesThePolicySyscallLists(t *testing.T) {
	openat := knownSyscall(t, "openat")
	pol := &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "prod"},
		Spec: policyv1alpha1.PahlevanPolicySpec{
			SyscallPolicy: &policyv1alpha1.SyscallPolicy{
				AllowedSyscalls: []string{"ptrace"},
				DeniedSyscalls:  []string{"futex"},
			},
		},
	}
	s, dir := syncerWith(t, pol, profile("prod", "cp-a", "nginx-1", "p1", openat))

	_, err := s.Sync(context.Background())
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	body := string(data)
	assert.Contains(t, body, `"ptrace"`, "a policy-allowed syscall must be in the file")
	assert.NotContains(t, body, `"futex"`, "a policy denial must win, baseline or not")
	assert.Contains(t, body, `"openat"`, "the learned set must still be there")
}

// A profile the cluster has forgotten must not linger: a workload can go on
// referencing it, so the node would keep enforcing a baseline nothing tracks.
func TestSyncPrunesStaleProfiles(t *testing.T) {
	openat := knownSyscall(t, "openat")
	s, dir := syncerWith(t, profile("prod", "cp-a", "nginx-1", "", openat))

	stale := filepath.Join(dir, "pahlevan-prod-deleted.json")
	require.NoError(t, os.WriteFile(stale, []byte("{}"), 0o644))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Removed)

	_, err = os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "the stale profile should be gone")
	_, err = os.Stat(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	assert.NoError(t, err, "the live profile must survive the prune")
}

// The directory may be shared. Deleting a file somebody else put there is worse
// than leaving a stale one, so only our own prefix is pruned.
func TestSyncLeavesForeignFilesAlone(t *testing.T) {
	s, dir := syncerWith(t)
	foreign := filepath.Join(dir, "someone-elses.json")
	require.NoError(t, os.WriteFile(foreign, []byte("{}"), 0o644))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Zero(t, res.Removed)

	_, err = os.Stat(foreign)
	assert.NoError(t, err, "a file we do not own must not be deleted")
}

// The sync runs on a timer. Rewriting an unchanged profile every tick would
// churn the disk and briefly truncate a file the kubelet may be reading during
// a pod start.
func TestSyncDoesNotRewriteUnchangedProfiles(t *testing.T) {
	openat := knownSyscall(t, "openat")
	s, dir := syncerWith(t, profile("prod", "cp-a", "nginx-1", "", openat))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, res.Written)

	before, err := os.Stat(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)

	res, err = s.Sync(context.Background())
	require.NoError(t, err)
	assert.Zero(t, res.Written, "an unchanged profile must not be rewritten")

	after, err := os.Stat(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime(), "the file should not have been touched")
}

// A changed learned set must reach the file, or the node keeps enforcing a
// baseline the cluster has moved on from.
func TestSyncRewritesWhenTheLearnedSetChanges(t *testing.T) {
	openat := knownSyscall(t, "openat")
	read := knownSyscall(t, "read")

	p := profile("prod", "cp-a", "nginx-1", "", openat)
	s, dir := syncerWith(t, p)
	_, err := s.Sync(context.Background())
	require.NoError(t, err)

	first, err := os.ReadFile(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(first), `"read"`)

	p.Status.LearnedSyscalls = []int64{openat, read}
	require.NoError(t, s.Client.Update(context.Background(), p))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Written)

	second, err := os.ReadFile(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	assert.Contains(t, string(second), `"read"`)
}

// Regeneration must be deterministic, or two nodes would hold different
// profiles for the same container and a rollout would behave differently
// depending on where it landed.
func TestSyncIsDeterministicAcrossNodes(t *testing.T) {
	openat := knownSyscall(t, "openat")
	objs := []client.Object{profile("prod", "cp-a", "nginx-1", "", openat)}

	nodeA, dirA := syncerWith(t, objs...)
	nodeB, dirB := syncerWith(t, objs...)
	_, err := nodeA.Sync(context.Background())
	require.NoError(t, err)
	_, err = nodeB.Sync(context.Background())
	require.NoError(t, err)

	a, err := os.ReadFile(filepath.Join(dirA, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(dirB, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b), "two nodes must produce byte-identical profiles")
}

// A negative syscall number cannot be a real one and must not be fed to the
// generator as a huge unsigned value.
func TestSyncIgnoresNegativeSyscallNumbers(t *testing.T) {
	openat := knownSyscall(t, "openat")
	s, dir := syncerWith(t, profile("prod", "cp-a", "nginx-1", "", -1, openat))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Zero(t, res.Errors)

	data, err := os.ReadFile(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `"openat"`)
}

// An empty Dir disables the syncer rather than writing to the process's working
// directory.
func TestSyncDisabledWithoutADirectory(t *testing.T) {
	s := &Syncer{Client: fake.NewClientBuilder().WithScheme(scheme(t)).Build(), Log: logr.Discard()}
	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, Result{}, res)
}

// A missing policy must not stop the profile being written: the learned set is
// still the best baseline available, and no file at all means a pod that will
// not start.
func TestSyncToleratesAMissingPolicy(t *testing.T) {
	openat := knownSyscall(t, "openat")
	s, dir := syncerWith(t, profile("prod", "cp-a", "nginx-1", "gone", openat))

	res, err := s.Sync(context.Background())
	require.NoError(t, err)
	assert.Zero(t, res.Errors)
	assert.Equal(t, 1, res.Written)

	_, err = os.Stat(filepath.Join(dir, "pahlevan-prod-nginx-1.json"))
	assert.NoError(t, err)
}

func TestProfileFileName(t *testing.T) {
	assert.Equal(t, "pahlevan-prod-nginx-1.json",
		ProfileFileName(profile("prod", "cp-a", "nginx-1", "")))
	// Falls back to the object name when the pod name is unknown, so two
	// containers never collide on one file.
	assert.Equal(t, "pahlevan-prod-cp-a.json",
		ProfileFileName(profile("prod", "cp-a", "", "")))
}

func BenchmarkSync(b *testing.B) {
	s := runtime.NewScheme()
	_ = policyv1alpha1.AddToScheme(s)
	objs := make([]client.Object, 0, 200)
	for i := 0; i < 200; i++ {
		objs = append(objs, profile("prod", "cp-"+string(rune('a'+i%26))+string(rune('a'+i/26)),
			"pod-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "", 0, 1, 2))
	}
	sy := &Syncer{
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build(),
		Log:    logr.Discard(),
		Dir:    b.TempDir(),
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sy.Sync(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
