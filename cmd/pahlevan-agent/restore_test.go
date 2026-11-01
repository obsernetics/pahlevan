package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func newRestoreFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, policyv1beta1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func containerProfile(name, node string, cgroupID int64, files, execs []string) *policyv1beta1.ContainerProfile {
	return &policyv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       policyv1beta1.ContainerProfileSpec{Node: node, CgroupID: cgroupID},
		Status: policyv1beta1.ContainerProfileStatus{
			LearnedFiles:       files,
			LearnedExecutables: execs,
		},
	}
}

// Only this node's profiles seed the kernel: another node's cgroup ids mean
// nothing here and would key allow-set entries onto whatever local cgroup
// happens to collide with them.
func TestRestoreAllowSetsFromProfilesScopesToTheNode(t *testing.T) {
	fc := newRestoreFakeClient(t,
		containerProfile("app-a", "node-a", 42, []string{"/etc/passwd"}, []string{"/bin/sh"}),
		containerProfile("app-b", "node-b", 43, []string{"/etc/hosts"}, nil),
	)
	m := &ebpf.Manager{}

	rep, err := restoreAllowSetsFromProfiles(context.Background(), fc, m, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Containers, "only the profile scoped to node-a should be restored")
}

// A profile with no CgroupID describes a container the agent never
// attributed, and seeding from it would key an allow-set entry onto cgroup 0,
// which belongs to no container at all.
func TestRestoreAllowSetsFromProfilesSkipsNoCgroup(t *testing.T) {
	fc := newRestoreFakeClient(t,
		containerProfile("no-cgroup", "node-a", 0, []string{"/etc/passwd"}, nil),
	)
	m := &ebpf.Manager{}

	rep, err := restoreAllowSetsFromProfiles(context.Background(), fc, m, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 0, rep.Containers)
}

// An empty node name is the single-node or non-DaemonSet case: every profile
// in the list applies, since there is no other node to scope away from.
func TestRestoreAllowSetsFromProfilesWithNoNodeFilter(t *testing.T) {
	fc := newRestoreFakeClient(t,
		containerProfile("app-a", "node-a", 42, []string{"/etc/passwd"}, nil),
		containerProfile("app-b", "node-b", 43, []string{"/etc/hosts"}, nil),
	)
	m := &ebpf.Manager{}

	rep, err := restoreAllowSetsFromProfiles(context.Background(), fc, m, "")
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Containers)
}

// Nothing to restore must report an empty, non-error result rather than a
// report that looks indistinguishable from "every write failed".
func TestRestoreAllowSetsFromProfilesWithNoProfiles(t *testing.T) {
	fc := newRestoreFakeClient(t)
	m := &ebpf.Manager{}

	rep, err := restoreAllowSetsFromProfiles(context.Background(), fc, m, "node-a")
	require.NoError(t, err)
	assert.Equal(t, ebpf.RestoreReport{}, rep)
}

// A reader that cannot list must surface its error rather than being read as
// "no profiles exist", which would silently restore nothing on a node that
// actually had state to recover.
func TestRestoreAllowSetsFromProfilesListError(t *testing.T) {
	// A client built on a scheme that never registered ContainerProfile
	// fails to List it the way a real API server outage would, rather than
	// reading as "no profiles exist".
	emptyScheme := runtime.NewScheme()
	unregistered := fake.NewClientBuilder().WithScheme(emptyScheme).Build()

	_, err := restoreAllowSetsFromProfiles(context.Background(), unregistered, &ebpf.Manager{}, "node-a")
	require.Error(t, err)
}
