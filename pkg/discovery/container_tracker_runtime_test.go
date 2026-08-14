package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestBuildRuntimeInfo_RuntimeDetection(t *testing.T) {
	ct := &ContainerTracker{}

	tests := []struct {
		fullID          string
		expectedRuntime string
		cgroupContains  string
	}{
		{"containerd://abcdef0123456789abcdef0123456789", "containerd", "kubepods"},
		{"docker://abcdef0123456789abcdef0123456789", "docker", "docker"},
		{"cri-o://abcdef0123456789abcdef0123456789", "cri-o", "kubepods"},
		{"weird://xyz", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.expectedRuntime, func(t *testing.T) {
			id := "abcdef0123456789abcdef0123456789"
			info := ct.buildRuntimeInfo(id, &corev1.ContainerStatus{ContainerID: tt.fullID})
			require.NotNil(t, info)
			assert.Equal(t, tt.expectedRuntime, info.Runtime)
			assert.Equal(t, tt.fullID, info.ExtraInfo["fullContainerID"])
			assert.Equal(t, "abcdef012345", info.ExtraInfo["shortID"])
			assert.NotEmpty(t, info.CgroupPath)
			if tt.cgroupContains != "" {
				assert.Contains(t, info.CgroupPath, tt.cgroupContains)
			}
		})
	}
}

func TestRuntimeFromContainerID(t *testing.T) {
	assert.Equal(t, "docker", runtimeFromContainerID("docker://abc"))
	assert.Equal(t, "containerd", runtimeFromContainerID("containerd://abc"))
	assert.Equal(t, "cri-o", runtimeFromContainerID("cri-o://abc"))
	assert.Equal(t, "unknown", runtimeFromContainerID(""))
}

func TestShortContainerID(t *testing.T) {
	assert.Equal(t, "abcdef012345", shortContainerID("abcdef0123456789"))
	assert.Equal(t, "short", shortContainerID("short"))
}

// TestFindContainerProcess_FromProcFixture verifies procfs parsing resolves a
// PID and cgroup path for a container ID referenced in a /proc/<pid>/cgroup.
func TestFindContainerProcess_FromProcFixture(t *testing.T) {
	containerID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	tmp := t.TempDir()
	pidDir := filepath.Join(tmp, "4242")
	require.NoError(t, os.MkdirAll(pidDir, 0o755))
	cgroupContent := "12:memory:/kubepods/burstable/podX/" + containerID + "\n" +
		"0::/kubepods/burstable/podX/" + containerID + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0o644))

	// A non-container process that must be ignored.
	otherDir := filepath.Join(tmp, "1")
	require.NoError(t, os.MkdirAll(otherDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(otherDir, "cgroup"), []byte("0::/init.scope\n"), 0o644))

	old := procRoot
	procRoot = tmp
	defer func() { procRoot = old }()

	pid, cgroupPath, ok := findContainerProcess(containerID)
	require.True(t, ok)
	assert.Equal(t, int32(4242), pid)
	assert.Contains(t, cgroupPath, containerID)
}

func TestFindContainerProcess_NotFound(t *testing.T) {
	old := procRoot
	procRoot = t.TempDir()
	defer func() { procRoot = old }()

	_, _, ok := findContainerProcess("nonexistent")
	assert.False(t, ok)
}

func TestMatchCgroupFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "cgroup")
	require.NoError(t, os.WriteFile(f, []byte("0::/kubepods/pod/deadbeefcafe0123\n"), 0o644))

	path, ok := matchCgroupFile(f, "deadbeefcafe0123", "deadbeefcafe")
	assert.True(t, ok)
	assert.Contains(t, path, "deadbeefcafe0123")

	_, ok = matchCgroupFile(f, "nomatch", "nomatch")
	assert.False(t, ok)
}
