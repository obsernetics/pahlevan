package attribution

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const testCID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

// inode returns the real inode number of a filesystem path, which on cgroup v2
// equals the cgroup id. Building the fixture out of real directories lets the
// tests assert that Lookup/Refresh map the exact ids the kernel would report.
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Ino
}

// buildCgroupFixture creates a temp cgroupfs-like tree containing one systemd
// pod cgroup with a container scope, plus a non-kubernetes system slice that
// must be ignored. It returns the root and the leaf container directory.
func buildCgroupFixture(t *testing.T) (root, containerDir, podDir string) {
	t.Helper()
	root = t.TempDir()

	podDir = filepath.Join(root,
		"kubepods.slice",
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod1234abcd_5678_90ef_1234_567890abcdef.slice",
	)
	containerDir = filepath.Join(podDir, "cri-containerd-"+testCID+".scope")
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		t.Fatalf("mkdir container: %v", err)
	}

	// A non-kubernetes subtree that ParseCgroupPath rejects.
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "kubelet.service"), 0o755); err != nil {
		t.Fatalf("mkdir system.slice: %v", err)
	}
	return root, containerDir, podDir
}

func TestResolver_RefreshMapsRealDirsToContainerRefs(t *testing.T) {
	root, containerDir, podDir := buildCgroupFixture(t)
	r := NewResolver(root)

	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// The pod cgroup dir and the container scope dir both parse as kube pod
	// cgroups, so both ids should be cached.
	if r.Size() != 2 {
		t.Fatalf("cache size = %d, want 2", r.Size())
	}

	containerID := inode(t, containerDir)
	ref, ok := r.Lookup(containerID)
	if !ok {
		t.Fatalf("container cgroup id %d not resolved", containerID)
	}
	if ref.ContainerID != testCID {
		t.Errorf("ContainerID = %q, want %q", ref.ContainerID, testCID)
	}
	if ref.PodUID != "1234abcd-5678-90ef-1234-567890abcdef" {
		t.Errorf("PodUID = %q, want dashed uid", ref.PodUID)
	}
	if ref.Runtime != "containerd" {
		t.Errorf("Runtime = %q, want containerd", ref.Runtime)
	}
	if ref.QoSClass != "besteffort" {
		t.Errorf("QoSClass = %q, want besteffort", ref.QoSClass)
	}

	// The pod-level cgroup resolves too, but without a container id.
	podID := inode(t, podDir)
	podRef, ok := r.Lookup(podID)
	if !ok {
		t.Fatalf("pod cgroup id %d not resolved", podID)
	}
	if podRef.ContainerID != "" {
		t.Errorf("pod cgroup ContainerID = %q, want empty", podRef.ContainerID)
	}
}

func TestResolver_LookupTriggersRefreshOnMiss(t *testing.T) {
	root, containerDir, _ := buildCgroupFixture(t)
	r := NewResolver(root)

	// No explicit Refresh: a cold Lookup must scan on demand and hit.
	if r.Size() != 0 {
		t.Fatalf("expected empty cache before lookup, got %d", r.Size())
	}
	id := inode(t, containerDir)
	if _, ok := r.Lookup(id); !ok {
		t.Fatalf("cold Lookup should refresh and resolve id %d", id)
	}
	if r.Size() == 0 {
		t.Fatalf("Lookup should have populated the cache")
	}
}

func TestResolver_LookupUnknownID(t *testing.T) {
	root, _, _ := buildCgroupFixture(t)
	r := NewResolver(root)
	if ref, ok := r.Lookup(0xdeadbeef); ok {
		t.Fatalf("unknown id should not resolve, got %+v", ref)
	}
}

func TestResolver_NonKubernetesTreeYieldsEmptyCache(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "sshd.service"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := NewResolver(root)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if r.Size() != 0 {
		t.Fatalf("no kube cgroups present, cache size = %d, want 0", r.Size())
	}
}

func TestResolver_RefreshReplacesStaleEntries(t *testing.T) {
	root, containerDir, _ := buildCgroupFixture(t)
	r := NewResolver(root)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	before := r.Size()

	// Remove the container scope; a rescan must drop its entry.
	if err := os.RemoveAll(containerDir); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if r.Size() >= before {
		t.Fatalf("stale container entry not evicted: before=%d after=%d", before, r.Size())
	}
}

func TestResolver_MissingRootReturnsError(t *testing.T) {
	r := NewResolver(filepath.Join(t.TempDir(), "does-not-exist"))
	if err := r.Refresh(); err == nil {
		t.Fatalf("Refresh over a missing root should error")
	}
}

func TestNewResolver_DefaultsRoot(t *testing.T) {
	r := NewResolver("")
	if r.root != DefaultCgroupRoot {
		t.Fatalf("empty root should default to %q, got %q", DefaultCgroupRoot, r.root)
	}
}

func TestResolver_UnreadableSubtreeIsSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permission checks")
	}
	root, containerDir, _ := buildCgroupFixture(t)

	// Make a sibling subtree unreadable; the walk must skip it, not abort.
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o755); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	r := NewResolver(root)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh should tolerate unreadable subtrees: %v", err)
	}
	if _, ok := r.Lookup(inode(t, containerDir)); !ok {
		t.Fatalf("readable container cgroup should still resolve despite blocked sibling")
	}
}

func BenchmarkParseCgroupPath(b *testing.B) {
	path := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234abcd_5678_90ef_1234_567890abcdef.slice/cri-containerd-" + testCID + ".scope"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := ParseCgroupPath(path); !ok {
			b.Fatal("expected parse to succeed")
		}
	}
}
