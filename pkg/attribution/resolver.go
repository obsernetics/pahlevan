package attribution

import (
	"io/fs"
	"path/filepath"
	"sync"
	"syscall"
)

// DefaultCgroupRoot is the cgroup v2 mount point. When the agent runs in a
// container with the host cgroupfs mounted at /sys/fs/cgroup, this resolves the
// host cgroup ids the eBPF programs report.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// Resolver maps cgroup ids (bpf_get_current_cgroup_id) to Kubernetes containers.
//
// On cgroup v2 the cgroup id is the inode number of the cgroup directory, so the
// resolver walks the cgroup filesystem, stats each directory, and parses the pod
// and container identity from the path. Results are cached; Refresh rescans.
type Resolver struct {
	root string

	mu    sync.RWMutex
	cache map[uint64]ContainerRef
}

// NewResolver returns a Resolver over the given cgroup root (use
// DefaultCgroupRoot in production).
func NewResolver(root string) *Resolver {
	if root == "" {
		root = DefaultCgroupRoot
	}
	return &Resolver{root: root, cache: map[uint64]ContainerRef{}}
}

// Lookup returns the container for a cgroup id from the cache. If missing, it
// triggers a single Refresh and retries once (cgroups appear as pods start).
func (r *Resolver) Lookup(cgroupID uint64) (ContainerRef, bool) {
	r.mu.RLock()
	ref, ok := r.cache[cgroupID]
	r.mu.RUnlock()
	if ok {
		return ref, true
	}
	if err := r.Refresh(); err != nil {
		return ContainerRef{}, false
	}
	r.mu.RLock()
	ref, ok = r.cache[cgroupID]
	r.mu.RUnlock()
	return ref, ok
}

// Refresh rescans the cgroup tree and rebuilds the cgroup-id -> container map.
func (r *Resolver) Refresh() error {
	next := map[uint64]ContainerRef{}
	err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable subtrees rather than aborting the whole walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel := "/" + filepath.ToSlash(mustRel(r.root, path))
		ref, ok := ParseCgroupPath(rel)
		if !ok {
			return nil
		}
		id, ok := cgroupID(path)
		if !ok {
			return nil
		}
		next[id] = ref
		return nil
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cache = next
	r.mu.Unlock()
	return nil
}

// Size returns the number of cached cgroup entries (for diagnostics/tests).
func (r *Resolver) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return rel
}

// cgroupID returns the cgroup v2 id for a cgroup directory, which equals its
// inode number.
func cgroupID(path string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return st.Ino, true
}
