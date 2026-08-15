package ebpf

import (
	"fmt"
	"sort"
	"strings"
)

// Process filter.
//
// The learned allow-set answers "has this container run this binary before".
// A policy's syscallPolicy.processFilter asks a different question: who is
// allowed to run it. The two are independent - a binary the container has run a
// thousand times is still not one that should be launched by a shell that
// arrived over the network, or run as root when the workload runs as uid 1000.
//
// Both are enforced in bprm_check_security, so a rejected exec fails with
// EPERM rather than being reported after the fact. The two rejections carry
// different flag bits, because "this container has never run curl" and "curl
// may not be launched by sh" call for entirely different responses.
//
// Every dimension is opt-in. An unset dimension must not become an empty
// allow-list that denies everything, which is why the enabled mask is a
// separate map rather than being inferred from the presence of entries.

// Filter dimensions, mirroring the FILTER_* constants in bpf/exec_monitor.c.
const (
	// FilterParent restricts which parent process may launch an exec, matched
	// on the parent's comm.
	FilterParent uint8 = 0x01
	// FilterUID restricts the effective uid at exec.
	FilterUID uint8 = 0x02
	// FilterGID restricts the effective gid at exec.
	FilterGID uint8 = 0x04
)

// Key kinds, mirroring the KIND_* constants in bpf/exec_monitor.c.
const (
	kindParent uint64 = 1
	kindUID    uint64 = 2
	kindGID    uint64 = 3
)

// commLen is the kernel's TASK_COMM_LEN. A parent comm is truncated to 15
// characters plus a NUL before it ever reaches the hash, so userspace must
// truncate identically or a long process name would be seeded under a key the
// kernel can never compute.
const commLen = 16

// ProcFilterKey derives the process-filter key for one (cgroup, kind, value)
// triple. Mirrors:
//
//	return cgroup_id ^ (kind * KIND_MIX) ^ value;
//
// The kind is folded in multiplicatively so a uid and a parent hash that happen
// to collide numerically do not alias onto each other.
func ProcFilterKey(cgroupID uint64, kind uint64, value uint64) uint64 {
	return cgroupID ^ (kind * protocolMix) ^ value
}

// ParentFilterKey derives the key for an allowed parent process name.
func ParentFilterKey(cgroupID uint64, comm string) uint64 {
	return ProcFilterKey(cgroupID, kindParent, FnvCommHash(comm))
}

// UIDFilterKey derives the key for an allowed effective uid.
func UIDFilterKey(cgroupID uint64, uid uint32) uint64 {
	return ProcFilterKey(cgroupID, kindUID, uint64(uid))
}

// GIDFilterKey derives the key for an allowed effective gid.
func GIDFilterKey(cgroupID uint64, gid uint32) uint64 {
	return ProcFilterKey(cgroupID, kindGID, uint64(gid))
}

// FnvCommHash hashes a process name the way the kernel does.
//
// It is not FnvPathHash: the kernel hashes the fixed-size comm buffer and stops
// at the NUL, so a name longer than TASK_COMM_LEN-1 hashes as its truncation.
// Hashing the untruncated string here would produce a key the kernel never
// computes, and the entry would be written and silently never match.
func FnvCommHash(comm string) uint64 {
	if len(comm) > commLen-1 {
		comm = comm[:commLen-1]
	}
	h := uint64(1469598103934665603)
	for i := 0; i < len(comm); i++ {
		if comm[i] == 0 {
			break
		}
		h ^= uint64(comm[i])
		h *= 1099511628211
	}
	return h
}

// ProcFilter is the set of process constraints for one cgroup.
//
// A nil or empty ProcFilter disables filtering entirely, which is the correct
// default: a policy that says nothing about who may exec must not be read as
// saying nobody may.
type ProcFilter struct {
	// ParentProcesses are the parent command names permitted to launch an
	// exec. Names are compared as the kernel sees them: truncated to
	// TASK_COMM_LEN-1, so "some-very-long-daemon" matches on its first 15
	// characters.
	ParentProcesses []string
	// UIDs are the effective uids permitted to exec.
	UIDs []uint32
	// GIDs are the effective gids permitted to exec.
	GIDs []uint32
}

// Empty reports whether the filter constrains nothing.
func (f *ProcFilter) Empty() bool {
	return f == nil ||
		(len(f.ParentProcesses) == 0 && len(f.UIDs) == 0 && len(f.GIDs) == 0)
}

// Mask is the FILTER_* bitmask this filter enables.
func (f *ProcFilter) Mask() uint8 {
	if f == nil {
		return 0
	}
	var m uint8
	if len(f.ParentProcesses) > 0 {
		m |= FilterParent
	}
	if len(f.UIDs) > 0 {
		m |= FilterUID
	}
	if len(f.GIDs) > 0 {
		m |= FilterGID
	}
	return m
}

// normalizedParents returns the parent names, trimmed, de-duplicated after
// kernel truncation and sorted. Sorting makes the write order deterministic,
// which is what lets a test compare two applications of the same filter.
func (f *ProcFilter) normalizedParents() []string {
	seen := make(map[string]struct{}, len(f.ParentProcesses))
	out := make([]string, 0, len(f.ParentProcesses))
	for _, p := range f.ParentProcesses {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) > commLen-1 {
			p = p[:commLen-1]
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// SetProcFilter installs the process filter for one cgroup.
//
// The allowed values are written before the enabled mask, so a cgroup is never
// briefly enforcing a dimension whose allow-list has not landed yet - that
// window would deny every exec in the container.
//
// Passing an empty filter clears the mask, which disables filtering. The value
// entries are left to the LRU rather than being deleted: they are keyed by
// cgroup and are not consulted while the mask is clear, and a delete sweep
// would need the previous filter, which the caller may no longer have.
func (m *Manager) SetProcFilter(cgroupID uint64, f *ProcFilter) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	onMap, err := m.allowMap(m.execCollection, "exec", "exec_filter_on")
	if err != nil {
		return err
	}
	if f.Empty() {
		_ = onMap.Delete(cgroupID)
		return nil
	}

	valMap, err := m.allowMap(m.execCollection, "exec", "exec_filter_allowed")
	if err != nil {
		return err
	}
	for _, p := range f.normalizedParents() {
		if err := valMap.Put(ParentFilterKey(cgroupID, p), uint8(1)); err != nil {
			return fmt.Errorf("seeding parent %q: %w", p, err)
		}
	}
	for _, uid := range f.UIDs {
		if err := valMap.Put(UIDFilterKey(cgroupID, uid), uint8(1)); err != nil {
			return fmt.Errorf("seeding uid %d: %w", uid, err)
		}
	}
	for _, gid := range f.GIDs {
		if err := valMap.Put(GIDFilterKey(cgroupID, gid), uint8(1)); err != nil {
			return fmt.Errorf("seeding gid %d: %w", gid, err)
		}
	}
	return onMap.Put(cgroupID, f.Mask())
}

// ClearProcFilter disables process filtering for a cgroup.
func (m *Manager) ClearProcFilter(cgroupID uint64) error {
	return m.SetProcFilter(cgroupID, nil)
}

// ProcFilterMask reports the dimensions currently enforced for a cgroup, which
// is what `pahlevan debug` needs to answer "is this filter actually live".
func (m *Manager) ProcFilterMask(cgroupID uint64) (uint8, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	onMap, err := m.allowMap(m.execCollection, "exec", "exec_filter_on")
	if err != nil {
		return 0, err
	}
	var mask uint8
	if err := onMap.Lookup(cgroupID, &mask); err != nil {
		// Absent means no filtering, which is the common case and not an error.
		return 0, nil
	}
	return mask, nil
}

// FilterMaskString renders a mask for logs and CLI output.
func FilterMaskString(mask uint8) string {
	if mask == 0 {
		return "none"
	}
	var parts []string
	if mask&FilterParent != 0 {
		parts = append(parts, "parent")
	}
	if mask&FilterUID != 0 {
		parts = append(parts, "uid")
	}
	if mask&FilterGID != 0 {
		parts = append(parts, "gid")
	}
	return strings.Join(parts, ",")
}
