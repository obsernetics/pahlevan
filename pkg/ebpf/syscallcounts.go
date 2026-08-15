package ebpf

import (
	"sort"
	"strconv"

	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

// SyscallNameOrNumber names a syscall for the build architecture, falling back
// to the number so an entry newer than the table is still identifiable rather
// than blank.
func SyscallNameOrNumber(nr uint64) string {
	if name, ok := seccomp.SyscallName[nr]; ok {
		return name
	}
	return "syscall_" + strconv.FormatUint(nr, 10)
}

// SyscallCount is how often one syscall was observed for one cgroup.
type SyscallCount struct {
	Number uint64
	Name   string
	Count  uint64
}

// SyscallCounts reports how often each syscall was made by a cgroup.
//
// The learned set says which syscalls a workload uses; this says which ones it
// leans on. That difference matters when tuning a profile: a syscall observed
// once during startup and one made a million times a second are equally
// present in the allow-set and are not equally safe to remove.
//
// The counts come from the same map that deduplicates events, so collecting
// them costs nothing at runtime. They are read on demand rather than streamed:
// emitting an event per syscall is exactly what the dedup exists to avoid.
//
// Counts are approximate under concurrency. The kernel increments without an
// atomic, because an exact count is not worth a contended atomic on the
// hottest path in the program and a lost increment only shifts a ranking by
// one.
func (m *Manager) SyscallCounts(cgroupID uint64) []SyscallCount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.syscallCollection == nil {
		return nil
	}
	mp := m.syscallCollection.Maps["syscall_seen"]
	if mp == nil {
		return nil
	}

	var key, count uint64
	out := make([]SyscallCount, 0, 64)
	it := mp.Iterate()
	for it.Next(&key, &count) {
		// key = (cgroup_id << 16) | (syscall_nr & 0xffff), mirroring
		// bpf/syscall_monitor.c.
		if key>>16 != cgroupID {
			continue
		}
		nr := key & 0xffff
		out = append(out, SyscallCount{
			Number: nr,
			Name:   SyscallNameOrNumber(nr),
			Count:  count,
		})
	}

	// Busiest first: the ranking is the reason to ask.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Number < out[j].Number
	})
	return out
}

// TotalSyscalls sums the counts for a cgroup, which is the workload's syscall
// rate denominator.
func (m *Manager) TotalSyscalls(cgroupID uint64) uint64 {
	var total uint64
	for _, c := range m.SyscallCounts(cgroupID) {
		total += c.Count
	}
	return total
}
