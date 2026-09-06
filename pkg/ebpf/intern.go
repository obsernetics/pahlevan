package ebpf

import (
	"strconv"
	"sync"
)

// String interning for the two values every decoded event carries and almost
// every event repeats.
//
// The ring-buffer decoders are the hottest userspace path in the agent: one run
// per event, on a busy node thousands of times a second. Profiling the decoders
// showed most of their allocation was not the event struct but two strings
// rebuilt from scratch every time:
//
//   - the process name, which comes from a fixed 16-byte kernel buffer and
//     repeats enormously. A node runs a few dozen distinct programs and sees
//     millions of events from them.
//   - "cgroup:<id>", which was built with fmt.Sprintf - reflection and two
//     allocations - for a value that is likewise drawn from a small set, one
//     per container.
//
// Both are therefore cached. After the first event for a given comm or cgroup,
// the decoder does a map read instead of an allocation, and the returned string
// is shared rather than copied.
//
// The tables are bounded. An attacker who can exec arbitrary program names, or
// a node churning through containers, would otherwise turn a cache into a leak;
// past the cap the decoders simply stop caching and allocate as before, which
// is slower but correct and constant in memory.

// internCap bounds each table. A few thousand distinct process names or live
// cgroups is far past what a real node has, and a node that exceeds it has
// something wrong with it that a cache should not paper over.
const internCap = 4096

type internTable struct {
	mu sync.RWMutex
	m  map[string]string
}

func (t *internTable) lookup(b []byte) string {
	// The map read takes []byte directly: Go compiles m[string(b)] on a map
	// read without copying the bytes, so the miss path is the only one that
	// allocates.
	t.mu.RLock()
	s, ok := t.m[string(b)]
	t.mu.RUnlock()
	if ok {
		return s
	}

	s = string(b)
	t.mu.Lock()
	if len(t.m) < internCap {
		t.m[s] = s
	}
	t.mu.Unlock()
	return s
}

var commTable = &internTable{m: make(map[string]string, 256)}

// internComm returns the process name from a kernel comm buffer, truncated at
// the first NUL, reusing a previously seen string where possible.
func internComm(b []byte) string {
	if i := indexZero(b); i >= 0 {
		b = b[:i]
	}
	if len(b) == 0 {
		return ""
	}
	return commTable.lookup(b)
}

type cgroupTable struct {
	mu sync.RWMutex
	m  map[uint64]string
}

var containerIDs = &cgroupTable{m: make(map[uint64]string, 256)}

// containerIDFor renders the cgroup id as the placeholder container identifier
// the events carry until pod attribution resolves a real one.
//
// It replaces fmt.Sprintf("cgroup:%d", id), which cost reflection and two
// allocations per event for a string drawn from a set the size of the node's
// container count.
func containerIDFor(cgroupID uint64) string {
	containerIDs.mu.RLock()
	s, ok := containerIDs.m[cgroupID]
	containerIDs.mu.RUnlock()
	if ok {
		return s
	}

	// strconv.AppendUint into a sized buffer: one allocation on the miss,
	// against Sprintf's two plus its reflection.
	buf := make([]byte, 0, 7+20)
	buf = append(buf, "cgroup:"...)
	buf = strconv.AppendUint(buf, cgroupID, 10)
	s = string(buf)

	containerIDs.mu.Lock()
	if len(containerIDs.m) < internCap {
		containerIDs.m[cgroupID] = s
	}
	containerIDs.mu.Unlock()
	return s
}

// pathTable is separate from commTable so a node with many distinct paths
// cannot evict the process names, and neither can exhaust the other's cap.
var pathTable = &internTable{m: make(map[string]string, 256)}

// internPath returns a NUL-terminated kernel path buffer as a string, reusing a
// previously seen one where possible.
//
// Used for the executable and working directory on exec events, which repeat as
// heavily as process names do - a container runs a handful of binaries out of a
// handful of directories, millions of times.
//
// Deliberately NOT used for argv. Arguments are arbitrary attacker-influenced
// input, and a cache keyed on them is a cache an attacker fills.
func internPath(b []byte) string {
	if i := indexZero(b); i >= 0 {
		b = b[:i]
	}
	if len(b) == 0 {
		return ""
	}
	return pathTable.lookup(b)
}

// splitArgs appends the NUL-separated fields of raw to dst.
//
// bytes.Split would allocate a slice of subslices before any string is made,
// which on the exec path is one allocation per event thrown away immediately.
// Scanning in place costs one allocation per argument and none for the split.
func splitArgs(dst []string, raw []byte) []string {
	for len(raw) > 0 {
		i := indexZero(raw)
		if i < 0 {
			if len(raw) > 0 {
				dst = append(dst, string(raw))
			}
			return dst
		}
		if i > 0 {
			dst = append(dst, string(raw[:i]))
		}
		raw = raw[i+1:]
	}
	return dst
}
