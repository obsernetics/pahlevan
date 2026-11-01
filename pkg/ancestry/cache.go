// Package ancestry extends a process's lineage past what a single exec event
// carries.
//
// bpf/exec_monitor.c captures up to AncestryDepth ancestors per exec and
// truncates there, so a policy or a detector asking "was any ancestor a
// shell" only ever sees the nearest few hops. Going further in-kernel would
// mean walking task_struct->real_parent an unbounded number of times inside
// a BPF LSM hook, which has no bound the verifier will accept.
//
// The fix stays in userspace instead. Every exec event already names the
// process and its immediate parent, so recording that one link as each exec
// arrives builds, over time, the same lineage a kernel walk would have
// produced - one hop per event rather than four at once, but with no limit
// on how many hops a lookup can later follow.
//
// A pid is not a stable identity on its own: the kernel recycles it, and a
// cached link for a pid that has since been reused would silently splice an
// unrelated process into the lineage. The guard is the comm each exec event
// already reports for every captured ancestor: Cache verifies it against
// what was recorded for that pid before trusting the cached link one hop
// further, and stops the moment the two disagree.
package ancestry

import (
	"container/list"
	"sync"
)

// DefaultMaxEntries bounds a Cache created with NewCache(0).
//
// Each entry is a handful of strings and integers, so even a generous bound
// costs well under a megabyte, and a long-running agent must not grow this
// without limit as containers churn through pids.
const DefaultMaxEntries = 8192

// Ancestor is one link in an extended lineage: a pid and the command name it
// ran, the same shape pkg/ebpf reports for the ancestors it captures
// directly.
type Ancestor struct {
	PID  uint32
	Comm string
}

// record is what Cache keeps for one process: enough to verify its identity
// on a later lookup and to continue one hop further.
type record struct {
	comm       string
	parentPID  uint32
	parentComm string
}

type key struct {
	cgroupID uint64
	pid      uint32
}

// Cache tracks each observed process's immediate parent, keyed by cgroup and
// pid so that two containers reusing the same pid in their own namespaces
// never collide.
//
// It is an LRU: Record evicts the least recently touched entry once the
// cache is full, which is the right failure mode for a lineage aid. Losing
// an old link only shortens how far back a later Extend can see; it never
// produces a wrong answer, because Extend refuses to trust a link whose
// recorded identity no longer matches.
type Cache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[key]*list.Element
}

type entry struct {
	key key
	rec record
}

// NewCache returns an empty Cache holding at most maxEntries processes.
// maxEntries <= 0 uses DefaultMaxEntries.
func NewCache(maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Cache{
		max:   maxEntries,
		ll:    list.New(),
		items: make(map[key]*list.Element, maxEntries),
	}
}

// Record notes that pid, running comm, was execed by parentPID/parentComm in
// cgroupID. Call it for every exec event observed, including ones a caller
// has no further use for: the value of an entry is only known once something
// later wants to walk back through it.
//
// A pid recorded a second time (the kernel reused it for an unrelated
// process) simply overwrites the old entry, which is what cuts the lineage a
// later Extend can trust at exactly that point.
func (c *Cache) Record(cgroupID uint64, pid uint32, comm string, parentPID uint32, parentComm string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := key{cgroupID: cgroupID, pid: pid}
	rec := record{comm: comm, parentPID: parentPID, parentComm: parentComm}
	if el, ok := c.items[k]; ok {
		el.Value.(*entry).rec = rec
		c.ll.MoveToFront(el)
		return
	}
	if c.ll.Len() >= c.max {
		c.evictOldest()
	}
	el := c.ll.PushFront(&entry{key: k, rec: rec})
	c.items[k] = el
}

// evictOldest drops the least recently touched entry. c.mu is held by the
// caller, which only calls this once the list is already at capacity, so
// Back is never nil.
func (c *Cache) evictOldest() {
	oldest := c.ll.Back()
	c.ll.Remove(oldest)
	delete(c.items, oldest.Value.(*entry).key)
}

// Extend walks the cache starting from a process the caller already knows
// about - typically the oldest ancestor a single exec event captured - and
// returns up to maxHops further links, nearest first.
//
// Each hop is trusted only as far as the cached comm for that pid matches
// what the caller asserts it to be; comm is what the caller already knows
// from the kernel (the oldest captured ancestor's own recorded name), so a
// mismatch means the pid has been reused since that ancestor last recorded
// itself, and the lineage beyond that point is unknowable rather than wrong.
// A pid with no recorded parent - never observed execing, or itself the root
// of the pid namespace - ends the walk the same way.
//
// Every entry Extend passes through, including ones at which the walk then
// stops, counts as touched for eviction purposes the same as a Record would:
// a lineage worth walking is a lineage worth keeping.
//
// Returns nil, never an error: an unextendable lineage is the common case,
// not a failure.
func (c *Cache) Extend(cgroupID uint64, pid uint32, comm string, maxHops int) []Ancestor {
	if maxHops <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []Ancestor
	for i := 0; i < maxHops; i++ {
		k := key{cgroupID: cgroupID, pid: pid}
		el, ok := c.items[k]
		if !ok {
			break
		}
		rec := el.Value.(*entry).rec
		if rec.comm != comm {
			break
		}
		c.ll.MoveToFront(el)
		if rec.parentPID == 0 {
			break
		}
		out = append(out, Ancestor{PID: rec.parentPID, Comm: rec.parentComm})
		pid, comm = rec.parentPID, rec.parentComm
	}
	return out
}

// Len reports how many processes the cache currently holds, for metrics and
// tests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
