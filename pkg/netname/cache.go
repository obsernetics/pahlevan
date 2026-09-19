package netname

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// entry is one remembered name for one address.
type entry struct {
	// name is empty for a remembered failure. Negative entries are kept on
	// purpose: without them, a destination that has no PTR record would be
	// looked up again on every single packet to it, which is how a naming
	// feature turns into the outbound flood it was supposed to describe.
	name    string
	source  Source
	expires time.Time
}

// cache remembers names for addresses under a hard cap on entries.
//
// The cap is the whole point. Destinations are attacker controlled: a process
// that wants to hide a single exfiltration connection can dial a million
// distinct addresses first, and every one of them would be a key here. An
// unbounded cache would make the agent's naming table the thing that OOMs the
// node it is defending, so the number of entries is capped and old ones are
// dropped even if that means naming an address twice.
//
// Eviction is generational rather than a strict LRU. A strict LRU has to write
// to a list on every hit, which means taking a write lock on the read path -
// and the read path here is the eBPF ring buffer reader, the one goroutine that
// must never queue behind anything. Two generations give approximate recency
// for the cost of a read lock on hits: when the live generation fills, it
// becomes the old generation and a fresh one is started, so total residency is
// bounded by 2*max, and an entry still being read is promoted back into the
// live generation so that recency, not insertion order, decides what survives.
type cache struct {
	// entries is the resident count, maintained under mu but readable without
	// it. With reverse lookups off and no observed answers - the default - the
	// cache stays empty for the life of the agent, and this lets every event
	// skip the lock rather than having every ring buffer reader contend on the
	// same RWMutex for an answer that is always "nothing here".
	entries atomic.Int64

	mu   sync.RWMutex
	max  int
	cur  map[netip.Addr]entry
	prev map[netip.Addr]entry
}

func newCache(max int) *cache {
	return &cache{max: max, cur: make(map[netip.Addr]entry)}
}

// get returns the remembered entry for addr. The bool reports whether anything
// is remembered at all, including a remembered failure, so a caller can tell
// "looked up and found nothing" from "never looked up" and avoid re-asking.
func (c *cache) get(addr netip.Addr, now time.Time) (entry, bool) {
	if c.entries.Load() == 0 {
		return entry{}, false
	}
	c.mu.RLock()
	e, ok := c.cur[addr]
	stale := false
	if !ok {
		e, ok = c.prev[addr]
		stale = ok
	}
	c.mu.RUnlock()
	if !ok {
		return entry{}, false
	}
	if !e.expires.IsZero() && now.After(e.expires) {
		// Expired entries are left in place rather than deleted here: deleting
		// would need the write lock on the read path, and the generation
		// rotation will drop them soon enough.
		return entry{}, false
	}
	if stale {
		// A hit in the old generation is rare by construction, so paying for
		// the write lock here does not put it on the common path, and it keeps
		// a destination that is still being dialled from being forgotten just
		// because the cache happened to rotate.
		c.put(addr, e)
	}
	return e, true
}

// put remembers e for addr, rotating generations when the live one is full.
func (c *cache) put(addr netip.Addr, e entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cur) >= c.max {
		c.prev = c.cur
		c.cur = make(map[netip.Addr]entry, c.max)
	}
	c.cur[addr] = e
	c.entries.Store(int64(len(c.cur) + len(c.prev)))
}

// len reports how many entries are resident across both generations, for the
// bound test and for a debug command answering "why is this destination still
// unnamed".
func (c *cache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cur) + len(c.prev)
}
