package netname

import (
	"net/netip"
	"testing"
	"time"
)

func addr4(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{8, byte(i >> 16), byte(i >> 8), byte(i)})
}

// The cap is the security property: destinations are attacker controlled, so
// cache keys are attacker controlled. A process that dials a million distinct
// addresses must not be able to make the naming table the thing that OOMs the
// node it is running on.
func TestCacheIsBounded(t *testing.T) {
	const max = 64
	c := newCache(max)
	now := time.Unix(0, 0)
	for i := 0; i < 100000; i++ {
		c.put(addr4(i), entry{name: "x", source: SourceReverse, expires: now.Add(time.Hour)})
		if got := c.len(); got > 2*max {
			t.Fatalf("after %d inserts the cache held %d entries, want at most %d", i+1, got, 2*max)
		}
	}
	if got := c.len(); got > 2*max {
		t.Fatalf("cache held %d entries, want at most %d", got, 2*max)
	}
	if c.len() == 0 {
		t.Fatal("cache is empty: eviction dropped everything, which would mean nothing is ever named")
	}
}

// Eviction has to actually drop old entries, not just stop accepting new ones:
// a cache that fills and then refuses writes would freeze on whatever the first
// burst of traffic happened to contain.
func TestCacheEvictsOldestGeneration(t *testing.T) {
	const max = 4
	c := newCache(max)
	now := time.Unix(0, 0)
	old := addr4(0)
	c.put(old, entry{name: "old", expires: now.Add(time.Hour)})

	// Two full generations of other addresses push it out.
	for i := 1; i <= 3*max; i++ {
		c.put(addr4(i), entry{name: "new", expires: now.Add(time.Hour)})
	}
	if _, ok := c.get(old, now); ok {
		t.Error("the oldest entry survived two generation rotations")
	}
	recent := addr4(3 * max)
	if _, ok := c.get(recent, now); !ok {
		t.Error("the most recent entry was evicted")
	}
}

// An entry still being read is promoted back into the live generation, so
// recency rather than insertion order decides what survives. Without this, a
// destination a workload talks to constantly would be re-resolved every time
// the cache happened to rotate.
func TestCacheGetPromotesFromTheOldGeneration(t *testing.T) {
	const max = 4
	c := newCache(max)
	now := time.Unix(0, 0)
	hot, cold := addr4(1000), addr4(2000)
	c.put(hot, entry{name: "hot", expires: now.Add(time.Hour)})
	c.put(cold, entry{name: "cold", expires: now.Add(time.Hour)})

	// A white box helper: inserting filler until the live generation holds a
	// single entry is exactly one rotation, and the test needs that to be
	// exact rather than approximately right.
	next := 0
	rotate := func() {
		for {
			c.put(addr4(next), entry{name: "filler", expires: now.Add(time.Hour)})
			next++
			if len(c.cur) == 1 {
				return
			}
		}
	}

	// One rotation: both entries are now in the old generation.
	rotate()
	// Reading hot promotes it back into the live generation. cold is left
	// untouched and is the control.
	if _, ok := c.get(hot, now); !ok {
		t.Fatal("hot entry lost after a single rotation")
	}
	// The next rotation replaces the old generation wholesale.
	rotate()

	if _, ok := c.get(cold, now); ok {
		t.Error("an entry nobody read survived two rotations")
	}
	if _, ok := c.get(hot, now); !ok {
		t.Error("a promoted entry was dropped by the next rotation")
	}
}

// An expired entry reads as absent, so a stale name is never reported. A wrong
// name is worse than no name: addresses get reused, and an operator acting on a
// name that no longer holds is worse off than one reading an address.
func TestCacheExpiry(t *testing.T) {
	c := newCache(16)
	now := time.Unix(0, 0)
	a := addr4(1)
	c.put(a, entry{name: "n", expires: now.Add(time.Minute)})

	if _, ok := c.get(a, now); !ok {
		t.Fatal("fresh entry missing")
	}
	if _, ok := c.get(a, now.Add(2*time.Minute)); ok {
		t.Error("expired entry was served")
	}
	// A zero expiry means no expiry, used by entries that are not time bound.
	b := addr4(2)
	c.put(b, entry{name: "n"})
	if _, ok := c.get(b, now.Add(100*time.Hour)); !ok {
		t.Error("an entry with no expiry was treated as expired")
	}
}

// A remembered failure is a real answer: the caller must be able to tell "asked
// and got nothing" from "never asked", or it re-asks on every packet.
func TestCacheRemembersFailures(t *testing.T) {
	c := newCache(16)
	now := time.Unix(0, 0)
	a := addr4(1)
	c.put(a, entry{source: SourceReverse, expires: now.Add(time.Minute)})
	e, ok := c.get(a, now)
	if !ok {
		t.Fatal("a remembered failure read as never looked up")
	}
	if e.name != "" {
		t.Errorf("name = %q, want empty", e.name)
	}
}

// The same bound seen through the Namer, which is where it actually protects
// the node: a flood of distinct destinations through the public path.
func TestNamerCacheIsBoundedUnderAFlood(t *testing.T) {
	n := New(Options{CacheSize: 32})
	defer n.Close()
	for i := 0; i < 50000; i++ {
		a := addr4(i)
		n.Observe("flood.example.com", []netip.Addr{a}, time.Minute)
		n.Lookup(a)
		if got := n.Len(); got > 64 {
			t.Fatalf("after %d destinations the namer held %d entries, want at most 64", i+1, got)
		}
	}
}
