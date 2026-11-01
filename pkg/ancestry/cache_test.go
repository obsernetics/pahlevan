package ancestry

import (
	"sync"
	"testing"
)

func TestNewCacheDefaultsNonPositiveSize(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		c := NewCache(n)
		if c.max != DefaultMaxEntries {
			t.Errorf("NewCache(%d).max = %d, want %d", n, c.max, DefaultMaxEntries)
		}
	}
}

func TestNewCachePositiveSize(t *testing.T) {
	c := NewCache(3)
	if c.max != 3 {
		t.Fatalf("max = %d, want 3", c.max)
	}
	if c.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 for an empty cache", c.Len())
	}
}

func TestExtendEmptyCache(t *testing.T) {
	c := NewCache(10)
	if got := c.Extend(1, 100, "sh", 4); got != nil {
		t.Errorf("Extend on empty cache = %v, want nil", got)
	}
}

func TestExtendMaxHopsNotPositive(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 100, "sh", 50, "php-fpm")
	for _, hops := range []int{0, -1, -50} {
		if got := c.Extend(1, 100, "sh", hops); got != nil {
			t.Errorf("Extend(maxHops=%d) = %v, want nil", hops, got)
		}
	}
}

func TestExtendSingleHop(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 100, "sh", 50, "php-fpm")

	got := c.Extend(1, 100, "sh", 4)
	want := []Ancestor{{PID: 50, Comm: "php-fpm"}}
	assertAncestors(t, got, want)
}

func TestExtendMultiHopChain(t *testing.T) {
	c := NewCache(10)
	// nginx(1) -> php-fpm(50) -> sh(100) -> curl(200), recorded in exec order.
	c.Record(1, 50, "php-fpm", 1, "nginx")
	c.Record(1, 100, "sh", 50, "php-fpm")
	c.Record(1, 200, "curl", 100, "sh")

	got := c.Extend(1, 200, "curl", 10)
	want := []Ancestor{
		{PID: 100, Comm: "sh"},
		{PID: 50, Comm: "php-fpm"},
		{PID: 1, Comm: "nginx"},
	}
	assertAncestors(t, got, want)
}

func TestExtendTruncatesAtMaxHops(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 50, "php-fpm", 1, "nginx")
	c.Record(1, 100, "sh", 50, "php-fpm")
	c.Record(1, 200, "curl", 100, "sh")

	got := c.Extend(1, 200, "curl", 2)
	want := []Ancestor{
		{PID: 100, Comm: "sh"},
		{PID: 50, Comm: "php-fpm"},
	}
	assertAncestors(t, got, want)
}

func TestExtendStopsAtUnrecordedParent(t *testing.T) {
	c := NewCache(10)
	// pid 50 was never itself recorded execing, so the chain ends at its
	// comm/parent as reported by the one caller-supplied hop.
	c.Record(1, 100, "sh", 50, "php-fpm")

	got := c.Extend(1, 100, "sh", 10)
	want := []Ancestor{{PID: 50, Comm: "php-fpm"}}
	assertAncestors(t, got, want)
}

func TestExtendStopsAtZeroParentPID(t *testing.T) {
	c := NewCache(10)
	// pid 1's parent is reported as pid 0: the root of the namespace, not an
	// unresolved lookup.
	c.Record(1, 1, "nginx", 0, "")

	got := c.Extend(1, 1, "nginx", 10)
	if got != nil {
		t.Errorf("Extend at the namespace root = %v, want nil", got)
	}
}

func TestExtendStopsOnCommMismatchFromPIDReuse(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 50, "php-fpm", 1, "nginx")
	c.Record(1, 100, "sh", 50, "php-fpm")

	// pid 50 execs again as an unrelated process. pid 100's own record of its
	// parent at the time it exec'd (pid 50, "php-fpm") is still trustworthy
	// and is returned; walking one hop further would mean trusting the new,
	// unrelated occupant of pid 50 as if it were "php-fpm", which is exactly
	// the splice this guards against.
	c.Record(1, 50, "cron", 1, "init")

	got := c.Extend(1, 100, "sh", 10)
	want := []Ancestor{{PID: 50, Comm: "php-fpm"}}
	assertAncestors(t, got, want)
}

func TestExtendCallerAssertedCommMismatchReturnsNothing(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 50, "php-fpm", 1, "nginx")

	// The caller believes pid 50 is "sh", which disagrees with what was
	// recorded; nothing is trustworthy to return.
	got := c.Extend(1, 50, "sh", 10)
	if got != nil {
		t.Errorf("Extend with a mismatched starting comm = %v, want nil", got)
	}
}

func TestExtendDoesNotCrossCgroups(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 100, "sh", 50, "php-fpm")
	// A different cgroup reused the same pid for something unrelated.
	c.Record(2, 50, "unrelated", 1, "init")

	got := c.Extend(1, 100, "sh", 10)
	want := []Ancestor{{PID: 50, Comm: "php-fpm"}}
	assertAncestors(t, got, want)

	if got := c.Extend(2, 100, "sh", 10); got != nil {
		t.Errorf("cgroup 2 Extend(pid 100) = %v, want nil (not recorded in that cgroup)", got)
	}
}

func TestRecordOverwritesExistingEntry(t *testing.T) {
	c := NewCache(10)
	c.Record(1, 50, "php-fpm", 1, "nginx")
	c.Record(1, 50, "php-fpm-reexeced", 1, "nginx")

	if n := c.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1 after overwriting the same key", n)
	}
	got := c.Extend(1, 100, "sh", 10)
	if got != nil {
		t.Fatalf("unexpected extension for an unrecorded pid: %v", got)
	}
}

func TestRecordEvictsLeastRecentlyUsed(t *testing.T) {
	c := NewCache(1)
	c.Record(1, 1, "a", 99, "grandparent")
	// With room for only one entry, recording pid 2 evicts pid 1 - including
	// the fact that pid 1's own parent was pid 99.
	c.Record(1, 2, "b", 1, "a")

	if n := c.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1", n)
	}

	// pid 2's own record still names pid 1 as its parent - that hop survives
	// because it is stored on pid 2's own entry. Going one hop further would
	// need pid 1's entry, which is gone.
	got := c.Extend(1, 2, "b", 10)
	want := []Ancestor{{PID: 1, Comm: "a"}}
	assertAncestors(t, got, want)
}

func TestRecordTouchKeepsEntryAlive(t *testing.T) {
	c := NewCache(2)
	c.Record(1, 1, "a", 0, "")
	c.Record(1, 2, "b", 1, "a")

	// Re-recording pid 1 marks it most recently used, so the next insert
	// should evict pid 2 instead.
	c.Record(1, 1, "a", 0, "")
	c.Record(1, 3, "c", 2, "b")

	got := c.Extend(1, 2, "b", 10)
	if got != nil {
		t.Errorf("Extend(pid 2) after it was evicted = %v, want nil", got)
	}

	// pid 1 should have survived the eviction.
	if _, ok := c.items[key{cgroupID: 1, pid: 1}]; !ok {
		t.Errorf("pid 1 was evicted despite being touched most recently")
	}
}

func TestExtendTouchesLRUOrder(t *testing.T) {
	c := NewCache(2)
	c.Record(1, 1, "a", 0, "")
	c.Record(1, 2, "b", 1, "a")

	// Walking from pid 2 through pid 1 should count as touching pid 1, the
	// same as a Record would, so a lineage lookup does not make the entries
	// it just walked through the next ones evicted.
	c.Extend(1, 2, "b", 10)

	// A third entry now evicts whichever of pid 1 / pid 2 is least recently
	// used. Having just been walked through, pid 1 should survive and pid 2,
	// untouched since its own Record, should not.
	c.Record(1, 3, "c", 2, "b")

	if _, ok := c.items[key{cgroupID: 1, pid: 1}]; !ok {
		t.Errorf("pid 1 was evicted despite being touched by Extend")
	}
	if _, ok := c.items[key{cgroupID: 1, pid: 2}]; ok {
		t.Errorf("pid 2 should have been evicted as the least recently used entry")
	}
}

func TestLenOnNilAndEmptyCache(t *testing.T) {
	c := NewCache(5)
	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0", c.Len())
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache(256)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			cgroup := uint64(g)
			for pid := uint32(1); pid < 100; pid++ {
				c.Record(cgroup, pid, "proc", pid-1, "parent")
				c.Extend(cgroup, pid, "proc", 4)
			}
		}(g)
	}
	wg.Wait()
}

func assertAncestors(t *testing.T, got, want []Ancestor) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Extend() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Extend()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
