package ancestry

import "testing"

// BenchmarkRecord measures the cost of the write every exec event pays: one
// Record call, which must stay cheap enough not to compete with the
// ring-buffer readers it runs alongside.
func BenchmarkRecord(b *testing.B) {
	c := NewCache(DefaultMaxEntries)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pid := uint32(i%DefaultMaxEntries) + 1
		c.Record(1, pid, "proc", pid-1, "parent")
	}
}

// BenchmarkExtendShallow measures a lookup that stops after one hop, the
// common case for a lineage most callers never need to walk far.
func BenchmarkExtendShallow(b *testing.B) {
	c := NewCache(DefaultMaxEntries)
	c.Record(1, 2, "sh", 1, "nginx")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Extend(1, 2, "sh", 4)
	}
}

// BenchmarkExtendDeepChain measures walking a long recorded lineage to its
// configured limit, the worst case for one call.
func BenchmarkExtendDeepChain(b *testing.B) {
	const depth = 64
	c := NewCache(DefaultMaxEntries)
	for pid := uint32(1); pid <= depth; pid++ {
		c.Record(1, pid, "proc", pid-1, "parent")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Extend(1, depth, "proc", depth)
	}
}
