package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

func TestSyscallNameOrNumber(t *testing.T) {
	// A name from the build architecture's table.
	var openat uint64
	for nr, name := range seccomp.SyscallName {
		if name == "openat" {
			openat = nr
		}
	}
	require.NotZero(t, openat, "the table should contain openat")
	assert.Equal(t, "openat", SyscallNameOrNumber(openat))

	// An entry newer than the table stays identifiable rather than blank.
	assert.Equal(t, "syscall_60000", SyscallNameOrNumber(60000))
}

// Without a loaded collection there are no counts, and asking must not panic.
func TestSyscallCountsWithoutPrograms(t *testing.T) {
	m := &Manager{}
	assert.Nil(t, m.SyscallCounts(42))
	assert.Zero(t, m.TotalSyscalls(42))
}

// The success path, against a real kernel hash map rather than a fake: two
// cgroups sharing the map, filtered to one, ranked busiest first with a
// number-ascending tiebreak, and a count past the seccomp table rendered
// numerically instead of blank.
func TestSyscallCountsRanksAndFilters(t *testing.T) {
	mp := newTestHashMap(t, 8, 8)
	const cgroup = uint64(7)
	const other = uint64(8)

	var openat uint64
	for nr, name := range seccomp.SyscallName {
		if name == "openat" {
			openat = nr
		}
	}
	require.NotZero(t, openat, "the table should contain openat")

	entries := map[uint64]uint64{
		(cgroup << 16) | (1 & 0xffff):      5,
		(cgroup << 16) | (2 & 0xffff):      50,
		(cgroup << 16) | (openat & 0xffff): 50,
		(other << 16) | (1 & 0xffff):       999,
	}
	for k, v := range entries {
		require.NoError(t, mp.Put(k, v))
	}

	m := &Manager{syscallCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"syscall_seen": mp}}}
	got := m.SyscallCounts(cgroup)
	require.Len(t, got, 3, "the other cgroup's entry must not appear")

	// Busiest first; a tie breaks on the lower syscall number.
	assert.Equal(t, uint64(50), got[0].Count)
	assert.Equal(t, uint64(2), got[0].Number)
	assert.Equal(t, uint64(50), got[1].Count)
	assert.Equal(t, openat, got[1].Number)
	assert.Equal(t, "openat", got[1].Name)
	assert.Equal(t, uint64(5), got[2].Count)
	assert.Equal(t, uint64(1), got[2].Number)

	assert.Equal(t, uint64(105), m.TotalSyscalls(cgroup))
}

// A missing map must report no counts rather than panic on a nil lookup.
func TestSyscallCountsWithoutTheMap(t *testing.T) {
	m := &Manager{syscallCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	assert.Nil(t, m.SyscallCounts(1))
}

// The key layout is the contract with bpf/syscall_monitor.c: a wrong shift
// would silently attribute every syscall to the wrong container.
func TestSyscallCountKeyLayout(t *testing.T) {
	const cgroup = uint64(0xdead)
	const nr = uint64(257)
	key := (cgroup << 16) | (nr & 0xffff)

	assert.Equal(t, cgroup, key>>16, "the cgroup must be recoverable from the key")
	assert.Equal(t, nr, key&0xffff, "the syscall number must be recoverable from the key")

	// A different cgroup must not collide with this one for the same syscall.
	other := ((cgroup + 1) << 16) | (nr & 0xffff)
	assert.NotEqual(t, key, other)
}

// Syscall numbers above 16 bits cannot be represented in the key. No Linux
// architecture is close, but the truncation should be a known property rather
// than a surprise.
func TestSyscallCountKeyTruncatesAbove16Bits(t *testing.T) {
	const cgroup = uint64(1)
	a := (cgroup << 16) | (0x10001 & 0xffff)
	b := (cgroup << 16) | (0x00001 & 0xffff)
	assert.Equal(t, a, b, "the key holds 16 bits of syscall number by construction")
	assert.Greater(t, 1000, seccomp.KnownSyscallCount(),
		"which is safe only while the real table stays far below 65536")
}

func BenchmarkSyscallNameOrNumber(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyscallNameOrNumber(257)
	}
}

// Read on demand rather than streamed, per the package doc, but a profile
// tool or dashboard asking for a busy cgroup still walks and sorts the whole
// map, so the cost of doing that is worth tracking.
func BenchmarkSyscallCounts(b *testing.B) {
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 400,
	})
	if err != nil {
		b.Skipf("system doesn't support eBPF maps: %v", err)
	}
	defer mp.Close()

	const cgroup = uint64(1)
	for nr := uint64(0); nr < 300; nr++ {
		if err := mp.Put((cgroup<<16)|(nr&0xffff), nr*7+1); err != nil {
			b.Fatalf("seeding entry %d: %v", nr, err)
		}
	}

	m := &Manager{syscallCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"syscall_seen": mp}}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SyscallCounts(cgroup)
	}
}
