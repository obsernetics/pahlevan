package ebpf

import (
	"testing"

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
