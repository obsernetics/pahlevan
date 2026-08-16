package ebpf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The kernel hashes a fixed 16-byte comm buffer and stops at the NUL, so a
// longer name hashes as its truncation. Hashing the untruncated string in
// userspace would write an entry under a key the kernel can never compute: the
// filter would look installed and match nothing.
func TestCommHashTruncatesLikeTheKernel(t *testing.T) {
	long := "a-very-long-process-name"
	require.Greater(t, len(long), commLen-1)
	assert.Equal(t, FnvCommHash(long[:commLen-1]), FnvCommHash(long),
		"a name past TASK_COMM_LEN-1 must hash as its truncation")
	// And a name that fits is hashed whole.
	assert.NotEqual(t, FnvCommHash("sh"), FnvCommHash("bash"))
}

func TestCommHashMatchesTheFnvSeed(t *testing.T) {
	// FNV-1a offset basis with no input.
	assert.Equal(t, uint64(1469598103934665603), FnvCommHash(""))
	// One byte: basis ^ 'a' then * prime, with the multiply wrapping as the
	// kernel's does.
	want := uint64(1469598103934665603) ^ uint64('a')
	want *= 1099511628211
	assert.Equal(t, want, FnvCommHash("a"))
}

// The kind is folded in multiplicatively. Without that, uid 1 and a parent
// hash of 1 would produce the same key and a filter on one dimension would
// silently satisfy the other.
func TestFilterKeyKindsDoNotAlias(t *testing.T) {
	const cg = 0xC0FFEE
	assert.NotEqual(t, ProcFilterKey(cg, kindUID, 1), ProcFilterKey(cg, kindParent, 1))
	assert.NotEqual(t, ProcFilterKey(cg, kindUID, 1), ProcFilterKey(cg, kindGID, 1))
	assert.NotEqual(t, ProcFilterKey(cg, kindParent, 1), ProcFilterKey(cg, kindGID, 1))
}

// Two cgroups must never share a filter entry, or one container's exception
// would apply to another's.
func TestFilterKeyIsPerCgroup(t *testing.T) {
	assert.NotEqual(t, UIDFilterKey(1, 1000), UIDFilterKey(2, 1000))
	assert.NotEqual(t, ParentFilterKey(1, "sh"), ParentFilterKey(2, "sh"))
}

func TestFilterKeyHelpersAgreeWithProcFilterKey(t *testing.T) {
	const cg = 42
	assert.Equal(t, ProcFilterKey(cg, kindParent, FnvCommHash("sh")), ParentFilterKey(cg, "sh"))
	assert.Equal(t, ProcFilterKey(cg, kindUID, 1000), UIDFilterKey(cg, 1000))
	assert.Equal(t, ProcFilterKey(cg, kindGID, 1000), GIDFilterKey(cg, 1000))
}

// A policy that says nothing about who may exec must not be read as saying
// nobody may. An empty filter is the single most dangerous thing to get wrong
// here: the failure mode is a container in which nothing can start.
func TestEmptyFilterConstrainsNothing(t *testing.T) {
	assert.True(t, (*ProcFilter)(nil).Empty())
	assert.True(t, (&ProcFilter{}).Empty())
	assert.Equal(t, uint8(0), (*ProcFilter)(nil).Mask())
	assert.Equal(t, uint8(0), (&ProcFilter{}).Mask())

	assert.False(t, (&ProcFilter{ParentProcesses: []string{"sh"}}).Empty())
	assert.False(t, (&ProcFilter{UIDs: []uint32{0}}).Empty(), "uid 0 is a constraint, not an absence")
	assert.False(t, (&ProcFilter{GIDs: []uint32{0}}).Empty())
}

func TestMaskReflectsOnlyThePopulatedDimensions(t *testing.T) {
	assert.Equal(t, FilterParent, (&ProcFilter{ParentProcesses: []string{"sh"}}).Mask())
	assert.Equal(t, FilterUID, (&ProcFilter{UIDs: []uint32{1000}}).Mask())
	assert.Equal(t, FilterGID, (&ProcFilter{GIDs: []uint32{1000}}).Mask())
	assert.Equal(t, FilterParent|FilterUID|FilterGID, (&ProcFilter{
		ParentProcesses: []string{"sh"}, UIDs: []uint32{0}, GIDs: []uint32{0},
	}).Mask())
}

// Two names that differ only past the kernel's truncation point are the same
// entry, and writing both would be a silent duplicate.
func TestNormalizedParentsDeduplicatesAfterTruncation(t *testing.T) {
	f := &ProcFilter{ParentProcesses: []string{
		"supervisord-aaaa-one", "supervisord-aaaa-two", " sh ", "sh", "", "   ",
	}}
	got := f.normalizedParents()
	assert.Equal(t, []string{"sh", "supervisord-aaa"}, got,
		"blank entries dropped, whitespace trimmed, truncated duplicates collapsed, sorted")
}

// The order the entries are written in must not depend on the caller's slice
// order, or two applications of the same policy would look different.
func TestNormalizedParentsIsOrderIndependent(t *testing.T) {
	a := (&ProcFilter{ParentProcesses: []string{"b", "a", "c"}}).normalizedParents()
	b := (&ProcFilter{ParentProcesses: []string{"c", "b", "a"}}).normalizedParents()
	assert.Equal(t, a, b)
}

func TestFilterMaskString(t *testing.T) {
	assert.Equal(t, "none", FilterMaskString(0))
	assert.Equal(t, "parent", FilterMaskString(FilterParent))
	assert.Equal(t, "uid", FilterMaskString(FilterUID))
	assert.Equal(t, "parent,uid,gid", FilterMaskString(FilterParent|FilterUID|FilterGID))
}

// The Go constants are the userspace half of a contract whose other half is a
// #define in bpf/exec_monitor.c. A silent divergence would enforce the wrong
// dimension, so the values are pinned here rather than only being compared to
// themselves.
func TestFilterConstantsMatchTheKernel(t *testing.T) {
	assert.Equal(t, uint8(0x01), FilterParent)
	assert.Equal(t, uint8(0x02), FilterUID)
	assert.Equal(t, uint8(0x04), FilterGID)
	assert.Equal(t, uint64(1), kindParent)
	assert.Equal(t, uint64(2), kindUID)
	assert.Equal(t, uint64(3), kindGID)
	assert.Equal(t, uint64(0x9E3779B97F4A7C15), protocolMix, "KIND_MIX")
	assert.Equal(t, 16, commLen, "TASK_COMM_LEN")
}

// A denial must say which of the two independent reasons fired: "never learned"
// is a learning-window question, "process filter" is a policy decision.
func TestDenialReasonDistinguishesTheTwoRejections(t *testing.T) {
	assert.Equal(t, "", (&ProcessEvent{}).DenialReason())
	assert.Equal(t, "not in the learned allow-set",
		(&ProcessEvent{Flags: DeniedFlag}).DenialReason())
	assert.Equal(t, "process filter",
		(&ProcessEvent{Flags: DeniedFlag | FilterDeniedFlag}).DenialReason())

	assert.False(t, (&ProcessEvent{Flags: DeniedFlag}).DeniedByFilter())
	assert.True(t, (&ProcessEvent{Flags: DeniedFlag | FilterDeniedFlag}).DeniedByFilter())
}

// FilterDeniedFlag must not collide with a bit already in use, or a filter
// denial would read as a kill or an exit.
func TestFilterDeniedFlagIsItsOwnBit(t *testing.T) {
	for name, other := range map[string]uint32{
		"denied": DeniedFlag, "killed": KilledFlag, "exited": ExitedFlag,
	} {
		assert.Zero(t, FilterDeniedFlag&other, "FilterDeniedFlag overlaps %s", name)
	}
}

// A manager with no exec program loaded must report that clearly rather than
// panic: a kernel without the BPF LSM runs the agent in observation-only mode.
func TestSetProcFilterWithoutTheProgramLoaded(t *testing.T) {
	m := &Manager{}
	err := m.SetProcFilter(1, &ProcFilter{UIDs: []uint32{0}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec monitor not loaded")

	// Clearing is also a map write, so it reports the same way.
	assert.Error(t, m.ClearProcFilter(1))

	_, err = m.ProcFilterMask(1)
	assert.Error(t, err)
}

func BenchmarkProcFilterKeyDerivation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParentFilterKey(uint64(i), "supervisord")
		_ = UIDFilterKey(uint64(i), 1000)
		_ = GIDFilterKey(uint64(i), 1000)
	}
}

func BenchmarkFnvCommHash(b *testing.B) {
	name := strings.Repeat("x", commLen-1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FnvCommHash(name)
	}
}

func BenchmarkNormalizedParents(b *testing.B) {
	f := &ProcFilter{ParentProcesses: []string{
		"supervisord", "entrypoint.sh", "tini", "dumb-init", "systemd", "sh", "bash",
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.normalizedParents()
	}
}

// The runC breakout class - CVE-2024-21626 and the vulnerabilities that
// followed - works by leaving the working directory pointing at a file
// descriptor the runtime leaked from the host mount namespace. Everything
// resolved relative to it resolves on the host.
//
// It is worth its own flag because nothing else Pahlevan observes separates it
// from an ordinary exec: no capability is used, no mount is made, and no
// syscall a seccomp profile would question is issued.
func TestBreakoutFlagIsItsOwnBit(t *testing.T) {
	for name, other := range map[string]uint32{
		"denied": DeniedFlag, "killed": KilledFlag,
		"exited": ExitedFlag, "filter": FilterDeniedFlag,
	} {
		assert.Zero(t, BreakoutFlag&other, "BreakoutFlag overlaps %s", name)
	}
	assert.Equal(t, uint32(0x08000000), BreakoutFlag, "must match EV_BREAKOUT in the C")
}

// The breakout reason outranks the others. An operator who reads "not in the
// learned allow-set" for a host escape goes looking for a missing exception,
// which is the wrong thing entirely.
func TestBreakoutOutranksTheOtherDenialReasons(t *testing.T) {
	assert.False(t, (&ProcessEvent{}).IsBreakout())
	assert.True(t, (&ProcessEvent{Flags: BreakoutFlag}).IsBreakout())

	assert.Contains(t,
		(&ProcessEvent{Flags: DeniedFlag | BreakoutFlag}).DenialReason(),
		"container breakout")
	assert.Contains(t,
		(&ProcessEvent{Flags: DeniedFlag | FilterDeniedFlag | BreakoutFlag}).DenialReason(),
		"container breakout")

	// And it is reported even while learning, when DeniedFlag is absent -
	// because the behavior is never legitimate and learning it would be
	// learning the exploit.
	assert.Contains(t, (&ProcessEvent{Flags: BreakoutFlag}).DenialReason(),
		"container breakout")
}
