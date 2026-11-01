package ebpf

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- FileEvent flag methods ---

func TestFileEvent_IsWrite(t *testing.T) {
	assert.False(t, (&FileEvent{}).IsWrite())
	assert.True(t, (&FileEvent{Flags: WriteFlag}).IsWrite())
	assert.True(t, (&FileEvent{Flags: WriteFlag | DeniedFlag}).IsWrite())
}

func TestFileEvent_IsDenied(t *testing.T) {
	assert.False(t, (&FileEvent{}).IsDenied())
	assert.True(t, (&FileEvent{Flags: DeniedFlag}).IsDenied())
}

func TestFileEvent_WouldDeny(t *testing.T) {
	assert.False(t, (&FileEvent{}).WouldDeny())
	assert.True(t, (&FileEvent{Flags: WouldDenyFlag}).WouldDeny())
	// Mutually exclusive with IsDenied by construction, but the accessor
	// itself only looks at its own bit.
	ev := &FileEvent{Flags: DeniedFlag}
	assert.False(t, ev.WouldDeny())
}

func TestFileEvent_WasKilled(t *testing.T) {
	assert.False(t, (&FileEvent{}).WasKilled())
	assert.True(t, (&FileEvent{Flags: FileKilledFlag}).WasKilled())
}

// --- CapabilityEvent flag methods ---

func TestCapabilityEvent_IsDenied(t *testing.T) {
	assert.False(t, (&CapabilityEvent{}).IsDenied())
	assert.True(t, (&CapabilityEvent{Flags: DeniedFlag}).IsDenied())
}

func TestCapabilityEvent_WouldDeny(t *testing.T) {
	assert.False(t, (&CapabilityEvent{}).WouldDeny())
	assert.True(t, (&CapabilityEvent{Flags: WouldDenyFlag}).WouldDeny())
}

func TestCapabilityEvent_WasKilled(t *testing.T) {
	assert.False(t, (&CapabilityEvent{}).WasKilled())
	assert.True(t, (&CapabilityEvent{Flags: KilledFlag}).WasKilled())
}

// --- enforcementSpecFor ---

func TestEnforcementSpecFor(t *testing.T) {
	assert.Equal(t, EnforcementSpec{Action: ActionDeny}, enforcementSpecFor(true))
	assert.Equal(t, EnforcementSpec{Action: ActionLearn}, enforcementSpecFor(false))
}

// --- isMissingKey ---

func TestIsMissingKey(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"unrelated error", errors.New("boom"), false},
		{"ebpf missing key message", errors.New("ebpf: key does not exist"), true},
		{"wrapped ENOENT", fmt.Errorf("lookup: %w", syscall.ENOENT), true},
		{"bare ENOENT", syscall.ENOENT, true},
		{"other errno", syscall.EINVAL, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMissingKey(tt.err))
		})
	}
}

// --- convertToEBPFPolicy ---

func TestConvertToEBPFPolicy_EnforcementMode(t *testing.T) {
	now := time.Now()
	learning := convertToEBPFPolicy(&ContainerPolicy{EnforcementMode: 0, LastUpdate: now})
	assert.Equal(t, uint32(1), learning.LearningMode)
	assert.Equal(t, uint64(now.UnixNano()), learning.LastUpdateNs)
	assert.Equal(t, uint32(0), learning.ViolationCount)

	enforcing := convertToEBPFPolicy(&ContainerPolicy{EnforcementMode: 1, LastUpdate: now})
	assert.Equal(t, uint32(0), enforcing.LearningMode)
}

func TestConvertToEBPFPolicy_EmptySyscalls(t *testing.T) {
	out := convertToEBPFPolicy(&ContainerPolicy{AllowedSyscalls: map[uint64]bool{}})
	for _, word := range out.AllowedSyscalls {
		assert.Equal(t, uint64(0), word)
	}
}

func TestConvertToEBPFPolicy_SyscallBitmap(t *testing.T) {
	out := convertToEBPFPolicy(&ContainerPolicy{
		AllowedSyscalls: map[uint64]bool{
			0:    true,  // word 0, bit 0
			63:   true,  // word 0, bit 63
			64:   true,  // word 1, bit 0
			4095: true,  // last valid syscall number -> word 63
			5:    false, // explicitly disallowed, must not set a bit
		},
	})
	assert.Equal(t, uint64(1)|uint64(1)<<63, out.AllowedSyscalls[0])
	assert.Equal(t, uint64(1), out.AllowedSyscalls[1])
	assert.Equal(t, uint64(1)<<63, out.AllowedSyscalls[63])
}

func TestConvertToEBPFPolicy_SyscallOutOfRangeIgnored(t *testing.T) {
	out := convertToEBPFPolicy(&ContainerPolicy{
		AllowedSyscalls: map[uint64]bool{
			4096:                                   true, // first number eBPF does not support
			1 << 20:                                true,
			18446744073709551615 /* max uint64 */ : true,
		},
	})
	for _, word := range out.AllowedSyscalls {
		assert.Equal(t, uint64(0), word, "no bit should be set for an out-of-range syscall number")
	}
}

// --- LearnedFileCount ---

func TestLearnedFileCount_NilCollection(t *testing.T) {
	m := &Manager{}
	assert.Equal(t, 0, m.LearnedFileCount())
}

func TestLearnedFileCount_MissingMap(t *testing.T) {
	m := &Manager{fileCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	assert.Equal(t, 0, m.LearnedFileCount())
}

func TestLearnedFileCount_CountsEntries(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	for i := uint64(0); i < 3; i++ {
		require.NoError(t, mp.Put(i, uint8(1)))
	}
	m := &Manager{fileCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"file_allowed": mp}}}
	assert.Equal(t, 3, m.LearnedFileCount())
}

// --- SetMapSizing ---

func TestSetMapSizing(t *testing.T) {
	m := &Manager{}
	sizing := MapSizing{FileAllowed: 1000, NetworkAllowed: 2000, ExecAllowed: 3000, SyscallSeen: 4000, RingBufBytes: 65536}
	m.SetMapSizing(sizing)
	assert.Equal(t, sizing, m.mapSizing)
}

// --- benchmarks ---

func BenchmarkConvertToEBPFPolicy(b *testing.B) {
	syscalls := make(map[uint64]bool, 300)
	for i := uint64(0); i < 300; i++ {
		syscalls[i] = true
	}
	policy := &ContainerPolicy{AllowedSyscalls: syscalls, LastUpdate: time.Now()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = convertToEBPFPolicy(policy)
	}
}
