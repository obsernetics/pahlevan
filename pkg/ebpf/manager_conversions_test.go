package ebpf

import (
	"bytes"
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

// --- convertToEBPFNetworkPolicy ---

func TestConvertToEBPFNetworkPolicy_Empty(t *testing.T) {
	out := convertToEBPFNetworkPolicy(&NetworkPolicy{LastUpdate: time.Now()})
	assert.Equal(t, uint32(1), out.LearningMode)
	for _, ip := range out.AllowedDestinations {
		assert.Equal(t, uint32(0), ip)
	}
	for _, port := range out.AllowedPorts {
		assert.Equal(t, uint16(0), port)
	}
}

func TestConvertToEBPFNetworkPolicy_IPsAndPorts(t *testing.T) {
	out := convertToEBPFNetworkPolicy(&NetworkPolicy{
		EnforcementMode:     1,
		AllowedEgressIPs:    []uint32{0x0A000001, 0x0A000002},
		AllowedIngressIPs:   []uint32{0x0A000003},
		AllowedEgressPorts:  map[uint16]bool{443: true},
		AllowedIngressPorts: map[uint16]bool{8080: true},
	})
	assert.Equal(t, uint32(0), out.LearningMode)
	assert.ElementsMatch(t, []uint32{0x0A000001, 0x0A000002, 0x0A000003}, nonZero32(out.AllowedDestinations[:]))
	assert.ElementsMatch(t, []uint16{443, 8080}, nonZero16(out.AllowedPorts[:]))
}

func TestConvertToEBPFNetworkPolicy_DestinationOverflowTruncates(t *testing.T) {
	egress := make([]uint32, 200)
	ingress := make([]uint32, 200)
	for i := range egress {
		egress[i] = uint32(i + 1)
	}
	for i := range ingress {
		ingress[i] = uint32(1000 + i)
	}
	out := convertToEBPFNetworkPolicy(&NetworkPolicy{AllowedEgressIPs: egress, AllowedIngressIPs: ingress})
	// 256-entry array: all 200 egress entries fit, then only the first 56
	// ingress entries do; the rest must be silently dropped, not panic.
	assert.Equal(t, uint32(1), out.AllowedDestinations[0])
	assert.Equal(t, uint32(200), out.AllowedDestinations[199])
	assert.Equal(t, uint32(1000), out.AllowedDestinations[200])
	assert.Equal(t, uint32(1055), out.AllowedDestinations[255])
}

func TestConvertToEBPFNetworkPolicy_PortOverflowTruncates(t *testing.T) {
	ports := make(map[uint16]bool, 100)
	for i := uint16(1); i <= 100; i++ {
		ports[i] = true
	}
	out := convertToEBPFNetworkPolicy(&NetworkPolicy{AllowedEgressPorts: ports})
	nz := nonZero16(out.AllowedPorts[:])
	assert.Len(t, nz, 64, "only the first 64 ports fit in the fixed-size array")
}

// --- convertToEBPFFilePolicy ---

func TestConvertToEBPFFilePolicy_Empty(t *testing.T) {
	out := convertToEBPFFilePolicy(&FilePolicy{LastUpdate: time.Now()})
	assert.Equal(t, uint32(1), out.LearningMode)
	assert.Equal(t, uint32(0), out.PathCount)
}

func TestConvertToEBPFFilePolicy_Paths(t *testing.T) {
	out := convertToEBPFFilePolicy(&FilePolicy{
		EnforcementMode: 1,
		AllowedPaths:    []string{"/etc/passwd", "/tmp/x"},
	})
	assert.Equal(t, uint32(0), out.LearningMode)
	assert.Equal(t, uint32(2), out.PathCount)
	assert.Equal(t, "/etc/passwd", nullTerminatedString(out.AllowedPaths[0][:]))
	assert.Equal(t, "/tmp/x", nullTerminatedString(out.AllowedPaths[1][:]))
}

func TestConvertToEBPFFilePolicy_LongPathTruncated(t *testing.T) {
	long := bytes.Repeat([]byte("a"), 200)
	out := convertToEBPFFilePolicy(&FilePolicy{AllowedPaths: []string{string(long)}})
	got := nullTerminatedString(out.AllowedPaths[0][:])
	assert.Len(t, got, 63, "path must be truncated to leave room for the null terminator")
	assert.Equal(t, string(bytes.Repeat([]byte("a"), 63)), got)
}

func TestConvertToEBPFFilePolicy_PathCountOverflowIgnored(t *testing.T) {
	paths := make([]string, 1100)
	for i := range paths {
		paths[i] = fmt.Sprintf("/p/%d", i)
	}
	out := convertToEBPFFilePolicy(&FilePolicy{AllowedPaths: paths})
	assert.Equal(t, uint32(1024), out.PathCount, "the eBPF-side array holds at most 1024 paths")
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

// --- helpers shared by these tests ---

func nonZero32(s []uint32) []uint32 {
	var out []uint32
	for _, v := range s {
		if v != 0 {
			out = append(out, v)
		}
	}
	return out
}

func nonZero16(s []uint16) []uint16 {
	var out []uint16
	for _, v := range s {
		if v != 0 {
			out = append(out, v)
		}
	}
	return out
}

func nullTerminatedString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
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

func BenchmarkConvertToEBPFNetworkPolicy(b *testing.B) {
	egress := make([]uint32, 100)
	for i := range egress {
		egress[i] = uint32(i)
	}
	ports := make(map[uint16]bool, 32)
	for i := uint16(0); i < 32; i++ {
		ports[i] = true
	}
	policy := &NetworkPolicy{
		AllowedEgressIPs:   egress,
		AllowedEgressPorts: ports,
		LastUpdate:         time.Now(),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = convertToEBPFNetworkPolicy(policy)
	}
}

func BenchmarkConvertToEBPFFilePolicy(b *testing.B) {
	paths := make([]string, 500)
	for i := range paths {
		paths[i] = fmt.Sprintf("/usr/bin/tool-%d", i)
	}
	policy := &FilePolicy{AllowedPaths: paths, LastUpdate: time.Now()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = convertToEBPFFilePolicy(policy)
	}
}
