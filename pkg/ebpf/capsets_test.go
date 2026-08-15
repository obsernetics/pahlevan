package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The capability being checked answers "what did it want". The sets answer
// "what could it have done", which is the question that decides whether a
// container is over-privileged.
func TestParseCapabilityEventDecodesSets(t *testing.T) {
	const (
		capChown    = 1 << 0
		capNetAdmin = 1 << 12
		capSysAdmin = 1 << 21
	)
	ev := parseCapabilityEvent(buildCapRecSets(7, 9, 42, 21, DeniedFlag, "nginx",
		capChown|capNetAdmin, capChown|capNetAdmin|capSysAdmin, capChown))
	require.NotNil(t, ev)

	assert.Equal(t, uint32(21), ev.Capability)
	assert.Equal(t, uint64(capChown|capNetAdmin), ev.CapEffective)
	assert.Equal(t, uint64(capChown|capNetAdmin|capSysAdmin), ev.CapPermitted)
	assert.Equal(t, uint64(capChown), ev.CapInheritable)
	// The other fields must survive the layout change.
	assert.Equal(t, uint64(7), ev.CgroupID)
	assert.Equal(t, uint32(42), ev.PID)
	assert.Equal(t, "nginx", ev.Comm)
	assert.True(t, ev.Flags&DeniedFlag != 0)
}

func TestCapabilityNames(t *testing.T) {
	assert.Nil(t, CapabilityNames(0), "an empty set has no names, not one empty name")

	names := CapabilityNames(1<<0 | 1<<12 | 1<<21)
	assert.Equal(t, []string{"CAP_CHOWN", "CAP_NET_ADMIN", "CAP_SYS_ADMIN"}, names)

	// A bit above the known table is rendered rather than dropped, so a newer
	// kernel's additions stay visible.
	high := CapabilityNames(1 << 62)
	require.Len(t, high, 1)
	assert.Equal(t, "CAP_62", high[0])
}

// A workload holding a capability it never exercises is a finding even though
// no check was ever denied. This is the shape of that query.
func TestCapabilitySetsRevealUnusedPrivilege(t *testing.T) {
	const capSysAdmin = uint64(1 << 21)
	ev := parseCapabilityEvent(buildCapRecSets(1, 1, 1, 0 /* CAP_CHOWN */, 0, "app",
		capSysAdmin|1, capSysAdmin|1, 0))
	require.NotNil(t, ev)

	held := CapabilityNames(ev.CapEffective)
	assert.Contains(t, held, "CAP_SYS_ADMIN",
		"the set must show privilege the workload holds but is not exercising")
	assert.Equal(t, "CAP_CHOWN", CapabilityName(ev.Capability),
		"while the checked capability is the mundane one")
}

func TestParseCapabilityEventShortBuffer(t *testing.T) {
	assert.Nil(t, parseCapabilityEvent(make([]byte, capEventSize-1)))
	assert.NotNil(t, parseCapabilityEvent(make([]byte, capEventSize)))
}

func BenchmarkCapabilityNames(b *testing.B) {
	const mask = uint64(1<<0 | 1<<12 | 1<<21 | 1<<39)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CapabilityNames(mask)
	}
}
