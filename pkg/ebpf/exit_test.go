package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An exit shares the exec record, so a consumer has to be able to tell them
// apart before reading fields an exit does not have.
func TestProcessEventExitIsDistinguishable(t *testing.T) {
	exit := parseProcessEvent(buildExecRecFull(7, 9, 400, 0, ExitedFlag, "nginx", "", nil, nil, false))
	require.NotNil(t, exit)
	assert.True(t, exit.IsExit())
	assert.False(t, exit.IsDenied())
	assert.False(t, exit.WasKilled())
	assert.Empty(t, exit.Filename, "an exit carries no binary")
	assert.Empty(t, exit.Args, "an exit carries no argv")

	execEv := parseProcessEvent(buildExecRecFull(7, 9, 400, 0, 0, "nginx", "/usr/sbin/nginx", nil,
		[]string{"nginx", "-g", "daemon off;"}, false))
	require.NotNil(t, execEv)
	assert.False(t, execEv.IsExit())
	assert.Equal(t, "/usr/sbin/nginx", execEv.Filename)
}

// The flags are independent bits: a denied exec that was also killed must
// report both, and neither must read as an exit.
func TestProcessEventFlagsAreIndependent(t *testing.T) {
	ev := parseProcessEvent(buildExecRecFull(1, 1, 1, 0, DeniedFlag|KilledFlag,
		"nc", "/usr/bin/nc", nil, nil, false))
	require.NotNil(t, ev)
	assert.True(t, ev.IsDenied())
	assert.True(t, ev.WasKilled())
	assert.False(t, ev.IsExit(), "a denial is not an exit")
}

// The three flags must not overlap, or one would be read as another.
func TestProcessEventFlagBitsAreDistinct(t *testing.T) {
	assert.Zero(t, DeniedFlag&KilledFlag)
	assert.Zero(t, DeniedFlag&ExitedFlag)
	assert.Zero(t, KilledFlag&ExitedFlag)
	assert.Equal(t, uint32(0x20000000), ExitedFlag)
}

func BenchmarkParseProcessEventExit(b *testing.B) {
	rec := buildExecRecFull(1, 1, 400, 0, ExitedFlag, "nginx", "", nil, nil, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseProcessEvent(rec)
	}
}
