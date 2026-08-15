package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A denied file open with no parent cannot be actioned: you know what was
// refused and not who tried. Exec events carry a full lineage; the other
// signals carry one hop, which is what stops them being anonymous.
func TestFileEventCarriesParent(t *testing.T) {
	ev := parseFileEvent(buildFileRecParent(7, 9, 400, 0, 0, DeniedFlag,
		"cat", "/etc/shadow", 300, "bash"))
	require.NotNil(t, ev)

	assert.Equal(t, uint32(300), ev.PPID)
	assert.Equal(t, "bash", ev.ParentComm)
	// The rest of the record must survive the layout change.
	assert.Equal(t, "/etc/shadow", ev.Path)
	assert.Equal(t, "cat", ev.Comm)
	assert.Equal(t, uint64(7), ev.CgroupID)
	assert.True(t, ev.IsDenied())
}

func TestNetworkEventCarriesParent(t *testing.T) {
	ev := parseNetworkEvent(buildNetRecParent(7, 9, 400, 0, 0x0100007f, 0, 4444,
		6, DeniedDirection, 2, nil, "nc", 300, "sh"))
	require.NotNil(t, ev)

	assert.Equal(t, uint32(300), ev.PPID)
	assert.Equal(t, "sh", ev.ParentComm)
	assert.Equal(t, "nc", ev.Comm)
	assert.Equal(t, uint16(4444), ev.DstPort)
	assert.Equal(t, uint8(6), ev.Protocol)
}

func TestCapabilityEventCarriesParent(t *testing.T) {
	ev := parseCapabilityEvent(buildCapRecSets(7, 9, 400, 21, DeniedFlag, "app",
		1<<21, 1<<21, 0))
	require.NotNil(t, ev)
	// The default encoder leaves the parent empty, which must decode as absent
	// rather than as garbage read past the comm.
	assert.Zero(t, ev.PPID)
	assert.Empty(t, ev.ParentComm)
	assert.Equal(t, "app", ev.Comm)
	assert.Equal(t, uint64(1<<21), ev.CapEffective)
}

// A process with no parent recorded must report none, not an empty-string comm
// that reads as a real process called "".
func TestParentAbsentDecodesAsZero(t *testing.T) {
	ev := parseFileEvent(buildFileRec(1, 2, 100, 0, 0, 0, "sh", "/etc/passwd"))
	require.NotNil(t, ev)
	assert.Zero(t, ev.PPID)
	assert.Empty(t, ev.ParentComm)
}

// The parent fields sit between comm and path in the file record; a wrong
// offset would silently truncate the path or read the parent out of it.
func TestFileEventParentDoesNotDisturbThePath(t *testing.T) {
	long := "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/config/settings.yaml"
	ev := parseFileEvent(buildFileRecParent(1, 2, 100, 0, 0, 0, "app", long, 42, "runc"))
	require.NotNil(t, ev)
	assert.Equal(t, long, ev.Path)
	assert.Equal(t, uint32(42), ev.PPID)
	assert.Equal(t, "runc", ev.ParentComm)
}

func BenchmarkParseFileEventWithParent(b *testing.B) {
	rec := buildFileRecParent(1, 2, 100, 0, 0, DeniedFlag, "cat", "/etc/shadow", 300, "bash")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseFileEvent(rec)
	}
}
