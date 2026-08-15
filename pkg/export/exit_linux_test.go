package export

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// An exit read as an exec would present a process running a binary with no
// name, so the distinction has to survive into the exported envelope.
func TestFromProcessEventMarksExit(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 42, PID: 400, Comm: "nginx", Flags: ebpf.ExitedFlag,
	}, ancestryNow)
	require.NotNil(t, ev)
	require.NotNil(t, ev.Exec)

	assert.True(t, ev.Exec.Exited)
	assert.Empty(t, ev.Exec.Binary)
	assert.Empty(t, ev.Exec.Args)
	// An exit is an observation, never a denial.
	assert.Equal(t, ActionObserve, ev.Action)
}

// An ordinary exec must not claim to be an exit, and must not emit the key.
func TestFromProcessEventExecIsNotAnExit(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 1, PID: 1, Comm: "nginx", Filename: "/usr/sbin/nginx",
	}, ancestryNow)
	require.NotNil(t, ev.Exec)
	assert.False(t, ev.Exec.Exited)

	data, err := json.Marshal(ev.Exec)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "exited")
}

// The parent must reach the envelope on every signal, not just execs: a denial
// attributed to a pid and a comm still does not say who caused it.
func TestParentReachesTheEnvelope(t *testing.T) {
	file := FromFileEvent(&ebpf.FileEvent{
		CgroupID: 1, PID: 400, Comm: "cat", Path: "/etc/shadow",
		Flags: ebpf.DeniedFlag, PPID: 300, ParentComm: "bash",
	}, ancestryNow)
	require.NotNil(t, file)
	assert.Equal(t, uint32(300), file.Process.PPID)
	assert.Equal(t, "bash", file.Process.ParentComm)

	// Network events already carried comm from the kernel and the exporter was
	// dropping it, so every egress denial named a pid and no process.
	net := FromNetworkEvent(&ebpf.NetworkEvent{
		CgroupID: 1, PID: 400, Comm: "nc", DstPort: 4444,
		Direction: DeniedDirection, PPID: 300, ParentComm: "sh",
	}, ancestryNow)
	require.NotNil(t, net)
	assert.Equal(t, "nc", net.Process.Comm, "comm was being dropped entirely")
	assert.Equal(t, uint32(300), net.Process.PPID)
	assert.Equal(t, "sh", net.Process.ParentComm)

	cap := FromCapabilityEvent(&ebpf.CapabilityEvent{
		CgroupID: 1, PID: 400, Comm: "app", Capability: 21,
		PPID: 300, ParentComm: "sh",
	}, ancestryNow)
	require.NotNil(t, cap)
	assert.Equal(t, uint32(300), cap.Process.PPID)
	assert.Equal(t, "sh", cap.Process.ParentComm)
}

// A process with no recorded parent must omit the keys rather than emit a pid
// of zero and an empty comm that reads as a real process.
func TestAbsentParentIsOmitted(t *testing.T) {
	ev := FromFileEvent(&ebpf.FileEvent{
		CgroupID: 1, PID: 1, Comm: "init", Path: "/etc/passwd",
	}, ancestryNow)
	data, err := json.Marshal(ev.Process)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "ppid")
	assert.NotContains(t, string(data), "parentComm")
}

// The capability sets have to reach the envelope as names, or a consumer needs
// to know the capability numbering to read the event.
func TestCapabilitySetsReachTheEnvelope(t *testing.T) {
	ev := FromCapabilityEvent(&ebpf.CapabilityEvent{
		CgroupID: 1, PID: 1, Comm: "app", Capability: 21,
		CapEffective: 1<<0 | 1<<21, CapPermitted: 1<<0 | 1<<21, CapInheritable: 0,
	}, ancestryNow)
	require.NotNil(t, ev.Capability)

	assert.Equal(t, "CAP_SYS_ADMIN", ev.Capability.Name)
	assert.Equal(t, []string{"CAP_CHOWN", "CAP_SYS_ADMIN"}, ev.Capability.Effective)
	assert.Equal(t, []string{"CAP_CHOWN", "CAP_SYS_ADMIN"}, ev.Capability.Permitted)
	assert.Empty(t, ev.Capability.Inheritable, "an empty set must be omitted, not listed as empty")
}
