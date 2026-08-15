package export

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

var ancestryNow = time.Unix(1700000000, 0).UTC()

// A denied exec is only actionable with the chain that led to it, so the
// lineage has to survive the conversion into the exported envelope.
func TestFromProcessEventCarriesAncestry(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 42,
		PID:      400,
		PPID:     300,
		Comm:     "curl",
		Filename: "/usr/bin/curl",
		Flags:    ebpf.DeniedFlag,
		Ancestry: []ebpf.Ancestor{
			{PID: 300, Comm: "sh"},
			{PID: 200, Comm: "nginx"},
		},
	}, ancestryNow)
	require.NotNil(t, ev)
	require.NotNil(t, ev.Exec)

	assert.Equal(t, ActionDeny, ev.Action)
	assert.Equal(t, "/usr/bin/curl", ev.Exec.Binary)
	assert.Equal(t, []AncestorInfo{{PID: 300, Comm: "sh"}, {PID: 200, Comm: "nginx"}}, ev.Exec.Ancestry)
	assert.Equal(t, "nginx -> sh -> curl", ev.Exec.AncestryChain)
}

// An exec with no recorded ancestors must not emit empty ancestry keys.
func TestFromProcessEventOmitsEmptyAncestry(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 1, PID: 1, Comm: "init", Filename: "/sbin/init",
	}, ancestryNow)
	require.NotNil(t, ev)
	require.NotNil(t, ev.Exec)
	assert.Empty(t, ev.Exec.Ancestry)
	assert.Empty(t, ev.Exec.AncestryChain)

	data, err := json.Marshal(ev.Exec)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "ancestry")
	assert.NotContains(t, string(data), "ancestryChain")
}

func TestExecInfoJSONShape(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 1, PID: 4, Comm: "nc", Filename: "/usr/bin/nc",
		Ancestry: []ebpf.Ancestor{{PID: 3, Comm: "sh"}},
	}, ancestryNow)
	data, err := json.Marshal(ev.Exec)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"binary":"/usr/bin/nc","ancestry":[{"pid":3,"comm":"sh"}],"ancestryChain":"sh -> nc"}`,
		string(data))
}

func BenchmarkFromProcessEventWithAncestry(b *testing.B) {
	src := &ebpf.ProcessEvent{
		CgroupID: 42, PID: 400, Comm: "curl", Filename: "/usr/bin/curl",
		Ancestry: []ebpf.Ancestor{
			{PID: 300, Comm: "sh"}, {PID: 200, Comm: "entrypoint"},
			{PID: 100, Comm: "nginx"}, {PID: 1, Comm: "init"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromProcessEvent(src, ancestryNow)
	}
}
