package adaptive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/seccomp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seccompController drives a container to enforcing with profile emission on,
// and returns the controller and the directory the profile landed in.
func seccompController(t *testing.T, root string, overrides Overrides) (*Controller, string) {
	t.Helper()
	kubeletRoot := t.TempDir()
	dir := filepath.Join(kubeletRoot, "pahlevan")

	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{
		window: time.Minute, blocking: true, ok: true, overrides: overrides,
	})
	c.SeccompDir = dir
	if root == "" {
		c.SeccompRoot = kubeletRoot
	} else {
		c.SeccompRoot = root
	}
	c.Node = "node-1"

	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257}))
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 0}))
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	return c, dir
}

// The profile was written to a node-local directory and nothing said where. A
// pod's seccompProfile cannot change after admission and there is no mutating
// webhook, so an operator has to reference it themselves; without this they
// would need to know the agent's flags and go looking on the node.
func TestSeccompProfileIsReportedOnTheProfile(t *testing.T) {
	c, dir := seccompController(t, "", Overrides{})

	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref, "the generated profile must be reported")

	assert.Equal(t, "node-1", ref.Node, "the file only exists on the node that wrote it")
	assert.Equal(t, dir, filepath.Dir(ref.Path))
	assert.NotEmpty(t, ref.LocalhostProfile)

	_, err := os.Stat(ref.Path)
	require.NoError(t, err, "the reported path must exist on disk")
}

// localhostProfile must be relative to the kubelet's seccomp root, which is
// what the pod spec field expects.
func TestSeccompLocalhostProfileIsRelativeToTheKubeletRoot(t *testing.T) {
	c, dir := seccompController(t, "", Overrides{})
	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref)

	assert.True(t, filepath.IsAbs(ref.Path), "the node path is absolute")
	assert.False(t, filepath.IsAbs(ref.LocalhostProfile),
		"localhostProfile is relative to the kubelet seccomp root, not absolute")
	assert.Equal(t, filepath.Join("pahlevan", filepath.Base(ref.Path)), ref.LocalhostProfile)
	assert.Equal(t, dir, filepath.Dir(ref.Path))
}

// A profile written outside the kubelet root cannot be referenced, so reporting
// a value the kubelet would fail to resolve is worse than reporting none.
func TestSeccompLocalhostProfileEmptyWhenOutsideTheRoot(t *testing.T) {
	c, _ := seccompController(t, "/somewhere/else", Overrides{})
	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref)
	assert.Empty(t, ref.LocalhostProfile,
		"a path outside the kubelet root has no usable localhostProfile")
	assert.NotEmpty(t, ref.Path, "the absolute path is still reported for debugging")
}

func TestSeccompCountsDescribeThePrivilegeReduction(t *testing.T) {
	c, _ := seccompController(t, "", Overrides{})
	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref)

	assert.Equal(t, int32(seccomp.KnownSyscallCount()), ref.TotalSyscalls)
	assert.Greater(t, ref.AllowedSyscalls, int32(0))
	assert.Less(t, ref.AllowedSyscalls, ref.TotalSyscalls,
		"a profile allowing everything would not be a reduction")
	assert.Zero(t, ref.SkippedUnknown)
	require.NotNil(t, ref.GeneratedAt)
}

// A learned syscall number with no name in this architecture's table cannot go
// in a profile, so the profile is narrower than what was observed and that is
// worth reporting rather than hiding.
func TestSeccompReportsSkippedUnknownSyscalls(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	root := t.TempDir()
	c.SeccompDir = filepath.Join(root, "pahlevan")
	c.SeccompRoot = root

	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257}))
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 1 << 40}))
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref)
	assert.Equal(t, int32(1), ref.SkippedUnknown)
}

// The file on disk must be the profile the status describes.
func TestSeccompFileMatchesTheReportedCounts(t *testing.T) {
	c, _ := seccompController(t, "", Overrides{AllowedSyscalls: []string{"ptrace"}})
	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	require.NotNil(t, ref)

	data, err := os.ReadFile(ref.Path)
	require.NoError(t, err, "the reported path must actually exist")

	var decoded struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names []string `json:"names"`
		} `json:"syscalls"`
	}
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "SCMP_ACT_ERRNO", decoded.DefaultAction)
	require.Len(t, decoded.Syscalls, 1)
	assert.Len(t, decoded.Syscalls[0].Names, int(ref.AllowedSyscalls),
		"the reported count must match the file")
	assert.Contains(t, decoded.Syscalls[0].Names, "ptrace",
		"the policy's allow list must be in the emitted file")
}

// With emission off, nothing is written and nothing is claimed.
func TestSeccompNotReportedWhenDisabled(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257}))
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	c.mu.Lock()
	ref := c.state[42].seccomp
	c.mu.Unlock()
	assert.Nil(t, ref, "no SeccompDir means no profile and nothing to report")
}
