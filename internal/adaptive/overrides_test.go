package adaptive

import (
	"net"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func learnOne(t *testing.T, c *Controller, id uint64, at time.Time) {
	t.Helper()
	c.now = func() time.Time { return at }
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: id, SyscallNr: 257}))
}

// The grace period was parsed from the CRD and dropped: enforcement began the
// moment the learning window closed, no matter what the policy asked for.
func TestGracePeriodDelaysEnforcement(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{
		window: time.Minute, gracePeriod: 2 * time.Minute, blocking: true, ok: true,
	})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)

	// Past the learning window but inside the grace period.
	c.now = func() time.Time { return base.Add(90 * time.Second) }
	c.Reconcile()
	assert.False(t, enf.enforced[42], "grace period must hold enforcement back")

	// Past both.
	c.now = func() time.Time { return base.Add(3*time.Minute + time.Second) }
	c.Reconcile()
	assert.True(t, enf.enforced[42], "enforcement must begin after window plus grace")
}

func TestZeroGracePeriodEnforcesAtTheWindow(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)

	c.now = func() time.Time { return base.Add(time.Minute) }
	c.Reconcile()
	assert.True(t, enf.enforced[42])
}

// Overrides must reach the kernel allow-sets, or a policy exception is just a
// comment in a YAML file.
func TestOverridesAreSeededIntoTheKernel(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{
		window: time.Minute, blocking: true, ok: true,
		overrides: Overrides{
			AllowedFiles:        []string{"/etc/resolv.conf"},
			DeniedFiles:         []string{"/etc/shadow"},
			AllowedExecs:        []string{"/usr/bin/curl"},
			DeniedExecs:         []string{"/usr/bin/nc"},
			AllowedCapabilities: []uint32{12},
			DeniedCapabilities:  []uint32{21},
			AllowedDestinations: []Destination{{IP: net.ParseIP("10.96.0.10"), Port: 53}},
			DeniedDestinations:  []Destination{{IP: net.ParseIP("1.2.3.4"), Port: 4444}},
		},
	})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42])

	assert.Equal(t, true, enf.files["/etc/resolv.conf"])
	assert.Equal(t, false, enf.files["/etc/shadow"], "denied paths are revoked, not added")
	assert.Equal(t, true, enf.execs["/usr/bin/curl"])
	assert.Equal(t, false, enf.execs["/usr/bin/nc"])
	assert.Equal(t, true, enf.caps[12])
	assert.Equal(t, false, enf.caps[21])
	assert.Equal(t, true, enf.dests["10.96.0.10:53"])
	assert.Equal(t, false, enf.dests["1.2.3.4:4444"])
}

// Seeding must happen before the mode flips, or there is a window in which a
// legitimately excepted path is denied. Brief, but long enough to kill a pod.
func TestOverridesAreSeededBeforeEnforcementIsEnabled(t *testing.T) {
	enf := &orderedEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{
		window: time.Minute, blocking: true, ok: true,
		overrides: Overrides{AllowedFiles: []string{"/etc/resolv.conf"}},
	})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	require.Contains(t, enf.calls, "seed:/etc/resolv.conf")
	require.Contains(t, enf.calls, "enforce:file")
	assert.Less(t,
		indexOf(enf.calls, "seed:/etc/resolv.conf"),
		indexOf(enf.calls, "enforce:file"),
		"the exception must be installed before enforcement starts")
}

// A kernel without the BPF LSM cannot hold the allow-sets. One unseedable
// exception must not stop the rest of the transition.
func TestSeedingErrorsDoNotBlockEnforcement(t *testing.T) {
	enf := &fakeEnforcer{}
	enf.err = errAllowSetWrite
	c := NewController(logr.Discard(), enf, nil, fakePolicies{
		window: time.Minute, blocking: true, ok: true,
		overrides: Overrides{AllowedFiles: []string{"/etc/resolv.conf", "/etc/hosts"}},
	})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	assert.True(t, enf.enforced[42], "a failed seed must not abandon the transition")
	assert.Len(t, enf.files, 2, "every entry is still attempted after the first failure")
}

func TestEmptyOverridesTouchNothing(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	assert.True(t, enf.enforced[42])
	assert.Empty(t, enf.files)
	assert.Empty(t, enf.dests)
}

// An Off policy is the operator saying "ignore this workload". It must cost no
// state, and must lift any enforcement a previous mode installed.
func TestOffPolicyDropsStateAndLiftsEnforcement(t *testing.T) {
	enf := &fakeEnforcer{}
	pol := &switchablePolicies{window: time.Minute, mode: ModeBlocking, ok: true}
	c := NewController(logr.Discard(), enf, nil, pol)

	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42], "precondition: enforcing")
	require.Len(t, c.Snapshot(), 1)

	// Flip the policy to Off; the next reconcile must clean up.
	pol.mode = ModeOff
	c.Reconcile()

	assert.False(t, enf.enforced[42], "enforcement must be lifted")
	assert.False(t, enf.netEnforced[42])
	assert.False(t, enf.execEnforced[42])
	assert.False(t, enf.capEnforced[42])
	assert.Empty(t, c.Snapshot(), "no profile should remain")
}

func TestOffPolicyDropsALearningContainer(t *testing.T) {
	enf := &fakeEnforcer{}
	pol := &switchablePolicies{window: time.Hour, mode: ModeOff, ok: true}
	c := NewController(logr.Discard(), enf, nil, pol)
	learnOne(t, c, 42, time.Unix(1700000000, 0))
	require.Len(t, c.Snapshot(), 1)

	c.Reconcile()
	assert.Empty(t, c.Snapshot())
}

// An unresolvable container must be kept, not dropped: no policy yet is not the
// same as a policy that says Off.
func TestUnresolvedContainerIsKept(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, &switchablePolicies{ok: false})
	learnOne(t, c, 42, time.Unix(1700000000, 0))
	c.Reconcile()
	assert.Len(t, c.Snapshot(), 1)
}

// The generated seccomp profile is the enforced artifact, so the operator's
// syscall lists have to be in it.
func TestSeccompProfileHonoursSyscallOverrides(t *testing.T) {
	dir := t.TempDir()
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{
		window: time.Minute, blocking: true, ok: true,
		overrides: Overrides{
			AllowedSyscalls: []string{"ptrace"},
			// Denies win over the safety baseline.
			DeniedSyscalls: []string{"futex"},
		},
	})
	c.SeccompDir = dir

	base := time.Unix(1700000000, 0)
	learnOne(t, c, 42, base)
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	profile := readOnlyProfile(t, dir)
	assert.Contains(t, profile, `"ptrace"`, "policy-allowed syscall must be in the profile")
	assert.NotContains(t, profile, `"futex"`, "policy-denied syscall must be removed, baseline or not")
}

func BenchmarkApplyOverrides(b *testing.B) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{ok: false})
	st := &cgState{}
	o := Overrides{
		AllowedFiles:        []string{"/etc/resolv.conf", "/etc/hosts", "/etc/ssl/cert.pem"},
		AllowedExecs:        []string{"/usr/bin/curl"},
		AllowedCapabilities: []uint32{12},
		AllowedDestinations: []Destination{{IP: net.ParseIP("10.96.0.10"), Port: 53}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.applyOverrides(1, st, o)
	}
}
