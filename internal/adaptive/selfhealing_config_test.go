package adaptive

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enforceThen drives a container to enforcing and returns the controller,
// enforcer, and the base time so a test can then generate denials.
func enforceThen(t *testing.T, pol fakePolicies) (*Controller, *fakeEnforcer, time.Time) {
	t.Helper()
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, pol)
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	require.NoError(t, c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257}))
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42], "precondition: container must be enforcing")
	return c, enf, base
}

func denyN(c *Controller, n int) {
	for i := 0; i < n; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	}
}

// spec.selfHealing.enabled was ignored, so a policy that switched self-healing
// off still had its containers un-enforced by denial noise. An attacker
// generating denials could therefore turn enforcement off.
func TestSelfHealingDisabledKeepsEnforcing(t *testing.T) {
	c, enf, base := enforceThen(t, fakePolicies{
		window: time.Minute, blocking: true, ok: true, selfHealingDisabled: true,
	})

	denyN(c, 1000)
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	assert.True(t, enf.enforced[42],
		"a policy with self-healing off must stay enforcing however many denials arrive")
}

func TestSelfHealingEnabledRollsBack(t *testing.T) {
	c, enf, base := enforceThen(t, fakePolicies{
		window: time.Minute, blocking: true, ok: true,
	})

	denyN(c, c.Rollback.DenialThreshold)
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	assert.False(t, enf.enforced[42])
}

// rollbackThreshold was accepted by the API and never read.
func TestPolicyRollbackThresholdIsHonoured(t *testing.T) {
	pol := fakePolicies{
		window: time.Minute, blocking: true, ok: true, rollbackThreshold: 3,
	}
	c, enf, base := enforceThen(t, pol)

	// Two denials is under the policy's threshold of three, though it would
	// also be under the default of ten.
	denyN(c, 2)
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42], "under the threshold, enforcement should hold")

	// The third crosses it, well before the compiled-in default would.
	denyN(c, 1)
	c.Reconcile()
	assert.False(t, enf.enforced[42], "the policy's threshold of 3 should have fired")
}

// A policy can also raise the threshold above the default.
func TestPolicyRollbackThresholdCanBeRaised(t *testing.T) {
	c, enf, base := enforceThen(t, fakePolicies{
		window: time.Minute, blocking: true, ok: true, rollbackThreshold: 500,
	})

	denyN(c, 100) // ten times the default, still under the policy's threshold
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()
	assert.True(t, enf.enforced[42], "the policy raised the threshold to 500")
}

// rollbackWindow was likewise accepted and never read.
func TestPolicyRollbackWindowIsHonoured(t *testing.T) {
	c, enf, base := enforceThen(t, fakePolicies{
		window: time.Minute, blocking: true, ok: true, rollbackWindow: 30 * time.Second,
	})

	denyN(c, 1000)
	// Four minutes after the transition: inside the 5m default, outside the
	// policy's 30s window, so the baseline is settled and must stand.
	c.now = func() time.Time { return base.Add(6 * time.Minute) }
	c.Reconcile()
	assert.True(t, enf.enforced[42],
		"denials past the policy's rollback window must not un-enforce the container")
}

func TestRollbackConfigDefaultsWhenPolicyIsSilent(t *testing.T) {
	c, _, _ := enforceThen(t, fakePolicies{window: time.Minute, blocking: true, ok: true})
	c.mu.Lock()
	cfg := c.rollbackConfigFor(42, c.state[42])
	c.mu.Unlock()
	assert.Equal(t, c.Rollback.DenialThreshold, cfg.DenialThreshold)
	assert.Equal(t, c.Rollback.ObservationWindow, cfg.ObservationWindow)
}

// An unresolvable container falls back to the controller defaults rather than
// silently losing its rollback protection.
func TestRollbackConfigFallsBackWhenUnresolved(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: false})
	st := &cgState{}
	c.mu.Lock()
	cfg := c.rollbackConfigFor(1, st)
	c.mu.Unlock()
	assert.Equal(t, c.Rollback, cfg)
}

func BenchmarkRollbackConfigFor(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true, rollbackThreshold: 3})
	st := &cgState{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.rollbackConfigFor(1, st)
	}
}
