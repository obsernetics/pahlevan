package adaptive

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/seccomp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// familyValue reads the single value of a scalar counter or gauge family from a
// registry. The policy-plane series are what an operator's dashboard reads, so
// these tests assert on the gathered output rather than on internal state.
func familyValue(t *testing.T, g prometheus.Gatherer, name string) (float64, bool) {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		require.Len(t, f.Metric, 1, "%s should have exactly one series", name)
		return metricValue(f.Metric[0]), true
	}
	return 0, false
}

func metricValue(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	case m.Histogram != nil:
		return float64(m.Histogram.GetSampleCount())
	}
	return 0
}

func metricsController(t *testing.T, enf Enforcer, pol PolicyResolver) (*Controller, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	c := NewController(logr.Discard(), enf, nil, pol)
	c.Metrics = metrics.NewManagerWithRegisterer(reg, reg)
	return c, reg
}

// A container reaching enforcement must be visible on /metrics. Before this
// wiring every one of these series was registered-but-never-written, so a
// working agent and a broken one produced identical (zero) output.
func TestMetricsRecordedOnEnforceTransition(t *testing.T) {
	enf := &fakeEnforcer{}
	c, reg := metricsController(t, enf, fakePolicies{window: time.Minute, blocking: true, ok: true})

	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257})
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 1})
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/hostname"})
	_ = c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 42, Capability: 21})

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42], "precondition: container must be enforcing")

	v, ok := familyValue(t, reg, "pahlevan_enforcement_actions_total")
	require.True(t, ok, "enforcement actions must be exported")
	assert.Equal(t, float64(1), v)

	v, ok = familyValue(t, reg, "pahlevan_container_learning_duration_seconds")
	require.True(t, ok, "learning duration must be exported")
	assert.Equal(t, float64(1), v, "one observation")

	// The privilege reduction is measured against the real syscall table.
	v, ok = familyValue(t, reg, "pahlevan_privilege_reduction_ratio")
	require.True(t, ok)
	expected := 1 - 2/float64(seccomp.KnownSyscallCount())
	assert.InDelta(t, expected, v, 1e-9)
	assert.Greater(t, v, 0.9, "learning two syscalls should be a large reduction")
}

// Denials must only be counted while enforcing: a denial seen during learning
// is not attributable to a baseline this controller installed.
func TestPolicyViolationsCountedOnlyWhileEnforcing(t *testing.T) {
	enf := &fakeEnforcer{}
	c, reg := metricsController(t, enf, fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// Denied while still learning: not a policy violation. The series exists
	// (it is registered unconditionally) but must still read zero.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	v, ok := familyValue(t, reg, "pahlevan_policy_violations_total")
	require.True(t, ok)
	assert.Equal(t, float64(0), v, "no violation should be recorded during learning")

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42])

	// Now the same denial is a real enforcement hit, across every signal.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	_ = c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 42, Filename: "/usr/bin/nc", Flags: DeniedFlag})
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 42, Direction: DeniedDirection})
	_ = c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 42, Capability: 21, Flags: DeniedFlag})

	v, ok = familyValue(t, reg, "pahlevan_policy_violations_total")
	require.True(t, ok)
	assert.Equal(t, float64(4), v, "one per denied signal")
}

func TestMetricsRecordedOnRollback(t *testing.T) {
	enf := &fakeEnforcer{}
	c, reg := metricsController(t, enf, fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257})

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	require.True(t, enf.enforced[42])

	// Drive past the denial threshold inside the observation window.
	for i := 0; i < c.Rollback.DenialThreshold; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	}
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()
	require.False(t, enf.enforced[42], "precondition: rollback must have happened")

	v, ok := familyValue(t, reg, "pahlevan_rollback_actions_total")
	require.True(t, ok, "rollbacks must be exported")
	assert.Equal(t, float64(1), v)

	v, ok = familyValue(t, reg, "pahlevan_self_healing_actions_total")
	require.True(t, ok, "self-healing actions must be exported")
	assert.Equal(t, float64(1), v)
}

func TestFleetGaugesTrackPhases(t *testing.T) {
	enf := &fakeEnforcer{}
	c, reg := metricsController(t, enf, fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	for _, id := range []uint64{1, 2, 3, 4} {
		_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: id, SyscallNr: 257})
	}
	c.Reconcile() // still learning: window has not elapsed

	tracked, ok := familyValue(t, reg, "pahlevan_containers_tracked")
	require.True(t, ok)
	assert.Equal(t, float64(4), tracked)
	learning, _ := familyValue(t, reg, "pahlevan_containers_learning")
	assert.Equal(t, float64(4), learning)
	enforced, _ := familyValue(t, reg, "pahlevan_containers_enforced")
	assert.Equal(t, float64(0), enforced)
	progress, ok := familyValue(t, reg, "pahlevan_learning_progress_ratio")
	require.True(t, ok)
	assert.Equal(t, float64(0), progress)

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	enforced, _ = familyValue(t, reg, "pahlevan_containers_enforced")
	assert.Equal(t, float64(4), enforced)
	learning, _ = familyValue(t, reg, "pahlevan_containers_learning")
	assert.Equal(t, float64(0), learning)
	progress, _ = familyValue(t, reg, "pahlevan_learning_progress_ratio")
	assert.Equal(t, float64(1), progress)
}

// An empty node must report zero progress rather than NaN from a 0/0 divide.
func TestFleetGaugesEmptyStateIsNotNaN(t *testing.T) {
	c, reg := metricsController(t, &fakeEnforcer{}, fakePolicies{ok: false})
	c.Reconcile()
	progress, ok := familyValue(t, reg, "pahlevan_learning_progress_ratio")
	require.True(t, ok)
	assert.Equal(t, float64(0), progress)
	assert.False(t, progress != progress, "must not be NaN")
}

// A controller with no metrics manager must behave identically. This is the
// configuration every other test in the package uses.
func TestNilMetricsManagerIsSafe(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{window: time.Minute, blocking: true, ok: true})
	require.Nil(t, c.Metrics)

	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257})
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})

	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	assert.NotPanics(t, func() { c.Reconcile() })
	assert.True(t, enf.enforced[42])
}

func BenchmarkHandleFileEventDeniedWithMetrics(b *testing.B) {
	reg := prometheus.NewRegistry()
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	c.Metrics = metrics.NewManagerWithRegisterer(reg, reg)
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257})
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()

	ev := &ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleFileEvent(ev)
	}
}

func BenchmarkRecordFleetMetrics(b *testing.B) {
	reg := prometheus.NewRegistry()
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{ok: false})
	c.Metrics = metrics.NewManagerWithRegisterer(reg, reg)
	for id := uint64(0); id < 500; id++ {
		_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: id + 1, SyscallNr: 257})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.mu.Lock()
		c.recordFleetMetrics()
		c.mu.Unlock()
	}
}
