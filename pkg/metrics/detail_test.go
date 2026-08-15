package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatheredNames(t *testing.T, g prometheus.Gatherer) map[string]bool {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	return names
}

func TestParseDetailLevel(t *testing.T) {
	assert.Equal(t, DetailHigh, ParseDetailLevel("high"))
	assert.Equal(t, DetailBasic, ParseDetailLevel("basic"))
	// A typo must not silently switch on the expensive path.
	assert.Equal(t, DetailBasic, ParseDetailLevel("hgih"))
	assert.Equal(t, DetailBasic, ParseDetailLevel(""))
	assert.Equal(t, DetailBasic, ParseDetailLevel("HIGH"))
}

// The whole package used to be inert: registerAllMetrics was never called, so
// no pahlevan_* policy-plane series reached /metrics at all.
func TestManagerRegistersBoundedMetricsByDefault(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithRegisterer(reg, reg)
	require.Equal(t, DetailBasic, m.Detail())

	// Give the bounded collectors a value so they are gathered.
	m.RecordPolicyViolation(MetricLabels{})
	m.RecordEnforcementAction(MetricLabels{}, "enforce")
	m.RecordRollbackAction(MetricLabels{})
	m.UpdateContainerCounts(3, 2, 1)

	names := gatheredNames(t, reg)
	for _, want := range []string{
		"pahlevan_policy_violations_total",
		"pahlevan_enforcement_actions_total",
		"pahlevan_rollback_actions_total",
		"pahlevan_containers_tracked",
	} {
		assert.True(t, names[want], "%s must be registered at DetailBasic", want)
	}
}

// At DetailBasic the per-container vectors must be neither registered nor fed.
// Feeding an unregistered vector would grow its children forever for series
// nobody can scrape.
func TestDetailLevelGating(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithRegisterer(reg, reg)
	labels := MetricLabels{ContainerID: "c1", PolicyName: "p1"}

	m.RecordSyscallEvent(labels, "open", "allow")
	m.RecordBlockedSyscall(labels, "ptrace", "policy")
	m.RecordBlockedFileAccess(labels, "/etc/shadow", "read")
	m.RecordBlockedConnection(labels, "tcp", "10.0.0.1:22")
	m.UpdateExposedSyscalls(labels, "learned", 7)
	m.UpdateWritablePaths(labels, "learned", 2)
	m.UpdateCapabilities(labels, "learned", 1)
	m.UpdateVulnerabilityScore(labels, "critical", 9)
	m.UpdatePolicyQualityScore(labels, 5)
	m.RecordSyscallLatency(labels, "open", time.Millisecond)
	m.UpdateActiveNetworkFlows(labels, "tcp", 3)
	m.RecordNetworkBandwidth(labels, "egress", 512)

	names := gatheredNames(t, reg)
	for _, unwanted := range []string{
		"pahlevan_syscall_events_total",
		"pahlevan_blocked_syscalls_total",
		"pahlevan_blocked_file_access_total",
		"pahlevan_blocked_connections_total",
		"pahlevan_exposed_syscalls_total",
	} {
		assert.False(t, names[unwanted], "%s must be absent at DetailBasic", unwanted)
	}

	// No children accumulated in the ungathered vectors either.
	assert.Equal(t, 0, testCollectAndCount(t, m.syscallEventsTotal))
	assert.Equal(t, 0, testCollectAndCount(t, m.blockedFileAccessTotal))
	assert.Equal(t, 0, testCollectAndCount(t, m.exposedSyscallsTotal))
}

func TestDetailHighRegistersPerContainerMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithDetail(reg, reg, DetailHigh)
	require.True(t, m.HighDetail())

	labels := MetricLabels{ContainerID: "c1"}
	m.RecordSyscallEvent(labels, "open", "allow")
	m.UpdateExposedSyscalls(labels, "learned", 7)

	names := gatheredNames(t, reg)
	assert.True(t, names["pahlevan_syscall_events_total"])
	assert.True(t, names["pahlevan_exposed_syscalls_total"])
	assert.Equal(t, 1, testCollectAndCount(t, m.syscallEventsTotal))
}

// A nil Manager must answer HighDetail without panicking: callers use it to
// decide whether to build expensive labels before checking for nil.
func TestHighDetailNilSafe(t *testing.T) {
	var m *Manager
	assert.False(t, m.HighDetail())
}

// Two managers on one shared registry must not panic. The agent and any test
// helper can both construct one against the controller-runtime registry.
func TestDuplicateRegistrationIsTolerated(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = NewManagerWithRegisterer(reg, reg)
	assert.NotPanics(t, func() { _ = NewManagerWithRegisterer(reg, reg) })
}

func testCollectAndCount(t *testing.T, c prometheus.Collector) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	go func() { c.Collect(ch); close(ch) }()
	n := 0
	for range ch {
		n++
	}
	return n
}

// The gated path must be cheap enough that leaving the call in the hot path
// costs nothing at DetailBasic.
func BenchmarkRecordSyscallEventGatedOff(b *testing.B) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithRegisterer(reg, reg)
	labels := MetricLabels{ContainerID: "c1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordSyscallEvent(labels, "open", "allow")
	}
}

func BenchmarkRecordSyscallEventHighDetail(b *testing.B) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithDetail(reg, reg, DetailHigh)
	labels := MetricLabels{ContainerID: "c1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordSyscallEvent(labels, "open", "allow")
	}
}
