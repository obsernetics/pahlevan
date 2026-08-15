/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// gather collects a single metric family by name from the manager's gatherer.
func gather(t *testing.T, m *Manager, name string) *dto.MetricFamily {
	t.Helper()
	families, err := m.GetGatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() == name {
			return fam
		}
	}
	return nil
}

// counterValue returns the aggregate value of a non-vector counter/gauge family.
func scalarValue(t *testing.T, m *Manager, name string) float64 {
	t.Helper()
	fam := gather(t, m, name)
	if fam == nil {
		t.Fatalf("metric family %q not found", name)
	}
	if len(fam.Metric) != 1 {
		t.Fatalf("metric %q: expected 1 series, got %d", name, len(fam.Metric))
	}
	mt := fam.Metric[0]
	switch {
	case mt.Counter != nil:
		return mt.Counter.GetValue()
	case mt.Gauge != nil:
		return mt.Gauge.GetValue()
	default:
		t.Fatalf("metric %q is neither counter nor gauge", name)
		return 0
	}
}

func TestNewManager_RegistersAllMetricsWithoutPanic(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.GetRegistry() == nil || m.GetGatherer() == nil {
		t.Fatal("registry/gatherer must be non-nil")
	}
	families, err := m.GetGatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	// All 42 registered collectors expose at least one metric family after
	// touching zero-value counters/gauges; verify a representative core metric
	// is present.
	if fam := gather(t, m, "pahlevan_policy_violations_total"); fam == nil {
		t.Fatalf("core metric not registered; got %d families", len(families))
	}
}

// Each NewManager uses its own private registry, so constructing many managers
// must never trigger a Prometheus duplicate-registration panic.
func TestNewManager_MultipleConstructionsNoDuplicatePanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("constructing multiple managers panicked: %v", r)
		}
	}()
	for i := 0; i < 5; i++ {
		if m := NewManager(); m == nil {
			t.Fatal("nil manager")
		}
	}
}

func TestManager_ScalarRecorders(t *testing.T) {
	m := NewManager()
	labels := MetricLabels{ContainerID: "c1", PolicyName: "p1"}

	m.RecordPolicyViolation(labels)
	m.RecordPolicyViolation(labels)
	if v := scalarValue(t, m, "pahlevan_policy_violations_total"); v != 2 {
		t.Errorf("policy violations = %v, want 2", v)
	}

	m.RecordEnforcementAction(labels, "block")
	if v := scalarValue(t, m, "pahlevan_enforcement_actions_total"); v != 1 {
		t.Errorf("enforcement actions = %v, want 1", v)
	}

	m.RecordSelfHealingAction(labels)
	m.RecordRollbackAction(labels)
	if v := scalarValue(t, m, "pahlevan_self_healing_actions_total"); v != 1 {
		t.Errorf("self healing = %v, want 1", v)
	}
	if v := scalarValue(t, m, "pahlevan_rollback_actions_total"); v != 1 {
		t.Errorf("rollback = %v, want 1", v)
	}

	m.UpdateLearningProgress(labels, 0.75)
	if v := scalarValue(t, m, "pahlevan_learning_progress_ratio"); v != 0.75 {
		t.Errorf("learning progress = %v, want 0.75", v)
	}

	m.UpdateAttackSurfaceRiskScore(6.5)
	if v := scalarValue(t, m, "pahlevan_attack_surface_risk_score"); v != 6.5 {
		t.Errorf("risk score = %v, want 6.5", v)
	}

	m.UpdateHealthCheckScore(labels, 0.9)
	if v := scalarValue(t, m, "pahlevan_health_check_score"); v != 0.9 {
		t.Errorf("health score = %v, want 0.9", v)
	}

	m.UpdatePrivilegeReductionRatio(labels, 0.42)
	if v := scalarValue(t, m, "pahlevan_privilege_reduction_ratio"); v != 0.42 {
		t.Errorf("privilege reduction = %v, want 0.42", v)
	}
}

func TestManager_PolicyAndContainerCounts(t *testing.T) {
	m := NewManager()
	m.UpdatePolicyCounts(3, 1, 2, 0)
	if v := scalarValue(t, m, "pahlevan_policies_active"); v != 3 {
		t.Errorf("policies active = %v, want 3", v)
	}
	if v := scalarValue(t, m, "pahlevan_policies_enforcing"); v != 2 {
		t.Errorf("policies enforcing = %v, want 2", v)
	}

	m.UpdateContainerCounts(10, 4, 6)
	if v := scalarValue(t, m, "pahlevan_containers_tracked"); v != 10 {
		t.Errorf("containers tracked = %v, want 10", v)
	}
	if v := scalarValue(t, m, "pahlevan_containers_enforced"); v != 6 {
		t.Errorf("containers enforced = %v, want 6", v)
	}
}

func TestManager_VectorRecorders(t *testing.T) {
	// The per-container vectors only collect at DetailHigh; see
	// TestDetailLevelGating for the default behaviour.
	reg := prometheus.NewRegistry()
	m := NewManagerWithDetail(reg, reg, DetailHigh)
	labels := MetricLabels{ContainerID: "c1", PolicyName: "p1", WorkloadName: "w", Namespace: "ns"}

	m.RecordSyscallEvent(labels, "open", "allow")
	m.RecordBlockedSyscall(labels, "ptrace", "policy")
	m.RecordAllowedSyscall(labels, "read")
	m.RecordUnknownSyscall(labels, "9999")
	m.RecordSyscallLatency(labels, "open", 5*time.Millisecond)

	m.RecordNetworkEvent(labels, "tcp", "egress", "allow")
	m.RecordBlockedConnection(labels, "tcp", "10.0.0.1:22")
	m.RecordAllowedConnection(labels, "tcp", "10.0.0.2:80")
	m.UpdateActiveNetworkFlows(labels, "tcp", 4)
	m.RecordNetworkBandwidth(labels, "egress", 1024)

	m.RecordFileEvent(labels, "read", "allow")
	m.RecordBlockedFileAccess(labels, "/etc/shadow", "read")
	m.RecordAllowedFileAccess(labels, "/tmp/x", "write")
	m.RecordFileLatency(labels, "read", time.Millisecond)

	m.UpdatePolicyQualityScore(labels, 8.0)
	m.RecordContainerStartupTime("Deployment", "ns", 2*time.Second)

	m.UpdateExposedSyscalls(labels, "high", 3)
	m.UpdateExposedPorts("w", "ns", "tcp", 2)
	m.UpdateWritablePaths(labels, "host", 1)
	m.UpdateCapabilities(labels, "risky", 2)
	m.UpdateVulnerabilityScore(labels, "critical", 9.5)

	m.RecordEBPFProgramLoad(50 * time.Millisecond)
	m.RecordEBPFMapOperation("events", "update")
	m.UpdateMemoryUsage("agent", 1<<20)
	m.UpdateCPUUsage("agent", 12.5)
	m.RecordProcessingLatency("enforce", "agent", time.Millisecond)

	// Spot-check a labeled counter value.
	fam := gather(t, m, "pahlevan_syscall_events_total")
	if fam == nil || len(fam.Metric) != 1 {
		t.Fatalf("syscall events family missing or wrong series count")
	}
	if got := fam.Metric[0].Counter.GetValue(); got != 1 {
		t.Errorf("syscall events value = %v, want 1", got)
	}

	// Labeled bandwidth counter should reflect the added bytes.
	bw := gather(t, m, "pahlevan_network_bandwidth_bytes_total")
	if bw == nil || bw.Metric[0].Counter.GetValue() != 1024 {
		t.Errorf("bandwidth = %+v, want 1024", bw)
	}
}

func TestManager_CustomMetricLifecycle(t *testing.T) {
	m := NewManager()
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_custom_test_total",
		Help: "custom",
	})

	if err := m.RegisterCustomMetric("custom", c); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Duplicate registration under the same name is rejected.
	if err := m.RegisterCustomMetric("custom", c); err == nil {
		t.Fatal("expected error registering duplicate custom metric name")
	}
	c.Inc()
	if v := scalarValue(t, m, "pahlevan_custom_test_total"); v != 1 {
		t.Errorf("custom metric = %v, want 1", v)
	}

	if !m.UnregisterCustomMetric("custom") {
		t.Fatal("unregister should return true for known metric")
	}
	if m.UnregisterCustomMetric("custom") {
		t.Fatal("unregister of unknown metric should return false")
	}
	if fam := gather(t, m, "pahlevan_custom_test_total"); fam != nil {
		t.Fatal("custom metric should be gone after unregister")
	}
}

func TestManager_RegisterConflictingCustomMetric(t *testing.T) {
	m := NewManager()
	// A collector duplicating a built-in metric name must fail registration and
	// not be tracked.
	dup := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_policy_violations_total",
		Help: "dup",
	})
	if err := m.RegisterCustomMetric("dup", dup); err == nil {
		t.Fatal("expected duplicate-name registration to fail")
	}
	// Since registration failed it should not have been cached, so a later
	// re-register under the same key with a valid collector must succeed.
	ok := prometheus.NewCounter(prometheus.CounterOpts{Name: "pahlevan_ok_total", Help: "ok"})
	if err := m.RegisterCustomMetric("dup", ok); err != nil {
		t.Fatalf("re-register after failed attempt: %v", err)
	}
}

func TestManager_SetMeterProviderEnablesOTelPath(t *testing.T) {
	m := NewManager()
	// Before wiring OTel, the recorders must not panic on nil otel instruments.
	m.RecordPolicyViolation(MetricLabels{})
	m.UpdateAttackSurfaceRiskScore(1.0)

	provider := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	m.SetMeterProvider(provider)

	if m.meter == nil {
		t.Fatal("meter should be set after SetMeterProvider")
	}
	if m.otelPolicyViolationsTotal == nil {
		t.Fatal("otel counter should be initialized")
	}
	// Now the OTel branch is exercised as well.
	m.RecordPolicyViolation(MetricLabels{})
	m.RecordEnforcementAction(MetricLabels{}, "block")
	m.UpdateLearningProgress(MetricLabels{}, 0.5)
	m.UpdateAttackSurfaceRiskScore(7.0)

	// Prometheus counter still increments independently.
	// One violation before wiring OTel, one after: the Prometheus counter tracks
	// both regardless of the OTel path.
	if v := scalarValue(t, m, "pahlevan_policy_violations_total"); v != 2 {
		t.Errorf("prometheus violations = %v, want 2", v)
	}
}

func BenchmarkRecordSyscallEvent(b *testing.B) {
	m := NewManager()
	labels := MetricLabels{ContainerID: "c1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordSyscallEvent(labels, "open", "allow")
	}
}

func BenchmarkRecordPolicyViolation(b *testing.B) {
	m := NewManager()
	labels := MetricLabels{ContainerID: "c1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordPolicyViolation(labels)
	}
}
