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

package observability

import (
	"context"
	"testing"
	"time"
)

func TestNewManager_ParsesExportersAndInitsProviders(t *testing.T) {
	m, err := NewManager("prometheus, otlp ,datadog")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m == nil {
		t.Fatal("nil manager")
	}
	if m.GetMeter() == nil {
		t.Fatal("meter should be initialized when metrics enabled")
	}
	if m.GetTracer() == nil {
		t.Fatal("tracer should be initialized when tracing enabled")
	}
	if len(m.config.MetricsExporters) != 3 {
		t.Fatalf("expected 3 metrics exporters, got %d", len(m.config.MetricsExporters))
	}
	// Endpoints defaulted per known exporter type.
	var promEndpoint, otlpEndpoint string
	for _, e := range m.config.MetricsExporters {
		switch e.Type {
		case ExporterTypePrometheus:
			promEndpoint = e.Endpoint
		case ExporterTypeOTLP:
			otlpEndpoint = e.Endpoint
		}
	}
	if promEndpoint != ":8080/metrics" {
		t.Errorf("prometheus endpoint = %q", promEndpoint)
	}
	if otlpEndpoint != "localhost:4317" {
		t.Errorf("otlp endpoint = %q", otlpEndpoint)
	}
}

func TestNewManager_EmptyExporterList(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if len(m.config.MetricsExporters) != 0 {
		t.Fatalf("expected no exporters, got %d", len(m.config.MetricsExporters))
	}
	if m.config.ServiceName != "pahlevan-operator" {
		t.Errorf("unexpected service name %q", m.config.ServiceName)
	}
}

// Constructing the manager repeatedly (each call resets the global OTel
// providers) must not panic or error.
func TestNewManager_RepeatedConstruction(t *testing.T) {
	for i := 0; i < 3; i++ {
		m, err := NewManager("console")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if err := m.Shutdown(); err != nil {
			t.Fatalf("shutdown %d: %v", i, err)
		}
	}
}

func TestManager_CreateInstruments(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	counter, err := m.CreateCounter("test_counter", "desc", "1")
	if err != nil {
		t.Fatalf("CreateCounter: %v", err)
	}
	counter.Add(context.Background(), 1)

	gauge, err := m.CreateGauge("test_gauge", "desc", "1")
	if err != nil {
		t.Fatalf("CreateGauge: %v", err)
	}
	gauge.Record(context.Background(), 1.5)

	hist, err := m.CreateHistogram("test_hist", "desc", "s")
	if err != nil {
		t.Fatalf("CreateHistogram: %v", err)
	}
	hist.Record(context.Background(), 0.2)

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, name := range []string{"test_counter", "test_gauge", "test_hist"} {
		if _, ok := m.customMetrics[name]; !ok {
			t.Errorf("custom metric %q not tracked", name)
		}
	}
}

func TestManager_CreateDashboard(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cfg := DashboardConfig{
		Name: "test",
		Type: DashboardTypeGrafana,
		Panels: []PanelConfig{
			{
				Title: "p1",
				Type:  PanelTypeGraph,
				Query: "up",
				Thresholds: []ThresholdConfig{
					{Value: 5, Color: "red", Op: ConditionOperatorGT},
				},
			},
		},
		Variables: []VariableConfig{
			{Name: "ns", Type: VariableTypeQuery, Default: "default"},
		},
	}
	d, err := m.CreateDashboard(cfg)
	if err != nil {
		t.Fatalf("CreateDashboard: %v", err)
	}
	if d.Name != "test" || len(d.Panels) != 1 || len(d.Variables) != 1 {
		t.Fatalf("unexpected dashboard %+v", d)
	}
	if len(d.Panels[0].Thresholds) != 1 || d.Panels[0].Thresholds[0].Value != 5 {
		t.Fatalf("threshold not carried over: %+v", d.Panels[0].Thresholds)
	}
	if d.Variables[0].Current != "default" {
		t.Fatalf("variable default not applied: %+v", d.Variables[0])
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.dashboards[d.ID]; !ok {
		t.Fatal("dashboard not stored")
	}
}

func TestManager_CreateAlertRule(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cfg := AlertRuleConfig{
		Name:      "test-rule",
		Query:     "rate(x[5m]) > 1",
		Severity:  AlertSeverityCritical,
		Frequency: time.Minute,
		For:       5 * time.Minute,
		Conditions: []ConditionConfig{
			{Operator: ConditionOperatorGT, Value: 1, Evaluator: EvaluatorTypeAvg},
		},
		Actions: []ActionConfig{
			{Type: ActionTypeSlack, Recipients: []string{"#ops"}},
		},
	}
	r, err := m.CreateAlertRule(cfg)
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if r.State != AlertStateOK {
		t.Fatalf("new alert rule should start OK, got %s", r.State)
	}
	if len(r.Conditions) != 1 || len(r.Actions) != 1 {
		t.Fatalf("conditions/actions not copied: %+v", r)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.alertRules[r.ID]; !ok {
		t.Fatal("alert rule not stored")
	}
}

func TestManager_StartCreatesDefaults(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	exp := &MockExporter{Type: ExporterTypePrometheus}
	m.RegisterExporter(exp)

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.mu.RLock()
	nDash := len(m.dashboards)
	nRules := len(m.alertRules)
	m.mu.RUnlock()
	if nDash == 0 {
		t.Fatal("Start should create at least one default dashboard")
	}
	if nRules == 0 {
		t.Fatal("Start should create at least one default alert rule")
	}
	if err := m.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestManager_ExportObservabilityData(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// A failing exporter must not break the export call (errors are logged).
	m.RegisterExporter(&MockExporter{Type: ExporterTypePrometheus})

	data, err := m.ExportObservabilityData()
	if err != nil {
		t.Fatalf("ExportObservabilityData: %v", err)
	}
	if data.Source != "pahlevan-operator" {
		t.Errorf("source = %q", data.Source)
	}
	if data.Labels["service"] != "pahlevan-operator" {
		t.Errorf("service label missing: %+v", data.Labels)
	}
	if data.Metrics == nil || data.Traces == nil || data.Logs == nil || data.Events == nil {
		t.Fatal("export data collections must be initialized")
	}
}

func TestManager_RegisterExporter(t *testing.T) {
	m, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.RegisterExporter(&MockExporter{Type: ExporterTypeJaeger})
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.exporters) != 1 {
		t.Fatalf("expected 1 exporter, got %d", len(m.exporters))
	}
}
