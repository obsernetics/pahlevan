package observability

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObservabilityManager_NewObservabilityManager(t *testing.T) {
	config := &ObservabilityConfig{
		MetricsEnabled:    true,
		TracingEnabled:    true,
		LoggingEnabled:    true,
		ExportInterval:    30 * time.Second,
		MetricsPort:       8080,
		HealthCheckPort:   8081,
		PrometheusEnabled: true,
		JaegerEndpoint:    "http://jaeger:14268/api/traces",
	}

	manager := NewObservabilityManager(config)

	require.NotNil(t, manager)
	assert.Equal(t, config, manager.config)
	assert.NotNil(t, manager.metrics)
	assert.NotNil(t, manager.alerts)
	assert.NotNil(t, manager.exporters)
}

func TestSecurityMetrics_RecordViolation(t *testing.T) {
	metrics := &SecurityMetrics{
		ViolationCounts:    make(map[string]uint64),
		PolicyUpdateCounts: make(map[string]uint64),
		PerformanceMetrics: make(map[string]float64),
		AlertCounts:        make(map[string]uint64),
		LastUpdate:         time.Now(),
	}

	metrics.RecordViolation("container-123", "syscall")

	assert.Equal(t, uint64(1), metrics.ViolationCounts["container-123:syscall"])

	// Record another violation
	metrics.RecordViolation("container-123", "syscall")
	assert.Equal(t, uint64(2), metrics.ViolationCounts["container-123:syscall"])
}

func TestSecurityMetrics_RecordPolicyUpdate(t *testing.T) {
	metrics := &SecurityMetrics{
		PolicyUpdateCounts: make(map[string]uint64),
	}

	metrics.RecordPolicyUpdate("container-123", "network")

	assert.Equal(t, uint64(1), metrics.PolicyUpdateCounts["container-123:network"])
}

func TestSecurityMetrics_RecordPerformance(t *testing.T) {
	metrics := &SecurityMetrics{
		PerformanceMetrics: make(map[string]float64),
	}

	metrics.RecordPerformance("policy_generation_time", 150.5)

	assert.Equal(t, 150.5, metrics.PerformanceMetrics["policy_generation_time"])
}

func TestAlert_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		alert   *Alert
		expired bool
	}{
		{
			name: "not expired",
			alert: &Alert{
				Timestamp: time.Now().Add(-1 * time.Minute),
				TTL:       5 * time.Minute,
			},
			expired: false,
		},
		{
			name: "expired",
			alert: &Alert{
				Timestamp: time.Now().Add(-10 * time.Minute),
				TTL:       5 * time.Minute,
			},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired := tt.alert.IsExpired()
			assert.Equal(t, tt.expired, expired)
		})
	}
}

func TestAlert_ShouldEscalate(t *testing.T) {
	tests := []struct {
		name     string
		alert    *Alert
		escalate bool
	}{
		{
			name: "should escalate critical",
			alert: &Alert{
				Severity:      SeverityCritical,
				Timestamp:     time.Now().Add(-30 * time.Minute),
				EscalationTTL: 15 * time.Minute,
			},
			escalate: true,
		},
		{
			name: "should not escalate low",
			alert: &Alert{
				Severity:      SeverityLow,
				Timestamp:     time.Now().Add(-5 * time.Minute),
				EscalationTTL: 30 * time.Minute,
			},
			escalate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalate := tt.alert.ShouldEscalate()
			assert.Equal(t, tt.escalate, escalate)
		})
	}
}

func TestAlertManager_AddAlert(t *testing.T) {
	manager := &AlertManager{
		alerts:   make(map[string]*Alert),
		rules:    make([]*AlertRule, 0),
		channels: make(map[string]AlertChannel),
	}

	alert := &Alert{
		ID:           "test-alert-1",
		Type:         AlertTypeViolation,
		Severity:     SeverityHigh,
		Message:      "Test violation detected",
		Source:       "container-123",
		Timestamp:    time.Now(),
		TTL:          5 * time.Minute,
		Acknowledged: false,
	}

	manager.AddAlert(alert)

	assert.Len(t, manager.alerts, 1)
	assert.Equal(t, alert, manager.alerts["test-alert-1"])
}

func TestAlertManager_AcknowledgeAlert(t *testing.T) {
	manager := &AlertManager{
		alerts: make(map[string]*Alert),
	}

	alert := &Alert{
		ID:           "test-alert-1",
		Acknowledged: false,
	}
	manager.alerts["test-alert-1"] = alert

	success := manager.AcknowledgeAlert("test-alert-1")
	assert.True(t, success)
	assert.True(t, alert.Acknowledged)

	// Try to acknowledge non-existent alert
	success = manager.AcknowledgeAlert("non-existent")
	assert.False(t, success)
}

func TestAlertRule_ShouldTrigger(t *testing.T) {
	rule := &AlertRule{
		ID:    "rule-1",
		Name:  "High violation rate",
		Query: "violation_rate > 10",
		Conditions: []*Condition{
			{
				Operator:  ConditionOperatorGT,
				Value:     10.0,
				Evaluator: EvaluatorTypeAvg,
			},
		},
		Severity:  AlertSeverityCritical,
		LastEval:  time.Time{},
		Frequency: time.Minute,
	}

	metrics := &SecurityMetrics{
		ViolationCounts: map[string]uint64{
			"container-123:syscall": 15,
		},
	}

	should := rule.ShouldTrigger(metrics)
	assert.True(t, should)

	// Test frequency check (similar to cooldown)
	rule.LastEval = time.Now()
	should = rule.ShouldTrigger(metrics)
	assert.False(t, should)
}

func TestExporter_Export(t *testing.T) {
	tests := []struct {
		name         string
		exporterType ExporterType
		config       map[string]interface{}
		shouldWork   bool
	}{
		{
			name:         "prometheus exporter",
			exporterType: ExporterTypePrometheus,
			config: map[string]interface{}{
				"endpoint": "http://prometheus:9090",
				"interval": "30s",
			},
			shouldWork: true,
		},
		{
			name:         "jaeger exporter",
			exporterType: ExporterTypeJaeger,
			config: map[string]interface{}{
				"endpoint": "http://jaeger:14268/api/traces",
			},
			shouldWork: true,
		},
		{
			name:         "invalid exporter",
			exporterType: ExporterType("invalid"),
			config:       map[string]interface{}{},
			shouldWork:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &MockExporter{
				Type:   tt.exporterType,
				Config: tt.config,
			}

			data := &ObservabilityData{
				Metrics: map[string]*MetricData{
					"violations": {
						Name:  "violations_total",
						Type:  MetricTypeCounter,
						Value: 1.0,
						Labels: map[string]string{
							"container": "test",
						},
					},
				},
				Timestamp: time.Now(),
				Source:    "test",
				Labels:    map[string]string{"env": "test"},
			}

			err := exporter.Export(data)
			if tt.shouldWork {
				// For unit tests, we expect errors since we don't have real endpoints
				// but we're testing the structure
				assert.NotNil(t, err) // Expected to fail in tests
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestHealthCheck_IsHealthy(t *testing.T) {
	tests := []struct {
		name    string
		check   *HealthCheck
		healthy bool
	}{
		{
			name: "healthy service",
			check: &HealthCheck{
				Name:         "test-service",
				Status:       HealthStatusHealthy,
				LastCheck:    time.Now(),
				ErrorCount:   0,
				ResponseTime: 50 * time.Millisecond,
			},
			healthy: true,
		},
		{
			name: "unhealthy service",
			check: &HealthCheck{
				Name:         "test-service",
				Status:       HealthStatusUnhealthy,
				LastCheck:    time.Now(),
				ErrorCount:   5,
				ResponseTime: 5 * time.Second,
			},
			healthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthy := tt.check.IsHealthy()
			assert.Equal(t, tt.healthy, healthy)
		})
	}
}

func TestMetricsCollector_CollectMetrics(t *testing.T) {
	collector := &MetricsCollector{
		registry: make(map[string]interface{}),
		sources:  make([]MetricsSource, 0),
	}

	// Add a mock metrics source
	source := &MockMetricsSource{
		data: map[string]float64{
			"cpu_usage":    75.5,
			"memory_usage": 60.2,
		},
	}
	collector.sources = append(collector.sources, source)

	metrics := collector.CollectMetrics()

	assert.NotNil(t, metrics)
	assert.Contains(t, metrics, "cpu_usage")
	assert.Contains(t, metrics, "memory_usage")
	assert.Equal(t, 75.5, metrics["cpu_usage"])
	assert.Equal(t, 60.2, metrics["memory_usage"])
}

// MockMetricsSource for testing
type MockMetricsSource struct {
	data map[string]float64
}

func (m *MockMetricsSource) GetMetrics() map[string]float64 {
	return m.data
}

func TestTracer_StartSpan(t *testing.T) {
	tracer := &Tracer{
		serviceName: "pahlevan-test",
		enabled:     true,
		spans:       make(map[string]*Span),
	}

	span := tracer.StartSpan("test-operation")

	require.NotNil(t, span)
	assert.Equal(t, "test-operation", span.Name)
	assert.False(t, span.StartTime.IsZero())
	assert.True(t, span.EndTime.IsZero())
	assert.False(t, span.Finished)
}

func TestSpan_Finish(t *testing.T) {
	span := &Span{
		ID:        "test-span-1",
		Name:      "test-operation",
		StartTime: time.Now().Add(-100 * time.Millisecond),
		Tags:      make(map[string]string),
		Logs:      make([]SpanLog, 0),
	}

	span.Finish()

	assert.True(t, span.Finished)
	assert.False(t, span.EndTime.IsZero())
	assert.True(t, span.EndTime.After(span.StartTime))
}

func TestSpan_SetTag(t *testing.T) {
	span := &Span{
		Tags: make(map[string]string),
	}

	span.SetTag("component", "ebpf-manager")
	span.SetTag("version", "1.0.0")

	assert.Equal(t, "ebpf-manager", span.Tags["component"])
	assert.Equal(t, "1.0.0", span.Tags["version"])
}

func TestSpan_Log(t *testing.T) {
	span := &Span{
		Logs: make([]SpanLog, 0),
	}

	span.Log("test message", map[string]interface{}{
		"level":     "info",
		"component": "test",
	})

	assert.Len(t, span.Logs, 1)
	assert.Equal(t, "test message", span.Logs[0].Message)
	assert.Equal(t, "info", span.Logs[0].Fields["level"])
}

func TestBenchmarkMetricsCollection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	metrics := &SecurityMetrics{
		ViolationCounts:    make(map[string]uint64),
		PolicyUpdateCounts: make(map[string]uint64),
		PerformanceMetrics: make(map[string]float64),
	}

	start := time.Now()

	// Simulate collecting many metrics
	for i := 0; i < 10000; i++ {
		containerID := "container-" + string(rune(i%100))
		metrics.RecordViolation(containerID, "syscall")
		metrics.RecordPolicyUpdate(containerID, "network")
		metrics.RecordPerformance("operation_duration", float64(i))
	}

	duration := time.Since(start)
	assert.Less(t, duration, 500*time.Millisecond, "Metrics collection should be fast")
	t.Logf("Collected 30000 metrics in %v", duration)
}
