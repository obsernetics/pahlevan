package observability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsManager_ErrorHandling(t *testing.T) {
	t.Run("nil metrics registration", func(t *testing.T) {
		manager := NewMetricsManager()

		// Should handle nil metric registration gracefully
		err := manager.RegisterMetric(nil)
		if err != nil {
			assert.Contains(t, err.Error(), "nil", "Error should indicate nil metric")
		}
	})

	t.Run("duplicate metric names", func(t *testing.T) {
		manager := NewMetricsManager()

		metric1 := &Metric{
			Name:        "test_metric",
			Type:        MetricTypeCounter,
			Description: "Test metric 1",
			Labels:      map[string]string{"version": "1"},
		}

		metric2 := &Metric{
			Name:        "test_metric", // Same name
			Type:        MetricTypeGauge,
			Description: "Test metric 2",
			Labels:      map[string]string{"version": "2"},
		}

		// First registration should succeed
		err1 := manager.RegisterMetric(metric1)
		assert.NoError(t, err1)

		// Second registration with same name should fail
		err2 := manager.RegisterMetric(metric2)
		assert.Error(t, err2, "Duplicate metric name should cause error")
		assert.Contains(t, err2.Error(), "already registered", "Error should indicate duplicate")
	})

	t.Run("invalid metric values", func(t *testing.T) {
		manager := NewMetricsManager()

		tests := []struct {
			name   string
			metric *Metric
			value  interface{}
			valid  bool
		}{
			{
				name: "counter with negative value",
				metric: &Metric{
					Name: "negative_counter",
					Type: MetricTypeCounter,
				},
				value: -10.0,
				valid: false,
			},
			{
				name: "histogram with nil buckets",
				metric: &Metric{
					Name: "nil_histogram",
					Type: MetricTypeHistogram,
				},
				value: nil,
				valid: false,
			},
			{
				name: "gauge with string value",
				metric: &Metric{
					Name: "string_gauge",
					Type: MetricTypeGauge,
				},
				value: "not_a_number",
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				manager.RegisterMetric(tt.metric)
				err := manager.UpdateMetric(tt.metric.Name, tt.value)
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("concurrent metric updates", func(t *testing.T) {
		manager := NewMetricsManager()

		metric := &Metric{
			Name: "concurrent_counter",
			Type: MetricTypeCounter,
		}
		manager.RegisterMetric(metric)

		var wg sync.WaitGroup
		errorChan := make(chan error, 100)

		// Concurrent updates
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(value int) {
				defer wg.Done()
				if err := manager.UpdateMetric("concurrent_counter", float64(value)); err != nil {
					errorChan <- err
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Should handle concurrent updates without errors
		for err := range errorChan {
			t.Errorf("Concurrent metric update failed: %v", err)
		}
	})
}

func TestAlertManager_EdgeCases(t *testing.T) {
	t.Run("malformed alert rules", func(t *testing.T) {
		manager := NewAlertManager()

		tests := []struct {
			name string
			rule *AlertRule
			valid bool
		}{
			{
				name: "empty rule ID",
				rule: &AlertRule{
					ID:   "",
					Name: "Test Rule",
					Query: "metric > 0",
				},
				valid: false,
			},
			{
				name: "invalid query syntax",
				rule: &AlertRule{
					ID:   "invalid-query",
					Name: "Invalid Query Rule",
					Query: "invalid query syntax >>>>",
				},
				valid: false,
			},
			{
				name: "nil conditions",
				rule: &AlertRule{
					ID:         "nil-conditions",
					Name:       "Nil Conditions Rule",
					Query:      "metric > 0",
					Conditions: nil,
				},
				valid: false,
			},
			{
				name: "negative frequency",
				rule: &AlertRule{
					ID:        "negative-freq",
					Name:      "Negative Frequency Rule",
					Query:     "metric > 0",
					Frequency: -1 * time.Minute,
				},
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := manager.AddRule(tt.rule)
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("alert flooding", func(t *testing.T) {
		manager := NewAlertManager()

		// Add many rules rapidly
		for i := 0; i < 1000; i++ {
			rule := &AlertRule{
				ID:   string(rune('a'+i%26)) + string(rune('0'+i%10)),
				Name: "Flood Rule",
				Query: "metric > 0",
				Conditions: []*Condition{
					{
						Operator:  ConditionOperatorGT,
						Value:     float64(i),
						Evaluator: EvaluatorTypeAvg,
					},
				},
				Severity:  AlertSeverityLow,
				Frequency: 1 * time.Second,
			}
			err := manager.AddRule(rule)
			assert.NoError(t, err, "Should handle many rules")
		}

		// Test evaluation performance
		start := time.Now()
		err := manager.EvaluateRules(map[string]float64{"metric": 500})
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Less(t, duration, 5*time.Second, "Rule evaluation should be efficient")
	})

	t.Run("circular alert dependencies", func(t *testing.T) {
		manager := NewAlertManager()

		// Create rules that might reference each other
		rule1 := &AlertRule{
			ID:    "rule1",
			Name:  "Rule 1",
			Query: "rule2_metric > 0", // References rule2
			Conditions: []*Condition{
				{
					Operator:  ConditionOperatorGT,
					Value:     0,
					Evaluator: EvaluatorTypeAvg,
				},
			},
			Severity: AlertSeverityMedium,
		}

		rule2 := &AlertRule{
			ID:    "rule2",
			Name:  "Rule 2",
			Query: "rule1_metric > 0", // References rule1
			Conditions: []*Condition{
				{
					Operator:  ConditionOperatorGT,
					Value:     0,
					Evaluator: EvaluatorTypeAvg,
				},
			},
			Severity: AlertSeverityMedium,
		}

		// Should handle potential circular dependencies
		err1 := manager.AddRule(rule1)
		err2 := manager.AddRule(rule2)
		assert.NoError(t, err1)
		assert.NoError(t, err2)

		// Evaluation should not hang
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- manager.EvaluateRules(map[string]float64{
				"rule1_metric": 1,
				"rule2_metric": 1,
			})
		}()

		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-ctx.Done():
			t.Error("Rule evaluation timed out - possible circular dependency")
		}
	})
}

func TestExporter_FailureHandling(t *testing.T) {
	t.Run("invalid exporter configuration", func(t *testing.T) {
		tests := []struct {
			name     string
			exporter *Exporter
			valid    bool
		}{
			{
				name: "nil config",
				exporter: &Exporter{
					Type:   ExporterTypePrometheus,
					Config: nil,
				},
				valid: false,
			},
			{
				name: "invalid endpoint URL",
				exporter: &Exporter{
					Type: ExporterTypeJaeger,
					Config: map[string]interface{}{
						"endpoint": "invalid-url-format",
					},
				},
				valid: false,
			},
			{
				name: "missing required fields",
				exporter: &Exporter{
					Type: ExporterTypeJaeger,
					Config: map[string]interface{}{
						"timeout": "30s",
						// Missing endpoint
					},
				},
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.exporter.Validate()
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("network failures simulation", func(t *testing.T) {
		// Test exporters with unreachable endpoints
		exporter := &Exporter{
			Type: ExporterTypeJaeger,
			Config: map[string]interface{}{
				"endpoint": "http://unreachable-host:14268/api/traces",
				"timeout":  "1s",
			},
		}

		// Should handle network failures gracefully
		err := exporter.Export(map[string]interface{}{
			"trace_id": "test-trace",
			"span_id":  "test-span",
			"data":     "test data",
		})

		if err != nil {
			// Network error is expected
			assert.Contains(t, err.Error(), "network\|timeout\|connection", "Should indicate network issue")
		}
	})

	t.Run("data corruption handling", func(t *testing.T) {
		exporter := &Exporter{
			Type: ExporterTypePrometheus,
			Config: map[string]interface{}{
				"endpoint": "http://localhost:9090",
			},
		}

		// Test with corrupted/invalid data
		corruptedData := map[string]interface{}{
			"invalid_metric": func() {}, // Function type - not serializable
			"circular_ref":   make(chan int), // Channel type
			"nil_value":      nil,
			"nested": map[string]interface{}{
				"deeply": map[string]interface{}{
					"nested": "value",
				},
			},
		}

		// Should handle corrupted data gracefully
		err := exporter.Export(corruptedData)
		if err != nil {
			assert.Contains(t, err.Error(), "invalid\|corrupt\|serialize", "Should indicate data issues")
		}
	})
}

func TestTracing_ErrorScenarios(t *testing.T) {
	t.Run("span nesting overflow", func(t *testing.T) {
		tracer := &Tracer{
			ServiceName: "test-service",
		}

		// Create deeply nested spans
		currentSpan := tracer.StartSpan("root")
		for i := 0; i < 1000; i++ {
			childSpan := tracer.StartSpan(string(rune('a'+i%26)) + "-operation")
			childSpan.SetParent(currentSpan)
			currentSpan = childSpan
		}

		// Should handle deep nesting without issues
		currentSpan.Finish()
		assert.NotNil(t, currentSpan)
	})

	t.Run("concurrent span operations", func(t *testing.T) {
		tracer := &Tracer{
			ServiceName: "concurrent-test",
		}

		var wg sync.WaitGroup
		errorChan := make(chan error, 100)

		// Concurrent span creation and operations
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				span := tracer.StartSpan(string(rune('s'+index%26)) + "-operation")
				if span == nil {
					errorChan <- errors.New("span creation failed")
					return
				}

				// Add tags and logs concurrently
				for j := 0; j < 10; j++ {
					span.SetTag(string(rune('t'+j%26)), j)
					span.LogEvent(string(rune('e'+j%26)), map[string]interface{}{
						"index": j,
						"time":  time.Now(),
					})
				}

				span.Finish()
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for errors
		for err := range errorChan {
			t.Errorf("Concurrent span operation failed: %v", err)
		}
	})

	t.Run("invalid span data", func(t *testing.T) {
		tracer := &Tracer{
			ServiceName: "error-test",
		}

		span := tracer.StartSpan("test-operation")
		require.NotNil(t, span)

		// Test with invalid tag values
		invalidValues := []interface{}{
			func() {},           // Function
			make(chan int),      // Channel
			[]func(){func() {}}, // Slice of functions
			map[string]func(){   // Map with function values
				"key": func() {},
			},
		}

		for i, val := range invalidValues {
			// Should handle invalid values gracefully
			span.SetTag(string(rune('i'+i)), val)
		}

		// Should not panic
		span.Finish()
	})
}

func TestObservabilityManager_ResourceExhaustion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource exhaustion test in short mode")
	}

	manager := NewObservabilityManager()

	t.Run("memory pressure", func(t *testing.T) {
		// Create many metrics rapidly
		for i := 0; i < 10000; i++ {
			metricName := string(rune('m'+i%26)) + string(rune('0'+i%10))
			metric := &Metric{
				Name:        metricName,
				Type:        MetricTypeCounter,
				Description: "Load test metric",
				Labels: map[string]string{
					"instance": string(rune('i' + i%26)),
					"iteration": string(rune('0' + i%10)),
				},
			}
			err := manager.RegisterMetric(metric)
			assert.NoError(t, err, "Should handle many metrics")
		}

		// Update all metrics rapidly
		start := time.Now()
		for i := 0; i < 10000; i++ {
			metricName := string(rune('m'+i%26)) + string(rune('0'+i%10))
			manager.UpdateMetric(metricName, float64(i))
		}
		duration := time.Since(start)

		assert.Less(t, duration, 10*time.Second, "Metric updates should be efficient")
	})

	t.Run("alert rule explosion", func(t *testing.T) {
		// Create many complex alert rules
		for i := 0; i < 1000; i++ {
			conditions := make([]*Condition, 10) // Many conditions per rule
			for j := 0; j < 10; j++ {
				conditions[j] = &Condition{
					Operator:  ConditionOperatorGT,
					Value:     float64(j),
					Evaluator: EvaluatorTypeAvg,
				}
			}

			rule := &AlertRule{
				ID:         string(rune('r'+i%26)) + string(rune('0'+i%10)),
				Name:       "Load Test Rule",
				Query:      "complex_metric > threshold",
				Conditions: conditions,
				Severity:   AlertSeverityLow,
				Frequency:  1 * time.Second,
			}

			err := manager.AddAlertRule(rule)
			assert.NoError(t, err, "Should handle many alert rules")
		}

		// Test evaluation performance
		start := time.Now()
		metrics := make(map[string]float64)
		for i := 0; i < 100; i++ {
			metrics[string(rune('m'+i%26))] = float64(i)
		}
		err := manager.EvaluateAlerts(metrics)
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Less(t, duration, 10*time.Second, "Alert evaluation should be efficient")
	})
}
