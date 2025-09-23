package observability

import (
	"context"
	"fmt"
	"time"
)

// Observability manager types

type ObservabilityManager struct {
	config    *ObservabilityConfig
	metrics   *SecurityMetrics
	alerts    *AlertManager
	exporters []*Exporter
}

type ObservabilityConfig struct {
	MetricsEnabled    bool
	TracingEnabled    bool
	LoggingEnabled    bool
	ExportInterval    time.Duration
	MetricsPort       int
	HealthCheckPort   int
	PrometheusEnabled bool
	JaegerEndpoint    string
}

type SecurityMetrics struct {
	ViolationCounts      map[string]uint64
	PolicyUpdateCounts   map[string]uint64
	PerformanceMetrics   map[string]float64
	AlertCounts          map[string]uint64
	LastUpdate           time.Time
}

type Alert struct {
	ID            string
	Type          AlertType
	Severity      Severity
	Message       string
	Source        string
	Timestamp     time.Time
	TTL           time.Duration
	EscalationTTL time.Duration
	Acknowledged  bool
	Tags          map[string]string
}

type AlertType string

const (
	AlertTypeViolation AlertType = "Violation"
	AlertTypePolicyUpdate AlertType = "PolicyUpdate"
	AlertTypeSystemHealth AlertType = "SystemHealth"
)

type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

type AlertManager struct {
	alerts   map[string]*Alert
	rules    []*AlertRule
	channels map[string]AlertChannel
}

// Note: AlertRule, Exporter, and ExporterType are defined in manager.go

type AlertChannel interface {
	Send(alert *Alert) error
}

type HealthCheck struct {
	Name         string
	Status       HealthStatus
	LastCheck    time.Time
	ErrorCount   int
	ResponseTime time.Duration
	Endpoint     string
}

type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "Healthy"
	HealthStatusUnhealthy HealthStatus = "Unhealthy"
	HealthStatusUnknown   HealthStatus = "Unknown"
)

type MetricsCollector struct {
	registry map[string]interface{}
	sources  []MetricsSource
}

type MetricsSource interface {
	GetMetrics() map[string]float64
}

type Tracer struct {
	serviceName string
	enabled     bool
	spans       map[string]*Span
}

type Span struct {
	ID        string
	Name      string
	StartTime time.Time
	EndTime   time.Time
	Tags      map[string]string
	Logs      []SpanLog
	Finished  bool
}

type SpanLog struct {
	Timestamp time.Time
	Message   string
	Fields    map[string]interface{}
}

// Constructor
func NewObservabilityManager(config *ObservabilityConfig) *ObservabilityManager {
	return &ObservabilityManager{
		config: config,
		metrics: &SecurityMetrics{
			ViolationCounts:    make(map[string]uint64),
			PolicyUpdateCounts: make(map[string]uint64),
			PerformanceMetrics: make(map[string]float64),
			AlertCounts:        make(map[string]uint64),
		},
		alerts: &AlertManager{
			alerts:   make(map[string]*Alert),
			rules:    make([]*AlertRule, 0),
			channels: make(map[string]AlertChannel),
		},
		exporters: make([]*Exporter, 0),
	}
}

// Methods
func (sm *SecurityMetrics) RecordViolation(containerID, violationType string) {
	key := containerID + ":" + violationType
	sm.ViolationCounts[key]++
	sm.LastUpdate = time.Now()
}

func (sm *SecurityMetrics) RecordPolicyUpdate(containerID, policyType string) {
	key := containerID + ":" + policyType
	sm.PolicyUpdateCounts[key]++
	sm.LastUpdate = time.Now()
}

func (sm *SecurityMetrics) RecordPerformance(metric string, value float64) {
	sm.PerformanceMetrics[metric] = value
	sm.LastUpdate = time.Now()
}

func (a *Alert) IsExpired() bool {
	return time.Since(a.Timestamp) > a.TTL
}

func (a *Alert) ShouldEscalate() bool {
	if a.Acknowledged {
		return false
	}
	if a.Severity == SeverityCritical || a.Severity == SeverityHigh {
		return time.Since(a.Timestamp) > a.EscalationTTL
	}
	return false
}

func (am *AlertManager) AddAlert(alert *Alert) {
	am.alerts[alert.ID] = alert
}

func (am *AlertManager) AcknowledgeAlert(id string) bool {
	alert, exists := am.alerts[id]
	if !exists {
		return false
	}
	alert.Acknowledged = true
	return true
}

func (ar *AlertRule) ShouldTrigger(metrics *SecurityMetrics) bool {
	// Check if we can evaluate based on last evaluation time
	if time.Since(ar.LastEval) < ar.Frequency {
		return false
	}

	// Simple threshold check for violation rate
	if ar.Query == "violation_rate > 10" {
		totalViolations := 0
		for _, count := range metrics.ViolationCounts {
			totalViolations += int(count)
		}
		// Use first condition if available
		if len(ar.Conditions) > 0 {
			return float64(totalViolations) > ar.Conditions[0].Value
		}
		return float64(totalViolations) > 10 // default threshold
	}

	return false
}

// Note: Exporter interface, ExporterMetadata, and ObservabilityData are defined in manager.go

// MockExporter implements the Exporter interface for testing
type MockExporter struct {
	Type   ExporterType
	Config map[string]interface{}
}

func (e *MockExporter) Start(ctx context.Context) error {
	return nil
}

func (e *MockExporter) Stop(ctx context.Context) error {
	return nil
}

func (e *MockExporter) Export(data *ObservabilityData) error {
	switch e.Type {
	case ExporterTypePrometheus:
		return fmt.Errorf("prometheus endpoint not available")
	case ExporterTypeJaeger:
		return fmt.Errorf("jaeger endpoint not available")
	default:
		return fmt.Errorf("unknown exporter type: %s", e.Type)
	}
}

func (e *MockExporter) GetType() ExporterType {
	return e.Type
}

func (e *MockExporter) GetMetadata() *ExporterMetadata {
	return &ExporterMetadata{
		Name:         string(e.Type),
		Version:      "1.0.0",
		Description:  "Mock exporter for testing",
		Capabilities: []string{"metrics", "logs"},
	}
}

func (hc *HealthCheck) IsHealthy() bool {
	return hc.Status == HealthStatusHealthy
}

func (mc *MetricsCollector) CollectMetrics() map[string]float64 {
	metrics := make(map[string]float64)
	for _, source := range mc.sources {
		sourceMetrics := source.GetMetrics()
		for key, value := range sourceMetrics {
			metrics[key] = value
		}
	}
	return metrics
}

func (t *Tracer) StartSpan(name string) *Span {
	span := &Span{
		ID:        fmt.Sprintf("span-%d", time.Now().UnixNano()),
		Name:      name,
		StartTime: time.Now(),
		Tags:      make(map[string]string),
		Logs:      make([]SpanLog, 0),
		Finished:  false,
	}
	t.spans[span.ID] = span
	return span
}

func (s *Span) Finish() {
	s.EndTime = time.Now()
	s.Finished = true
}

func (s *Span) SetTag(key, value string) {
	s.Tags[key] = value
}

func (s *Span) Log(message string, fields map[string]interface{}) {
	log := SpanLog{
		Timestamp: time.Now(),
		Message:   message,
		Fields:    fields,
	}
	s.Logs = append(s.Logs, log)
}