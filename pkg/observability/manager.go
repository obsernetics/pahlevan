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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"

	// "go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Manager provides comprehensive observability for Pahlevan
type Manager struct {
	mu             sync.RWMutex
	config         *Config
	meterProvider  *sdkmetric.MeterProvider
	tracerProvider *sdktrace.TracerProvider
	meter          metric.Meter
	tracer         trace.Tracer
	exporters      []Exporter
	customMetrics  map[string]interface{}
	dashboards     map[string]*Dashboard
	alertRules     map[string]*AlertRule
	stopCh         chan struct{}
}

// Config defines observability configuration
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string

	// Metrics configuration
	MetricsEnabled   bool
	MetricsExporters []ExporterConfig
	MetricsInterval  time.Duration

	// Tracing configuration
	TracingEnabled    bool
	TracingExporters  []ExporterConfig
	TracingSampleRate float64

	// Logging configuration
	LoggingEnabled bool
	LogLevel       string
	LogFormat      string
	LogOutputs     []LogOutput

	// Dashboard configuration
	DashboardsEnabled bool
	CustomDashboards  []DashboardConfig

	// Alerting configuration
	AlertingEnabled      bool
	AlertRules           []AlertRuleConfig
	NotificationChannels []NotificationChannel
}

// ExporterConfig defines exporter configuration
type ExporterConfig struct {
	Type ExporterType
	// Endpoint is the collector address, e.g. otel-collector:4317 for OTLP/gRPC.
	Endpoint string
	// Insecure disables TLS to the collector (common for in-cluster collectors).
	Insecure   bool
	Headers    map[string]string
	Attributes map[string]string
	Config     map[string]interface{}
}

// ExporterType defines supported exporter types
type ExporterType string

const (
	ExporterTypePrometheus ExporterType = "prometheus"
	ExporterTypeOTLP       ExporterType = "otlp"
	ExporterTypeDatadog    ExporterType = "datadog"
	ExporterTypeGrafana    ExporterType = "grafana"
	ExporterTypeElastic    ExporterType = "elastic"
	ExporterTypeJaeger     ExporterType = "jaeger"
	ExporterTypeConsole    ExporterType = "console"
)

// Exporter interface for custom exporters
type Exporter interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Export(data *ObservabilityData) error
	GetType() ExporterType
	GetMetadata() *ExporterMetadata
}

// ObservabilityData contains all observability data
type ObservabilityData struct {
	Metrics   map[string]*MetricData
	Traces    []*TraceData
	Logs      []*LogData
	Events    []*EventData
	Timestamp time.Time
	Source    string
	Labels    map[string]string
}

// MetricData represents metric information
type MetricData struct {
	Name        string
	Type        MetricType
	Value       float64
	Labels      map[string]string
	Timestamp   time.Time
	Unit        string
	Description string
}

// MetricType defines metric types
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// TraceData represents trace information
type TraceData struct {
	TraceID   string
	SpanID    string
	Operation string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Status    TraceStatus
	Tags      map[string]string
	Events    []*TraceEvent
	Parent    *TraceData
	Children  []*TraceData
}

// TraceStatus defines trace status
type TraceStatus string

const (
	TraceStatusOK    TraceStatus = "ok"
	TraceStatusError TraceStatus = "error"
)

// TraceEvent represents events within a trace
type TraceEvent struct {
	Time       time.Time
	Name       string
	Attributes map[string]string
}

// LogData represents log information
type LogData struct {
	Timestamp time.Time
	Level     LogLevel
	Message   string
	Fields    map[string]interface{}
	Source    string
	TraceID   string
	SpanID    string
}

// LogLevel defines log levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// EventData represents event information
type EventData struct {
	ID       string
	Type     EventType
	Source   string
	Subject  string
	Time     time.Time
	Data     map[string]interface{}
	Severity EventSeverity
	Category EventCategory
}

// EventType defines event types
type EventType string

const (
	EventTypePolicyViolation  EventType = "policy.violation"
	EventTypePolicyGenerated  EventType = "policy.generated"
	EventTypeSelfHealing      EventType = "self.healing"
	EventTypeRollback         EventType = "rollback"
	EventTypeAnomalyDetected  EventType = "anomaly.detected"
	EventTypeHealthCheck      EventType = "health.check"
	EventTypeSecurityIncident EventType = "security.incident"
)

// EventSeverity defines event severity levels
type EventSeverity string

const (
	EventSeverityLow      EventSeverity = "low"
	EventSeverityMedium   EventSeverity = "medium"
	EventSeverityHigh     EventSeverity = "high"
	EventSeverityCritical EventSeverity = "critical"
)

// EventCategory defines event categories
type EventCategory string

const (
	EventCategorySecurity    EventCategory = "security"
	EventCategoryPerformance EventCategory = "performance"
	EventCategoryCompliance  EventCategory = "compliance"
	EventCategoryOperational EventCategory = "operational"
)

// Dashboard configuration
type DashboardConfig struct {
	Name      string
	Type      DashboardType
	Config    map[string]interface{}
	Panels    []PanelConfig
	Variables []VariableConfig
	Refresh   time.Duration
}

type DashboardType string

const (
	DashboardTypeGrafana DashboardType = "grafana"
	DashboardTypeDatadog DashboardType = "datadog"
	DashboardTypeCustom  DashboardType = "custom"
)

type PanelConfig struct {
	Title         string
	Type          PanelType
	Query         string
	Visualization map[string]interface{}
	Thresholds    []ThresholdConfig
}

type PanelType string

const (
	PanelTypeGraph      PanelType = "graph"
	PanelTypeTable      PanelType = "table"
	PanelTypeSingleStat PanelType = "singlestat"
	PanelTypeHeatmap    PanelType = "heatmap"
	PanelTypeAlerts     PanelType = "alerts"
)

type VariableConfig struct {
	Name    string
	Type    VariableType
	Query   string
	Options []string
	Default string
}

type VariableType string

const (
	VariableTypeQuery    VariableType = "query"
	VariableTypeCustom   VariableType = "custom"
	VariableTypeInterval VariableType = "interval"
)

// Alert configuration
type AlertRuleConfig struct {
	Name        string
	Query       string
	Conditions  []ConditionConfig
	Actions     []ActionConfig
	Severity    AlertSeverity
	Frequency   time.Duration
	For         time.Duration
	Labels      map[string]string
	Annotations map[string]string
}

type ConditionConfig struct {
	Operator  ConditionOperator
	Value     float64
	Evaluator EvaluatorType
}

type ConditionOperator string

const (
	ConditionOperatorGT ConditionOperator = "gt"
	ConditionOperatorLT ConditionOperator = "lt"
	ConditionOperatorEQ ConditionOperator = "eq"
	ConditionOperatorNE ConditionOperator = "ne"
)

type EvaluatorType string

const (
	EvaluatorTypeAvg EvaluatorType = "avg"
	EvaluatorTypeMin EvaluatorType = "min"
	EvaluatorTypeMax EvaluatorType = "max"
	EvaluatorTypeSum EvaluatorType = "sum"
)

type ActionConfig struct {
	Type       ActionType
	Recipients []string
	Template   string
	Config     map[string]interface{}
}

type ActionType string

const (
	ActionTypeEmail     ActionType = "email"
	ActionTypeSlack     ActionType = "slack"
	ActionTypeWebhook   ActionType = "webhook"
	ActionTypePagerDuty ActionType = "pagerduty"
)

type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// Dashboard and alert rule implementations
type Dashboard struct {
	ID          string
	Name        string
	Type        DashboardType
	Panels      []*Panel
	Variables   []*Variable
	LastUpdated time.Time
	Config      map[string]interface{}
}

type Panel struct {
	ID            string
	Title         string
	Type          PanelType
	Query         string
	DataSource    string
	Visualization *Visualization
	Thresholds    []*Threshold
}

type Visualization struct {
	Type    string
	Options map[string]interface{}
}

type Threshold struct {
	Value float64
	Color string
	Op    ConditionOperator
}

type Variable struct {
	Name    string
	Type    VariableType
	Query   string
	Options []string
	Current string
}

type AlertRule struct {
	ID         string
	Name       string
	Query      string
	Conditions []*Condition
	Actions    []*Action
	Severity   AlertSeverity
	State      AlertState
	LastEval   time.Time
	Frequency  time.Duration
	For        time.Duration
}

type Condition struct {
	Operator  ConditionOperator
	Value     float64
	Evaluator EvaluatorType
}

type Action struct {
	Type       ActionType
	Recipients []string
	Template   string
	Config     map[string]interface{}
}

type AlertState string

const (
	AlertStateOK       AlertState = "ok"
	AlertStatePending  AlertState = "pending"
	AlertStateAlerting AlertState = "alerting"
	AlertStateNoData   AlertState = "no_data"
)

// Notification channels
type NotificationChannel struct {
	Name     string
	Type     string
	Settings map[string]interface{}
}

type LogOutput struct {
	Type   string
	Config map[string]interface{}
}

type ThresholdConfig struct {
	Value float64
	Color string
	Op    ConditionOperator
}

type ExporterMetadata struct {
	Name         string
	Version      string
	Description  string
	Capabilities []string
}

func NewManager(exportsList string) (*Manager, error) {
	config := &Config{
		ServiceName:       "pahlevan-operator",
		ServiceVersion:    "1.0.0",
		Environment:       "production",
		MetricsEnabled:    true,
		TracingEnabled:    true,
		LoggingEnabled:    true,
		MetricsInterval:   30 * time.Second,
		TracingSampleRate: 0.1,
		LogLevel:          "info",
		LogFormat:         "json",
	}

	// Parse exporters list
	if exportsList != "" {
		exporters := strings.Split(exportsList, ",")
		for _, exp := range exporters {
			exporterConfig := ExporterConfig{
				Type: ExporterType(strings.TrimSpace(exp)),
			}

			switch exporterConfig.Type {
			case ExporterTypePrometheus:
				exporterConfig.Endpoint = ":8080/metrics"
			case ExporterTypeOTLP:
				exporterConfig.Endpoint = "localhost:4317"
			case ExporterTypeDatadog:
				exporterConfig.Endpoint = "https://api.datadoghq.com"
			}

			config.MetricsExporters = append(config.MetricsExporters, exporterConfig)
			config.TracingExporters = append(config.TracingExporters, exporterConfig)
		}
	}

	manager := &Manager{
		config:        config,
		customMetrics: make(map[string]interface{}),
		dashboards:    make(map[string]*Dashboard),
		alertRules:    make(map[string]*AlertRule),
		stopCh:        make(chan struct{}),
	}

	if err := manager.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	return manager, nil
}

func (m *Manager) initializeProviders() error {
	// Initialize resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(m.config.ServiceName),
			semconv.ServiceVersion(m.config.ServiceVersion),
			semconv.DeploymentEnvironment(m.config.Environment),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize metrics provider
	if m.config.MetricsEnabled {
		if err := m.initializeMetrics(res); err != nil {
			return fmt.Errorf("failed to initialize metrics: %w", err)
		}
	}

	// Initialize tracing provider
	if m.config.TracingEnabled {
		if err := m.initializeTracing(res); err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	return nil
}

// wantedReader counts the exporter configs this package knows how to build.
// A datadog or grafana entry is not a failure when no reader appears for it -
// those are served by exporters registered through RegisterExporter.
func wantedReader(configs []ExporterConfig) int {
	n := 0
	for _, c := range configs {
		switch c.Type {
		case ExporterTypePrometheus, ExporterTypeOTLP, ExporterTypeConsole:
			n++
		}
	}
	return n
}

// newPrometheusReader builds the pull-based Prometheus reader against a given
// registerer. The registerer is a parameter rather than hard-coded so a test
// can assert on a private registry instead of whatever the process has
// accumulated globally.
func newPrometheusReader(reg prometheus.Registerer) (sdkmetric.Reader, error) {
	return otelprom.New(otelprom.WithRegisterer(reg))
}

func (m *Manager) initializeMetrics(res *resource.Resource) error {
	var exporters []sdkmetric.Exporter

	// Every branch here used to be a log line saying the exporter was
	// "temporarily disabled", which meant the meter provider was built with no
	// readers at all: instruments recorded happily and nothing ever left the
	// process, while --observability-exports still reported the exporter as
	// configured. That is the same failure the tracing side had, fixed the same
	// way.
	var readers []sdkmetric.Reader

	for _, exporterConfig := range m.config.MetricsExporters {
		switch exporterConfig.Type {
		case ExporterTypePrometheus:
			// The Prometheus exporter is a reader, not a pull-based Exporter:
			// it registers as a collector and is scraped, so it does not belong
			// behind a PeriodicReader. Registering into the controller-runtime
			// registry puts OTel instruments on the same /metrics endpoint the
			// native collectors already serve.
			exp, err := newPrometheusReader(ctrlmetrics.Registry)
			if err != nil {
				log.Log.Error(err, "failed to create Prometheus metric exporter")
				continue
			}
			readers = append(readers, exp)

		case ExporterTypeOTLP:
			opts := []otlpmetricgrpc.Option{}
			if exporterConfig.Endpoint != "" {
				opts = append(opts, otlpmetricgrpc.WithEndpoint(exporterConfig.Endpoint))
			}
			if exporterConfig.Insecure {
				opts = append(opts, otlpmetricgrpc.WithInsecure())
			}
			if len(exporterConfig.Headers) > 0 {
				opts = append(opts, otlpmetricgrpc.WithHeaders(exporterConfig.Headers))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			exp, err := otlpmetricgrpc.New(ctx, opts...)
			cancel()
			if err != nil {
				log.Log.Error(err, "failed to create OTLP metric exporter", "endpoint", exporterConfig.Endpoint)
				continue
			}
			exporters = append(exporters, exp)

		case ExporterTypeConsole:
			exp, err := stdoutmetric.New()
			if err != nil {
				log.Log.Error(err, "failed to create console metric exporter")
				continue
			}
			exporters = append(exporters, exp)
		}
	}

	// Push-based exporters are driven by a periodic reader; the Prometheus
	// reader added above is pull-based and is already in the list.
	for _, exporter := range exporters {
		reader := sdkmetric.NewPeriodicReader(
			exporter,
			sdkmetric.WithInterval(m.config.MetricsInterval),
		)
		readers = append(readers, reader)
	}

	// Configured but nothing built: the operator asked for metrics export and
	// would otherwise get a provider that accepts every recording and drops it.
	// Unknown exporter types (datadog, grafana) are not counted, since those are
	// served by registered custom exporters rather than by this function.
	if wantedReader(m.config.MetricsExporters) > 0 && len(readers) == 0 {
		return fmt.Errorf("none of the %d configured metrics exporters could be created",
			wantedReader(m.config.MetricsExporters))
	}

	// Create meter provider
	options := []sdkmetric.Option{sdkmetric.WithResource(res)}
	for _, reader := range readers {
		options = append(options, sdkmetric.WithReader(reader))
	}
	m.meterProvider = sdkmetric.NewMeterProvider(options...)

	// Set global meter provider
	otel.SetMeterProvider(m.meterProvider)

	// Create meter
	m.meter = otel.Meter(
		"pahlevan.io/operator",
		metric.WithInstrumentationVersion(m.config.ServiceVersion),
	)

	return nil
}

func (m *Manager) initializeTracing(res *resource.Resource) error {
	var exporters []sdktrace.SpanExporter

	for _, exporterConfig := range m.config.TracingExporters {
		switch exporterConfig.Type {
		case ExporterTypeOTLP:
			// Real OTLP/gRPC exporter. Both exporters used to be stubbed out with
			// a log line, so the provider was built with zero span processors and
			// tracing silently did nothing while still being advertised.
			opts := []otlptracegrpc.Option{}
			if exporterConfig.Endpoint != "" {
				opts = append(opts, otlptracegrpc.WithEndpoint(exporterConfig.Endpoint))
			}
			if exporterConfig.Insecure {
				opts = append(opts, otlptracegrpc.WithInsecure())
			}
			if len(exporterConfig.Headers) > 0 {
				opts = append(opts, otlptracegrpc.WithHeaders(exporterConfig.Headers))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			exp, err := otlptracegrpc.New(ctx, opts...)
			cancel()
			if err != nil {
				log.Log.Error(err, "failed to create OTLP trace exporter", "endpoint", exporterConfig.Endpoint)
				continue
			}
			exporters = append(exporters, exp)
		case ExporterTypeConsole:
			exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
			if err != nil {
				log.Log.Error(err, "failed to create console trace exporter")
				continue
			}
			exporters = append(exporters, exp)
		}
	}

	if wantedReader(m.config.TracingExporters) > 0 && len(exporters) == 0 {
		return fmt.Errorf("none of the %d configured tracing exporters could be created",
			wantedReader(m.config.TracingExporters))
	}

	// Create span processors
	var processors []sdktrace.SpanProcessor
	for _, exporter := range exporters {
		processor := sdktrace.NewBatchSpanProcessor(exporter)
		processors = append(processors, processor)
	}

	// Create tracer provider
	traceOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(m.config.TracingSampleRate)),
	}
	for _, processor := range processors {
		traceOptions = append(traceOptions, sdktrace.WithSpanProcessor(processor))
	}
	m.tracerProvider = sdktrace.NewTracerProvider(traceOptions...)

	// Set global tracer provider
	otel.SetTracerProvider(m.tracerProvider)

	// Set global propagator
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Create tracer
	m.tracer = otel.Tracer(
		"pahlevan.io/operator",
		trace.WithInstrumentationVersion(m.config.ServiceVersion),
	)

	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	log.Log.Info("Starting observability manager")

	// Start custom exporters
	for _, exporter := range m.exporters {
		if err := exporter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start exporter %s: %w", exporter.GetType(), err)
		}
	}

	// Initialize default dashboards
	if err := m.createDefaultDashboards(); err != nil {
		return fmt.Errorf("failed to create default dashboards: %w", err)
	}

	// Initialize default alert rules
	if err := m.createDefaultAlertRules(); err != nil {
		return fmt.Errorf("failed to create default alert rules: %w", err)
	}

	return nil
}

// shutdownTimeout bounds the final flush.
//
// An OTLP exporter whose collector is unreachable retries until its own
// deadline, so an unbounded shutdown makes the agent hang on exit for as long
// as the collector stays down - during a rollout, on every pod, while the
// kubelet counts toward the termination grace period and then SIGKILLs it.
// Losing the last batch of spans is much cheaper than that.
const shutdownTimeout = 5 * time.Second

// Shutdown flushes and stops every provider.
//
// Each provider is shut down even if an earlier one failed, and the errors are
// reported together. Returning at the first failure used to leave the tracer
// provider running, so a meter that could not flush also cost every buffered
// span.
func (m *Manager) Shutdown() error {
	close(m.stopCh)

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var errs []string
	if m.meterProvider != nil {
		if err := m.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("meter provider: %v", err))
		}
	}
	if m.tracerProvider != nil {
		if err := m.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("tracer provider: %v", err))
		}
	}

	// Stop custom exporters
	for _, exporter := range m.exporters {
		if err := exporter.Stop(ctx); err != nil {
			log.Log.Error(err, "Failed to stop exporter", "type", exporter.GetType())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("observability shutdown: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *Manager) GetMeter() metric.Meter {
	return m.meter
}

func (m *Manager) GetTracer() trace.Tracer {
	return m.tracer
}

func (m *Manager) CreateCounter(name, description, unit string) (metric.Int64Counter, error) {
	counter, err := m.meter.Int64Counter(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create counter: %w", err)
	}

	m.mu.Lock()
	m.customMetrics[name] = counter
	m.mu.Unlock()

	return counter, nil
}

func (m *Manager) CreateGauge(name, description, unit string) (metric.Float64Histogram, error) {
	gauge, err := m.meter.Float64Histogram(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gauge: %w", err)
	}

	m.mu.Lock()
	m.customMetrics[name] = gauge
	m.mu.Unlock()

	return gauge, nil
}

func (m *Manager) CreateHistogram(name, description, unit string) (metric.Float64Histogram, error) {
	histogram, err := m.meter.Float64Histogram(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create histogram: %w", err)
	}

	m.mu.Lock()
	m.customMetrics[name] = histogram
	m.mu.Unlock()

	return histogram, nil
}

func (m *Manager) RegisterExporter(exporter Exporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exporters = append(m.exporters, exporter)
}

func (m *Manager) CreateDashboard(config DashboardConfig) (*Dashboard, error) {
	dashboard := &Dashboard{
		ID:          fmt.Sprintf("dashboard-%d", time.Now().Unix()),
		Name:        config.Name,
		Type:        config.Type,
		Panels:      make([]*Panel, 0),
		Variables:   make([]*Variable, 0),
		LastUpdated: time.Now(),
		Config:      config.Config,
	}

	// Create panels
	for _, panelConfig := range config.Panels {
		panel := &Panel{
			ID:            fmt.Sprintf("panel-%d", time.Now().UnixNano()),
			Title:         panelConfig.Title,
			Type:          panelConfig.Type,
			Query:         panelConfig.Query,
			Visualization: &Visualization{},
		}

		// Create thresholds
		for _, thresholdConfig := range panelConfig.Thresholds {
			threshold := &Threshold{
				Value: thresholdConfig.Value,
				Color: thresholdConfig.Color,
				Op:    thresholdConfig.Op,
			}
			panel.Thresholds = append(panel.Thresholds, threshold)
		}

		dashboard.Panels = append(dashboard.Panels, panel)
	}

	// Create variables
	for _, variableConfig := range config.Variables {
		variable := &Variable{
			Name:    variableConfig.Name,
			Type:    variableConfig.Type,
			Query:   variableConfig.Query,
			Options: variableConfig.Options,
			Current: variableConfig.Default,
		}
		dashboard.Variables = append(dashboard.Variables, variable)
	}

	m.mu.Lock()
	m.dashboards[dashboard.ID] = dashboard
	m.mu.Unlock()

	return dashboard, nil
}

func (m *Manager) CreateAlertRule(config AlertRuleConfig) (*AlertRule, error) {
	alertRule := &AlertRule{
		ID:        fmt.Sprintf("alert-%d", time.Now().Unix()),
		Name:      config.Name,
		Query:     config.Query,
		Severity:  config.Severity,
		State:     AlertStateOK,
		Frequency: config.Frequency,
		For:       config.For,
	}

	// Create conditions
	for _, conditionConfig := range config.Conditions {
		condition := &Condition{
			Operator:  conditionConfig.Operator,
			Value:     conditionConfig.Value,
			Evaluator: conditionConfig.Evaluator,
		}
		alertRule.Conditions = append(alertRule.Conditions, condition)
	}

	// Create actions
	for _, actionConfig := range config.Actions {
		action := &Action{
			Type:       actionConfig.Type,
			Recipients: actionConfig.Recipients,
			Template:   actionConfig.Template,
			Config:     actionConfig.Config,
		}
		alertRule.Actions = append(alertRule.Actions, action)
	}

	m.mu.Lock()
	m.alertRules[alertRule.ID] = alertRule
	m.mu.Unlock()

	return alertRule, nil
}

func (m *Manager) createDefaultDashboards() error {
	// Create main overview dashboard
	overviewConfig := DashboardConfig{
		Name: "Pahlevan Overview",
		Type: DashboardTypeGrafana,
		Panels: []PanelConfig{
			{
				Title: "Policy Violations",
				Type:  PanelTypeGraph,
				Query: "rate(pahlevan_policy_violations_total[5m])",
			},
			{
				Title: "Enforcement Actions",
				Type:  PanelTypeGraph,
				Query: "rate(pahlevan_enforcement_actions_total[5m])",
			},
			{
				Title: "Self-Healing Events",
				Type:  PanelTypeGraph,
				Query: "rate(pahlevan_self_healing_actions_total[5m])",
			},
			{
				Title: "Attack Surface Risk Score",
				Type:  PanelTypeSingleStat,
				Query: "pahlevan_attack_surface_risk_score",
			},
		},
	}

	_, err := m.CreateDashboard(overviewConfig)
	return err
}

func (m *Manager) createDefaultAlertRules() error {
	// Create high violation rate alert
	violationAlertConfig := AlertRuleConfig{
		Name:      "High Policy Violation Rate",
		Query:     "rate(pahlevan_policy_violations_total[5m]) > 0.1",
		Severity:  AlertSeverityWarning,
		Frequency: 1 * time.Minute,
		For:       5 * time.Minute,
		Conditions: []ConditionConfig{
			{
				Operator:  ConditionOperatorGT,
				Value:     0.1,
				Evaluator: EvaluatorTypeAvg,
			},
		},
	}

	_, err := m.CreateAlertRule(violationAlertConfig)
	return err
}

func (m *Manager) ExportObservabilityData() (*ObservabilityData, error) {
	data := &ObservabilityData{
		Metrics:   make(map[string]*MetricData),
		Traces:    make([]*TraceData, 0),
		Logs:      make([]*LogData, 0),
		Events:    make([]*EventData, 0),
		Timestamp: time.Now(),
		Source:    "pahlevan-operator",
		Labels: map[string]string{
			"service": m.config.ServiceName,
			"version": m.config.ServiceVersion,
		},
	}

	// Export to registered exporters
	for _, exporter := range m.exporters {
		if err := exporter.Export(data); err != nil {
			log.Log.Error(err, "Failed to export observability data", "exporter", exporter.GetType())
		}
	}

	return data, nil
}

// StartSpan begins a span on the manager's tracer. It is safe to call before or
// after tracing is configured: when tracing is disabled the global no-op tracer
// is used, so callers never need to nil-check. Previously the manager built a
// TracerProvider with no exporters and no caller ever started a span, so tracing
// was advertised but produced nothing.
func (m *Manager) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	m.mu.RLock()
	tr := m.tracer
	m.mu.RUnlock()
	if tr == nil {
		tr = otel.Tracer("pahlevan.io/operator")
	}
	ctx, span := tr.Start(ctx, name)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	return ctx, span
}

// TracingEnabled reports whether at least one span exporter is configured, so
// callers and tests can distinguish "tracing off" from "tracing broken".
func (m *Manager) TracingEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tracerProvider != nil
}
