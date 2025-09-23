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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/metric"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Manager handles all metrics collection for Pahlevan
type Manager struct {
	mu            sync.RWMutex
	registry      prometheus.Registerer
	gatherer      prometheus.Gatherer
	meterProvider metric.MeterProvider
	meter         metric.Meter

	// Core metrics
	policyViolationsTotal     prometheus.Counter
	enforcementActionsTotal   prometheus.Counter
	selfHealingActionsTotal   prometheus.Counter
	learningProgressGauge     prometheus.Gauge
	attackSurfaceRiskScore    prometheus.Gauge
	containerLearningDuration prometheus.Histogram
	policyGenerationDuration  prometheus.Histogram
	rollbackActionsTotal      prometheus.Counter
	healthCheckScore          prometheus.Gauge
	privilegeReductionRatio   prometheus.Gauge

	// Syscall metrics
	syscallEventsTotal      *prometheus.CounterVec
	blockedSyscallsTotal    *prometheus.CounterVec
	allowedSyscallsTotal    *prometheus.CounterVec
	unknownSyscallsTotal    *prometheus.CounterVec
	syscallLatencyHistogram *prometheus.HistogramVec

	// Network metrics
	networkEventsTotal      *prometheus.CounterVec
	blockedConnectionsTotal *prometheus.CounterVec
	allowedConnectionsTotal *prometheus.CounterVec
	networkFlowsActive      *prometheus.GaugeVec
	networkBandwidthBytes   *prometheus.CounterVec

	// File system metrics
	fileEventsTotal            *prometheus.CounterVec
	blockedFileAccessTotal     *prometheus.CounterVec
	allowedFileAccessTotal     *prometheus.CounterVec
	fileSystemLatencyHistogram *prometheus.HistogramVec

	// Policy metrics
	policiesActive     prometheus.Gauge
	policiesLearning   prometheus.Gauge
	policiesEnforcing  prometheus.Gauge
	policiesFailed     prometheus.Gauge
	policyQualityScore *prometheus.GaugeVec

	// Container metrics
	containersTracked    prometheus.Gauge
	containersLearning   prometheus.Gauge
	containersEnforced   prometheus.Gauge
	containerStartupTime *prometheus.HistogramVec

	// Attack surface metrics
	exposedSyscallsTotal *prometheus.GaugeVec
	exposedPortsTotal    *prometheus.GaugeVec
	writablePathsTotal   *prometheus.GaugeVec
	capabilitiesTotal    *prometheus.GaugeVec
	vulnerabilityScore   *prometheus.GaugeVec

	// Performance metrics
	ebpfProgramLoad   prometheus.Histogram
	ebpfMapOperations *prometheus.CounterVec
	memoryUsageBytes  *prometheus.GaugeVec
	cpuUsagePercent   *prometheus.GaugeVec
	processingLatency *prometheus.HistogramVec

	// OpenTelemetry metrics
	otelPolicyViolationsTotal   metric.Int64Counter
	otelEnforcementActionsTotal metric.Int64Counter
	otelLearningProgressGauge   metric.Float64Histogram
	otelRiskScoreGauge          metric.Float64Histogram

	// Custom metrics registry
	customMetrics map[string]prometheus.Collector
}

// MetricLabels defines common metric labels
type MetricLabels struct {
	ContainerID  string
	Namespace    string
	PodName      string
	WorkloadName string
	WorkloadKind string
	PolicyName   string
	Phase        string
}

func NewManager() *Manager {
	// Create Prometheus registry
	registry := prometheus.NewRegistry()

	m := &Manager{
		registry:      registry,
		gatherer:      registry,
		customMetrics: make(map[string]prometheus.Collector),
	}

	m.initializePrometheusMetrics()

	return m
}

func (m *Manager) initializePrometheusMetrics() {
	// Core metrics
	m.policyViolationsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_policy_violations_total",
		Help: "Total number of policy violations detected",
	})

	m.enforcementActionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_enforcement_actions_total",
		Help: "Total number of enforcement actions taken",
	})

	m.selfHealingActionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_self_healing_actions_total",
		Help: "Total number of self-healing actions performed",
	})

	m.learningProgressGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_learning_progress_ratio",
		Help: "Current learning progress as a ratio (0-1)",
	})

	m.attackSurfaceRiskScore = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_attack_surface_risk_score",
		Help: "Current attack surface risk score (0-10)",
	})

	m.containerLearningDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pahlevan_container_learning_duration_seconds",
		Help:    "Time taken for container learning phase",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	})

	m.policyGenerationDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pahlevan_policy_generation_duration_seconds",
		Help:    "Time taken to generate security policies",
		Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
	})

	m.rollbackActionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_rollback_actions_total",
		Help: "Total number of policy rollback actions",
	})

	m.healthCheckScore = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_health_check_score",
		Help: "Current health check score (0-1)",
	})

	m.privilegeReductionRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_privilege_reduction_ratio",
		Help: "Ratio of privileges reduced through policy tightening",
	})

	// Syscall metrics
	m.syscallEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_syscall_events_total",
		Help: "Total number of syscall events processed",
	}, []string{"container_id", "syscall", "action"})

	m.blockedSyscallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_blocked_syscalls_total",
		Help: "Total number of blocked syscalls",
	}, []string{"container_id", "syscall", "reason"})

	m.allowedSyscallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_allowed_syscalls_total",
		Help: "Total number of allowed syscalls",
	}, []string{"container_id", "syscall"})

	m.unknownSyscallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_unknown_syscalls_total",
		Help: "Total number of unknown syscalls encountered",
	}, []string{"container_id", "syscall"})

	m.syscallLatencyHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pahlevan_syscall_processing_latency_seconds",
		Help:    "Latency of syscall processing",
		Buckets: prometheus.ExponentialBuckets(0.000001, 2, 20),
	}, []string{"container_id", "syscall"})

	// Network metrics
	m.networkEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_network_events_total",
		Help: "Total number of network events processed",
	}, []string{"container_id", "protocol", "direction", "action"})

	m.blockedConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_blocked_connections_total",
		Help: "Total number of blocked network connections",
	}, []string{"container_id", "protocol", "destination"})

	m.allowedConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_allowed_connections_total",
		Help: "Total number of allowed network connections",
	}, []string{"container_id", "protocol", "destination"})

	m.networkFlowsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_network_flows_active",
		Help: "Number of active network flows",
	}, []string{"container_id", "protocol"})

	m.networkBandwidthBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_network_bandwidth_bytes_total",
		Help: "Total network bandwidth in bytes",
	}, []string{"container_id", "direction"})

	// File system metrics
	m.fileEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_file_events_total",
		Help: "Total number of file system events processed",
	}, []string{"container_id", "operation", "action"})

	m.blockedFileAccessTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_blocked_file_access_total",
		Help: "Total number of blocked file access attempts",
	}, []string{"container_id", "path", "operation"})

	m.allowedFileAccessTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_allowed_file_access_total",
		Help: "Total number of allowed file access attempts",
	}, []string{"container_id", "path", "operation"})

	m.fileSystemLatencyHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pahlevan_file_processing_latency_seconds",
		Help:    "Latency of file system processing",
		Buckets: prometheus.ExponentialBuckets(0.000001, 2, 20),
	}, []string{"container_id", "operation"})

	// Policy metrics
	m.policiesActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_policies_active",
		Help: "Number of active PahlevanPolicies",
	})

	m.policiesLearning = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_policies_learning",
		Help: "Number of policies in learning phase",
	})

	m.policiesEnforcing = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_policies_enforcing",
		Help: "Number of policies in enforcing phase",
	})

	m.policiesFailed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_policies_failed",
		Help: "Number of failed policies",
	})

	m.policyQualityScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_policy_quality_score",
		Help: "Quality score of generated policies",
	}, []string{"policy_name", "container_id"})

	// Container metrics
	m.containersTracked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_containers_tracked",
		Help: "Number of containers being tracked",
	})

	m.containersLearning = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_containers_learning",
		Help: "Number of containers in learning phase",
	})

	m.containersEnforced = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_containers_enforced",
		Help: "Number of containers with enforced policies",
	})

	m.containerStartupTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pahlevan_container_startup_time_seconds",
		Help:    "Time from container start to policy enforcement",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	}, []string{"workload_kind", "namespace"})

	// Attack surface metrics
	m.exposedSyscallsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_exposed_syscalls_total",
		Help: "Number of exposed syscalls per container",
	}, []string{"container_id", "criticality"})

	m.exposedPortsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_exposed_ports_total",
		Help: "Number of exposed network ports",
	}, []string{"workload_name", "namespace", "protocol"})

	m.writablePathsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_writable_paths_total",
		Help: "Number of writable file paths",
	}, []string{"container_id", "path_type"})

	m.capabilitiesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_capabilities_total",
		Help: "Number of Linux capabilities granted",
	}, []string{"container_id", "capability_type"})

	m.vulnerabilityScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_vulnerability_score",
		Help: "Vulnerability score for containers",
	}, []string{"container_id", "severity"})

	// Performance metrics
	m.ebpfProgramLoad = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pahlevan_ebpf_program_load_duration_seconds",
		Help:    "Time taken to load eBPF programs",
		Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
	})

	m.ebpfMapOperations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_ebpf_map_operations_total",
		Help: "Total number of eBPF map operations",
	}, []string{"map_name", "operation"})

	m.memoryUsageBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_memory_usage_bytes",
		Help: "Memory usage in bytes",
	}, []string{"component"})

	m.cpuUsagePercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pahlevan_cpu_usage_percent",
		Help: "CPU usage percentage",
	}, []string{"component"})

	m.processingLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pahlevan_processing_latency_seconds",
		Help:    "Processing latency for various operations",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
	}, []string{"operation", "component"})

	// Register all metrics
	m.registerAllMetrics()
}

func (m *Manager) registerAllMetrics() {
	metrics := []prometheus.Collector{
		m.policyViolationsTotal,
		m.enforcementActionsTotal,
		m.selfHealingActionsTotal,
		m.learningProgressGauge,
		m.attackSurfaceRiskScore,
		m.containerLearningDuration,
		m.policyGenerationDuration,
		m.rollbackActionsTotal,
		m.healthCheckScore,
		m.privilegeReductionRatio,
		m.syscallEventsTotal,
		m.blockedSyscallsTotal,
		m.allowedSyscallsTotal,
		m.unknownSyscallsTotal,
		m.syscallLatencyHistogram,
		m.networkEventsTotal,
		m.blockedConnectionsTotal,
		m.allowedConnectionsTotal,
		m.networkFlowsActive,
		m.networkBandwidthBytes,
		m.fileEventsTotal,
		m.blockedFileAccessTotal,
		m.allowedFileAccessTotal,
		m.fileSystemLatencyHistogram,
		m.policiesActive,
		m.policiesLearning,
		m.policiesEnforcing,
		m.policiesFailed,
		m.policyQualityScore,
		m.containersTracked,
		m.containersLearning,
		m.containersEnforced,
		m.containerStartupTime,
		m.exposedSyscallsTotal,
		m.exposedPortsTotal,
		m.writablePathsTotal,
		m.capabilitiesTotal,
		m.vulnerabilityScore,
		m.ebpfProgramLoad,
		m.ebpfMapOperations,
		m.memoryUsageBytes,
		m.cpuUsagePercent,
		m.processingLatency,
	}

	for _, metric := range metrics {
		m.registry.MustRegister(metric)
	}
}

func (m *Manager) SetMeterProvider(provider metric.MeterProvider) {
	m.meterProvider = provider
	m.meter = provider.Meter("pahlevan.io/operator")

	// Initialize OpenTelemetry metrics
	m.initializeOTelMetrics()
}

func (m *Manager) initializeOTelMetrics() {
	var err error

	m.otelPolicyViolationsTotal, err = m.meter.Int64Counter(
		"pahlevan_policy_violations_total",
		metric.WithDescription("Total number of policy violations detected"),
	)
	if err != nil {
		log.Log.Error(err, "Failed to create OTel policy violations counter")
	}

	m.otelEnforcementActionsTotal, err = m.meter.Int64Counter(
		"pahlevan_enforcement_actions_total",
		metric.WithDescription("Total number of enforcement actions taken"),
	)
	if err != nil {
		log.Log.Error(err, "Failed to create OTel enforcement actions counter")
	}

	m.otelLearningProgressGauge, err = m.meter.Float64Histogram(
		"pahlevan_learning_progress_ratio",
		metric.WithDescription("Current learning progress as a ratio (0-1)"),
	)
	if err != nil {
		log.Log.Error(err, "Failed to create OTel learning progress gauge")
	}

	m.otelRiskScoreGauge, err = m.meter.Float64Histogram(
		"pahlevan_attack_surface_risk_score",
		metric.WithDescription("Current attack surface risk score (0-10)"),
	)
	if err != nil {
		log.Log.Error(err, "Failed to create OTel risk score gauge")
	}
}

// Metric recording methods

func (m *Manager) RecordPolicyViolation(labels MetricLabels) {
	m.policyViolationsTotal.Inc()
	if m.otelPolicyViolationsTotal != nil {
		m.otelPolicyViolationsTotal.Add(context.Background(), 1)
	}
}

func (m *Manager) RecordEnforcementAction(labels MetricLabels, actionType string) {
	m.enforcementActionsTotal.Inc()
	if m.otelEnforcementActionsTotal != nil {
		m.otelEnforcementActionsTotal.Add(context.Background(), 1)
	}
}

func (m *Manager) RecordSelfHealingAction(labels MetricLabels) {
	m.selfHealingActionsTotal.Inc()
}

func (m *Manager) UpdateLearningProgress(labels MetricLabels, progress float64) {
	m.learningProgressGauge.Set(progress)
	if m.otelLearningProgressGauge != nil {
		m.otelLearningProgressGauge.Record(context.Background(), progress)
	}
}

func (m *Manager) UpdateAttackSurfaceRiskScore(score float64) {
	m.attackSurfaceRiskScore.Set(score)
	if m.otelRiskScoreGauge != nil {
		m.otelRiskScoreGauge.Record(context.Background(), score)
	}
}

func (m *Manager) RecordContainerLearningDuration(labels MetricLabels, duration time.Duration) {
	m.containerLearningDuration.Observe(duration.Seconds())
}

func (m *Manager) RecordPolicyGenerationDuration(labels MetricLabels, duration time.Duration) {
	m.policyGenerationDuration.Observe(duration.Seconds())
}

func (m *Manager) RecordRollbackAction(labels MetricLabels) {
	m.rollbackActionsTotal.Inc()
}

func (m *Manager) UpdateHealthCheckScore(labels MetricLabels, score float64) {
	m.healthCheckScore.Set(score)
}

func (m *Manager) UpdatePrivilegeReductionRatio(labels MetricLabels, ratio float64) {
	m.privilegeReductionRatio.Set(ratio)
}

func (m *Manager) RecordSyscallEvent(labels MetricLabels, syscall string, action string) {
	m.syscallEventsTotal.WithLabelValues(labels.ContainerID, syscall, action).Inc()
}

func (m *Manager) RecordBlockedSyscall(labels MetricLabels, syscall string, reason string) {
	m.blockedSyscallsTotal.WithLabelValues(labels.ContainerID, syscall, reason).Inc()
}

func (m *Manager) RecordAllowedSyscall(labels MetricLabels, syscall string) {
	m.allowedSyscallsTotal.WithLabelValues(labels.ContainerID, syscall).Inc()
}

func (m *Manager) RecordUnknownSyscall(labels MetricLabels, syscall string) {
	m.unknownSyscallsTotal.WithLabelValues(labels.ContainerID, syscall).Inc()
}

func (m *Manager) RecordSyscallLatency(labels MetricLabels, syscall string, latency time.Duration) {
	m.syscallLatencyHistogram.WithLabelValues(labels.ContainerID, syscall).Observe(latency.Seconds())
}

func (m *Manager) RecordNetworkEvent(labels MetricLabels, protocol string, direction string, action string) {
	m.networkEventsTotal.WithLabelValues(labels.ContainerID, protocol, direction, action).Inc()
}

func (m *Manager) RecordBlockedConnection(labels MetricLabels, protocol string, destination string) {
	m.blockedConnectionsTotal.WithLabelValues(labels.ContainerID, protocol, destination).Inc()
}

func (m *Manager) RecordAllowedConnection(labels MetricLabels, protocol string, destination string) {
	m.allowedConnectionsTotal.WithLabelValues(labels.ContainerID, protocol, destination).Inc()
}

func (m *Manager) UpdateActiveNetworkFlows(labels MetricLabels, protocol string, count float64) {
	m.networkFlowsActive.WithLabelValues(labels.ContainerID, protocol).Set(count)
}

func (m *Manager) RecordNetworkBandwidth(labels MetricLabels, direction string, bytes float64) {
	m.networkBandwidthBytes.WithLabelValues(labels.ContainerID, direction).Add(bytes)
}

func (m *Manager) RecordFileEvent(labels MetricLabels, operation string, action string) {
	m.fileEventsTotal.WithLabelValues(labels.ContainerID, operation, action).Inc()
}

func (m *Manager) RecordBlockedFileAccess(labels MetricLabels, path string, operation string) {
	m.blockedFileAccessTotal.WithLabelValues(labels.ContainerID, path, operation).Inc()
}

func (m *Manager) RecordAllowedFileAccess(labels MetricLabels, path string, operation string) {
	m.allowedFileAccessTotal.WithLabelValues(labels.ContainerID, path, operation).Inc()
}

func (m *Manager) RecordFileLatency(labels MetricLabels, operation string, latency time.Duration) {
	m.fileSystemLatencyHistogram.WithLabelValues(labels.ContainerID, operation).Observe(latency.Seconds())
}

func (m *Manager) UpdatePolicyCounts(active, learning, enforcing, failed float64) {
	m.policiesActive.Set(active)
	m.policiesLearning.Set(learning)
	m.policiesEnforcing.Set(enforcing)
	m.policiesFailed.Set(failed)
}

func (m *Manager) UpdatePolicyQualityScore(labels MetricLabels, score float64) {
	m.policyQualityScore.WithLabelValues(labels.PolicyName, labels.ContainerID).Set(score)
}

func (m *Manager) UpdateContainerCounts(tracked, learning, enforced float64) {
	m.containersTracked.Set(tracked)
	m.containersLearning.Set(learning)
	m.containersEnforced.Set(enforced)
}

func (m *Manager) RecordContainerStartupTime(workloadKind, namespace string, duration time.Duration) {
	m.containerStartupTime.WithLabelValues(workloadKind, namespace).Observe(duration.Seconds())
}

func (m *Manager) UpdateExposedSyscalls(labels MetricLabels, criticality string, count float64) {
	m.exposedSyscallsTotal.WithLabelValues(labels.ContainerID, criticality).Set(count)
}

func (m *Manager) UpdateExposedPorts(workloadName, namespace, protocol string, count float64) {
	m.exposedPortsTotal.WithLabelValues(workloadName, namespace, protocol).Set(count)
}

func (m *Manager) UpdateWritablePaths(labels MetricLabels, pathType string, count float64) {
	m.writablePathsTotal.WithLabelValues(labels.ContainerID, pathType).Set(count)
}

func (m *Manager) UpdateCapabilities(labels MetricLabels, capabilityType string, count float64) {
	m.capabilitiesTotal.WithLabelValues(labels.ContainerID, capabilityType).Set(count)
}

func (m *Manager) UpdateVulnerabilityScore(labels MetricLabels, severity string, score float64) {
	m.vulnerabilityScore.WithLabelValues(labels.ContainerID, severity).Set(score)
}

func (m *Manager) RecordEBPFProgramLoad(duration time.Duration) {
	m.ebpfProgramLoad.Observe(duration.Seconds())
}

func (m *Manager) RecordEBPFMapOperation(mapName, operation string) {
	m.ebpfMapOperations.WithLabelValues(mapName, operation).Inc()
}

func (m *Manager) UpdateMemoryUsage(component string, bytes float64) {
	m.memoryUsageBytes.WithLabelValues(component).Set(bytes)
}

func (m *Manager) UpdateCPUUsage(component string, percent float64) {
	m.cpuUsagePercent.WithLabelValues(component).Set(percent)
}

func (m *Manager) RecordProcessingLatency(operation, component string, latency time.Duration) {
	m.processingLatency.WithLabelValues(operation, component).Observe(latency.Seconds())
}

// Custom metrics management

func (m *Manager) RegisterCustomMetric(name string, metric prometheus.Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.customMetrics[name]; exists {
		return prometheus.AlreadyRegisteredError{}
	}

	if err := m.registry.Register(metric); err != nil {
		return err
	}

	m.customMetrics[name] = metric
	return nil
}

func (m *Manager) UnregisterCustomMetric(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if metric, exists := m.customMetrics[name]; exists {
		m.registry.Unregister(metric)
		delete(m.customMetrics, name)
		return true
	}
	return false
}

func (m *Manager) GetGatherer() prometheus.Gatherer {
	return m.gatherer
}

func (m *Manager) GetRegistry() prometheus.Registerer {
	return m.registry
}
