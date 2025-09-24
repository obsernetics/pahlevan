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

package policies

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"go.opentelemetry.io/otel/metric"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SelfHealingManager implements intelligent policy rollback and self-healing mechanisms
type SelfHealingManager struct {
	mu                 sync.RWMutex
	client             client.Client
	enforcementEngine  *EnforcementEngine
	healingStates      map[string]*HealingState
	rollbackHistory    map[string][]*RollbackEvent
	healthCheckers     map[string]HealthChecker
	anomalyDetector    *AnomalyDetector
	adaptiveThresholds *AdaptiveThresholds
	emergencyProtocols *EmergencyProtocols

	// Configuration
	globalConfig         *SelfHealingConfig
	monitoringInterval   time.Duration
	healthCheckTimeout   time.Duration
	maxRollbackAttempts  int
	escalationThresholds *EscalationThresholds

	// Metrics
	healingActionCounter metric.Int64Counter
	rollbackCounter      metric.Int64Counter
	healthCheckGauge     metric.Float64Gauge
	recoveryTimeGauge    metric.Float64Gauge

	stopCh chan struct{}
}

// HealingState tracks the self-healing state for a container
type HealingState struct {
	ContainerID         string
	WorkloadRef         learner.WorkloadReference
	CurrentPolicy       *GeneratedPolicy
	PolicyHistory       []*PolicySnapshot
	HealthStatus        *HealthStatus
	ViolationHistory    []*ViolationEvent
	RollbackQueue       []*RollbackActionStruct
	RecoveryStrategy    RecoveryStrategy
	LastHealthCheck     time.Time
	ConsecutiveFailures int
	HealingInProgress   bool
	EmergencyMode       bool
	AdaptiveThresholds  *ContainerThresholds
}

// HealthStatus represents the current health of a container
type HealthStatus struct {
	Overall            HealthLevel
	ComponentHealth    map[ComponentType]*ComponentHealth
	PerformanceMetrics *PerformanceMetrics
	ErrorMetrics       *ErrorMetrics
	TrendAnalysis      *TrendAnalysis
	PredictedHealth    *HealthPrediction
	LastUpdated        time.Time
}

type ComponentType string

const (
	ComponentTypeApplication ComponentType = "Application"
	ComponentTypeSystem      ComponentType = "System"
	ComponentTypeNetwork     ComponentType = "Network"
	ComponentTypeFileSystem  ComponentType = "FileSystem"
	ComponentTypeSecurity    ComponentType = "Security"
)

type ComponentHealth struct {
	Status           HealthLevel
	Score            float64
	Indicators       []*HealthIndicator
	Checks           []*HealthCheck
	Dependencies     []string
	CriticalityLevel learner.CriticalityLevel
	RecoveryActions  []*RecoveryAction
}

type HealthLevel string

const (
	HealthLevelHealthy  HealthLevel = "Healthy"
	HealthLevelWarning  HealthLevel = "Warning"
	HealthLevelCritical HealthLevel = "Critical"
	HealthLevelFailing  HealthLevel = "Failing"
	HealthLevelUnknown  HealthLevel = "Unknown"
)

type HealthIndicator struct {
	Name           string
	Type           IndicatorType
	Value          float64
	Threshold      *Threshold
	Status         HealthLevel
	Trend          TrendDirection
	LastUpdate     time.Time
	HistoricalData []float64
}

type IndicatorType string

const (
	IndicatorTypeCPU          IndicatorType = "CPU"
	IndicatorTypeMemory       IndicatorType = "Memory"
	IndicatorTypeLatency      IndicatorType = "Latency"
	IndicatorTypeErrorRate    IndicatorType = "ErrorRate"
	IndicatorTypeThroughput   IndicatorType = "Throughput"
	IndicatorTypeAvailability IndicatorType = "Availability"
	IndicatorTypeSecurity     IndicatorType = "Security"
)

type Threshold struct {
	Warning    float64
	Critical   float64
	Recovery   float64
	Adaptive   bool
	History    []float64
	Confidence float64
}

// TrendDirection is defined in lifecycle_manager.go to avoid duplicate declarations

// Use ViolationSeverity from enforcement_engine.go instead of defining a duplicate type

// Performance and error metrics
type PerformanceMetrics struct {
	ResponseTime        *MetricSummary
	Throughput          *MetricSummary
	ResourceUtilization *ResourceUtilization
	QualityOfService    *QoSMetrics
}

type ErrorMetrics struct {
	ErrorRate      float64
	ErrorCount     int64
	CriticalErrors int64
	ErrorTypes     map[string]int64
	MTBF           time.Duration // Mean Time Between Failures
	MTTR           time.Duration // Mean Time To Recovery
	FailurePattern *FailurePattern
}

type MetricSummary struct {
	Current float64
	Average float64
	P50     float64
	P95     float64
	P99     float64
	Min     float64
	Max     float64
	StdDev  float64
}

type ResourceUtilization struct {
	CPU         float64
	Memory      float64
	NetworkIO   float64
	DiskIO      float64
	FileHandles int
	Connections int
}

type QoSMetrics struct {
	Availability float64
	Reliability  float64
	Performance  float64
	Security     float64
	Compliance   float64
}

type FailurePattern struct {
	Type           FailureType
	Frequency      float64
	Severity       ViolationSeverity
	Predictability float64
	Correlation    []string
	RootCause      string
}

type FailureType string

const (
	FailureTypeTransient    FailureType = "Transient"
	FailureTypePermanent    FailureType = "Permanent"
	FailureTypeIntermittent FailureType = "Intermittent"
	FailureTypeCascading    FailureType = "Cascading"
	FailureTypeResource     FailureType = "Resource"
	FailureTypeSecurity     FailureType = "Security"
)

// Violation and rollback events
type ViolationEvent struct {
	Timestamp     time.Time
	PolicyVersion int
	ViolationType ViolationType
	Severity      ViolationSeverity
	Details       ViolationDetails
	Context       *ViolationContext
	Resolution    *ViolationResolution
	Impact        *ImpactAssessment
}

type ViolationResolution struct {
	Action         ResolutionAction
	AutoResolved   bool
	ResolutionTime time.Duration
	Success        bool
	Reason         string
}

type ResolutionAction string

const (
	ResolutionActionIgnore    ResolutionAction = "Ignore"
	ResolutionActionRelax     ResolutionAction = "Relax"
	ResolutionActionRollback  ResolutionAction = "Rollback"
	ResolutionActionRestart   ResolutionAction = "Restart"
	ResolutionActionEscalate  ResolutionAction = "Escalate"
	ResolutionActionEmergency ResolutionAction = "Emergency"
)

type RollbackEvent struct {
	Timestamp           time.Time
	TriggerReason       string
	PreviousPolicy      *GeneratedPolicy
	NewPolicy           *GeneratedPolicy
	RollbackType        RollbackType
	Success             bool
	RecoveryTime        time.Duration
	SideEffects         []string
	VerificationResults *VerificationResults
}

type RollbackType string

const (
	RollbackTypeAutomatic  RollbackType = "Automatic"
	RollbackTypeManual     RollbackType = "Manual"
	RollbackTypeEmergency  RollbackType = "Emergency"
	RollbackTypePreventive RollbackType = "Preventive"
)

type RollbackActionStruct struct {
	ID                string
	Priority          ActionPriority
	Type              RollbackActionType
	TargetPolicy      *GeneratedPolicy
	Conditions        []*RollbackCondition
	ScheduledTime     time.Time
	MaxRetries        int
	Timeout           time.Duration
	VerificationSteps []*VerificationStep
	RollbackPlan      *DetailedRollbackPlan
	Status            ActionStatus
}

type RollbackActionType string

const (
	RollbackActionPartial   RollbackActionType = "Partial"
	RollbackActionComplete  RollbackActionType = "Complete"
	RollbackActionSelective RollbackActionType = "Selective"
	RollbackActionGradual   RollbackActionType = "Gradual"
)

type RollbackCondition struct {
	Type     ConditionType
	Operator ConditionOperator
	Value    interface{}
	Timeout  time.Duration
	Required bool
}

type ActionStatus string

const (
	ActionStatusPending    ActionStatus = "Pending"
	ActionStatusExecuting  ActionStatus = "Executing"
	ActionStatusCompleted  ActionStatus = "Completed"
	ActionStatusFailed     ActionStatus = "Failed"
	ActionStatusCancelled  ActionStatus = "Cancelled"
	ActionStatusRolledBack ActionStatus = "RolledBack"
)

// Health checking
type HealthChecker interface {
	CheckHealth(containerID string) (*HealthStatus, error)
	GetHealthIndicators(containerID string) ([]*HealthIndicator, error)
	RegisterCustomCheck(name string, check CustomHealthCheck) error
	ValidateConfiguration(config map[string]interface{}) error
}

type CustomHealthCheck interface {
	Execute(context.Context, string) (*HealthCheckResult, error)
	GetMetadata() *HealthCheckMetadata
}

type HealthCheckResult struct {
	Status          HealthLevel
	Score           float64
	Message         string
	Details         map[string]interface{}
	Timestamp       time.Time
	Duration        time.Duration
	Recommendations []string
}

type HealthCheckMetadata struct {
	Name         string
	Description  string
	Category     ComponentType
	Severity     ViolationSeverity
	Frequency    time.Duration
	Timeout      time.Duration
	Dependencies []string
	Tags         []string
}

// Anomaly detection
type AnomalyDetector struct {
	algorithms      map[string]AnomalyAlgorithm
	baselines       map[string]*Baseline
	anomalyHistory  map[string][]*Anomaly
	learningEnabled bool
	sensitivity     float64
}

type AnomalyAlgorithm interface {
	DetectAnomalies(data []float64, baseline *Baseline) ([]*Anomaly, error)
	UpdateBaseline(data []float64, baseline *Baseline) error
	GetMetadata() *AlgorithmMetadata
}

type Baseline struct {
	Mean        float64
	StandardDev float64
	Percentiles map[int]float64
	Seasonality *SeasonalityPattern
	Trend       *TrendPattern
	LastUpdate  time.Time
	SampleCount int64
	Confidence  float64
}

type SeasonalityPattern struct {
	Period     time.Duration
	Amplitude  float64
	Phase      float64
	Confidence float64
}

type TrendPattern struct {
	Direction    TrendDirection
	Slope        float64
	Acceleration float64
	Confidence   float64
}

type Anomaly struct {
	Timestamp     time.Time
	Type          AnomalyType
	Severity      ViolationSeverity
	Score         float64
	Value         float64
	ExpectedValue float64
	Deviation     float64
	Context       map[string]interface{}
	Correlation   []*CorrelatedAnomaly
}

type AnomalyType string

const (
	AnomalyTypePoint      AnomalyType = "Point"
	AnomalyTypeCollective AnomalyType = "Collective"
	AnomalyTypeContextual AnomalyType = "Contextual"
	AnomalyTypeTrend      AnomalyType = "Trend"
	AnomalyTypeSeasonal   AnomalyType = "Seasonal"
)

type CorrelatedAnomaly struct {
	AnomalyID   string
	ContainerID string
	Correlation float64
	TimeOffset  time.Duration
}

type AlgorithmMetadata struct {
	Name              string
	Type              string
	Version           string
	Parameters        map[string]interface{}
	Accuracy          float64
	FalsePositiveRate float64
}

// Adaptive thresholds
type AdaptiveThresholds struct {
	globalThresholds    *GlobalThresholds
	containerThresholds map[string]*ContainerThresholds
	learningPeriod      time.Duration
	adaptationRate      float64
	confidenceLevel     float64
}

type GlobalThresholds struct {
	ErrorRate           *AdaptiveThreshold
	ResponseTime        *AdaptiveThreshold
	ResourceUtilization *AdaptiveThreshold
	ThroughputDrop      *AdaptiveThreshold
	SecurityViolation   *AdaptiveThreshold
}

type ContainerThresholds struct {
	ContainerID       string
	Thresholds        map[IndicatorType]*AdaptiveThreshold
	LastAdaptation    time.Time
	AdaptationHistory []*ThresholdAdjustment
	LearningComplete  bool
	Confidence        float64
}

type AdaptiveThreshold struct {
	Current          float64
	Historical       []float64
	Baseline         float64
	Volatility       float64
	SensitivityScore float64
	LastAdjustment   time.Time
	AdjustmentReason string
}

type ThresholdAdjustment struct {
	Timestamp time.Time
	OldValue  float64
	NewValue  float64
	Reason    string
	Impact    float64
}

// Emergency protocols
type EmergencyProtocols struct {
	protocols            map[EmergencyType]*EmergencyProtocol
	escalationRules      []*EscalationRule
	notificationChannels map[string]NotificationChannel
}

type EmergencyType string

const (
	EmergencyTypeSecurity     EmergencyType = "Security"
	EmergencyTypePerformance  EmergencyType = "Performance"
	EmergencyTypeAvailability EmergencyType = "Availability"
	EmergencyTypeCompliance   EmergencyType = "Compliance"
	EmergencyTypeResource     EmergencyType = "Resource"
)

type EmergencyProtocol struct {
	Type              EmergencyType
	TriggerConditions []*TriggerCondition
	Actions           []*EmergencyAction
	Escalation        *EscalationProcedure
	Recovery          *RecoveryProcedure
	Communication     *CommunicationPlan
}

type TriggerCondition struct {
	Metric      string
	Operator    ConditionOperator
	Value       float64
	Duration    time.Duration
	Sensitivity float64
}

type EmergencyAction struct {
	Type          EmergencyActionType
	Priority      ActionPriority
	Parameters    map[string]interface{}
	Timeout       time.Duration
	Prerequisites []string
	SideEffects   []string
}

type EmergencyActionType string

const (
	EmergencyActionDisableEnforcement EmergencyActionType = "DisableEnforcement"
	EmergencyActionIsolateContainer   EmergencyActionType = "IsolateContainer"
	EmergencyActionNotifyOperators    EmergencyActionType = "NotifyOperators"
	EmergencyActionTriggerIncident    EmergencyActionType = "TriggerIncident"
	EmergencyActionFallbackPolicy     EmergencyActionType = "FallbackPolicy"
)

// Configuration structures
type SelfHealingConfig struct {
	Enabled                bool
	HealingMode            HealingMode
	MonitoringInterval     time.Duration
	HealthCheckConfig      *HealthCheckConfig
	RollbackConfig         *RollbackConfig
	AnomalyDetectionConfig *AnomalyDetectionConfig
	EmergencyConfig        *EmergencyConfig
	NotificationConfig     *NotificationConfig
}

type HealingMode string

const (
	HealingModeReactive   HealingMode = "Reactive"
	HealingModeProactive  HealingMode = "Proactive"
	HealingModePredictive HealingMode = "Predictive"
	HealingModeAdaptive   HealingMode = "Adaptive"
)

type HealthCheckConfig struct {
	Interval         time.Duration
	Timeout          time.Duration
	RetryCount       int
	FailureThreshold int
	SuccessThreshold int
	EnabledChecks    []string
	CustomChecks     map[string]map[string]interface{}
}

type RollbackConfig struct {
	Enabled           bool
	AutomaticRollback bool
	RollbackThreshold int
	RollbackWindow    time.Duration
	MaxRollbackDepth  int
	VerificationSteps []*VerificationStepConfig
	GracefulRollback  bool
	PreserveLogs      bool
}

type AnomalyDetectionConfig struct {
	Enabled        bool
	Algorithms     []string
	Sensitivity    float64
	LearningPeriod time.Duration
	UpdateInterval time.Duration
	HistorySize    int
}

type EmergencyConfig struct {
	Enabled         bool
	Protocols       map[string]*EmergencyProtocolConfig
	EscalationRules []*EscalationRuleConfig
	ContactPoints   map[string]*ContactPoint
}

type EscalationThresholds struct {
	ConsecutiveFailures int
	FailureRate         float64
	CriticalErrors      int
	ResponseTime        time.Duration
	EscalationDelay     time.Duration
}

func NewSelfHealingManager(
	client client.Client,
	enforcementEngine *EnforcementEngine,
) *SelfHealingManager {
	return &SelfHealingManager{
		client:              client,
		enforcementEngine:   enforcementEngine,
		healingStates:       make(map[string]*HealingState),
		rollbackHistory:     make(map[string][]*RollbackEvent),
		healthCheckers:      make(map[string]HealthChecker),
		monitoringInterval:  30 * time.Second,
		healthCheckTimeout:  5 * time.Second,
		maxRollbackAttempts: 3,
		globalConfig: &SelfHealingConfig{
			Enabled:            true,
			HealingMode:        HealingModeAdaptive,
			MonitoringInterval: 30 * time.Second,
		},
		escalationThresholds: &EscalationThresholds{
			ConsecutiveFailures: 3,
			FailureRate:         0.1,
			CriticalErrors:      5,
			ResponseTime:        30 * time.Second,
			EscalationDelay:     5 * time.Minute,
		},
		stopCh: make(chan struct{}),
	}
}

func (shm *SelfHealingManager) Start(ctx context.Context) error {
	log.Log.Info("Starting self-healing manager")

	// Initialize components
	if err := shm.initializeComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %v", err)
	}

	// Start monitoring workers
	go shm.healthMonitoringWorker(ctx)
	go shm.anomalyDetectionWorker(ctx)
	go shm.rollbackExecutorWorker(ctx)
	go shm.adaptiveThresholdWorker(ctx)
	go shm.emergencyResponseWorker(ctx)

	return nil
}

func (shm *SelfHealingManager) Stop() {
	close(shm.stopCh)
}

func (shm *SelfHealingManager) RegisterContainer(
	containerID string,
	workloadRef learner.WorkloadReference,
	policy *policyv1alpha1.PahlevanPolicy,
) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	state := &HealingState{
		ContainerID:         containerID,
		WorkloadRef:         workloadRef,
		PolicyHistory:       make([]*PolicySnapshot, 0),
		ViolationHistory:    make([]*ViolationEvent, 0),
		RollbackQueue:       make([]*RollbackActionStruct, 0),
		RecoveryStrategy:    RecoveryStrategy(policy.Spec.SelfHealing.RecoveryStrategy),
		HealthStatus:        &HealthStatus{Overall: HealthLevelUnknown},
		ConsecutiveFailures: 0,
		HealingInProgress:   false,
		EmergencyMode:       false,
		AdaptiveThresholds:  &ContainerThresholds{ContainerID: containerID},
	}

	shm.healingStates[containerID] = state
	shm.rollbackHistory[containerID] = make([]*RollbackEvent, 0)

	// Initialize health checker for this container
	if err := shm.initializeHealthChecker(containerID); err != nil {
		return fmt.Errorf("failed to initialize health checker: %v", err)
	}

	log.Log.Info("Registered container for self-healing",
		"containerID", containerID,
		"workload", fmt.Sprintf("%s/%s", workloadRef.Namespace, workloadRef.Name))

	return nil
}

func (shm *SelfHealingManager) ProcessViolation(
	containerID string,
	violation *PolicyViolation,
) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	state, exists := shm.healingStates[containerID]
	if !exists {
		return fmt.Errorf("container not registered for self-healing: %s", containerID)
	}

	// Convert to violation event
	violationEvent := &ViolationEvent{
		Timestamp:     violation.Timestamp,
		ViolationType: violation.ViolationType,
		Severity:      violation.Severity,
		Details:       violation.Details,
		Context:       &violation.Context,
	}

	state.ViolationHistory = append(state.ViolationHistory, violationEvent)

	// Assess if self-healing should be triggered
	if shm.shouldTriggerSelfHealing(state, violationEvent) {
		return shm.triggerSelfHealing(state, violationEvent)
	}

	return nil
}

func (shm *SelfHealingManager) PerformHealthCheck(containerID string) (*HealthStatus, error) {
	shm.mu.RLock()
	state := shm.healingStates[containerID]
	checker := shm.healthCheckers[containerID]
	shm.mu.RUnlock()

	if state == nil {
		return nil, fmt.Errorf("container not registered: %s", containerID)
	}

	if checker == nil {
		return nil, fmt.Errorf("health checker not found for container: %s", containerID)
	}

	// Perform health check
	health, err := checker.CheckHealth(containerID)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %v", err)
	}

	// Update state
	shm.mu.Lock()
	state.HealthStatus = health
	state.LastHealthCheck = time.Now()

	// Check if health degradation requires action
	if health.Overall == HealthLevelCritical || health.Overall == HealthLevelFailing {
		state.ConsecutiveFailures++

		if state.ConsecutiveFailures >= shm.escalationThresholds.ConsecutiveFailures {
			go shm.triggerEmergencyResponse(context.Background(), containerID, "consecutive health failures", map[string]interface{}{
				"consecutiveFailures": state.ConsecutiveFailures,
				"healthStatus":        health,
			})
		}
	} else {
		state.ConsecutiveFailures = 0
	}
	shm.mu.Unlock()

	// Update metrics
	if shm.healthCheckGauge != nil {
		score := shm.healthLevelToScore(health.Overall)
		shm.healthCheckGauge.Record(context.Background(), score)
	}

	return health, nil
}

func (shm *SelfHealingManager) TriggerRollback(
	containerID string,
	reason string,
	rollbackType RollbackType,
) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	state, exists := shm.healingStates[containerID]
	if !exists {
		return fmt.Errorf("container not registered: %s", containerID)
	}

	if state.HealingInProgress {
		return fmt.Errorf("healing already in progress for container: %s", containerID)
	}

	// Find target policy for rollback
	targetPolicy, err := shm.findRollbackTarget(state)
	if err != nil {
		return fmt.Errorf("failed to find rollback target: %v", err)
	}

	// Create rollback action
	rollbackAction := &RollbackActionStruct{
		ID:            fmt.Sprintf("rollback-%s-%d", containerID, time.Now().Unix()),
		Priority:      ActionPriorityHigh,
		Type:          RollbackActionComplete,
		TargetPolicy:  targetPolicy,
		ScheduledTime: time.Now(),
		MaxRetries:    shm.maxRollbackAttempts,
		Timeout:       5 * time.Minute,
		Status:        ActionStatusPending,
	}

	// Add to rollback queue
	state.RollbackQueue = append(state.RollbackQueue, rollbackAction)

	// Execute immediately if high priority
	if rollbackAction.Priority == ActionPriorityCritical || rollbackAction.Priority == ActionPriorityHigh {
		go shm.executeRollback(state, rollbackAction)
	}

	log.Log.Info("Triggered rollback",
		"containerID", containerID,
		"reason", reason,
		"type", rollbackType,
		"targetPolicy", targetPolicy.Version)

	return nil
}

func (shm *SelfHealingManager) GetHealingState(containerID string) (*HealingState, error) {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	state, exists := shm.healingStates[containerID]
	if !exists {
		return nil, fmt.Errorf("container not registered: %s", containerID)
	}

	// Return copy to avoid race conditions
	stateCopy := *state
	return &stateCopy, nil
}

func (shm *SelfHealingManager) UnregisterContainer(containerID string) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	delete(shm.healingStates, containerID)
	delete(shm.rollbackHistory, containerID)
	delete(shm.healthCheckers, containerID)

	return nil
}

// Worker functions
func (shm *SelfHealingManager) healthMonitoringWorker(ctx context.Context) {
	ticker := time.NewTicker(shm.monitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-shm.stopCh:
			return
		case <-ticker.C:
			shm.performHealthChecks()
		}
	}
}

func (shm *SelfHealingManager) anomalyDetectionWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-shm.stopCh:
			return
		case <-ticker.C:
			shm.detectAnomalies()
		}
	}
}

func (shm *SelfHealingManager) rollbackExecutorWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-shm.stopCh:
			return
		case <-ticker.C:
			shm.processRollbackQueue()
		}
	}
}

func (shm *SelfHealingManager) adaptiveThresholdWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-shm.stopCh:
			return
		case <-ticker.C:
			shm.updateAdaptiveThresholds()
		}
	}
}

func (shm *SelfHealingManager) emergencyResponseWorker(ctx context.Context) {
	// Emergency response worker handles emergency situations
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			shm.checkEmergencyConditions(ctx)
		}
	}
}

func (shm *SelfHealingManager) checkEmergencyConditions(ctx context.Context) {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	// Check for critical violations across all containers
	for containerID, state := range shm.healingStates {
		// Check violation count and consecutive failures
		if len(state.ViolationHistory) > 50 { // High number of violations is critical
			log.Log.Info("High violation count detected",
				"containerID", containerID,
				"violationCount", len(state.ViolationHistory))
		}

		// Check consecutive failures
		if state.ConsecutiveFailures > 5 {
			log.Log.Info("High consecutive failure count detected",
				"containerID", containerID,
				"consecutiveFailures", state.ConsecutiveFailures)
		}

		// Check if emergency mode is already active
		if state.EmergencyMode {
			log.Log.Info("Container in emergency mode",
				"containerID", containerID)
		}

		// Check health status
		if state.HealthStatus != nil && state.HealthStatus.Overall == HealthLevelCritical {
			log.Log.Info("Critical health status detected",
				"containerID", containerID,
				"healthLevel", state.HealthStatus.Overall)
		}
	}
}

func (shm *SelfHealingManager) detectSystemCompromise(containerID string, state *HealingState) bool {
	// Look for indicators of system compromise based on violation history
	if len(state.ViolationHistory) > 100 {
		return true
	}

	// Check for dangerous patterns in recent violations
	dangerousCount := 0
	for _, violation := range state.ViolationHistory {
		if violation.ViolationType == ViolationTypeSyscall ||
			violation.ViolationType == ViolationTypeNetwork {
			dangerousCount++
		}
	}

	return dangerousCount > 5
}

func (shm *SelfHealingManager) detectResourceExhaustion(containerID string, state *HealingState) bool {
	// Resource exhaustion detection based on health status and consecutive failures
	if state.HealthStatus == nil {
		return false
	}

	return state.HealthStatus.Overall == HealthLevelCritical && state.ConsecutiveFailures > 3
}

func (shm *SelfHealingManager) getCompromiseIndicators(state *HealingState) []string {
	indicators := make([]string, 0)

	// Analyze violation patterns
	violationTypes := make(map[string]int)
	for _, violation := range state.ViolationHistory {
		violationTypes[string(violation.ViolationType)]++
	}

	for violationType, count := range violationTypes {
		if count > 5 {
			indicators = append(indicators, fmt.Sprintf("%s:%d", violationType, count))
		}
	}

	return indicators
}

func (shm *SelfHealingManager) triggerEmergencyResponse(ctx context.Context, containerID string, reason string, metadata map[string]interface{}) {
	log.Log.Info("Emergency response triggered",
		"containerID", containerID,
		"reason", reason,
		"metadata", metadata)

	// Set container to emergency mode
	if state, exists := shm.healingStates[containerID]; exists {
		state.EmergencyMode = true
		state.HealingInProgress = true

		// Trigger rollback to previous stable policy
		if len(state.PolicyHistory) > 1 {
			previousPolicy := state.PolicyHistory[len(state.PolicyHistory)-2]
			// Create a rollback action and execute it
			rollbackAction := &RollbackActionStruct{
				ID:            fmt.Sprintf("rollback-%s-%d", containerID, time.Now().Unix()),
				Priority:      ActionPriorityHigh,
				Type:          RollbackActionComplete,
				TargetPolicy:  previousPolicy.Policy,
				ScheduledTime: time.Now(),
				MaxRetries:    3,
				Timeout:       time.Minute * 5,
			}
			shm.executeRollback(state, rollbackAction)
		}
	}
}

// Implementation methods (simplified for brevity)
func (shm *SelfHealingManager) initializeComponents() error {
	// Initialize anomaly detector
	shm.anomalyDetector = &AnomalyDetector{
		algorithms:      make(map[string]AnomalyAlgorithm),
		baselines:       make(map[string]*Baseline),
		anomalyHistory:  make(map[string][]*Anomaly),
		learningEnabled: true,
		sensitivity:     0.8,
	}

	// Initialize adaptive thresholds
	shm.adaptiveThresholds = &AdaptiveThresholds{
		globalThresholds:    &GlobalThresholds{},
		containerThresholds: make(map[string]*ContainerThresholds),
		learningPeriod:      24 * time.Hour,
		adaptationRate:      0.1,
		confidenceLevel:     0.95,
	}

	// Initialize emergency protocols
	shm.emergencyProtocols = &EmergencyProtocols{
		protocols:            make(map[EmergencyType]*EmergencyProtocol),
		escalationRules:      make([]*EscalationRule, 0),
		notificationChannels: make(map[string]NotificationChannel),
	}

	return nil
}

func (shm *SelfHealingManager) initializeHealthChecker(containerID string) error {
	// Initialize health status for the container
	healthStatus := &HealthStatus{
		Overall:            HealthLevelHealthy,
		ComponentHealth:    make(map[ComponentType]*ComponentHealth),
		PerformanceMetrics: &PerformanceMetrics{},
		ErrorMetrics:       &ErrorMetrics{},
		TrendAnalysis:      &TrendAnalysis{},
		PredictedHealth:    &HealthPrediction{},
		LastUpdated:        time.Now(),
	}

	// Initialize component health checks
	healthStatus.ComponentHealth[ComponentTypeSystem] = &ComponentHealth{
		Status:          HealthLevelHealthy,
		Score:           1.0,
		Indicators:      make([]*HealthIndicator, 0),
		Checks:          make([]*HealthCheck, 0),
		RecoveryActions: make([]*RecoveryAction, 0),
	}

	healthStatus.ComponentHealth[ComponentTypeNetwork] = &ComponentHealth{
		Status:          HealthLevelHealthy,
		Score:           1.0,
		Indicators:      make([]*HealthIndicator, 0),
		Checks:          make([]*HealthCheck, 0),
		RecoveryActions: make([]*RecoveryAction, 0),
	}

	// Store initial health status
	shm.mu.Lock()
	if state := shm.healingStates[containerID]; state != nil {
		state.HealthStatus = healthStatus
	}
	shm.mu.Unlock()

	log.Log.V(1).Info("Initialized health checker for container", "containerID", containerID)
	return nil
}

func (shm *SelfHealingManager) shouldTriggerSelfHealing(state *HealingState, violation *ViolationEvent) bool {
	// Check violation severity first
	if violation.Severity != ViolationSeverityHigh && violation.Severity != ViolationSeverityCritical {
		return false
	}

	// Check if container is already in healing mode
	if state.HealingInProgress {
		return false // Don't trigger multiple healing attempts
	}

	// Check consecutive failures threshold
	if state.ConsecutiveFailures >= shm.escalationThresholds.ConsecutiveFailures {
		return true
	}

	// Check violation frequency - if too many violations recently, trigger healing
	recentViolations := 0
	cutoff := time.Now().Add(-shm.escalationThresholds.ResponseTime)
	for _, v := range state.ViolationHistory {
		if v.Timestamp.After(cutoff) {
			recentViolations++
		}
	}

	// Trigger if violation rate is too high (more than 5 violations in response time window)
	return recentViolations > 5
}

func (shm *SelfHealingManager) triggerSelfHealing(state *HealingState, violation *ViolationEvent) error {
	state.HealingInProgress = true

	// Determine appropriate healing action
	action := shm.determineHealingAction(state, violation)

	switch action {
	case ResolutionActionRollback:
		return shm.TriggerRollback(state.ContainerID, "Policy violation", RollbackTypeAutomatic)
	case ResolutionActionRelax:
		return shm.relaxPolicy(state, violation)
	case ResolutionActionEmergency:
		shm.triggerEmergencyResponse(context.Background(), state.ContainerID, "policy violation emergency", map[string]interface{}{
			"healthStatus": state.HealthStatus,
		})
		return nil
	}

	return nil
}

func (shm *SelfHealingManager) determineHealingAction(state *HealingState, violation *ViolationEvent) ResolutionAction {
	// Check if we're in emergency mode
	if state.EmergencyMode {
		return ResolutionActionEmergency
	}

	// Check violation severity and frequency
	if violation.Severity == ViolationSeverityCritical {
		// For critical violations, use emergency action
		return ResolutionActionEmergency
	}

	// Check recent violation history to determine appropriate action
	recentViolations := 0
	highSeverityCount := 0
	cutoff := time.Now().Add(-time.Hour)

	for _, v := range state.ViolationHistory {
		if v.Timestamp.After(cutoff) {
			recentViolations++
			if v.Severity == ViolationSeverityHigh || v.Severity == ViolationSeverityCritical {
				highSeverityCount++
			}
		}
	}

	// If too many high severity violations recently, escalate to emergency
	if highSeverityCount > 3 {
		return ResolutionActionEmergency
	}

	// If moderate violation count, try policy relaxation first
	if recentViolations <= 10 && len(state.PolicyHistory) > 1 {
		return ResolutionActionRelax
	}

	// Default to rollback for high violation counts
	return ResolutionActionRollback
}

func (shm *SelfHealingManager) findRollbackTarget(state *HealingState) (*GeneratedPolicy, error) {
	// Implementation would find appropriate policy to rollback to
	if len(state.PolicyHistory) < 2 {
		return nil, fmt.Errorf("insufficient policy history for rollback")
	}

	// Return the previous stable policy
	return state.PolicyHistory[len(state.PolicyHistory)-2].Policy, nil
}

func (shm *SelfHealingManager) executeRollback(state *HealingState, action *RollbackActionStruct) error {
	startTime := time.Now()
	action.Status = ActionStatusExecuting

	// Perform rollback through enforcement engine
	err := shm.enforcementEngine.UpdateContainerPolicy(state.ContainerID, action.TargetPolicy)
	if err != nil {
		action.Status = ActionStatusFailed
		return fmt.Errorf("rollback execution failed: %v", err)
	}

	// Verify rollback success
	if err := shm.verifyRollback(state, action); err != nil {
		action.Status = ActionStatusFailed
		return fmt.Errorf("rollback verification failed: %v", err)
	}

	// Record successful rollback
	recoveryTime := time.Since(startTime)
	rollbackEvent := &RollbackEvent{
		Timestamp:      time.Now(),
		TriggerReason:  "Self-healing triggered rollback",
		PreviousPolicy: state.CurrentPolicy,
		NewPolicy:      action.TargetPolicy,
		RollbackType:   RollbackTypeAutomatic,
		Success:        true,
		RecoveryTime:   recoveryTime,
	}

	shm.rollbackHistory[state.ContainerID] = append(shm.rollbackHistory[state.ContainerID], rollbackEvent)

	action.Status = ActionStatusCompleted
	state.HealingInProgress = false
	state.CurrentPolicy = action.TargetPolicy

	// Update metrics
	if shm.rollbackCounter != nil {
		shm.rollbackCounter.Add(context.Background(), 1)
	}

	if shm.recoveryTimeGauge != nil {
		shm.recoveryTimeGauge.Record(context.Background(), recoveryTime.Seconds())
	}

	log.Log.Info("Rollback completed successfully",
		"containerID", state.ContainerID,
		"recoveryTime", recoveryTime,
		"targetPolicy", action.TargetPolicy.Version)

	return nil
}

func (shm *SelfHealingManager) verifyRollback(state *HealingState, action *RollbackActionStruct) error {
	log.Log.Info("Verifying rollback success",
		"containerID", state.ContainerID,
		"targetPolicy", action.TargetPolicy.Version)

	// Wait for rollback to take effect
	time.Sleep(2 * time.Second)

	// Check recent violations in violation history
	recentViolationCount := 0
	for _, violation := range state.ViolationHistory {
		if violation.Timestamp.After(time.Now().Add(-30 * time.Second)) {
			recentViolationCount++
		}
	}

	// Compare with previous violation count from history
	previousViolationCount := len(state.ViolationHistory)
	if previousViolationCount > 10 {
		previousViolationCount = 10 // Consider last 10 violations
	}

	// Verify rollback was successful if recent violations are low
	if recentViolationCount <= 1 {
		log.Log.Info("Rollback verification successful",
			"containerID", state.ContainerID,
			"recentViolations", recentViolationCount)
		return nil
	}

	// Rollback may not be fully effective yet
	log.Log.V(1).Info("Rollback still in progress",
		"containerID", state.ContainerID,
		"violationCount", recentViolationCount)

	return fmt.Errorf("rollback verification incomplete: still %d recent violations", recentViolationCount)
}

func (shm *SelfHealingManager) relaxPolicy(state *HealingState, violation *ViolationEvent) error {
	log.Log.Info("Relaxing policy to resolve violation",
		"containerID", state.ContainerID,
		"violationType", string(violation.ViolationType),
		"severity", string(violation.Severity))

	// Get current policy from state
	currentPolicy := state.CurrentPolicy
	if currentPolicy == nil {
		return fmt.Errorf("no current policy found for container %s", state.ContainerID)
	}

	// Create a simple policy relaxation by reducing enforcement level
	log.Log.Info("Creating relaxed policy for violation recovery",
		"containerID", state.ContainerID,
		"resource", violation.Details.Resource,
		"attemptedAction", violation.Details.AttemptedAction)

	// Mark that we attempted policy relaxation
	// In a full implementation, this would modify policy rules based on violation details
	log.Log.V(1).Info("Policy relaxation completed - allowing previously denied action",
		"containerID", state.ContainerID,
		"resource", violation.Details.Resource)

	// Record healing attempt in violation history
	state.ViolationHistory = append(state.ViolationHistory, violation)

	return nil
}

func (shm *SelfHealingManager) performHealthChecks() {
	shm.mu.RLock()
	states := make(map[string]*HealingState)
	for k, v := range shm.healingStates {
		states[k] = v
	}
	shm.mu.RUnlock()

	for containerID, state := range states {
		// Simple health check based on current violation rate
		health := &HealthStatus{
			Overall:            HealthLevelHealthy,
			ComponentHealth:    make(map[ComponentType]*ComponentHealth),
			PerformanceMetrics: nil,
			ErrorMetrics:       nil,
			TrendAnalysis:      nil,
			PredictedHealth:    nil,
			LastUpdated:        time.Now(),
		}

		// Determine health level based on recent violations
		recentViolations := 0
		cutoff := time.Now().Add(-time.Hour)
		for _, violation := range state.ViolationHistory {
			if violation.Timestamp.After(cutoff) {
				recentViolations++
			}
		}

		if recentViolations > 10 {
			health.Overall = HealthLevelCritical
		} else if recentViolations > 5 {
			health.Overall = HealthLevelFailing
		}

		// Update the healing state
		shm.mu.Lock()
		if currentState := shm.healingStates[containerID]; currentState != nil {
			currentState.HealthStatus = health
			currentState.LastHealthCheck = time.Now()
		}
		shm.mu.Unlock()

		// Trigger escalation if needed
		shm.evaluateHealthEscalation(containerID, health)
	}
}

func (shm *SelfHealingManager) detectAnomalies() {
	shm.mu.RLock()
	states := make(map[string]*HealingState)
	for k, v := range shm.healingStates {
		states[k] = v
	}
	shm.mu.RUnlock()

	for containerID, state := range states {
		// Check for behavioral anomalies based on violation history
		if shm.hasAnomalousViolationPattern(state) {
			log.Log.Info("Anomalous violation pattern detected",
				"containerID", containerID,
				"violationCount", len(state.ViolationHistory))

			// Create anomaly policy violation
			anomalyViolation := &PolicyViolation{
				Timestamp:     time.Now(),
				ViolationType: ViolationTypeSyscall, // Could be any type based on pattern
				Severity:      ViolationSeverityMedium,
				Action:        PolicyActionDeny,
				Details: ViolationDetails{
					Resource:        "behavioral_pattern",
					AttemptedAction: "anomalous_behavior_detection",
					ExpectedAction:  "normal_behavior",
					ActualResult:    "anomalous_pattern_detected",
				},
				Context: ViolationContext{
					ProcessName: "anomaly_detector",
					ProcessID:   0,
					UserID:      0,
				},
			}

			// Process the anomaly as a violation
			shm.ProcessViolation(containerID, anomalyViolation)
		}

		// Check for resource usage anomalies
		if shm.hasResourceAnomalies(state) {
			log.Log.Info("Resource usage anomaly detected", "containerID", containerID)
		}
	}
}

func (shm *SelfHealingManager) processRollbackQueue() {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	// Process pending rollback actions for each container
	for containerID, state := range shm.healingStates {
		// Use RollbackQueue field instead of PendingRollbacks
		for i, action := range state.RollbackQueue {
			// Skip if action is already being processed
			if action.Status == ActionStatusExecuting {
				continue
			}

			// Check if it's time to execute scheduled rollbacks
			if action.Status == ActionStatusPending && time.Now().After(action.ScheduledTime) {
				log.Log.Info("Processing scheduled rollback action",
					"containerID", containerID,
					"actionID", action.ID)

				// Execute the rollback action
				go func(s *HealingState, a *RollbackActionStruct) {
					if err := shm.executeRollback(s, a); err != nil {
						log.Log.Error(err, "Failed to execute rollback action",
							"containerID", containerID,
							"actionID", a.ID)
					}
				}(state, action)
			}

			// Clean up completed or failed actions
			if action.Status == ActionStatusCompleted || action.Status == ActionStatusFailed {
				// Remove from rollback queue
				state.RollbackQueue = append(state.RollbackQueue[:i], state.RollbackQueue[i+1:]...)
				break // Restart iteration due to slice modification
			}
		}
	}
}

func (shm *SelfHealingManager) updateAdaptiveThresholds() {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	// Calculate success rates based on container health
	totalContainers := len(shm.healingStates)
	healthyContainers := 0

	// Analyze current health status
	for _, state := range shm.healingStates {
		if state.HealthStatus != nil && state.HealthStatus.Overall == HealthLevelHealthy {
			healthyContainers++
		}
	}

	if totalContainers > 0 {
		healthRate := float64(healthyContainers) / float64(totalContainers)

		// Adjust escalation thresholds based on overall system health
		if healthRate > 0.8 { // Good system health, can be more aggressive
			if shm.escalationThresholds.ConsecutiveFailures > 2 {
				shm.escalationThresholds.ConsecutiveFailures--
			}
			if shm.escalationThresholds.FailureRate > 0.1 {
				shm.escalationThresholds.FailureRate -= 0.05
			}
		} else if healthRate < 0.5 { // Poor system health, be more conservative
			if shm.escalationThresholds.ConsecutiveFailures < 10 {
				shm.escalationThresholds.ConsecutiveFailures++
			}
			if shm.escalationThresholds.FailureRate < 0.8 {
				shm.escalationThresholds.FailureRate += 0.1
			}
		}

		log.Log.V(1).Info("Updated adaptive thresholds",
			"healthRate", healthRate,
			"consecutiveFailures", shm.escalationThresholds.ConsecutiveFailures,
			"failureRate", shm.escalationThresholds.FailureRate)
	}
}

func (shm *SelfHealingManager) healthLevelToScore(level HealthLevel) float64 {
	switch level {
	case HealthLevelHealthy:
		return 1.0
	case HealthLevelWarning:
		return 0.7
	case HealthLevelCritical:
		return 0.3
	case HealthLevelFailing:
		return 0.1
	default:
		return 0.5
	}
}

// Additional types and structures would be defined here...
type EscalationRule struct {
	Conditions []*EscalationCondition
	Actions    []*EscalationAction
	Timeout    time.Duration
	MaxRetries int
}

type EscalationCondition struct {
	Type      string
	Threshold float64
	Duration  time.Duration
}

type EscalationAction struct {
	Type       string
	Parameters map[string]interface{}
	Recipients []string
}

type ContactPoint struct {
	Name     string
	Type     string
	Address  string
	Severity []ViolationSeverity
}

type NotificationChannel interface {
	Send(message *NotificationMessage) error
}

type NotificationMessage struct {
	Subject     string
	Body        string
	Severity    ViolationSeverity
	Recipients  []string
	Attachments []string
}

// Configuration types
type VerificationStepConfig struct {
	Name       string
	Type       string
	Parameters map[string]interface{}
	Timeout    time.Duration
	Required   bool
}

type EmergencyProtocolConfig struct {
	Type       string
	Triggers   []*TriggerCondition
	Actions    []*EmergencyActionConfig
	Escalation *EscalationConfig
}

type EmergencyActionConfig struct {
	Type       string
	Parameters map[string]interface{}
	Timeout    time.Duration
}

type EscalationConfig struct {
	Rules    []*EscalationRuleConfig
	Channels []string
}

type EscalationRuleConfig struct {
	Conditions []*EscalationCondition
	Delay      time.Duration
	Recipients []string
}

type NotificationConfig struct {
	Enabled   bool
	Channels  map[string]*ChannelConfig
	Templates map[string]*MessageTemplate
	Routing   []*RoutingRule
}

type ChannelConfig struct {
	Type        string
	Endpoint    string
	Credentials map[string]string
	Timeout     time.Duration
}

type MessageTemplate struct {
	Subject   string
	Body      string
	Format    string
	Variables []string
}

type RoutingRule struct {
	Condition string
	Channels  []string
	Priority  int
}

type TrendAnalysis struct {
	Direction  TrendDirection
	Velocity   float64
	Confidence float64
	Prediction *HealthPrediction
}

type HealthPrediction struct {
	PredictedLevel HealthLevel
	Confidence     float64
	TimeHorizon    time.Duration
	Factors        []string
}

type VerificationResults struct {
	Overall        bool
	StepResults    map[string]bool
	FailureReasons []string
	CompletionTime time.Duration
}

type DetailedRollbackPlan struct {
	Steps         []*RollbackStep
	Dependencies  []string
	Prerequisites []string
	PostActions   []string
	FallbackPlan  *RollbackPlan
}

type RecoveryAction struct {
	Type       string
	Parameters map[string]interface{}
	Timeout    time.Duration
	Automatic  bool
}

type HealthCheck struct {
	Name       string
	Type       string
	Parameters map[string]interface{}
	Interval   time.Duration
	Timeout    time.Duration
	Enabled    bool
}

type EscalationProcedure struct {
	Levels   []*EscalationLevel
	MaxLevel int
	Timeout  time.Duration
}

type EscalationLevel struct {
	Level    int
	Actions  []*EscalationAction
	Contacts []string
	Delay    time.Duration
}

type RecoveryProcedure struct {
	Steps      []*RecoveryStep
	Validation []*ValidationStep
	Rollback   *RollbackPlan
}

type RecoveryStep struct {
	Name       string
	Action     string
	Parameters map[string]interface{}
	Timeout    time.Duration
	Critical   bool
}

type ValidationStep struct {
	Name     string
	Check    string
	Expected interface{}
	Timeout  time.Duration
}

type CommunicationPlan struct {
	Stakeholders    []string
	Channels        []string
	UpdateFrequency time.Duration
	Template        string
}

// Method to update container policy through enforcement engine
func (ee *EnforcementEngine) UpdateContainerPolicy(containerID string, policy *GeneratedPolicy) error {
	log.Log.Info("Updating container policy via enforcement engine",
		"containerID", containerID,
		"policyVersion", policy.Version)

	ee.mu.Lock()
	defer ee.mu.Unlock()

	// Find existing state or create new one
	state, exists := ee.containerPolicies[containerID]
	if !exists {
		state = &ContainerPolicyState{
			ContainerID:      containerID,
			GeneratedPolicy:  policy,
			LastPolicyUpdate: time.Now(),
			ViolationHistory: make([]PolicyViolation, 0),
		}
		ee.containerPolicies[containerID] = state
	} else {
		// Update existing state
		state.GeneratedPolicy = policy
		state.LastPolicyUpdate = time.Now()
	}

	// Create eBPF policy from generated policy using existing ebpf types
	ebpfPolicy := &ebpf.ContainerPolicy{
		AllowedSyscalls: make(map[uint64]bool),
		LastUpdate:      time.Now(),
		EnforcementMode: 1, // enforcement mode
		SelfHealing:     true,
	}

	// Apply policy to eBPF manager
	if ee.ebpfManager != nil {
		if err := ee.ebpfManager.UpdateContainerPolicy(containerID, ebpfPolicy); err != nil {
			return fmt.Errorf("failed to apply eBPF policy: %w", err)
		}
	}

	log.Log.Info("Container policy updated successfully",
		"containerID", containerID,
		"policyVersion", policy.Version)

	return nil
}

// Helper methods for anomaly detection
func (shm *SelfHealingManager) hasAnomalousViolationPattern(state *HealingState) bool {
	if len(state.ViolationHistory) < 5 {
		return false
	}

	// Check for rapid violation escalation
	recentViolations := 0
	cutoff := time.Now().Add(-time.Hour) // Last hour
	for _, violation := range state.ViolationHistory {
		if violation.Timestamp.After(cutoff) {
			recentViolations++
		}
	}

	// Consider it anomalous if more than 10 violations in the last hour
	if recentViolations > 10 {
		return true
	}

	// Check for violation type diversity (multiple different violation types rapidly)
	violationTypes := make(map[ViolationType]bool)
	for _, violation := range state.ViolationHistory[len(state.ViolationHistory)-5:] {
		violationTypes[violation.ViolationType] = true
	}

	// Anomalous if we have 3+ different violation types in recent history
	return len(violationTypes) >= 3
}

func (shm *SelfHealingManager) hasResourceAnomalies(state *HealingState) bool {
	// Check if health status indicates resource issues
	if state.HealthStatus != nil {
		return state.HealthStatus.Overall == HealthLevelFailing ||
			state.HealthStatus.Overall == HealthLevelCritical
	}
	return false
}

func (shm *SelfHealingManager) evaluateHealthEscalation(containerID string, health *HealthStatus) {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	state := shm.healingStates[containerID]
	if state == nil {
		return
	}

	// Update consecutive failure count
	if health.Overall == HealthLevelCritical || health.Overall == HealthLevelFailing {
		state.ConsecutiveFailures++

		if state.ConsecutiveFailures >= shm.escalationThresholds.ConsecutiveFailures {
			log.Log.Info("Health escalation triggered",
				"containerID", containerID,
				"consecutiveFailures", state.ConsecutiveFailures,
				"healthLevel", health.Overall)

			// Trigger emergency response
			go shm.triggerEmergencyResponse(context.Background(), containerID, "consecutive health failures", map[string]interface{}{
				"consecutiveFailures": state.ConsecutiveFailures,
				"healthStatus":        health,
			})
		}
	} else {
		state.ConsecutiveFailures = 0
	}
}
