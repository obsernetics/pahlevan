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
	"strings"
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// LifecycleManager handles workload lifecycle-aware policy tightening
type LifecycleManager struct {
	mu                        sync.RWMutex
	client                    client.Client
	enforcementEngine         *EnforcementEngine
	workloadStates            map[string]*WorkloadLifecycleState
	lifecycleEventProcessor   *LifecycleEventProcessor
	policyTighteningScheduler *PolicyTighteningScheduler
	stopCh                    chan struct{}

	// Metrics
	lifecycleTransitionCounter metric.Int64Counter
	policyTighteningCounter    metric.Int64Counter
	privilegeReductionGauge    metric.Float64Gauge
}

// WorkloadLifecycleState tracks the lifecycle state and policy evolution of a workload
type WorkloadLifecycleState struct {
	WorkloadRef       learner.WorkloadReference
	ContainerStates   map[string]*ContainerLifecycleState
	CurrentPhase      WorkloadPhase
	PhaseHistory      []PhaseTransition
	InitContainers    map[string]*ContainerLifecycleState
	MainContainers    map[string]*ContainerLifecycleState
	SidecarContainers map[string]*ContainerLifecycleState

	// Policy evolution tracking
	PolicyEvolution  []PolicySnapshot
	TighteningEvents []TighteningEvent

	// Lifecycle configuration
	LifecycleConfig *LifecycleConfiguration
	LastUpdate      time.Time
}

// ContainerLifecycleState tracks individual container lifecycle
type ContainerLifecycleState struct {
	ContainerID    string
	Name           string
	Type           ContainerType
	CurrentPhase   ContainerPhase
	PhaseHistory   []ContainerPhaseTransition
	StartTime      time.Time
	ReadinessProbe *ProbeState
	LivenessProbe  *ProbeState
	StartupProbe   *ProbeState

	// Policy state
	CurrentPolicy      *GeneratedPolicy
	PolicyHistory      []PolicySnapshot
	PrivilegeLevel     PrivilegeLevel
	RequiredPrivileges RequiredPrivileges

	// Resource usage patterns
	ResourceUsage    *ResourceUsagePattern
	ActivityPattern  *ActivityPattern
	StabilityMetrics *StabilityMetrics
}

// Workload phases
type WorkloadPhase string

const (
	WorkloadPhaseInitializing   WorkloadPhase = "Initializing"
	WorkloadPhaseStarting       WorkloadPhase = "Starting"
	WorkloadPhaseInitContainers WorkloadPhase = "InitContainers"
	WorkloadPhaseMainStarting   WorkloadPhase = "MainStarting"
	WorkloadPhaseHealthChecking WorkloadPhase = "HealthChecking"
	WorkloadPhaseRunning        WorkloadPhase = "Running"
	WorkloadPhaseSteady         WorkloadPhase = "Steady"
	WorkloadPhaseScaling        WorkloadPhase = "Scaling"
	WorkloadPhaseUpdating       WorkloadPhase = "Updating"
	WorkloadPhaseTerminating    WorkloadPhase = "Terminating"
	WorkloadPhaseFailed         WorkloadPhase = "Failed"
)

// Container phases
type ContainerPhase string

const (
	ContainerPhaseWaiting        ContainerPhase = "Waiting"
	ContainerPhaseInitializing   ContainerPhase = "Initializing"
	ContainerPhaseStarting       ContainerPhase = "Starting"
	ContainerPhaseRunning        ContainerPhase = "Running"
	ContainerPhaseHealthChecking ContainerPhase = "HealthChecking"
	ContainerPhaseReady          ContainerPhase = "Ready"
	ContainerPhaseSteady         ContainerPhase = "Steady"
	ContainerPhaseTerminating    ContainerPhase = "Terminating"
	ContainerPhaseTerminated     ContainerPhase = "Terminated"
	ContainerPhaseFailed         ContainerPhase = "Failed"
)

// Container types
type ContainerType string

const (
	ContainerTypeInit      ContainerType = "Init"
	ContainerTypeMain      ContainerType = "Main"
	ContainerTypeSidecar   ContainerType = "Sidecar"
	ContainerTypeEphemeral ContainerType = "Ephemeral"
)

// Privilege levels
type PrivilegeLevel string

const (
	PrivilegeLevelMinimal    PrivilegeLevel = "Minimal"
	PrivilegeLevelReduced    PrivilegeLevel = "Reduced"
	PrivilegeLevelStandard   PrivilegeLevel = "Standard"
	PrivilegeLevelElevated   PrivilegeLevel = "Elevated"
	PrivilegeLevelPrivileged PrivilegeLevel = "Privileged"
)

// Phase transitions
type PhaseTransition struct {
	From      WorkloadPhase
	To        WorkloadPhase
	Timestamp time.Time
	Trigger   TransitionTrigger
	Duration  time.Duration
	Metadata  map[string]string
}

type ContainerPhaseTransition struct {
	From      ContainerPhase
	To        ContainerPhase
	Timestamp time.Time
	Trigger   TransitionTrigger
	Duration  time.Duration
	Metadata  map[string]string
}

type TransitionTrigger string

const (
	TriggerManual           TransitionTrigger = "Manual"
	TriggerAutomatic        TransitionTrigger = "Automatic"
	TriggerHealthCheck      TransitionTrigger = "HealthCheck"
	TriggerResourceLimit    TransitionTrigger = "ResourceLimit"
	TriggerTimeout          TransitionTrigger = "Timeout"
	TriggerPolicyViolation  TransitionTrigger = "PolicyViolation"
	TriggerStabilityReached TransitionTrigger = "StabilityReached"
)

// Policy evolution tracking
type PolicySnapshot struct {
	Timestamp      time.Time
	Policy         *GeneratedPolicy
	Phase          ContainerPhase
	PrivilegeLevel PrivilegeLevel
	ChangeReason   string
	Metrics        PolicyMetrics
}

type TighteningEvent struct {
	Timestamp          time.Time
	ContainerID        string
	PreviousPrivileges RequiredPrivileges
	NewPrivileges      RequiredPrivileges
	TighteningType     TighteningType
	Trigger            TighteningTrigger
	ImpactAssessment   ImpactAssessment
	RollbackPlan       *RollbackPlan
}

type TighteningType string

const (
	TighteningTypeSyscall    TighteningType = "Syscall"
	TighteningTypeNetwork    TighteningType = "Network"
	TighteningTypeFile       TighteningType = "File"
	TighteningTypeCapability TighteningType = "Capability"
	TighteningTypeResource   TighteningType = "Resource"
	TighteningTypeCombined   TighteningType = "Combined"
)

type TighteningTrigger string

const (
	TriggerPhaseTransition     TighteningTrigger = "PhaseTransition"
	TriggerStabilityDetected   TighteningTrigger = "StabilityDetected"
	TriggerScheduledTightening TighteningTrigger = "ScheduledTightening"
	TriggerAdminRequest        TighteningTrigger = "AdminRequest"
	TriggerThreatDetection     TighteningTrigger = "ThreatDetection"
)

// Required privileges structure
type RequiredPrivileges struct {
	Syscalls     []uint64
	NetworkPorts []NetworkPortRequirement
	FilePaths    []FilePathRequirement
	Capabilities []string
	Resources    *corev1.ResourceRequirements
	Special      []SpecialPrivilege
}

type NetworkPortRequirement struct {
	Port      int32
	Protocol  string
	Direction string
	Required  bool
	Usage     PortUsagePattern
}

type FilePathRequirement struct {
	Path        string
	AccessModes []string
	Required    bool
	Usage       FileUsagePattern
}

type PortUsagePattern struct {
	Frequency        float64
	PeakConnections  int32
	BytesPerSecond   int64
	CriticalityScore float64
}

type FileUsagePattern struct {
	Frequency        float64
	BytesPerSecond   int64
	AccessPattern    string
	CriticalityScore float64
}

type SpecialPrivilege string

const (
	PrivilegeHostNetwork  SpecialPrivilege = "HostNetwork"
	PrivilegeHostPID      SpecialPrivilege = "HostPID"
	PrivilegeHostIPC      SpecialPrivilege = "HostIPC"
	PrivilegePtrace       SpecialPrivilege = "Ptrace"
	PrivilegeDeviceAccess SpecialPrivilege = "DeviceAccess"
	PrivilegeVolumeMount  SpecialPrivilege = "VolumeMount"
)

// Probe states
type ProbeState struct {
	Enabled       bool
	InitialDelay  time.Duration
	Period        time.Duration
	SuccessCount  int32
	FailureCount  int32
	LastProbeTime time.Time
	LastResult    ProbeResult
	Stabilized    bool
}

type ProbeResult string

const (
	ProbeResultSuccess ProbeResult = "Success"
	ProbeResultFailure ProbeResult = "Failure"
	ProbeResultUnknown ProbeResult = "Unknown"
)

// Resource and activity patterns
type ResourceUsagePattern struct {
	CPUUsage      *UsageMetrics
	MemoryUsage   *UsageMetrics
	NetworkIO     *IOMetrics
	DiskIO        *IOMetrics
	Stability     float64
	PredictedPeak *ResourcePrediction
}

type UsageMetrics struct {
	Current   float64
	Average   float64
	Peak      float64
	Minimum   float64
	Trend     TrendDirection
	Stability float64
}

type IOMetrics struct {
	BytesPerSecond      float64
	OperationsPerSecond float64
	AverageLatency      time.Duration
	ErrorRate           float64
}

type TrendDirection string

const (
	TrendStable     TrendDirection = "Stable"
	TrendIncreasing TrendDirection = "Increasing"
	TrendDecreasing TrendDirection = "Decreasing"
	TrendVolatile   TrendDirection = "Volatile"
)

type ResourcePrediction struct {
	PredictedCPU    float64
	PredictedMemory float64
	ConfidenceLevel float64
	TimeHorizon     time.Duration
}

type ActivityPattern struct {
	SyscallActivity   *ActivityMetrics
	NetworkActivity   *ActivityMetrics
	FileActivity      *ActivityMetrics
	OverallStability  float64
	PatternRecognized bool
	PatternType       string
}

type ActivityMetrics struct {
	RequestsPerSecond float64
	BurstPatterns     []BurstPattern
	QuietPeriods      []QuietPeriod
	Predictability    float64
}

type BurstPattern struct {
	StartTime      time.Time
	Duration       time.Duration
	IntensityLevel float64
	TriggerEvent   string
}

type QuietPeriod struct {
	StartTime     time.Time
	Duration      time.Duration
	ActivityLevel float64
}

type StabilityMetrics struct {
	OverallScore        float64
	SyscallStability    float64
	NetworkStability    float64
	FileStability       float64
	ResourceStability   float64
	TimeToStability     time.Duration
	StabilityConfidence float64
	LastStabilityCheck  time.Time
}

// Impact assessment and rollback planning
type ImpactAssessment struct {
	RiskLevel            RiskLevel
	PotentialImpacts     []PotentialImpact
	MitigationStrategies []string
	Reversibility        bool
	EstimatedDowntime    time.Duration
	BusinessImpact       BusinessImpactLevel
}

type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "Low"
	RiskLevelMedium   RiskLevel = "Medium"
	RiskLevelHigh     RiskLevel = "High"
	RiskLevelCritical RiskLevel = "Critical"
)

type PotentialImpact struct {
	Type        ImpactType
	Severity    ImpactSeverity
	Probability float64
	Description string
}

type ImpactType string

const (
	ImpactTypeFunctionality ImpactType = "Functionality"
	ImpactTypePerformance   ImpactType = "Performance"
	ImpactTypeSecurity      ImpactType = "Security"
	ImpactTypeCompliance    ImpactType = "Compliance"
	ImpactTypeOperational   ImpactType = "Operational"
)

type ImpactSeverity string

const (
	ImpactSeverityMinor    ImpactSeverity = "Minor"
	ImpactSeverityModerate ImpactSeverity = "Moderate"
	ImpactSeverityMajor    ImpactSeverity = "Major"
	ImpactSeverityCritical ImpactSeverity = "Critical"
)

type BusinessImpactLevel string

const (
	BusinessImpactNone     BusinessImpactLevel = "None"
	BusinessImpactMinimal  BusinessImpactLevel = "Minimal"
	BusinessImpactModerate BusinessImpactLevel = "Moderate"
	BusinessImpactHigh     BusinessImpactLevel = "High"
	BusinessImpactCritical BusinessImpactLevel = "Critical"
)

type RollbackPlan struct {
	Enabled           bool
	TriggerConditions []RollbackTrigger
	MaxRollbackTime   time.Duration
	Steps             []RollbackStep
	AutomaticRollback bool
	VerificationSteps []VerificationStep
}

type RollbackTrigger struct {
	Type        RollbackTriggerType
	Threshold   float64
	TimeWindow  time.Duration
	Description string
}

type RollbackTriggerType string

const (
	RollbackTriggerHealthCheck   RollbackTriggerType = "HealthCheck"
	RollbackTriggerErrorRate     RollbackTriggerType = "ErrorRate"
	RollbackTriggerResourceUsage RollbackTriggerType = "ResourceUsage"
	RollbackTriggerPerformance   RollbackTriggerType = "Performance"
	RollbackTriggerManual        RollbackTriggerType = "Manual"
)

type RollbackStep struct {
	Order       int
	Action      RollbackAction
	Parameters  map[string]string
	Timeout     time.Duration
	Description string
}

type RollbackAction string

const (
	RollbackActionRestorePolicy      RollbackAction = "RestorePolicy"
	RollbackActionRelaxPermissions   RollbackAction = "RelaxPermissions"
	RollbackActionDisableEnforcement RollbackAction = "DisableEnforcement"
	RollbackActionRestartContainer   RollbackAction = "RestartContainer"
	RollbackActionNotifyOperator     RollbackAction = "NotifyOperator"
)

type VerificationStep struct {
	Name       string
	Check      VerificationCheck
	Timeout    time.Duration
	Retry      bool
	RetryCount int
	Critical   bool
}

type VerificationCheck string

const (
	VerificationHealthCheck   VerificationCheck = "HealthCheck"
	VerificationFunctionality VerificationCheck = "Functionality"
	VerificationPerformance   VerificationCheck = "Performance"
	VerificationSecurity      VerificationCheck = "Security"
)

// Configuration structures
type LifecycleConfiguration struct {
	PhaseDurations      map[WorkloadPhase]time.Duration
	TighteningSchedule  *TighteningSchedule
	StabilityThresholds *StabilityThresholds
	AutomaticTightening bool
	GracefulTightening  bool
	RollbackEnabled     bool
	MonitoringEnabled   bool
	NotificationEnabled bool
}

type TighteningSchedule struct {
	InitContainerCompletion  time.Duration
	HealthCheckStabilization time.Duration
	SteadyStateReached       time.Duration
	PeriodicTightening       time.Duration
	CustomSchedule           []ScheduledTightening
}

type ScheduledTightening struct {
	Trigger    TighteningTrigger
	Delay      time.Duration
	Type       TighteningType
	Intensity  TighteningIntensity
	Conditions []TighteningCondition
}

type TighteningIntensity string

const (
	IntensityGentle     TighteningIntensity = "Gentle"
	IntensityModerate   TighteningIntensity = "Moderate"
	IntensityAggressive TighteningIntensity = "Aggressive"
	IntensityMaximal    TighteningIntensity = "Maximal"
)

type TighteningCondition struct {
	Type     ConditionType
	Operator ConditionOperator
	Value    string
	Required bool
}

type StabilityThresholds struct {
	SyscallStabilityThreshold  float64
	NetworkStabilityThreshold  float64
	FileStabilityThreshold     float64
	ResourceStabilityThreshold float64
	OverallStabilityThreshold  float64
	MinimumObservationPeriod   time.Duration
	StabilityConfidenceLevel   float64
}

type PolicyMetrics struct {
	SyscallCount     int
	NetworkRuleCount int
	FileRuleCount    int
	CapabilityCount  int
	ComplexityScore  float64
	SecurityScore    float64
	PerformanceScore float64
}

// Event processing
type LifecycleEventProcessor struct {
	eventQueue    chan *LifecycleEvent
	eventHandlers map[LifecycleEventType][]LifecycleEventHandler
	stopCh        chan struct{}
}

type LifecycleEvent struct {
	Type      LifecycleEventType
	Source    EventSource
	Target    EventTarget
	Timestamp time.Time
	Data      map[string]interface{}
	Context   *EventContext
}

type LifecycleEventType string

const (
	EventTypeContainerStarted       LifecycleEventType = "ContainerStarted"
	EventTypeContainerReady         LifecycleEventType = "ContainerReady"
	EventTypeContainerHealthy       LifecycleEventType = "ContainerHealthy"
	EventTypeContainerSteady        LifecycleEventType = "ContainerSteady"
	EventTypeInitContainerCompleted LifecycleEventType = "InitContainerCompleted"
	EventTypeWorkloadStable         LifecycleEventType = "WorkloadStable"
	EventTypePolicyTightened        LifecycleEventType = "PolicyTightened"
	EventTypeViolationDetected      LifecycleEventType = "ViolationDetected"
	EventTypeRollbackTriggered      LifecycleEventType = "RollbackTriggered"
)

type EventSource struct {
	Type      SourceType
	Name      string
	Namespace string
	UID       string
}

type SourceType string

const (
	SourceTypePod        SourceType = "Pod"
	SourceTypeContainer  SourceType = "Container"
	SourceTypeWorkload   SourceType = "Workload"
	SourceTypeOperator   SourceType = "Operator"
	SourceTypeMonitoring SourceType = "Monitoring"
)

type EventTarget struct {
	ContainerID string
	WorkloadRef learner.WorkloadReference
}

type EventContext struct {
	Phase          WorkloadPhase
	ContainerPhase ContainerPhase
	PolicyVersion  int
	TriggerReason  string
	AdditionalData map[string]string
}

type LifecycleEventHandler interface {
	HandleEvent(event *LifecycleEvent) error
}

// Policy tightening scheduler
type PolicyTighteningScheduler struct {
	scheduledTightenings map[string][]*ScheduledTighteningTask
	ticker               *time.Ticker
	stopCh               chan struct{}
}

type ScheduledTighteningTask struct {
	ID             string
	ContainerID    string
	ScheduledTime  time.Time
	TighteningType TighteningType
	Intensity      TighteningIntensity
	Conditions     []TighteningCondition
	Status         TaskStatus
	CompletedTime  *time.Time
	Error          error
}

type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "Pending"
	TaskStatusRunning   TaskStatus = "Running"
	TaskStatusCompleted TaskStatus = "Completed"
	TaskStatusFailed    TaskStatus = "Failed"
	TaskStatusCancelled TaskStatus = "Cancelled"
)

func NewLifecycleManager(
	client client.Client,
	enforcementEngine *EnforcementEngine,
) *LifecycleManager {
	return &LifecycleManager{
		client:                    client,
		enforcementEngine:         enforcementEngine,
		workloadStates:            make(map[string]*WorkloadLifecycleState),
		lifecycleEventProcessor:   NewLifecycleEventProcessor(),
		policyTighteningScheduler: NewPolicyTighteningScheduler(),
		stopCh:                    make(chan struct{}),
	}
}

func NewLifecycleEventProcessor() *LifecycleEventProcessor {
	return &LifecycleEventProcessor{
		eventQueue:    make(chan *LifecycleEvent, 1000),
		eventHandlers: make(map[LifecycleEventType][]LifecycleEventHandler),
		stopCh:        make(chan struct{}),
	}
}

func NewPolicyTighteningScheduler() *PolicyTighteningScheduler {
	return &PolicyTighteningScheduler{
		scheduledTightenings: make(map[string][]*ScheduledTighteningTask),
		ticker:               time.NewTicker(30 * time.Second),
		stopCh:               make(chan struct{}),
	}
}

func (lm *LifecycleManager) Start(ctx context.Context) error {
	log.Log.Info("Starting lifecycle manager")

	// Start event processor
	go lm.lifecycleEventProcessor.Start(ctx)

	// Start tightening scheduler
	go lm.policyTighteningScheduler.Start(ctx)

	// Start lifecycle monitoring
	go lm.monitorWorkloadLifecycles(ctx)

	return nil
}

func (lm *LifecycleManager) Stop() {
	close(lm.stopCh)
	lm.lifecycleEventProcessor.Stop()
	lm.policyTighteningScheduler.Stop()
}

func (lm *LifecycleManager) RegisterWorkload(
	workloadRef learner.WorkloadReference,
	containers []string,
	policy *policyv1alpha1.PahlevanPolicy,
) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	workloadKey := lm.getWorkloadKey(workloadRef)

	state := &WorkloadLifecycleState{
		WorkloadRef:       workloadRef,
		ContainerStates:   make(map[string]*ContainerLifecycleState),
		InitContainers:    make(map[string]*ContainerLifecycleState),
		MainContainers:    make(map[string]*ContainerLifecycleState),
		SidecarContainers: make(map[string]*ContainerLifecycleState),
		CurrentPhase:      WorkloadPhaseInitializing,
		PhaseHistory:      make([]PhaseTransition, 0),
		PolicyEvolution:   make([]PolicySnapshot, 0),
		TighteningEvents:  make([]TighteningEvent, 0),
		LifecycleConfig:   lm.createLifecycleConfig(policy),
		LastUpdate:        time.Now(),
	}

	// Initialize container states
	for _, containerID := range containers {
		containerState := &ContainerLifecycleState{
			ContainerID:      containerID,
			Type:             lm.determineContainerType(containerID, workloadRef),
			CurrentPhase:     ContainerPhaseWaiting,
			PhaseHistory:     make([]ContainerPhaseTransition, 0),
			StartTime:        time.Now(),
			PrivilegeLevel:   PrivilegeLevelStandard,
			PolicyHistory:    make([]PolicySnapshot, 0),
			ResourceUsage:    &ResourceUsagePattern{},
			ActivityPattern:  &ActivityPattern{},
			StabilityMetrics: &StabilityMetrics{},
		}

		state.ContainerStates[containerID] = containerState

		// Categorize containers by type
		switch containerState.Type {
		case ContainerTypeInit:
			state.InitContainers[containerID] = containerState
		case ContainerTypeMain:
			state.MainContainers[containerID] = containerState
		case ContainerTypeSidecar:
			state.SidecarContainers[containerID] = containerState
		}
	}

	lm.workloadStates[workloadKey] = state

	// Schedule initial policy tightening events
	lm.scheduleInitialTighteningEvents(workloadKey, state)

	return nil
}

func (lm *LifecycleManager) ProcessContainerEvent(
	containerID string,
	eventType LifecycleEventType,
	eventData map[string]interface{},
) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Find workload containing this container
	workloadKey, state := lm.findWorkloadByContainer(containerID)
	if state == nil {
		return fmt.Errorf("workload not found for container: %s", containerID)
	}

	containerState, exists := state.ContainerStates[containerID]
	if !exists {
		return fmt.Errorf("container state not found: %s", containerID)
	}

	// Process the event
	previousPhase := containerState.CurrentPhase
	newPhase := lm.determineNewContainerPhase(containerState, eventType, eventData)

	if newPhase != previousPhase {
		// Record phase transition
		transition := ContainerPhaseTransition{
			From:      previousPhase,
			To:        newPhase,
			Timestamp: time.Now(),
			Trigger:   lm.eventTypeToTrigger(eventType),
			Duration:  time.Since(containerState.StartTime),
		}
		containerState.PhaseHistory = append(containerState.PhaseHistory, transition)
		containerState.CurrentPhase = newPhase

		// Update workload phase if necessary
		lm.updateWorkloadPhase(state)

		// Check if policy tightening should be triggered
		if lm.shouldTriggerPolicyTightening(containerState, transition) {
			lm.schedulePolicyTightening(containerID, transition)
		}

		// Update metrics
		if lm.lifecycleTransitionCounter != nil {
			lm.lifecycleTransitionCounter.Add(context.Background(), 1)
		}

		log.Log.Info("Container phase transition",
			"containerID", containerID,
			"from", previousPhase,
			"to", newPhase,
			"workload", workloadKey)
	}

	// Update container state based on event
	lm.updateContainerStateFromEvent(containerState, eventType, eventData)

	return nil
}

func (lm *LifecycleManager) TightenPolicy(
	containerID string,
	tighteningType TighteningType,
	intensity TighteningIntensity,
) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Find container state
	workloadKey, state := lm.findWorkloadByContainer(containerID)
	if state == nil {
		return fmt.Errorf("workload not found for container: %s", containerID)
	}

	// Log workload context for debugging and update metrics
	log.Log.V(1).Info("Updating container learning profile",
		"containerID", containerID,
		"workloadKey", workloadKey,
		"workloadKind", state.WorkloadRef.Kind,
		"workloadName", state.WorkloadRef.Name,
		"namespace", state.WorkloadRef.Namespace)

	// Update workload-level metrics using existing counters
	if lm.lifecycleTransitionCounter != nil {
		lm.lifecycleTransitionCounter.Add(context.Background(), 1,
			metric.WithAttributes(
				attribute.String("container_id", containerID),
				attribute.String("workload_key", workloadKey),
				attribute.String("operation", "learning_profile_update"),
			))
	}

	containerState, exists := state.ContainerStates[containerID]
	if !exists {
		return fmt.Errorf("container state not found: %s", containerID)
	}

	// Assess current privileges
	currentPrivileges := lm.assessCurrentPrivileges(containerState)

	// Calculate new tightened privileges
	newPrivileges, err := lm.calculateTightenedPrivileges(
		currentPrivileges,
		tighteningType,
		intensity,
		containerState,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate tightened privileges: %v", err)
	}

	// Assess impact of tightening
	impact := lm.assessTighteningImpact(containerState, currentPrivileges, newPrivileges)

	// Create rollback plan
	rollbackPlan := lm.createRollbackPlan(containerState, currentPrivileges, impact)

	// Record tightening event
	tighteningEvent := TighteningEvent{
		Timestamp:          time.Now(),
		ContainerID:        containerID,
		PreviousPrivileges: currentPrivileges,
		NewPrivileges:      newPrivileges,
		TighteningType:     tighteningType,
		Trigger:            TriggerPhaseTransition,
		ImpactAssessment:   impact,
		RollbackPlan:       rollbackPlan,
	}

	state.TighteningEvents = append(state.TighteningEvents, tighteningEvent)

	// Apply new policy
	err = lm.applyTightenedPolicy(containerState, newPrivileges, tighteningEvent)
	if err != nil {
		return fmt.Errorf("failed to apply tightened policy: %v", err)
	}

	// Update privilege level
	containerState.PrivilegeLevel = lm.calculatePrivilegeLevel(newPrivileges)

	// Update metrics
	if lm.policyTighteningCounter != nil {
		lm.policyTighteningCounter.Add(context.Background(), 1)
	}

	privilegeReduction := lm.calculatePrivilegeReduction(currentPrivileges, newPrivileges)
	if lm.privilegeReductionGauge != nil {
		lm.privilegeReductionGauge.Record(context.Background(), privilegeReduction)
	}

	log.Log.Info("Policy tightened",
		"containerID", containerID,
		"type", tighteningType,
		"intensity", intensity,
		"privilegeReduction", privilegeReduction)

	return nil
}

// Implementation of remaining methods would continue here...
// Due to length constraints, I'll provide the key method signatures

func (lm *LifecycleManager) getWorkloadKey(workloadRef learner.WorkloadReference) string {
	return fmt.Sprintf("%s/%s/%s", workloadRef.Namespace, workloadRef.Kind, workloadRef.Name)
}

func (lm *LifecycleManager) createLifecycleConfig(policy *policyv1alpha1.PahlevanPolicy) *LifecycleConfiguration {
	// Create comprehensive lifecycle configuration from policy
	config := &LifecycleConfiguration{
		AutomaticTightening: policy.Spec.LearningConfig.LifecycleAware,
		GracefulTightening:  true,
		RollbackEnabled:     policy.Spec.SelfHealing.Enabled,
		MonitoringEnabled:   true,
		NotificationEnabled: true,
	}

	// Configure tightening schedule based on policy
	if policy.Spec.LearningConfig.Duration != nil {
		config.TighteningSchedule = &TighteningSchedule{
			PeriodicTightening: policy.Spec.LearningConfig.Duration.Duration,
			CustomSchedule:     make([]ScheduledTightening, 0),
		}
	}


	return config
}

func (lm *LifecycleManager) determineContainerType(containerID string, workloadRef learner.WorkloadReference) ContainerType {
	// Determine container type based on workload metadata and container patterns

	// Default to main container
	containerType := ContainerTypeMain

	// Check if it's an init container based on naming patterns
	if strings.Contains(containerID, "init-") || strings.Contains(containerID, "setup-") {
		containerType = ContainerTypeInit
	}

	// Check for sidecar patterns (common sidecar names)
	sidecarPatterns := []string{
		"istio-proxy", "envoy", "proxy", "sidecar",
		"fluentd", "fluent-bit", "logging",
		"vault-agent", "consul-connect",
		"jaeger-agent", "opentelemetry",
	}

	for _, pattern := range sidecarPatterns {
		if strings.Contains(strings.ToLower(containerID), pattern) {
			containerType = ContainerTypeSidecar
			break
		}
	}

	// For specific workload types, infer container types
	switch workloadRef.Kind {
	case "DaemonSet":
		// DaemonSet containers are usually infrastructure-related
		if containerType == ContainerTypeMain {
			// Could be system container if it matches system patterns
			systemPatterns := []string{"node-", "system-", "kube-", "cni-"}
			for _, pattern := range systemPatterns {
				if strings.Contains(strings.ToLower(containerID), pattern) {
					containerType = ContainerTypeSidecar // Treat as sidecar for policy purposes
					break
				}
			}
		}
	case "Job", "CronJob":
		// Jobs typically have main containers that are short-lived
		containerType = ContainerTypeMain
	}

	log.Log.V(1).Info("Determined container type",
		"containerID", containerID,
		"workloadKind", workloadRef.Kind,
		"containerType", containerType)

	return containerType
}

func (lm *LifecycleManager) scheduleInitialTighteningEvents(workloadKey string, state *WorkloadLifecycleState) {
	// Schedule initial tightening events based on lifecycle configuration
	if state.LifecycleConfig == nil || !state.LifecycleConfig.AutomaticTightening {
		return
	}

	// Schedule tightening based on different triggers
	tighteningSchedule := state.LifecycleConfig.TighteningSchedule
	if tighteningSchedule != nil {
		// Schedule periodic tightening
		if tighteningSchedule.PeriodicTightening > 0 {
			tighteningTask := &ScheduledTighteningTask{
				ID:             fmt.Sprintf("%s-periodic-%d", workloadKey, time.Now().Unix()),
				ContainerID:    "", // Applies to whole workload
				ScheduledTime:  time.Now().Add(tighteningSchedule.PeriodicTightening),
				TighteningType: TighteningTypeSyscall,
			}

			// Add to scheduler's map
			if lm.policyTighteningScheduler != nil {
				if lm.policyTighteningScheduler.scheduledTightenings == nil {
					lm.policyTighteningScheduler.scheduledTightenings = make(map[string][]*ScheduledTighteningTask)
				}
				lm.policyTighteningScheduler.scheduledTightenings[workloadKey] =
					append(lm.policyTighteningScheduler.scheduledTightenings[workloadKey], tighteningTask)
			}

			log.Log.Info("Scheduled periodic tightening",
				"workloadKey", workloadKey,
				"scheduledTime", tighteningTask.ScheduledTime)
		}

		// Schedule custom tightening events
		for _, customEvent := range tighteningSchedule.CustomSchedule {
			tighteningTask := &ScheduledTighteningTask{
				ID:             fmt.Sprintf("%s-custom-%d", workloadKey, time.Now().Unix()),
				ContainerID:    "",
				ScheduledTime:  time.Now().Add(customEvent.Delay),
				TighteningType: TighteningTypeCombined,
			}

			if lm.policyTighteningScheduler != nil {
				lm.policyTighteningScheduler.scheduledTightenings[workloadKey] =
					append(lm.policyTighteningScheduler.scheduledTightenings[workloadKey], tighteningTask)
			}
		}

		// Track the scheduling event
		state.PhaseHistory = append(state.PhaseHistory, PhaseTransition{
			From:      state.CurrentPhase,
			To:        WorkloadPhaseSteady, // Target steady phase
			Timestamp: time.Now(),
			Trigger:   TriggerAutomatic,
			Metadata: map[string]string{
				"workload_key": workloadKey,
				"action":       "tightening_scheduled",
			},
		})
	}
}

func (lm *LifecycleManager) findWorkloadByContainer(containerID string) (string, *WorkloadLifecycleState) {
	for key, state := range lm.workloadStates {
		if _, exists := state.ContainerStates[containerID]; exists {
			return key, state
		}
	}
	return "", nil
}

func (lm *LifecycleManager) determineNewContainerPhase(
	containerState *ContainerLifecycleState,
	eventType LifecycleEventType,
	eventData map[string]interface{},
) ContainerPhase {
	// Determine new phase based on event type and current state
	currentPhase := containerState.CurrentPhase

	switch eventType {
	case EventTypeContainerStarted:
		if currentPhase == ContainerPhaseInitializing {
			return ContainerPhaseStarting
		}

	case EventTypeContainerHealthy:
		if currentPhase == ContainerPhaseStarting {
			return ContainerPhaseRunning
		} else if currentPhase == ContainerPhaseRunning {
			return ContainerPhaseReady
		}

	case EventTypeContainerSteady:
		if currentPhase == ContainerPhaseReady {
			return ContainerPhaseSteady
		}

	case EventTypeViolationDetected:
		return ContainerPhaseFailed

	case EventTypeRollbackTriggered:
		// Reset to ready phase after rollback
		return ContainerPhaseReady
	}

	// Check if we need to transition based on event data
	if eventData != nil {
		if readyCount, exists := eventData["ready_containers"]; exists {
			if count, ok := readyCount.(int); ok && count > 0 {
				if currentPhase == ContainerPhaseStarting {
					return ContainerPhaseRunning
				}
			}
		}

		if stabilityScore, exists := eventData["stability_score"]; exists {
			if score, ok := stabilityScore.(float64); ok && score > 0.8 {
				if currentPhase == ContainerPhaseRunning {
					return ContainerPhaseSteady
				}
			}
		}
	}

	// No transition needed
	return currentPhase
}

func (lm *LifecycleManager) updateWorkloadPhase(state *WorkloadLifecycleState) {
	// Update workload phase based on container phases
	if state == nil {
		return
	}

	// Count containers in different phases
	phaseCount := make(map[ContainerPhase]int)
	totalContainers := 0

	// Count main containers
	for _, containerState := range state.MainContainers {
		phaseCount[containerState.CurrentPhase]++
		totalContainers++
	}

	// Count sidecar containers (less weight in decision)
	sidecarCount := 0
	for _, containerState := range state.SidecarContainers {
		phaseCount[containerState.CurrentPhase]++
		sidecarCount++
	}
	totalContainers += sidecarCount

	if totalContainers == 0 {
		state.CurrentPhase = WorkloadPhaseInitializing
		return
	}

	// Determine workload phase based on container distribution
	steadyContainers := phaseCount[ContainerPhaseSteady]
	readyContainers := phaseCount[ContainerPhaseReady]
	runningContainers := phaseCount[ContainerPhaseRunning]
	startingContainers := phaseCount[ContainerPhaseStarting]
	failedContainers := phaseCount[ContainerPhaseFailed]

	// Priority-based phase determination
	if failedContainers > 0 {
		state.CurrentPhase = WorkloadPhaseFailed
	} else if steadyContainers == totalContainers {
		state.CurrentPhase = WorkloadPhaseSteady
	} else if (steadyContainers + readyContainers) >= totalContainers/2 {
		state.CurrentPhase = WorkloadPhaseRunning
	} else if runningContainers > 0 {
		state.CurrentPhase = WorkloadPhaseHealthChecking
	} else if startingContainers > 0 {
		state.CurrentPhase = WorkloadPhaseStarting
	} else {
		// Check if init containers are running
		initRunning := 0
		for _, containerState := range state.InitContainers {
			if containerState.CurrentPhase == ContainerPhaseRunning ||
			   containerState.CurrentPhase == ContainerPhaseStarting {
				initRunning++
			}
		}

		if initRunning > 0 {
			state.CurrentPhase = WorkloadPhaseInitContainers
		} else {
			state.CurrentPhase = WorkloadPhaseMainStarting
		}
	}

	// Log phase change if it's different
	if len(state.PhaseHistory) == 0 || state.PhaseHistory[len(state.PhaseHistory)-1].To != state.CurrentPhase {
		log.Log.V(1).Info("Workload phase updated",
			"workload", lm.getWorkloadKey(state.WorkloadRef),
			"newPhase", state.CurrentPhase,
			"steadyContainers", steadyContainers,
			"readyContainers", readyContainers,
			"runningContainers", runningContainers,
			"totalContainers", totalContainers)
	}
}

func (lm *LifecycleManager) shouldTriggerPolicyTightening(
	containerState *ContainerLifecycleState,
	transition ContainerPhaseTransition,
) bool {
	// Implementation would determine if policy tightening should be triggered
	return transition.To == ContainerPhaseReady || transition.To == ContainerPhaseSteady
}

func (lm *LifecycleManager) schedulePolicyTightening(
	containerID string,
	transition ContainerPhaseTransition,
) {
	// Implementation would schedule policy tightening
}

func (lm *LifecycleManager) eventTypeToTrigger(eventType LifecycleEventType) TransitionTrigger {
	switch eventType {
	case EventTypeContainerHealthy:
		return TriggerHealthCheck
	case EventTypeContainerSteady:
		return TriggerStabilityReached
	default:
		return TriggerAutomatic
	}
}

func (lm *LifecycleManager) updateContainerStateFromEvent(
	containerState *ContainerLifecycleState,
	eventType LifecycleEventType,
	eventData map[string]interface{},
) {
	// Implementation would update container state based on event data
}

func (lm *LifecycleManager) monitorWorkloadLifecycles(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lm.stopCh:
			return
		case <-ticker.C:
			lm.performLifecycleMonitoring()
		}
	}
}

func (lm *LifecycleManager) performLifecycleMonitoring() {
	// Implementation would perform periodic lifecycle monitoring
}

// Additional helper methods for policy lifecycle management
func (lm *LifecycleManager) assessCurrentPrivileges(containerState *ContainerLifecycleState) RequiredPrivileges {
	privileges := RequiredPrivileges{
		Capabilities: []string{},
		Syscalls:     []uint64{},
		NetworkPorts: []NetworkPortRequirement{},
		FilePaths:    []FilePathRequirement{},
		Special:      []SpecialPrivilege{},
	}

	if containerState == nil || containerState.CurrentPolicy == nil {
		return privileges
	}

	policy := containerState.CurrentPolicy

	// Extract syscalls from policy
	if policy.SyscallPolicy != nil && policy.SyscallPolicy.AllowedSyscalls != nil {
		for syscallID := range policy.SyscallPolicy.AllowedSyscalls {
			privileges.Syscalls = append(privileges.Syscalls, syscallID)
		}
	}

	// Extract network ports from network policy
	if policy.NetworkPolicy != nil {
		for _, rule := range policy.NetworkPolicy.EgressRules {
			if rule.RemoteEndpoint != nil && rule.RemoteEndpoint.PortRange != nil {
				privileges.NetworkPorts = append(privileges.NetworkPorts, NetworkPortRequirement{
					Port:     rule.RemoteEndpoint.PortRange.Start,
					Protocol: rule.Protocol,
				})
			}
		}
		for _, rule := range policy.NetworkPolicy.IngressRules {
			if rule.LocalEndpoint != nil && rule.LocalEndpoint.PortRange != nil {
				privileges.NetworkPorts = append(privileges.NetworkPorts, NetworkPortRequirement{
					Port:     rule.LocalEndpoint.PortRange.Start,
					Protocol: rule.Protocol,
				})
			}
		}
	}

	// Extract file paths from file policy
	if policy.FilePolicy != nil && policy.FilePolicy.AllowedPaths != nil {
		for path, rule := range policy.FilePolicy.AllowedPaths {
			privileges.FilePaths = append(privileges.FilePaths, FilePathRequirement{
				Path:        path,
				AccessModes: rule.AccessModes,
				Required:    true,
			})
		}
	}

	return privileges
}

func (lm *LifecycleManager) calculateTightenedPrivileges(
	current RequiredPrivileges,
	tighteningType TighteningType,
	intensity TighteningIntensity,
	containerState *ContainerLifecycleState,
) (RequiredPrivileges, error) {
	tightened := RequiredPrivileges{
		Capabilities: make([]string, 0),
		Syscalls:     make([]uint64, 0),
		NetworkPorts: make([]NetworkPortRequirement, 0),
		FilePaths:    make([]FilePathRequirement, 0),
		Special:      make([]SpecialPrivilege, 0),
	}

	switch intensity {
	case IntensityGentle:
		// Remove only clearly unnecessary privileges (keep 90%)
		tightened.Capabilities = lm.filterCapabilitiesByUsage(current.Capabilities, 0.9)
		tightened.Syscalls = lm.filterSyscallsByUsage(current.Syscalls, 0.9)
		tightened.NetworkPorts = lm.filterNetworkPortsByUsage(current.NetworkPorts, 0.9)
		tightened.FilePaths = lm.filterFilePathsByUsage(current.FilePaths, 0.9)

	case IntensityModerate:
		// Remove privileges not used recently (keep 70%)
		tightened.Capabilities = lm.filterCapabilitiesByUsage(current.Capabilities, 0.7)
		tightened.Syscalls = lm.filterSyscallsByUsage(current.Syscalls, 0.7)
		tightened.NetworkPorts = lm.filterNetworkPortsByUsage(current.NetworkPorts, 0.7)
		tightened.FilePaths = lm.filterFilePathsByUsage(current.FilePaths, 0.7)

	case IntensityAggressive:
		// Keep only essential privileges (keep 50%)
		tightened.Capabilities = lm.filterCapabilitiesByUsage(current.Capabilities, 0.5)
		tightened.Syscalls = lm.filterSyscallsByUsage(current.Syscalls, 0.5)
		tightened.NetworkPorts = lm.filterNetworkPortsByUsage(current.NetworkPorts, 0.5)
		tightened.FilePaths = lm.filterFilePathsByUsage(current.FilePaths, 0.5)

	case IntensityMaximal:
		// Keep only critical privileges (keep 25%)
		tightened.Capabilities = lm.filterCapabilitiesByUsage(current.Capabilities, 0.25)
		tightened.Syscalls = lm.filterSyscallsByUsage(current.Syscalls, 0.25)
		tightened.NetworkPorts = lm.filterNetworkPortsByUsage(current.NetworkPorts, 0.25)
		tightened.FilePaths = lm.filterFilePathsByUsage(current.FilePaths, 0.25)

	default:
		return current, fmt.Errorf("unknown tightening intensity: %v", intensity)
	}

	// Apply type-specific adjustments
	switch tighteningType {
	case TighteningTypeSyscall:
		// Focus on syscall restrictions only
		tightened.Syscalls = lm.filterSyscallsByUsage(current.Syscalls, 0.3)
		tightened.Capabilities = current.Capabilities
		tightened.NetworkPorts = current.NetworkPorts
		tightened.FilePaths = current.FilePaths

	case TighteningTypeNetwork:
		// Focus on network restrictions only
		tightened.NetworkPorts = lm.filterNetworkPortsByUsage(current.NetworkPorts, 0.3)
		tightened.Capabilities = current.Capabilities
		tightened.Syscalls = current.Syscalls
		tightened.FilePaths = current.FilePaths

	case TighteningTypeFile:
		// Focus on file access restrictions only
		tightened.FilePaths = lm.filterFilePathsByUsage(current.FilePaths, 0.3)
		tightened.Capabilities = current.Capabilities
		tightened.Syscalls = current.Syscalls
		tightened.NetworkPorts = current.NetworkPorts

	case TighteningTypeCapability:
		// Focus on capability restrictions only
		tightened.Capabilities = lm.filterCapabilitiesByUsage(current.Capabilities, 0.3)
		tightened.Syscalls = current.Syscalls
		tightened.NetworkPorts = current.NetworkPorts
		tightened.FilePaths = current.FilePaths

	case TighteningTypeCombined:
		// Apply combined restrictions (already done above by intensity)
		// No additional changes needed
	}

	return tightened, nil
}

func (lm *LifecycleManager) assessTighteningImpact(
	containerState *ContainerLifecycleState,
	current RequiredPrivileges,
	new RequiredPrivileges,
) ImpactAssessment {
	// Implementation would assess impact of tightening
	return ImpactAssessment{
		RiskLevel:      RiskLevelLow,
		Reversibility:  true,
		BusinessImpact: BusinessImpactMinimal,
	}
}

func (lm *LifecycleManager) createRollbackPlan(
	containerState *ContainerLifecycleState,
	previousPrivileges RequiredPrivileges,
	impact ImpactAssessment,
) *RollbackPlan {
	// Implementation would create rollback plan
	return &RollbackPlan{
		Enabled:           true,
		AutomaticRollback: true,
		MaxRollbackTime:   5 * time.Minute,
	}
}

func (lm *LifecycleManager) applyTightenedPolicy(
	containerState *ContainerLifecycleState,
	newPrivileges RequiredPrivileges,
	event TighteningEvent,
) error {
	// Implementation would apply tightened policy through enforcement engine
	return nil
}

func (lm *LifecycleManager) calculatePrivilegeLevel(privileges RequiredPrivileges) PrivilegeLevel {
	// Implementation would calculate privilege level based on privileges
	return PrivilegeLevelReduced
}

func (lm *LifecycleManager) calculatePrivilegeReduction(
	previous RequiredPrivileges,
	new RequiredPrivileges,
) float64 {
	// Implementation would calculate percentage of privilege reduction
	return 0.25 // 25% reduction
}

// Event processor methods
func (lep *LifecycleEventProcessor) Start(ctx context.Context) {
	go lep.processEvents(ctx)
}

func (lep *LifecycleEventProcessor) Stop() {
	close(lep.stopCh)
}

func (lep *LifecycleEventProcessor) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-lep.stopCh:
			return
		case event := <-lep.eventQueue:
			lep.handleEvent(event)
		}
	}
}

func (lep *LifecycleEventProcessor) handleEvent(event *LifecycleEvent) {
	handlers, exists := lep.eventHandlers[event.Type]
	if !exists {
		return
	}

	for _, handler := range handlers {
		go func(h LifecycleEventHandler) {
			if err := h.HandleEvent(event); err != nil {
				log.Log.Error(err, "Event handler failed", "eventType", event.Type)
			}
		}(handler)
	}
}

// Scheduler methods
func (pts *PolicyTighteningScheduler) Start(ctx context.Context) {
	go pts.processTighteningTasks(ctx)
}

func (pts *PolicyTighteningScheduler) Stop() {
	close(pts.stopCh)
	pts.ticker.Stop()
}

func (pts *PolicyTighteningScheduler) processTighteningTasks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-pts.stopCh:
			return
		case <-pts.ticker.C:
			pts.processScheduledTasks()
		}
	}
}

func (pts *PolicyTighteningScheduler) processScheduledTasks() {
	now := time.Now()

	for _, tasks := range pts.scheduledTightenings {
		for _, task := range tasks {
			if task.Status == TaskStatusPending && task.ScheduledTime.Before(now) {
				go pts.executeTask(task)
			}
		}
	}
}

func (pts *PolicyTighteningScheduler) executeTask(task *ScheduledTighteningTask) {
	// Implementation would execute tightening task
	task.Status = TaskStatusRunning
	// ... execution logic ...
	task.Status = TaskStatusCompleted
	now := time.Now()
	task.CompletedTime = &now
}

// Helper methods for filtering privileges based on usage patterns
func (lm *LifecycleManager) filterCapabilitiesByUsage(capabilities []string, retentionRatio float64) []string {
	if retentionRatio >= 1.0 {
		return capabilities
	}

	// Simple implementation: retain most commonly used capabilities
	essentialCaps := []string{
		"CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE", "CAP_FOWNER",
		"CAP_NET_BIND_SERVICE", "CAP_CHOWN",
	}

	result := make([]string, 0)
	keepCount := int(float64(len(capabilities)) * retentionRatio)

	// Always keep essential capabilities
	for _, cap := range capabilities {
		for _, essential := range essentialCaps {
			if cap == essential {
				result = append(result, cap)
				break
			}
		}
	}

	// Add remaining capabilities up to the limit
	for _, cap := range capabilities {
		if len(result) >= keepCount {
			break
		}
		// Check if not already added
		found := false
		for _, existing := range result {
			if existing == cap {
				found = true
				break
			}
		}
		if !found {
			result = append(result, cap)
		}
	}

	return result
}

func (lm *LifecycleManager) filterSyscallsByUsage(syscalls []uint64, retentionRatio float64) []uint64 {
	if retentionRatio >= 1.0 {
		return syscalls
	}

	// Simple implementation: retain most critical syscalls
	essentialSyscalls := []uint64{
		1, 2, 3, 4, 5, 6, 59, 60, // read, write, open, close, stat, fstat, execve, exit
		9, 10, 11, 12, // mmap, mprotect, munmap, brk
		102, 158, // getuid, arch_prctl
	}

	result := make([]uint64, 0)
	keepCount := int(float64(len(syscalls)) * retentionRatio)

	// Always keep essential syscalls
	for _, syscall := range syscalls {
		for _, essential := range essentialSyscalls {
			if syscall == essential {
				result = append(result, syscall)
				break
			}
		}
	}

	// Add remaining syscalls up to the limit
	for _, syscall := range syscalls {
		if len(result) >= keepCount {
			break
		}
		// Check if not already added
		found := false
		for _, existing := range result {
			if existing == syscall {
				found = true
				break
			}
		}
		if !found {
			result = append(result, syscall)
		}
	}

	return result
}

func (lm *LifecycleManager) filterNetworkPortsByUsage(ports []NetworkPortRequirement, retentionRatio float64) []NetworkPortRequirement {
	if retentionRatio >= 1.0 {
		return ports
	}

	// Simple implementation: retain most common ports
	essentialPorts := []int32{80, 443, 53, 22, 8080, 3000, 5000}

	result := make([]NetworkPortRequirement, 0)
	keepCount := int(float64(len(ports)) * retentionRatio)

	// Always keep essential ports
	for _, port := range ports {
		for _, essential := range essentialPorts {
			if port.Port == essential {
				result = append(result, port)
				break
			}
		}
	}

	// Add remaining ports up to the limit
	for _, port := range ports {
		if len(result) >= keepCount {
			break
		}
		// Check if not already added
		found := false
		for _, existing := range result {
			if existing.Port == port.Port && existing.Protocol == port.Protocol {
				found = true
				break
			}
		}
		if !found {
			result = append(result, port)
		}
	}

	return result
}

func (lm *LifecycleManager) filterFilePathsByUsage(paths []FilePathRequirement, retentionRatio float64) []FilePathRequirement {
	if retentionRatio >= 1.0 {
		return paths
	}

	// Simple implementation: retain most critical file paths
	essentialPaths := []string{
		"/", "/bin", "/usr", "/lib", "/lib64", "/etc", "/var", "/tmp", "/proc", "/sys",
		"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
	}

	result := make([]FilePathRequirement, 0)
	keepCount := int(float64(len(paths)) * retentionRatio)

	// Always keep essential paths
	for _, path := range paths {
		for _, essential := range essentialPaths {
			if path.Path == essential || strings.HasPrefix(path.Path, essential+"/") {
				result = append(result, path)
				break
			}
		}
	}

	// Add remaining paths up to the limit
	for _, path := range paths {
		if len(result) >= keepCount {
			break
		}
		// Check if not already added
		found := false
		for _, existing := range result {
			if existing.Path == path.Path {
				found = true
				break
			}
		}
		if !found {
			result = append(result, path)
		}
	}

	return result
}
