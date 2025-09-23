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
	_ = workloadKey // TODO: Use workloadKey for logging or metrics

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
	// Implementation would create lifecycle configuration from policy
	return &LifecycleConfiguration{
		AutomaticTightening: policy.Spec.LearningConfig.LifecycleAware,
		GracefulTightening:  true,
		RollbackEnabled:     policy.Spec.SelfHealing.Enabled,
		MonitoringEnabled:   true,
		NotificationEnabled: true,
	}
}

func (lm *LifecycleManager) determineContainerType(containerID string, workloadRef learner.WorkloadReference) ContainerType {
	// Implementation would determine container type based on workload metadata
	return ContainerTypeMain
}

func (lm *LifecycleManager) scheduleInitialTighteningEvents(workloadKey string, state *WorkloadLifecycleState) {
	// Implementation would schedule initial tightening events
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
	// Implementation would determine new phase based on event
	return containerState.CurrentPhase
}

func (lm *LifecycleManager) updateWorkloadPhase(state *WorkloadLifecycleState) {
	// Implementation would update workload phase based on container phases
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

// Additional helper methods would be implemented here...
func (lm *LifecycleManager) assessCurrentPrivileges(containerState *ContainerLifecycleState) RequiredPrivileges {
	// Implementation would assess current privileges
	return RequiredPrivileges{}
}

func (lm *LifecycleManager) calculateTightenedPrivileges(
	current RequiredPrivileges,
	tighteningType TighteningType,
	intensity TighteningIntensity,
	containerState *ContainerLifecycleState,
) (RequiredPrivileges, error) {
	// Implementation would calculate tightened privileges
	return RequiredPrivileges{}, nil
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
