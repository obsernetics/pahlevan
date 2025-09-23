package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PahlevanPolicySpec defines the desired state of PahlevanPolicy
type PahlevanPolicySpec struct {
	// Selector specifies the target workloads for this policy
	Selector LabelSelector `json:"selector"`

	// LearningConfig controls the learning phase behavior
	LearningConfig LearningConfig `json:"learningConfig,omitempty"`

	// EnforcementConfig controls enforcement behavior
	EnforcementConfig EnforcementConfig `json:"enforcementConfig,omitempty"`

	// SyscallPolicy defines syscall-specific policies
	SyscallPolicy *SyscallPolicy `json:"syscallPolicy,omitempty"`

	// NetworkPolicy defines network-specific policies
	NetworkPolicy *NetworkPolicy `json:"networkPolicy,omitempty"`

	// FilePolicy defines file access policies
	FilePolicy *FilePolicy `json:"filePolicy,omitempty"`

	// SelfHealing enables automatic policy rollback on failures
	SelfHealing SelfHealingConfig `json:"selfHealing,omitempty"`

	// ObservabilityConfig controls observability exports
	ObservabilityConfig ObservabilityConfig `json:"observabilityConfig,omitempty"`
}

// LabelSelector specifies target workloads
type LabelSelector struct {
	// MatchLabels is a map of {key,value} pairs
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is a list of label selector requirements
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`

	// NamespaceSelector specifies target namespaces
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
}

// LabelSelectorRequirement contains a key, operator, and values for label selection
type LabelSelectorRequirement struct {
	Key      string                `json:"key"`
	Operator LabelSelectorOperator `json:"operator"`
	Values   []string              `json:"values,omitempty"`
}

// LabelSelectorOperator represents a label selector operator
type LabelSelectorOperator string

const (
	LabelSelectorOpIn           LabelSelectorOperator = "In"
	LabelSelectorOpNotIn        LabelSelectorOperator = "NotIn"
	LabelSelectorOpExists       LabelSelectorOperator = "Exists"
	LabelSelectorOpDoesNotExist LabelSelectorOperator = "DoesNotExist"
)

// LearningConfig controls the learning phase
type LearningConfig struct {
	// Duration specifies how long to run in learning mode
	Duration *metav1.Duration `json:"duration,omitempty"`

	// WindowSize specifies the minimum learning window size
	WindowSize *metav1.Duration `json:"windowSize,omitempty"`

	// MinSamples specifies minimum number of samples before transitioning
	MinSamples *int32 `json:"minSamples,omitempty"`

	// AutoTransition enables automatic transition to enforcement
	AutoTransition bool `json:"autoTransition,omitempty"`

	// LifecycleAware enables lifecycle-based learning transitions
	LifecycleAware bool `json:"lifecycleAware,omitempty"`
}

// EnforcementConfig controls enforcement behavior
type EnforcementConfig struct {
	// Mode specifies the enforcement mode
	Mode EnforcementMode `json:"mode,omitempty"`

	// GracePeriod specifies grace period before strict enforcement
	GracePeriod *metav1.Duration `json:"gracePeriod,omitempty"`

	// AlertOnly enables alert-only mode for testing
	AlertOnly bool `json:"alertOnly,omitempty"`

	// BlockUnknown blocks unknown syscalls/access patterns
	BlockUnknown bool `json:"blockUnknown,omitempty"`

	// Exceptions defines enforcement exceptions
	Exceptions []EnforcementException `json:"exceptions,omitempty"`
}

// EnforcementMode defines enforcement behavior
type EnforcementMode string

const (
	EnforcementModeOff        EnforcementMode = "Off"
	EnforcementModeMonitoring EnforcementMode = "Monitoring"
	EnforcementModeBlocking   EnforcementMode = "Blocking"
)

// EnforcementException defines enforcement exceptions
type EnforcementException struct {
	// Type specifies exception type
	Type ExceptionType `json:"type"`

	// Patterns specifies patterns to match
	Patterns []string `json:"patterns"`

	// Reason provides human-readable reason
	Reason string `json:"reason,omitempty"`

	// Temporary indicates if exception is temporary
	Temporary bool `json:"temporary,omitempty"`

	// ExpiresAt specifies when temporary exception expires
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// ExceptionType defines types of enforcement exceptions
type ExceptionType string

const (
	ExceptionTypeSyscall ExceptionType = "Syscall"
	ExceptionTypeNetwork ExceptionType = "Network"
	ExceptionTypeFile    ExceptionType = "File"
)

// SyscallPolicy defines syscall enforcement policies
type SyscallPolicy struct {
	// AllowedSyscalls explicitly allows specific syscalls
	AllowedSyscalls []string `json:"allowedSyscalls,omitempty"`

	// DeniedSyscalls explicitly denies specific syscalls
	DeniedSyscalls []string `json:"deniedSyscalls,omitempty"`

	// DefaultAction specifies default action for unknown syscalls
	DefaultAction PolicyAction `json:"defaultAction,omitempty"`

	// CapabilityFilter filters based on Linux capabilities
	CapabilityFilter []string `json:"capabilityFilter,omitempty"`

	// ProcessFilter filters based on process attributes
	ProcessFilter *ProcessFilter `json:"processFilter,omitempty"`
}

// NetworkPolicy defines network enforcement policies
type NetworkPolicy struct {
	// EgressRules defines allowed egress traffic
	EgressRules []NetworkRule `json:"egressRules,omitempty"`

	// IngressRules defines allowed ingress traffic
	IngressRules []NetworkRule `json:"ingressRules,omitempty"`

	// DefaultAction specifies default action for unknown connections
	DefaultAction PolicyAction `json:"defaultAction,omitempty"`

	// AllowLoopback allows loopback traffic
	AllowLoopback bool `json:"allowLoopback,omitempty"`

	// AllowDNS allows DNS traffic
	AllowDNS bool `json:"allowDNS,omitempty"`
}

// NetworkRule defines a network access rule
type NetworkRule struct {
	// Protocols specifies allowed protocols
	Protocols []string `json:"protocols,omitempty"`

	// Ports specifies allowed ports
	Ports []NetworkPort `json:"ports,omitempty"`

	// Peers specifies allowed peers
	Peers []NetworkPeer `json:"peers,omitempty"`

	// Action specifies the action to take
	Action PolicyAction `json:"action,omitempty"`
}

// NetworkPort defines port specifications
type NetworkPort struct {
	// Port specifies the port number
	Port *int32 `json:"port,omitempty"`

	// StartPort specifies start of port range
	StartPort *int32 `json:"startPort,omitempty"`

	// EndPort specifies end of port range
	EndPort *int32 `json:"endPort,omitempty"`

	// Protocol specifies the protocol
	Protocol string `json:"protocol,omitempty"`
}

// NetworkPeer defines network peer specifications
type NetworkPeer struct {
	// IPBlock specifies IP CIDR blocks
	IPBlock *IPBlock `json:"ipBlock,omitempty"`

	// NamespaceSelector selects namespaces
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector selects pods
	PodSelector *LabelSelector `json:"podSelector,omitempty"`
}

// IPBlock defines IP CIDR block
type IPBlock struct {
	// CIDR specifies the IP range
	CIDR string `json:"cidr"`

	// Except specifies exceptions within the CIDR
	Except []string `json:"except,omitempty"`
}

// FilePolicy defines file access policies
type FilePolicy struct {
	// AllowedPaths explicitly allows specific paths
	AllowedPaths []string `json:"allowedPaths,omitempty"`

	// DeniedPaths explicitly denies specific paths
	DeniedPaths []string `json:"deniedPaths,omitempty"`

	// DefaultAction specifies default action for unknown paths
	DefaultAction PolicyAction `json:"defaultAction,omitempty"`

	// ReadOnlyPaths specifies read-only paths
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`

	// WriteAllowedPaths specifies write-allowed paths
	WriteAllowedPaths []string `json:"writeAllowedPaths,omitempty"`

	// ExecutableFilter controls executable access
	ExecutableFilter *ExecutableFilter `json:"executableFilter,omitempty"`
}

// ExecutableFilter defines executable access controls
type ExecutableFilter struct {
	// AllowedExecutables specifies allowed executables
	AllowedExecutables []string `json:"allowedExecutables,omitempty"`

	// DeniedExecutables specifies denied executables
	DeniedExecutables []string `json:"deniedExecutables,omitempty"`

	// RequireSignature requires signed executables
	RequireSignature bool `json:"requireSignature,omitempty"`
}

// ProcessFilter defines process-based filtering
type ProcessFilter struct {
	// Commands specifies allowed command patterns
	Commands []string `json:"commands,omitempty"`

	// Users specifies allowed users
	Users []string `json:"users,omitempty"`

	// Groups specifies allowed groups
	Groups []string `json:"groups,omitempty"`

	// ParentProcesses specifies allowed parent processes
	ParentProcesses []string `json:"parentProcesses,omitempty"`
}

// PolicyAction defines policy actions
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "Allow"
	PolicyActionDeny  PolicyAction = "Deny"
	PolicyActionAlert PolicyAction = "Alert"
	PolicyActionAudit PolicyAction = "Audit"
)

// SelfHealingConfig controls self-healing behavior
type SelfHealingConfig struct {
	// Enabled enables self-healing
	Enabled bool `json:"enabled,omitempty"`

	// RollbackThreshold specifies failure threshold for rollback
	RollbackThreshold int32 `json:"rollbackThreshold,omitempty"`

	// RollbackWindow specifies time window for failure counting
	RollbackWindow *metav1.Duration `json:"rollbackWindow,omitempty"`

	// RecoveryStrategy specifies recovery strategy
	RecoveryStrategy RecoveryStrategy `json:"recoveryStrategy,omitempty"`
}

// RecoveryStrategy defines recovery strategies
type RecoveryStrategy string

const (
	RecoveryStrategyRollback    RecoveryStrategy = "Rollback"
	RecoveryStrategyRelax       RecoveryStrategy = "Relax"
	RecoveryStrategyMaintenance RecoveryStrategy = "Maintenance"
)

// ObservabilityConfig controls observability exports
type ObservabilityConfig struct {
	// Metrics controls metrics export
	Metrics MetricsConfig `json:"metrics,omitempty"`

	// Tracing controls distributed tracing
	Tracing TracingConfig `json:"tracing,omitempty"`

	// Logging controls structured logging
	Logging LoggingConfig `json:"logging,omitempty"`

	// Visualization controls attack surface visualization
	Visualization VisualizationConfig `json:"visualization,omitempty"`
}

// MetricsConfig controls metrics export
type MetricsConfig struct {
	// Enabled enables metrics export
	Enabled bool `json:"enabled,omitempty"`

	// Exporters specifies metrics exporters
	Exporters []MetricsExporter `json:"exporters,omitempty"`

	// Interval specifies metrics collection interval
	Interval *metav1.Duration `json:"interval,omitempty"`
}

// TracingConfig controls distributed tracing
type TracingConfig struct {
	// Enabled enables tracing
	Enabled bool `json:"enabled,omitempty"`

	// SamplingRate specifies trace sampling rate as a string to avoid CRD generation issues
	// Format: "0.1" for 10% sampling, "1.0" for 100% sampling
	SamplingRate *string `json:"samplingRate,omitempty"`

	// Exporter specifies trace exporter
	Exporter TracingExporter `json:"exporter,omitempty"`
}

// LoggingConfig controls structured logging
type LoggingConfig struct {
	// Level specifies log level
	Level string `json:"level,omitempty"`

	// Format specifies log format
	Format string `json:"format,omitempty"`

	// Outputs specifies log outputs
	Outputs []LogOutput `json:"outputs,omitempty"`
}

// VisualizationConfig controls attack surface visualization
type VisualizationConfig struct {
	// Enabled enables visualization
	Enabled bool `json:"enabled,omitempty"`

	// UpdateInterval specifies visualization update interval
	UpdateInterval *metav1.Duration `json:"updateInterval,omitempty"`

	// Exporters specifies visualization exporters
	Exporters []VisualizationExporter `json:"exporters,omitempty"`
}

// MetricsExporter defines metrics export configuration
type MetricsExporter struct {
	// Type specifies exporter type
	Type string `json:"type"`

	// Endpoint specifies exporter endpoint
	Endpoint string `json:"endpoint,omitempty"`

	// Config specifies exporter-specific configuration
	Config runtime.RawExtension `json:"config,omitempty"`
}

// TracingExporter defines tracing export configuration
type TracingExporter struct {
	// Type specifies exporter type
	Type string `json:"type"`

	// Endpoint specifies exporter endpoint
	Endpoint string `json:"endpoint,omitempty"`

	// Config specifies exporter-specific configuration
	Config runtime.RawExtension `json:"config,omitempty"`
}

// LogOutput defines log output configuration
type LogOutput struct {
	// Type specifies output type
	Type string `json:"type"`

	// Config specifies output-specific configuration
	Config runtime.RawExtension `json:"config,omitempty"`
}

// VisualizationExporter defines visualization export configuration
type VisualizationExporter struct {
	// Type specifies exporter type
	Type string `json:"type"`

	// Endpoint specifies exporter endpoint
	Endpoint string `json:"endpoint,omitempty"`

	// Config specifies exporter-specific configuration
	Config runtime.RawExtension `json:"config,omitempty"`
}

// PahlevanPolicyStatus defines the observed state of PahlevanPolicy
type PahlevanPolicyStatus struct {
	// Phase indicates the current phase of the policy
	Phase PolicyPhase `json:"phase,omitempty"`

	// Conditions represents the latest available observations
	Conditions []PolicyCondition `json:"conditions,omitempty"`

	// LearningStatus provides learning phase status
	LearningStatus *LearningStatus `json:"learningStatus,omitempty"`

	// EnforcementStatus provides enforcement status
	EnforcementStatus *EnforcementStatus `json:"enforcementStatus,omitempty"`

	// AttackSurface provides current attack surface analysis
	AttackSurface *AttackSurfaceStatus `json:"attackSurface,omitempty"`

	// TargetWorkloads lists target workloads
	TargetWorkloads []WorkloadReference `json:"targetWorkloads,omitempty"`

	// LastUpdated indicates when status was last updated
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// PolicyPhase indicates the current phase of policy execution
type PolicyPhase string

const (
	PolicyPhaseInitializing PolicyPhase = "Initializing"
	PolicyPhaseLearning     PolicyPhase = "Learning"
	PolicyPhaseTransition   PolicyPhase = "Transition"
	PolicyPhaseEnforcing    PolicyPhase = "Enforcing"
	PolicyPhaseFailed       PolicyPhase = "Failed"
	PolicyPhaseRollingBack  PolicyPhase = "RollingBack"
)

// PolicyCondition describes a condition of policy execution
type PolicyCondition struct {
	// Type of the condition
	Type PolicyConditionType `json:"type"`

	// Status of the condition
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the last time the condition transitioned
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason contains a programmatic identifier indicating the reason
	Reason string `json:"reason,omitempty"`

	// Message contains a human readable message indicating details
	Message string `json:"message,omitempty"`
}

// PolicyConditionType defines condition types
type PolicyConditionType string

const (
	PolicyConditionReady     PolicyConditionType = "Ready"
	PolicyConditionLearning  PolicyConditionType = "Learning"
	PolicyConditionEnforcing PolicyConditionType = "Enforcing"
	PolicyConditionHealthy   PolicyConditionType = "Healthy"
	PolicyConditionError     PolicyConditionType = "Error"
)

// ConditionStatus defines condition status
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// LearningStatus provides learning phase status
type LearningStatus struct {
	// StartTime indicates when learning started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// EndTime indicates when learning ended
	EndTime *metav1.Time `json:"endTime,omitempty"`

	// SamplesCollected indicates samples collected
	SamplesCollected int64 `json:"samplesCollected,omitempty"`

	// SyscallsLearned indicates unique syscalls learned
	SyscallsLearned int32 `json:"syscallsLearned,omitempty"`

	// NetworkFlowsLearned indicates network flows learned
	NetworkFlowsLearned int32 `json:"networkFlowsLearned,omitempty"`

	// FilePathsLearned indicates file paths learned
	FilePathsLearned int32 `json:"filePathsLearned,omitempty"`

	// Progress indicates learning progress percentage
	Progress *int32 `json:"progress,omitempty"`
}

// EnforcementStatus provides enforcement status
type EnforcementStatus struct {
	// StartTime indicates when enforcement started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// BlockedSyscalls indicates blocked syscall count
	BlockedSyscalls int64 `json:"blockedSyscalls,omitempty"`

	// BlockedNetworkConnections indicates blocked network connections
	BlockedNetworkConnections int64 `json:"blockedNetworkConnections,omitempty"`

	// BlockedFileAccess indicates blocked file access count
	BlockedFileAccess int64 `json:"blockedFileAccess,omitempty"`

	// AlertsGenerated indicates alerts generated count
	AlertsGenerated int64 `json:"alertsGenerated,omitempty"`

	// RollbackCount indicates number of rollbacks performed
	RollbackCount int32 `json:"rollbackCount,omitempty"`
}

// AttackSurfaceStatus provides attack surface analysis
type AttackSurfaceStatus struct {
	// ExposedSyscalls lists exposed syscalls
	ExposedSyscalls []string `json:"exposedSyscalls,omitempty"`

	// ExposedPorts lists exposed network ports
	ExposedPorts []int32 `json:"exposedPorts,omitempty"`

	// WritableFiles lists writable file paths
	WritableFiles []string `json:"writableFiles,omitempty"`

	// Capabilities lists effective capabilities
	Capabilities []string `json:"capabilities,omitempty"`

	// RiskScore provides overall risk score
	RiskScore *int32 `json:"riskScore,omitempty"`

	// LastAnalysis indicates when analysis was last performed
	LastAnalysis *metav1.Time `json:"lastAnalysis,omitempty"`
}

// WorkloadReference references a target workload
type WorkloadReference struct {
	// APIVersion of the workload
	APIVersion string `json:"apiVersion"`

	// Kind of the workload
	Kind string `json:"kind"`

	// Name of the workload
	Name string `json:"name"`

	// Namespace of the workload
	Namespace string `json:"namespace"`

	// UID of the workload
	UID string `json:"uid,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Learning",type=string,JSONPath=`.status.learningStatus.progress`
// +kubebuilder:printcolumn:name="Blocked",type=integer,JSONPath=`.status.enforcementStatus.blockedSyscalls`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PahlevanPolicy is the Schema for the pahlevanpolicies API
type PahlevanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PahlevanPolicySpec   `json:"spec,omitempty"`
	Status PahlevanPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PahlevanPolicyList contains a list of PahlevanPolicy
type PahlevanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PahlevanPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PahlevanPolicy{}, &PahlevanPolicyList{})
}
