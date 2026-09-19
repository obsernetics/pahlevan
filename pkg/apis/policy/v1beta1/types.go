// +kubebuilder:object:generate=true

// Package v1beta1 is the version the API server stores and the version new
// policies should be written against.
//
// It exists because `v1alpha1` has meant "the shape may move" since the first
// commit, and the shape did move. Graduating is the point at which the project
// stops reserving that right, so it is also the last chance to correct the
// shapes that were wrong. Every difference from v1alpha1 carries a comment
// naming the concrete failure it avoids, because a graduation that renames
// fields for taste costs every user a migration and buys nothing.
//
// The differences, in full:
//
//  1. `spec.selector` and the network peer selectors are separate types.
//     v1alpha1 used one LabelSelector for both, so a peer advertised a
//     `namespaceSelector` that no code path reads.
//  2. `enforcementStatus.blockedSyscalls` is gone. It could only ever be zero.
//  3. `exceptions[].temporary` is gone. An expiry is the fact; the flag was a
//     second way to state it that disagreed with it.
//  4. Every string field with a fixed value set carries an enum, so a typo is
//     refused at apply time instead of being mapped onto a default.
//  5. Counts and percentages carry bounds.
//  6. `status.conditions` is declared a map list keyed by type, which is how
//     the controller has always treated it.
//  7. `learningConfig.expectedBehavior` and the `declared*` lists on a
//     ContainerProfile's status exist only here. They are the one addition
//     rather than a correction: learning is a window of wall-clock time, so a
//     workload's once-a-day operation is absent from the baseline for the same
//     reason an attack is, and there was no way to say in advance which is
//     which. See ExpectedBehavior.
//
// Conversion to and from v1alpha1 lives in the v1alpha1 package, which is the
// spoke; this package is the hub. Items 1, 2 and 3 above cannot round-trip and
// are enumerated, with reasons, in v1alpha1's IntentionallyDropped; item 7 has
// no v1alpha1 counterpart at all and is enumerated in IntentionallyAdded.
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PahlevanPolicySpec defines the desired state of PahlevanPolicy
type PahlevanPolicySpec struct {
	// Selector specifies the target workloads for this policy
	Selector WorkloadSelector `json:"selector"`

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

// WorkloadSelector selects the workloads a policy governs, optionally
// restricted to a set of namespaces.
//
// It is a separate type from LabelSelector, which is what v1alpha1 got wrong.
// There, one LabelSelector carrying a namespaceSelector served both the
// top-level workload selector and the peer selectors inside a network rule. A
// peer's namespaceSelector is already a namespace selector, so
// `peers[].namespaceSelector.namespaceSelector` was a legal thing to write, as
// was `peers[].podSelector.namespaceSelector`. Neither is read anywhere. A
// field that applies cleanly and is never consulted is the failure this whole
// document exists to prevent, so the two roles now have two types and only the
// one that means something carries the field.
type WorkloadSelector struct {
	// MatchLabels is a map of {key,value} pairs
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is a list of label selector requirements
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`

	// NamespaceSelector specifies target namespaces, matched against the
	// namespace's own labels.
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
}

// NamespaceSelector selects namespaces by their labels.
//
// It is a distinct type from LabelSelector rather than a self-reference, for
// two reasons. A namespace selector that itself carried a namespace selector
// is meaningless. And the self-reference made the CRD uninstallable:
// controller-gen cannot express infinite recursion, so it truncated the chain
// into a node carrying a description and no type, and the API server rejects
// that with "must have a type". Applying install.yaml failed partway through
// and left a half-installed cluster.
type NamespaceSelector struct {
	// MatchLabels is a map of {key,value} pairs matched against namespace labels.
	// Kubernetes stamps every namespace with kubernetes.io/metadata.name, so
	// selecting a namespace by name works through this field.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is a list of namespace label selector requirements.
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// LabelSelector selects objects by their labels. It has no namespaceSelector:
// the scope a selector applies within is decided by where the selector sits,
// not by the selector itself. See WorkloadSelector for what that fixes.
type LabelSelector struct {
	// MatchLabels is a map of {key,value} pairs
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is a list of label selector requirements
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// LabelSelectorRequirement contains a key, operator, and values for label selection
type LabelSelectorRequirement struct {
	Key      string                `json:"key"`
	Operator LabelSelectorOperator `json:"operator"`
	Values   []string              `json:"values,omitempty"`
}

// LabelSelectorOperator represents a label selector operator
//
// +kubebuilder:validation:Enum=In;NotIn;Exists;DoesNotExist
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

	// MinSamples specifies minimum number of samples before transitioning.
	//
	// Bounded below by 1: zero means "transition with no evidence at all",
	// which is a policy that enforces an empty baseline and kills the workload
	// on its first syscall. Negative was accepted and compared against a count
	// that can never be less than it, so it silently meant the same thing.
	//
	// +kubebuilder:validation:Minimum=1
	MinSamples *int32 `json:"minSamples,omitempty"`

	// AutoTransition enables automatic transition to enforcement
	AutoTransition bool `json:"autoTransition,omitempty"`

	// LifecycleAware enables lifecycle-based learning transitions
	LifecycleAware bool `json:"lifecycleAware,omitempty"`

	// ExpectedBehavior declares operations the operator knows the workload
	// performs but which may not happen during the learning window.
	//
	// Learning is a window of wall-clock time, so anything the workload does
	// once a day is simply absent from the baseline: a nightly batch, a weekly
	// certificate renewal, a log rotation, a backup that opens a path nothing
	// else opens. Under Blocking the kernel then refuses it, and from the
	// kernel's side that refusal is correct - the only evidence against the
	// operation is that the workload has never done it before, which is exactly
	// what an attacker produces too. Without this field the operator's only
	// options are to guess a longer duration, or to let self-healing roll
	// enforcement back after the job has already been denied at 03:00.
	//
	// Declarations are additive. Every entry is merged into the allow-set
	// alongside what was learned, none can remove a learned entry, and an entry
	// that cannot be represented exactly is refused with a warning naming the
	// field rather than widened into something broader.
	ExpectedBehavior *ExpectedBehavior `json:"expectedBehavior,omitempty"`
}

// ExpectedBehavior is what an operator asserts a workload does, as against
// what the agent observed it doing. The two are kept apart everywhere they are
// reported, because "the workload opened this path" and "somebody said it
// would" are different grades of evidence and an operator reviewing a profile
// has to be able to tell them apart.
//
// The vocabulary is deliberately the one filePolicy and networkPolicy already
// use - absolute resolved paths, single-host CIDRs, capability names without
// the CAP_ prefix - so that declaring an operation and allowing one are not two
// things to learn. The same limits apply for the same reason: the kernel
// allow-set is a hash of the exact operation, so a wildcard path or a prefix
// wider than one host has no representation in it.
//
// MinProperties because an `expectedBehavior: {}` that declares nothing is
// almost always a half-written block, and accepting it silently is how an
// operator comes to believe a rare operation is covered when nothing was
// written down at all.
//
// +kubebuilder:validation:MinProperties=1
type ExpectedBehavior struct {
	// Files are paths the workload opens on a code path the learning window may
	// not reach.
	Files []ExpectedFile `json:"files,omitempty"`

	// NetworkDestinations are egress endpoints the workload dials rarely.
	NetworkDestinations []ExpectedDestination `json:"networkDestinations,omitempty"`

	// Executables are binary paths the workload executes rarely - a backup
	// tool, a migration runner, a cert-renewal hook. Absolute and fully
	// resolved, the same rule filePolicy.executableFilter.allowedExecutables
	// carries, because the kernel matches the path bprm_check_security resolves.
	//
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:Pattern=`^/`
	Executables []string `json:"executables,omitempty"`

	// Capabilities are Linux capabilities the workload exercises rarely, as
	// names with or without the CAP_ prefix - the spelling
	// syscallPolicy.capabilityFilter accepts and the one
	// containerProfile.status.learnedCapabilities reports. A name outside the
	// kernel's table is refused at translation, because the API server has no
	// list to check it against and a typo would otherwise be a declaration that
	// covers nothing.
	//
	// +kubebuilder:validation:items:MinLength=1
	Capabilities []string `json:"capabilities,omitempty"`
}

// ExpectedFile declares one path the workload uses.
//
// filePolicy draws the read/write line with two lists, readOnlyPaths and
// writeAllowedPaths. A declaration is a list of operations rather than a list
// of paths, so the line is drawn per entry instead - but it is the same line,
// and it means the same thing: reads and writes are separate entries in the
// kernel allow-set, so declaring a read does not permit a write.
type ExpectedFile struct {
	// Path is the fully resolved absolute path. Enforcement keys on the path
	// the kernel resolves, which follows symlinks, so declaring
	// "/etc/os-release" grants nothing where it links to /usr/lib/os-release.
	// Wildcards have no representation in the allow-set and are refused at
	// translation rather than matched literally and silently never firing.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^/`
	Path string `json:"path"`

	// Write declares the workload writes the path as well as reading it, which
	// is what filePolicy.writeAllowedPaths grants. Omitted means read only,
	// matching filePolicy.readOnlyPaths.
	Write bool `json:"write,omitempty"`
}

// ExpectedDestination declares one egress endpoint the workload dials.
//
// It is flatter than a networkPolicy egress rule - one address, one port, one
// protocol - because a rule's peer selectors and port ranges exist to describe
// a class of traffic, and a declaration is the opposite: it names the one
// operation an operator is willing to vouch for. The field names and the
// single-host rule are the egress rule's, so the same CIDR that works in
// egressRules works here.
type ExpectedDestination struct {
	// CIDR is the destination as a single-host prefix (10.43.12.7/32, or a /128
	// for IPv6) or a bare address. The allow-set is a hash of the exact
	// destination and cannot express a prefix, so anything wider is refused at
	// translation - seeding only the network address would grant one host that
	// was never declared and none of the others.
	//
	// +kubebuilder:validation:MinLength=1
	CIDR string `json:"cidr"`

	// Port is the destination port.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Protocol is the transport. Empty means TCP.
	//
	// UDP is accepted by the API server and refused at translation: the
	// allow-set key folds the protocol in, but the decision a policy translates
	// into carries only (address, port), so a declared UDP destination would be
	// written into the kernel as a TCP entry - granting a protocol nobody
	// declared and not granting the one that was. The field exists rather than
	// being omitted so that limit is visible where the declaration is written,
	// instead of being a silent assumption about what "port 53" meant.
	//
	// The enum lives on TransportProtocol rather than here: repeating it on the
	// field as well makes controller-gen emit the same enum twice inside an
	// allOf, which validates identically and reads as a generator bug.
	Protocol TransportProtocol `json:"protocol,omitempty"`
}

// TransportProtocol is the transport of a declared destination.
//
// +kubebuilder:validation:Enum=TCP;UDP
type TransportProtocol string

const (
	TransportProtocolTCP TransportProtocol = "TCP"
	TransportProtocolUDP TransportProtocol = "UDP"
)

// EnforcementConfig controls enforcement behavior
type EnforcementConfig struct {
	// Mode specifies the enforcement mode.
	//
	// The enum is load-bearing rather than decorative. Without it the API
	// server accepts any string and the controller maps whatever it does not
	// recognize onto Monitoring, so a typo produces a policy that looks applied
	// and enforces nothing. The trap that found this: `mode: Off` unquoted is a
	// YAML 1.1 boolean, so it arrives as `false` and silently became Monitoring
	// - the opposite of switching a policy off. Quote it, or the API server now
	// says so.
	Mode EnforcementMode `json:"mode,omitempty"`

	// GracePeriod specifies grace period before strict enforcement
	GracePeriod *metav1.Duration `json:"gracePeriod,omitempty"`

	// AlertOnly enables alert-only mode for testing. It downgrades Blocking to
	// Monitoring and is kept as its own field because it is a temporary
	// override an operator flips during an incident and flips back, without
	// losing the mode the policy is meant to run in.
	AlertOnly bool `json:"alertOnly,omitempty"`

	// BlockUnknown blocks behavior outside the learned baseline. Nil means
	// "the default for the mode", which is true under Blocking: default-deny of
	// unlearned behavior is the only enforcement the data plane performs, so a
	// Blocking policy that did not block it would enforce nothing. Explicitly
	// false downgrades the policy to Monitoring. A bare bool could not express
	// the difference between unset and false.
	BlockUnknown *bool `json:"blockUnknown,omitempty"`

	// Exceptions defines enforcement exceptions
	Exceptions []EnforcementException `json:"exceptions,omitempty"`
}

// EnforcementMode defines enforcement behavior
//
// +kubebuilder:validation:Enum=Off;Monitoring;Blocking
type EnforcementMode string

const (
	EnforcementModeOff        EnforcementMode = "Off"
	EnforcementModeMonitoring EnforcementMode = "Monitoring"
	EnforcementModeBlocking   EnforcementMode = "Blocking"
)

// EnforcementException defines enforcement exceptions.
//
// v1alpha1 had both `temporary: true` and `expiresAt`, and enforcement applied
// an expiry only when both were set. So `expiresAt` on its own was accepted,
// displayed, and never acted on: an operator who wrote a deadline got a
// permanent hole in the policy and no warning, which is the worst possible
// outcome for a field whose entire purpose is to close itself. The expiry is
// now the only statement of the fact, and an exception is temporary exactly
// when it has one.
type EnforcementException struct {
	// Type specifies exception type
	Type ExceptionType `json:"type"`

	// Patterns specifies patterns to match
	Patterns []string `json:"patterns"`

	// Reason provides human-readable reason
	Reason string `json:"reason,omitempty"`

	// ExpiresAt is when this exception stops being applied. Unset means the
	// exception is permanent.
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// ExceptionType defines types of enforcement exceptions
//
// +kubebuilder:validation:Enum=Syscall;Network;File
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

// NetworkPort defines port specifications.
//
// The bounds are not decoration. A port is a uint16 on the wire and this field
// is an int32, so v1alpha1 accepted 0, -1 and 70000 and the translation
// truncated them into whatever the low sixteen bits happened to be. Port 70000
// became port 4464, and the rule looked applied.
type NetworkPort struct {
	// Port specifies the port number
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`

	// StartPort specifies start of port range
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	StartPort *int32 `json:"startPort,omitempty"`

	// EndPort specifies end of port range
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	EndPort *int32 `json:"endPort,omitempty"`

	// Protocol specifies the protocol
	Protocol string `json:"protocol,omitempty"`
}

// NetworkPeer defines network peer specifications
type NetworkPeer struct {
	// IPBlock specifies IP CIDR blocks
	IPBlock *IPBlock `json:"ipBlock,omitempty"`

	// NamespaceSelector selects namespaces by their labels.
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector selects pods by their labels.
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
	// AllowedPaths explicitly allows specific paths.
	//
	// Paths must be fully resolved and exact. Enforcement keys on the path the
	// kernel resolves, which follows symlinks, so "/etc/os-release" grants
	// nothing where it links to /usr/lib/os-release. Wildcards are not
	// supported and are matched literally.
	AllowedPaths []string `json:"allowedPaths,omitempty"`

	// DeniedPaths explicitly denies specific paths, removing them from the
	// learned baseline. The same resolution rules as AllowedPaths apply.
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
//
// +kubebuilder:validation:Enum=Allow;Deny;Alert;Audit
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
	//
	// +kubebuilder:validation:Minimum=0
	RollbackThreshold int32 `json:"rollbackThreshold,omitempty"`

	// RollbackWindow specifies time window for failure counting
	RollbackWindow *metav1.Duration `json:"rollbackWindow,omitempty"`

	// RecoveryStrategy specifies recovery strategy
	RecoveryStrategy RecoveryStrategy `json:"recoveryStrategy,omitempty"`
}

// RecoveryStrategy defines recovery strategies
//
// +kubebuilder:validation:Enum=Rollback;Relax;Maintenance
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

	// Conditions represents the latest available observations.
	//
	// Declared a map list keyed by type, which is what the controller has
	// always meant: updateCondition searches for the entry with a matching
	// type and replaces it. The schema did not say so, so server-side apply
	// merged the array by position instead, and two writers updating different
	// conditions overwrote each other's entries rather than merging them.
	//
	// +listType=map
	// +listMapKey=type
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
//
// +kubebuilder:validation:Enum=Initializing;Learning;Transition;Enforcing;Failed;RollingBack
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
//
// +kubebuilder:validation:Enum=Ready;Learning;Enforcing;Healthy;Error
type PolicyConditionType string

const (
	PolicyConditionReady     PolicyConditionType = "Ready"
	PolicyConditionLearning  PolicyConditionType = "Learning"
	PolicyConditionEnforcing PolicyConditionType = "Enforcing"
	PolicyConditionHealthy   PolicyConditionType = "Healthy"
	PolicyConditionError     PolicyConditionType = "Error"
)

// ConditionStatus defines condition status
//
// +kubebuilder:validation:Enum=True;False;Unknown
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

	// Progress indicates learning progress percentage.
	//
	// Bounded, because it is printed verbatim in the Learning column of
	// `kubectl get pahlevanpolicy`. An unbounded int32 there reads as "413"
	// next to a header that says a percentage, and nothing rejects it.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Progress *int32 `json:"progress,omitempty"`
}

// EnforcementStatus provides enforcement status.
//
// v1alpha1 carried a blockedSyscalls counter that was always zero by
// construction: syscalls are confined by the generated seccomp profile, whose
// denials the kernel does not report back to this agent, and the BPF syscall
// program is observation only. A counter that can only read zero answers "are
// we blocking anything?" with "no" forever, so it is gone rather than
// documented again.
type EnforcementStatus struct {
	// StartTime indicates when enforcement started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// BlockedNetworkConnections indicates connect() calls denied in-kernel.
	BlockedNetworkConnections int64 `json:"blockedNetworkConnections,omitempty"`

	// BlockedFileAccess indicates file opens denied in-kernel.
	BlockedFileAccess int64 `json:"blockedFileAccess,omitempty"`

	// BlockedExecs indicates execve calls denied in-kernel.
	BlockedExecs int64 `json:"blockedExecs,omitempty"`

	// BlockedCapabilities indicates capability checks denied in-kernel.
	BlockedCapabilities int64 `json:"blockedCapabilities,omitempty"`

	// BlockedTotal is the sum of every in-kernel denial across the containers
	// this policy governs. It exists so the printed column reports the whole
	// picture rather than one signal.
	BlockedTotal int64 `json:"blockedTotal,omitempty"`

	// EnforcingContainers and TotalContainers describe how many of the
	// containers this policy selects have actually reached enforcement.
	EnforcingContainers int32 `json:"enforcingContainers,omitempty"`
	TotalContainers     int32 `json:"totalContainers,omitempty"`

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

	// RiskScore provides overall risk score, 0 to 100.
	//
	// Bounded for the same reason as Progress: it is the Risk printer column,
	// and the analyzer's arithmetic has no upper clamp of its own.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
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
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Learning",type=string,JSONPath=`.status.learningStatus.progress`
// +kubebuilder:printcolumn:name="Blocked",type=integer,JSONPath=`.status.enforcementStatus.blockedTotal`
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
