package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerProfileSpec identifies the container a learned profile belongs to.
type ContainerProfileSpec struct {
	// PolicyRef is the name of the PahlevanPolicy that governs this container.
	PolicyRef string `json:"policyRef,omitempty"`

	// Workload identifies the owning Kubernetes workload.
	Workload *WorkloadReference `json:"workload,omitempty"`

	// PodName / Namespace of the container's pod.
	PodName   string `json:"podName,omitempty"`
	Namespace string `json:"namespace,omitempty"`

	// ContainerID is the container runtime ID (if resolved).
	ContainerID string `json:"containerID,omitempty"`

	// CgroupID is the cgroup v2 id the eBPF data plane keys enforcement on.
	// Signed because Kubernetes API types may not use unsigned integers; the
	// serialized schema is int64 either way, and cgroup ids never approach the
	// sign bit. Using uint64 here also broke server-side apply, whose
	// structured-merge-diff reflection has no uint64 kind.
	CgroupID int64 `json:"cgroupID,omitempty"`

	// Node is the node whose agent owns this profile.
	Node string `json:"node,omitempty"`
}

// ProfilePhase is where a container is in the learn-then-enforce lifecycle.
//
// v1alpha1 typed this as a bare string with no enum, which meant the one field
// an operator greps for to answer "is this container protected yet?" accepted
// any value at all. A profile written with a misspelled or renamed phase is
// indistinguishable from one that is genuinely still learning, and the CLI
// prints whatever it finds.
//
// +kubebuilder:validation:Enum=Learning;Enforcing
type ProfilePhase string

const (
	ProfilePhaseLearning  ProfilePhase = "Learning"
	ProfilePhaseEnforcing ProfilePhase = "Enforcing"
)

// ContainerProfileStatus is the learned behavioral baseline reported by the
// node agent. It is what the kernel enforces once the container is enforcing -
// a first-class, inspectable, git-backupable record.
type ContainerProfileStatus struct {
	// Phase is Learning or Enforcing.
	Phase ProfilePhase `json:"phase,omitempty"`

	// LearnedSyscalls is the set of syscall numbers observed during learning.
	LearnedSyscalls []int64 `json:"learnedSyscalls,omitempty"`

	// LearnedFiles is the set of file paths the container opened during learning.
	LearnedFiles []string `json:"learnedFiles,omitempty"`

	// LearnedNetworkDestinations is the set of egress destinations (ip:port).
	LearnedNetworkDestinations []string `json:"learnedNetworkDestinations,omitempty"`

	// LearnedNetworkPeers is the same observed egress as
	// LearnedNetworkDestinations, recorded as what the peer is rather than as
	// where it was: "pod:prod/api:5432", "service:prod/postgres:5432",
	// "node:worker-1:10250", and "external:cloud-metadata:80" for the address
	// ranges worth naming as a class rather than one by one.
	//
	// A pod address is leased, not owned. The CNI hands it back seconds after
	// the pod dies and gives it to whatever is scheduled next, so a baseline
	// of addresses is wrong in both directions: a peer that is rescheduled
	// onto a new address drops out of a baseline that should still hold, and
	// a new workload that inherits the old address walks into one that should
	// have broken. A namespace, a workload and a port survive the first and do
	// not transfer in the second.
	//
	// Genuinely external destinations are not listed here beyond their class.
	// They have no Kubernetes identity to record, pkg/netname names them on
	// the export path, and leaving them out keeps this list bounded: an
	// outbound scan touches thousands of distinct addresses, and a learned set
	// an attacker can grow at will does not belong in a CR.
	LearnedNetworkPeers []string `json:"learnedNetworkPeers,omitempty"`

	// NetworkPeerCount is how many distinct identities the container was
	// observed talking to. Reported next to NetworkCount because the two
	// answer different questions: "forty addresses" and "three workloads" can
	// be the same week of traffic.
	NetworkPeerCount int32 `json:"networkPeerCount,omitempty"`

	// LearnedExecutables is the set of binary paths the container executed.
	LearnedExecutables []string `json:"learnedExecutables,omitempty"`

	// LearnedCapabilities is the set of Linux capabilities the container was
	// observed using, as names without the CAP_ prefix so they match the
	// spelling a pod spec uses in securityContext.capabilities.
	//
	// Reported because it was otherwise the only learned signal invisible from
	// outside the agent, and because it is what lets admission reject a new
	// revision asking for privilege the workload has never needed.
	LearnedCapabilities []string `json:"learnedCapabilities,omitempty"`

	// The declared* lists below mirror the learned* lists above for the entries
	// that are in this container's allow-set because the governing policy's
	// spec.learningConfig.expectedBehavior declared them, not because this
	// container was observed doing them.
	//
	// They are separate fields rather than extra entries in the learned lists
	// because the two are different claims. "The workload opened this path" is
	// an observation; "somebody said it would" is an assertion, and an operator
	// auditing a profile - or an incident responder asking how a path came to
	// be permitted - has to be able to tell which one they are looking at. A
	// declaration folded into learnedFiles would be indistinguishable from
	// evidence, which is the one thing a learned baseline is for.
	//
	// internal/policy.Declaration.ReportInto writes all four, so the entries
	// the agent reports and the entries it seeds into the kernel come from one
	// place and cannot disagree.

	// DeclaredFiles are the paths permitted because the policy declared them
	// rather than because this container was observed opening them. A declared
	// write is suffixed " (write)": declaring a write is a materially larger
	// assertion than declaring a read, and the two must not read alike here.
	DeclaredFiles []string `json:"declaredFiles,omitempty"`

	// DeclaredNetworkDestinations are the ip:port destinations permitted by
	// declaration rather than by observation.
	DeclaredNetworkDestinations []string `json:"declaredNetworkDestinations,omitempty"`

	// DeclaredExecutables are the binary paths permitted by declaration rather
	// than by observation.
	DeclaredExecutables []string `json:"declaredExecutables,omitempty"`

	// DeclaredCapabilities are the capabilities permitted by declaration rather
	// than by observation, spelled without the CAP_ prefix like
	// LearnedCapabilities.
	DeclaredCapabilities []string `json:"declaredCapabilities,omitempty"`

	// Counts for quick inspection / printcolumns.
	SyscallCount int32 `json:"syscallCount,omitempty"`
	FileCount    int32 `json:"fileCount,omitempty"`
	NetworkCount int32 `json:"networkCount,omitempty"`

	// FirstSeen / EnforcingSince timestamps.
	FirstSeen      *metav1.Time `json:"firstSeen,omitempty"`
	EnforcingSince *metav1.Time `json:"enforcingSince,omitempty"`

	// LastUpdated is when the agent last refreshed this profile.
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// EnforcementAttempts is how many times this container has been transitioned
	// to enforcing. More than one means an earlier attempt was rolled back.
	EnforcementAttempts int32 `json:"enforcementAttempts,omitempty"`

	// RollbackCount is how many times self-healing returned this container from
	// enforcing to learning because the learned baseline was breaking it.
	RollbackCount int32 `json:"rollbackCount,omitempty"`

	// LastRollbackTime is when the most recent rollback happened.
	LastRollbackTime *metav1.Time `json:"lastRollbackTime,omitempty"`

	// LastRollbackReason explains the most recent rollback (denial rate or the
	// specific pod distress that was observed).
	LastRollbackReason string `json:"lastRollbackReason,omitempty"`

	// DenialCount is the number of in-kernel denials observed since the current
	// enforce transition. It resets on every transition and on rollback.
	DenialCount int32 `json:"denialCount,omitempty"`

	// Seccomp describes the profile generated from LearnedSyscalls, if the
	// agent was configured to emit one.
	Seccomp *SeccompProfileRef `json:"seccomp,omitempty"`

	// Per-signal breakdown of DenialCount. Split out because "twelve denials"
	// and "twelve denied egress attempts" are very different findings, and the
	// operator aggregates these into the governing policy's status.
	DeniedFiles        int32 `json:"deniedFiles,omitempty"`
	DeniedNetwork      int32 `json:"deniedNetwork,omitempty"`
	DeniedExecs        int32 `json:"deniedExecs,omitempty"`
	DeniedCapabilities int32 `json:"deniedCapabilities,omitempty"`
}

// SeccompProfileRef points at the seccomp profile the agent generated from a
// container's learned syscall set.
//
// The profile is written to a node-local directory. Reporting it here is what
// makes it usable: a pod's seccompProfile cannot be changed after admission and
// the operator deliberately runs without a mutating webhook, so an operator has
// to reference the profile themselves on the next rollout. Without this they
// would have to know the agent's flags and go looking on the node.
type SeccompProfileRef struct {
	// LocalhostProfile is the value to put in the pod's
	// securityContext.seccompProfile.localhostProfile. It is relative to the
	// kubelet's seccomp root, which is what that field expects.
	LocalhostProfile string `json:"localhostProfile,omitempty"`

	// Path is the absolute path on the node, for debugging.
	Path string `json:"path,omitempty"`

	// Node is the node the file lives on. The profile is written by each node's
	// agent, so it exists only where that container ran.
	Node string `json:"node,omitempty"`

	// AllowedSyscalls is how many syscalls the profile permits, including the
	// safety baseline. TotalSyscalls is the size of the architecture's syscall
	// table, so the pair states the privilege reduction without arithmetic.
	AllowedSyscalls int32 `json:"allowedSyscalls,omitempty"`
	TotalSyscalls   int32 `json:"totalSyscalls,omitempty"`

	// SkippedUnknown counts learned syscall numbers with no name in this
	// architecture's table. They cannot appear in a profile, so a non-zero
	// value means the profile is narrower than what was observed.
	SkippedUnknown int32 `json:"skippedUnknown,omitempty"`

	// GeneratedAt is when the profile was last written.
	GeneratedAt *metav1.Time `json:"generatedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=cprof
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Syscalls",type=integer,JSONPath=`.status.syscallCount`
// +kubebuilder:printcolumn:name="Files",type=integer,JSONPath=`.status.fileCount`
// +kubebuilder:printcolumn:name="Rollbacks",type=integer,JSONPath=`.status.rollbackCount`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.node`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ContainerProfile is the learned behavioral baseline for a single container.
type ContainerProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContainerProfileSpec   `json:"spec,omitempty"`
	Status ContainerProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ContainerProfileList contains a list of ContainerProfile.
type ContainerProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContainerProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ContainerProfile{}, &ContainerProfileList{})
}
