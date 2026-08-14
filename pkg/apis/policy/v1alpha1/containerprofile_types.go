package v1alpha1

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
	CgroupID uint64 `json:"cgroupID,omitempty"`

	// Node is the node whose agent owns this profile.
	Node string `json:"node,omitempty"`
}

// ContainerProfileStatus is the learned behavioural baseline reported by the
// node agent. It is what the kernel enforces once the container is enforcing -
// a first-class, inspectable, git-backupable record (no equivalent in Falco or
// Tetragon).
type ContainerProfileStatus struct {
	// Phase is Learning or Enforcing.
	Phase string `json:"phase,omitempty"`

	// LearnedSyscalls is the set of syscall numbers observed during learning.
	LearnedSyscalls []int64 `json:"learnedSyscalls,omitempty"`

	// LearnedFiles is the set of file paths the container opened during learning.
	LearnedFiles []string `json:"learnedFiles,omitempty"`

	// LearnedNetworkDestinations is the set of egress destinations (ip:port).
	LearnedNetworkDestinations []string `json:"learnedNetworkDestinations,omitempty"`

	// LearnedExecutables is the set of binary paths the container executed.
	LearnedExecutables []string `json:"learnedExecutables,omitempty"`

	// Counts for quick inspection / printcolumns.
	SyscallCount int32 `json:"syscallCount,omitempty"`
	FileCount    int32 `json:"fileCount,omitempty"`
	NetworkCount int32 `json:"networkCount,omitempty"`

	// FirstSeen / EnforcingSince timestamps.
	FirstSeen      *metav1.Time `json:"firstSeen,omitempty"`
	EnforcingSince *metav1.Time `json:"enforcingSince,omitempty"`

	// LastUpdated is when the agent last refreshed this profile.
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=cprof
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Syscalls",type=integer,JSONPath=`.status.syscallCount`
// +kubebuilder:printcolumn:name="Files",type=integer,JSONPath=`.status.fileCount`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.node`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ContainerProfile is the learned behavioural baseline for a single container.
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
