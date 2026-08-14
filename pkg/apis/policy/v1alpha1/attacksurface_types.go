package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttackSurfaceSpec identifies the workload an attack-surface report describes.
type AttackSurfaceSpec struct {
	// PolicyRef is the PahlevanPolicy this surface was computed for.
	PolicyRef string `json:"policyRef,omitempty"`

	// Workload identifies the analyzed workload.
	Workload *WorkloadReference `json:"workload,omitempty"`

	// Namespace of the analyzed workload.
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=asurf
// +kubebuilder:printcolumn:name="Risk",type=integer,JSONPath=`.status.riskScore`
// +kubebuilder:printcolumn:name="Analyzed",type=date,JSONPath=`.status.lastAnalysis`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AttackSurface is a computed, inspectable attack-surface report for a workload
// (exposed syscalls/ports, writable files, capabilities, and an overall risk
// score). It reuses the AttackSurfaceStatus schema already tracked on
// PahlevanPolicy, promoted to a first-class resource.
type AttackSurface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AttackSurfaceSpec   `json:"spec,omitempty"`
	Status AttackSurfaceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AttackSurfaceList contains a list of AttackSurface.
type AttackSurfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttackSurface `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AttackSurface{}, &AttackSurfaceList{})
}
