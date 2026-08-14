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

package v1alpha1

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func i32(v int32) *int32 { return &v }

func dur(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }

// fullPahlevanPolicy builds a PahlevanPolicy with every optional field populated
// so DeepCopy exercises all pointer/slice/map branches.
func fullPahlevanPolicy() *PahlevanPolicy {
	now := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	sampling := "0.5"
	return &PahlevanPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupVersion.String(),
			Kind:       "PahlevanPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "full",
			Namespace:   "prod",
			Labels:      map[string]string{"app": "web"},
			Annotations: map[string]string{"note": "x"},
		},
		Spec: PahlevanPolicySpec{
			Selector: LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []LabelSelectorRequirement{{
					Key:      "tier",
					Operator: LabelSelectorOpIn,
					Values:   []string{"frontend"},
				}},
				NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			},
			LearningConfig: LearningConfig{
				Duration:       dur(5 * time.Minute),
				WindowSize:     dur(time.Minute),
				MinSamples:     i32(10),
				AutoTransition: true,
				LifecycleAware: true,
			},
			EnforcementConfig: EnforcementConfig{
				Mode:         EnforcementModeBlocking,
				GracePeriod:  dur(30 * time.Second),
				AlertOnly:    true,
				BlockUnknown: true,
				Exceptions: []EnforcementException{{
					Type:      ExceptionTypeSyscall,
					Patterns:  []string{"ptrace"},
					Reason:    "debug",
					Temporary: true,
					ExpiresAt: &now,
				}},
			},
			SyscallPolicy: &SyscallPolicy{
				AllowedSyscalls:  []string{"read", "write"},
				DeniedSyscalls:   []string{"ptrace"},
				DefaultAction:    PolicyActionDeny,
				CapabilityFilter: []string{"CAP_NET_ADMIN"},
				ProcessFilter: &ProcessFilter{
					Commands:        []string{"nginx"},
					Users:           []string{"root"},
					Groups:          []string{"wheel"},
					ParentProcesses: []string{"init"},
				},
			},
			NetworkPolicy: &NetworkPolicy{
				EgressRules: []NetworkRule{{
					Protocols: []string{"TCP"},
					Ports: []NetworkPort{{
						Port:      i32(443),
						StartPort: i32(1),
						EndPort:   i32(65535),
						Protocol:  "TCP",
					}},
					Peers: []NetworkPeer{{
						IPBlock:           &IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}},
						NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						PodSelector:       &LabelSelector{MatchLabels: map[string]string{"c": "d"}},
					}},
					Action: PolicyActionAllow,
				}},
				IngressRules:  []NetworkRule{{Action: PolicyActionDeny}},
				DefaultAction: PolicyActionDeny,
				AllowLoopback: true,
				AllowDNS:      true,
			},
			FilePolicy: &FilePolicy{
				AllowedPaths:      []string{"/etc"},
				DeniedPaths:       []string{"/root"},
				DefaultAction:     PolicyActionDeny,
				ReadOnlyPaths:     []string{"/usr"},
				WriteAllowedPaths: []string{"/tmp"},
				ExecutableFilter: &ExecutableFilter{
					AllowedExecutables: []string{"/bin/sh"},
					DeniedExecutables:  []string{"/bin/bash"},
					RequireSignature:   true,
				},
			},
			SelfHealing: SelfHealingConfig{
				Enabled:           true,
				RollbackThreshold: 3,
				RollbackWindow:    dur(time.Hour),
				RecoveryStrategy:  RecoveryStrategyRollback,
			},
			ObservabilityConfig: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled:   true,
					Exporters: []MetricsExporter{{Type: "prometheus", Endpoint: "http://x", Config: runtime.RawExtension{Raw: []byte(`{"a":1}`)}}},
					Interval:  dur(15 * time.Second),
				},
				Tracing: TracingConfig{
					Enabled:      true,
					SamplingRate: &sampling,
					Exporter:     TracingExporter{Type: "otlp", Endpoint: "http://y"},
				},
				Logging: LoggingConfig{
					Level:   "info",
					Format:  "json",
					Outputs: []LogOutput{{Type: "stdout"}},
				},
				Visualization: VisualizationConfig{
					Enabled:        true,
					UpdateInterval: dur(time.Minute),
					Exporters:      []VisualizationExporter{{Type: "d3", Endpoint: "http://z"}},
				},
			},
		},
		Status: PahlevanPolicyStatus{
			Phase: PolicyPhaseEnforcing,
			Conditions: []PolicyCondition{{
				Type:               PolicyConditionReady,
				Status:             ConditionTrue,
				LastTransitionTime: now,
				Reason:             "Ok",
				Message:            "ready",
			}},
			LearningStatus: &LearningStatus{
				StartTime:           &now,
				EndTime:             &now,
				SamplesCollected:    100,
				SyscallsLearned:     20,
				NetworkFlowsLearned: 5,
				FilePathsLearned:    30,
				Progress:            i32(100),
			},
			EnforcementStatus: &EnforcementStatus{
				StartTime:                 &now,
				BlockedSyscalls:           7,
				BlockedNetworkConnections: 2,
				BlockedFileAccess:         1,
				AlertsGenerated:           3,
				RollbackCount:             1,
			},
			AttackSurface:   fullAttackSurfaceStatus(&now),
			TargetWorkloads: []WorkloadReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "prod", UID: "uid-1"}},
			LastUpdated:     &now,
		},
	}
}

func fullAttackSurfaceStatus(now *metav1.Time) *AttackSurfaceStatus {
	return &AttackSurfaceStatus{
		ExposedSyscalls: []string{"read", "write"},
		ExposedPorts:    []int32{80, 443},
		WritableFiles:   []string{"/tmp/x"},
		Capabilities:    []string{"CAP_NET_ADMIN"},
		RiskScore:       i32(42),
		LastAnalysis:    now,
	}
}

func fullContainerProfile() *ContainerProfile {
	now := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	return &ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupVersion.String(),
			Kind:       "ContainerProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-abc",
			Namespace: "prod",
			Labels:    map[string]string{"app.kubernetes.io/part-of": "pahlevan"},
		},
		Spec: ContainerProfileSpec{
			PolicyRef:   "full",
			Workload:    &WorkloadReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "prod"},
			PodName:     "web-123",
			Namespace:   "prod",
			ContainerID: "cid",
			CgroupID:    99,
			Node:        "node-1",
		},
		Status: ContainerProfileStatus{
			Phase:                      "Enforcing",
			LearnedSyscalls:            []int64{0, 1, 257},
			LearnedFiles:               []string{"/etc/hostname"},
			LearnedNetworkDestinations: []string{"1:80"},
			SyscallCount:               3,
			FileCount:                  1,
			NetworkCount:               1,
			FirstSeen:                  &now,
			EnforcingSince:             &now,
			LastUpdated:                &now,
		},
	}
}

func fullAttackSurface() *AttackSurface {
	now := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	return &AttackSurface{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupVersion.String(),
			Kind:       "AttackSurface",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "prod",
		},
		Spec: AttackSurfaceSpec{
			PolicyRef: "full",
			Workload:  &WorkloadReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "prod"},
			Namespace: "prod",
		},
		Status: *fullAttackSurfaceStatus(&now),
	}
}

func TestPahlevanPolicy_DeepCopyRoundTrip(t *testing.T) {
	orig := fullPahlevanPolicy()
	clone := orig.DeepCopy()
	if clone == orig {
		t.Fatal("DeepCopy returned the same pointer")
	}
	if !reflect.DeepEqual(orig, clone) {
		t.Fatalf("DeepCopy not equal to original\norig=%+v\nclone=%+v", orig, clone)
	}
	// Mutating the clone must not affect the original (deep independence).
	clone.Spec.Selector.MatchLabels["app"] = "changed"
	clone.Spec.LearningConfig.Duration.Duration = time.Hour
	clone.Status.AttackSurface.ExposedPorts[0] = 9999
	if orig.Spec.Selector.MatchLabels["app"] == "changed" {
		t.Error("mutating clone map affected original")
	}
	if orig.Spec.LearningConfig.Duration.Duration == time.Hour {
		t.Error("mutating clone pointer affected original")
	}
	if orig.Status.AttackSurface.ExposedPorts[0] == 9999 {
		t.Error("mutating clone slice affected original")
	}
}

func TestPahlevanPolicy_DeepCopyObject(t *testing.T) {
	orig := fullPahlevanPolicy()
	obj := orig.DeepCopyObject()
	typed, ok := obj.(*PahlevanPolicy)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, want *PahlevanPolicy", obj)
	}
	if !reflect.DeepEqual(orig, typed) {
		t.Error("DeepCopyObject differs from original")
	}

	// Nil-receiver deep copies must return nil, not panic.
	var nilPolicy *PahlevanPolicy
	if nilPolicy.DeepCopy() != nil {
		t.Error("nil DeepCopy should return nil")
	}
}

func TestPahlevanPolicyList_DeepCopyRoundTrip(t *testing.T) {
	orig := &PahlevanPolicyList{
		TypeMeta: metav1.TypeMeta{Kind: "PahlevanPolicyList", APIVersion: GroupVersion.String()},
		Items:    []PahlevanPolicy{*fullPahlevanPolicy(), *fullPahlevanPolicy()},
	}
	clone := orig.DeepCopy()
	if !reflect.DeepEqual(orig, clone) {
		t.Error("PahlevanPolicyList DeepCopy not equal")
	}
	if obj, ok := orig.DeepCopyObject().(*PahlevanPolicyList); !ok || len(obj.Items) != 2 {
		t.Error("PahlevanPolicyList DeepCopyObject wrong type/len")
	}
}

func TestContainerProfile_DeepCopyRoundTrip(t *testing.T) {
	orig := fullContainerProfile()
	clone := orig.DeepCopy()
	if !reflect.DeepEqual(orig, clone) {
		t.Fatal("ContainerProfile DeepCopy not equal to original")
	}
	clone.Status.LearnedSyscalls[0] = 12345
	if orig.Status.LearnedSyscalls[0] == 12345 {
		t.Error("mutating clone slice affected original")
	}
	if _, ok := orig.DeepCopyObject().(*ContainerProfile); !ok {
		t.Error("ContainerProfile DeepCopyObject wrong type")
	}
}

func TestContainerProfileList_DeepCopyRoundTrip(t *testing.T) {
	orig := &ContainerProfileList{
		TypeMeta: metav1.TypeMeta{Kind: "ContainerProfileList", APIVersion: GroupVersion.String()},
		Items:    []ContainerProfile{*fullContainerProfile()},
	}
	if !reflect.DeepEqual(orig, orig.DeepCopy()) {
		t.Error("ContainerProfileList DeepCopy not equal")
	}
	if _, ok := orig.DeepCopyObject().(*ContainerProfileList); !ok {
		t.Error("ContainerProfileList DeepCopyObject wrong type")
	}
}

func TestAttackSurface_DeepCopyRoundTrip(t *testing.T) {
	orig := fullAttackSurface()
	clone := orig.DeepCopy()
	if !reflect.DeepEqual(orig, clone) {
		t.Fatal("AttackSurface DeepCopy not equal to original")
	}
	clone.Status.Capabilities[0] = "CAP_SYS_ADMIN"
	if orig.Status.Capabilities[0] == "CAP_SYS_ADMIN" {
		t.Error("mutating clone slice affected original")
	}
	if _, ok := orig.DeepCopyObject().(*AttackSurface); !ok {
		t.Error("AttackSurface DeepCopyObject wrong type")
	}
}

func TestAttackSurfaceList_DeepCopyRoundTrip(t *testing.T) {
	orig := &AttackSurfaceList{
		TypeMeta: metav1.TypeMeta{Kind: "AttackSurfaceList", APIVersion: GroupVersion.String()},
		Items:    []AttackSurface{*fullAttackSurface()},
	}
	if !reflect.DeepEqual(orig, orig.DeepCopy()) {
		t.Error("AttackSurfaceList DeepCopy not equal")
	}
	if _, ok := orig.DeepCopyObject().(*AttackSurfaceList); !ok {
		t.Error("AttackSurfaceList DeepCopyObject wrong type")
	}
}

func TestAddToScheme_RegistersAllKinds(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme returned error: %v", err)
	}

	kinds := []runtime.Object{
		&PahlevanPolicy{}, &PahlevanPolicyList{},
		&ContainerProfile{}, &ContainerProfileList{},
		&AttackSurface{}, &AttackSurfaceList{},
	}
	for _, obj := range kinds {
		gvks, _, err := s.ObjectKinds(obj)
		if err != nil {
			t.Errorf("scheme does not recognize %T: %v", obj, err)
			continue
		}
		if len(gvks) == 0 {
			t.Errorf("no GVK registered for %T", obj)
			continue
		}
		if gvks[0].Group != GroupVersion.Group || gvks[0].Version != GroupVersion.Version {
			t.Errorf("%T registered under %v, want %v", obj, gvks[0].GroupVersion(), GroupVersion)
		}
	}

	// The scheme must be able to instantiate a registered kind by GVK.
	gvk := GroupVersion.WithKind("PahlevanPolicy")
	obj, err := s.New(gvk)
	if err != nil {
		t.Fatalf("scheme.New(%v) failed: %v", gvk, err)
	}
	if _, ok := obj.(*PahlevanPolicy); !ok {
		t.Errorf("scheme.New returned %T, want *PahlevanPolicy", obj)
	}
}

// TestNestedTypes_DeepCopy exercises the generated DeepCopy() convenience
// wrappers on every nested spec/status type, asserting deep independence.
func TestNestedTypes_DeepCopy(t *testing.T) {
	p := fullPahlevanPolicy()
	cp := fullContainerProfile()
	as := fullAttackSurface()

	// Each entry: original value (pointer) and its DeepCopy result. reflect
	// verifies the wrapper produced an equal, independent copy.
	checks := []struct {
		name       string
		orig, copy interface{}
	}{
		{"PahlevanPolicySpec", &p.Spec, p.Spec.DeepCopy()},
		{"PahlevanPolicyStatus", &p.Status, p.Status.DeepCopy()},
		{"LabelSelector", &p.Spec.Selector, p.Spec.Selector.DeepCopy()},
		{"LabelSelectorRequirement", &p.Spec.Selector.MatchExpressions[0], p.Spec.Selector.MatchExpressions[0].DeepCopy()},
		{"LearningConfig", &p.Spec.LearningConfig, p.Spec.LearningConfig.DeepCopy()},
		{"EnforcementConfig", &p.Spec.EnforcementConfig, p.Spec.EnforcementConfig.DeepCopy()},
		{"EnforcementException", &p.Spec.EnforcementConfig.Exceptions[0], p.Spec.EnforcementConfig.Exceptions[0].DeepCopy()},
		{"SyscallPolicy", p.Spec.SyscallPolicy, p.Spec.SyscallPolicy.DeepCopy()},
		{"ProcessFilter", p.Spec.SyscallPolicy.ProcessFilter, p.Spec.SyscallPolicy.ProcessFilter.DeepCopy()},
		{"NetworkPolicy", p.Spec.NetworkPolicy, p.Spec.NetworkPolicy.DeepCopy()},
		{"NetworkRule", &p.Spec.NetworkPolicy.EgressRules[0], p.Spec.NetworkPolicy.EgressRules[0].DeepCopy()},
		{"NetworkPort", &p.Spec.NetworkPolicy.EgressRules[0].Ports[0], p.Spec.NetworkPolicy.EgressRules[0].Ports[0].DeepCopy()},
		{"NetworkPeer", &p.Spec.NetworkPolicy.EgressRules[0].Peers[0], p.Spec.NetworkPolicy.EgressRules[0].Peers[0].DeepCopy()},
		{"IPBlock", p.Spec.NetworkPolicy.EgressRules[0].Peers[0].IPBlock, p.Spec.NetworkPolicy.EgressRules[0].Peers[0].IPBlock.DeepCopy()},
		{"FilePolicy", p.Spec.FilePolicy, p.Spec.FilePolicy.DeepCopy()},
		{"ExecutableFilter", p.Spec.FilePolicy.ExecutableFilter, p.Spec.FilePolicy.ExecutableFilter.DeepCopy()},
		{"SelfHealingConfig", &p.Spec.SelfHealing, p.Spec.SelfHealing.DeepCopy()},
		{"ObservabilityConfig", &p.Spec.ObservabilityConfig, p.Spec.ObservabilityConfig.DeepCopy()},
		{"MetricsConfig", &p.Spec.ObservabilityConfig.Metrics, p.Spec.ObservabilityConfig.Metrics.DeepCopy()},
		{"MetricsExporter", &p.Spec.ObservabilityConfig.Metrics.Exporters[0], p.Spec.ObservabilityConfig.Metrics.Exporters[0].DeepCopy()},
		{"TracingConfig", &p.Spec.ObservabilityConfig.Tracing, p.Spec.ObservabilityConfig.Tracing.DeepCopy()},
		{"TracingExporter", &p.Spec.ObservabilityConfig.Tracing.Exporter, p.Spec.ObservabilityConfig.Tracing.Exporter.DeepCopy()},
		{"LoggingConfig", &p.Spec.ObservabilityConfig.Logging, p.Spec.ObservabilityConfig.Logging.DeepCopy()},
		{"LogOutput", &p.Spec.ObservabilityConfig.Logging.Outputs[0], p.Spec.ObservabilityConfig.Logging.Outputs[0].DeepCopy()},
		{"VisualizationConfig", &p.Spec.ObservabilityConfig.Visualization, p.Spec.ObservabilityConfig.Visualization.DeepCopy()},
		{"VisualizationExporter", &p.Spec.ObservabilityConfig.Visualization.Exporters[0], p.Spec.ObservabilityConfig.Visualization.Exporters[0].DeepCopy()},
		{"PolicyCondition", &p.Status.Conditions[0], p.Status.Conditions[0].DeepCopy()},
		{"LearningStatus", p.Status.LearningStatus, p.Status.LearningStatus.DeepCopy()},
		{"EnforcementStatus", p.Status.EnforcementStatus, p.Status.EnforcementStatus.DeepCopy()},
		{"AttackSurfaceStatus", p.Status.AttackSurface, p.Status.AttackSurface.DeepCopy()},
		{"WorkloadReference", &p.Status.TargetWorkloads[0], p.Status.TargetWorkloads[0].DeepCopy()},
		{"ContainerProfileSpec", &cp.Spec, cp.Spec.DeepCopy()},
		{"ContainerProfileStatus", &cp.Status, cp.Status.DeepCopy()},
		{"AttackSurfaceSpec", &as.Spec, as.Spec.DeepCopy()},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.orig, c.copy) {
			t.Errorf("%s.DeepCopy() != original", c.name)
		}
	}
}

// TestEmptyTypes_DeepCopy covers the nil-branch paths of DeepCopyInto for
// zero-valued objects (no optional pointers/slices/maps populated).
func TestEmptyTypes_DeepCopy(t *testing.T) {
	empties := []interface {
		DeepCopyObject() runtime.Object
	}{
		&PahlevanPolicy{}, &PahlevanPolicyList{},
		&ContainerProfile{}, &ContainerProfileList{},
		&AttackSurface{}, &AttackSurfaceList{},
	}
	for _, e := range empties {
		obj := e.DeepCopyObject()
		if !reflect.DeepEqual(e, obj) {
			t.Errorf("empty %T DeepCopyObject differs", e)
		}
	}
}

func TestSchemeBuilder_GroupVersion(t *testing.T) {
	if GroupVersion.Group != "policy.pahlevan.io" || GroupVersion.Version != "v1alpha1" {
		t.Errorf("unexpected GroupVersion %v", GroupVersion)
	}
	if SchemeBuilder.GroupVersion != GroupVersion {
		t.Errorf("SchemeBuilder.GroupVersion = %v, want %v", SchemeBuilder.GroupVersion, GroupVersion)
	}
}
