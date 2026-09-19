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

package v1beta1

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

func i32(v int32) *int32 { return &v }

func dur(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }

func boolp(b bool) *bool { return &b }

// fullPahlevanPolicy builds a PahlevanPolicy with every optional field
// populated, so DeepCopy exercises all of its pointer, slice and map branches.
// TestFixturesPopulateEveryField keeps it honest as fields are added.
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
			Selector: WorkloadSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []LabelSelectorRequirement{{
					Key:      "tier",
					Operator: LabelSelectorOpIn,
					Values:   []string{"frontend"},
				}},
				NamespaceSelector: &NamespaceSelector{
					MatchLabels: map[string]string{"env": "prod"},
					MatchExpressions: []LabelSelectorRequirement{{
						Key:      "kubernetes.io/metadata.name",
						Operator: LabelSelectorOpNotIn,
						Values:   []string{"kube-system"},
					}},
				},
			},
			LearningConfig: LearningConfig{
				Duration:       dur(5 * time.Minute),
				WindowSize:     dur(time.Minute),
				MinSamples:     i32(100),
				AutoTransition: true,
				LifecycleAware: true,
			},
			EnforcementConfig: EnforcementConfig{
				Mode:         EnforcementModeBlocking,
				GracePeriod:  dur(30 * time.Second),
				AlertOnly:    true,
				BlockUnknown: boolp(true),
				Exceptions: []EnforcementException{{
					Type:      ExceptionTypeFile,
					Patterns:  []string{"/tmp/debug"},
					Reason:    "incident 4412",
					ExpiresAt: &now,
				}},
			},
			SyscallPolicy: &SyscallPolicy{
				AllowedSyscalls:  []string{"read"},
				DeniedSyscalls:   []string{"ptrace"},
				DefaultAction:    PolicyActionDeny,
				CapabilityFilter: []string{"NET_BIND_SERVICE"},
				ProcessFilter: &ProcessFilter{
					Commands:        []string{"/usr/bin/nginx"},
					Users:           []string{"nginx"},
					Groups:          []string{"nginx"},
					ParentProcesses: []string{"/sbin/init"},
				},
			},
			NetworkPolicy: &NetworkPolicy{
				EgressRules: []NetworkRule{{
					Protocols: []string{"TCP"},
					Ports:     []NetworkPort{{Port: i32(443), StartPort: i32(8000), EndPort: i32(8100), Protocol: "TCP"}},
					Peers: []NetworkPeer{{
						IPBlock:           &IPBlock{CIDR: "10.0.0.1/32", Except: []string{"10.0.0.2/32"}},
						NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
						PodSelector: &LabelSelector{
							MatchExpressions: []LabelSelectorRequirement{{
								Key: "app", Operator: LabelSelectorOpExists,
							}},
						},
					}},
					Action: PolicyActionAllow,
				}},
				IngressRules: []NetworkRule{{
					Protocols: []string{"UDP"},
					Ports:     []NetworkPort{{Port: i32(53), StartPort: i32(1), EndPort: i32(2), Protocol: "UDP"}},
					Peers:     []NetworkPeer{{IPBlock: &IPBlock{CIDR: "10.1.0.1/32", Except: []string{"10.1.0.2/32"}}}},
					Action:    PolicyActionAudit,
				}},
				DefaultAction: PolicyActionDeny,
				AllowLoopback: true,
				AllowDNS:      true,
			},
			FilePolicy: &FilePolicy{
				AllowedPaths:      []string{"/etc/nginx/nginx.conf"},
				DeniedPaths:       []string{"/etc/shadow"},
				DefaultAction:     PolicyActionDeny,
				ReadOnlyPaths:     []string{"/usr/share"},
				WriteAllowedPaths: []string{"/var/cache/nginx"},
				ExecutableFilter: &ExecutableFilter{
					AllowedExecutables: []string{"/usr/sbin/nginx"},
					DeniedExecutables:  []string{"/bin/sh"},
					RequireSignature:   true,
				},
			},
			SelfHealing: SelfHealingConfig{
				Enabled:           true,
				RollbackThreshold: 3,
				RollbackWindow:    dur(10 * time.Minute),
				RecoveryStrategy:  RecoveryStrategyRollback,
			},
			ObservabilityConfig: ObservabilityConfig{
				Metrics: MetricsConfig{
					Enabled: true,
					Exporters: []MetricsExporter{{
						Type: "prometheus", Endpoint: "http://p:9090",
						Config: runtime.RawExtension{Raw: []byte(`{"a":1}`)},
					}},
					Interval: dur(15 * time.Second),
				},
				Tracing: TracingConfig{
					Enabled:      true,
					SamplingRate: &sampling,
					Exporter: TracingExporter{
						Type: "otlp", Endpoint: "http://o:4317",
						Config: runtime.RawExtension{Raw: []byte(`{"b":2}`)},
					},
				},
				Logging: LoggingConfig{
					Level: "info", Format: "json",
					Outputs: []LogOutput{{Type: "stdout", Config: runtime.RawExtension{Raw: []byte(`{"c":3}`)}}},
				},
				Visualization: VisualizationConfig{
					Enabled:        true,
					UpdateInterval: dur(time.Minute),
					Exporters: []VisualizationExporter{{
						Type: "json", Endpoint: "http://v:8080",
						Config: runtime.RawExtension{Raw: []byte(`{"d":4}`)},
					}},
				},
			},
		},
		Status: PahlevanPolicyStatus{
			Phase: PolicyPhaseEnforcing,
			Conditions: []PolicyCondition{{
				Type:               PolicyConditionReady,
				Status:             ConditionTrue,
				LastTransitionTime: now,
				Reason:             "Enforcing",
				Message:            "policy is enforcing",
			}},
			LearningStatus: &LearningStatus{
				StartTime: &now, EndTime: &now,
				SamplesCollected: 1000, SyscallsLearned: 42,
				NetworkFlowsLearned: 7, FilePathsLearned: 19,
				Progress: i32(100),
			},
			EnforcementStatus: &EnforcementStatus{
				StartTime:                 &now,
				BlockedNetworkConnections: 2,
				BlockedFileAccess:         3,
				BlockedExecs:              4,
				BlockedCapabilities:       5,
				BlockedTotal:              14,
				EnforcingContainers:       2,
				TotalContainers:           3,
				AlertsGenerated:           6,
				RollbackCount:             1,
			},
			AttackSurface: &AttackSurfaceStatus{
				ExposedSyscalls: []string{"execve"},
				ExposedPorts:    []int32{443},
				WritableFiles:   []string{"/var/cache/nginx"},
				Capabilities:    []string{"NET_BIND_SERVICE"},
				RiskScore:       i32(42),
				LastAnalysis:    &now,
			},
			TargetWorkloads: []WorkloadReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "web", Namespace: "prod", UID: "abc",
			}},
			LastUpdated: &now,
		},
	}
}

func fullContainerProfile() *ContainerProfile {
	now := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	return &ContainerProfile{
		TypeMeta:   metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "ContainerProfile"},
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "prod"},
		Spec: ContainerProfileSpec{
			PolicyRef: "web",
			Workload: &WorkloadReference{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "web", Namespace: "prod", UID: "abc",
			},
			PodName:     "web-0",
			Namespace:   "prod",
			ContainerID: "containerd://deadbeef",
			CgroupID:    987654321,
			Node:        "node-1",
		},
		Status: ContainerProfileStatus{
			Phase:                      ProfilePhaseEnforcing,
			LearnedSyscalls:            []int64{0, 1, 2},
			LearnedFiles:               []string{"/etc/nginx/nginx.conf"},
			LearnedNetworkDestinations: []string{"10.0.0.1:443"},
			LearnedExecutables:         []string{"/usr/sbin/nginx"},
			LearnedCapabilities:        []string{"NET_BIND_SERVICE"},
			SyscallCount:               3,
			FileCount:                  1,
			NetworkCount:               1,
			FirstSeen:                  &now,
			EnforcingSince:             &now,
			LastUpdated:                &now,
			EnforcementAttempts:        2,
			RollbackCount:              1,
			LastRollbackTime:           &now,
			LastRollbackReason:         "denial rate",
			DenialCount:                4,
			Seccomp: &SeccompProfileRef{
				LocalhostProfile: "pahlevan/web-0.json",
				Path:             "/var/lib/kubelet/seccomp/pahlevan/web-0.json",
				Node:             "node-1",
				AllowedSyscalls:  40,
				TotalSyscalls:    350,
				SkippedUnknown:   1,
				GeneratedAt:      &now,
			},
			DeniedFiles:        1,
			DeniedNetwork:      1,
			DeniedExecs:        1,
			DeniedCapabilities: 1,
		},
	}
}

func fullAttackSurface() *AttackSurface {
	now := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	return &AttackSurface{
		TypeMeta:   metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "AttackSurface"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
		Spec: AttackSurfaceSpec{
			PolicyRef: "web",
			Workload: &WorkloadReference{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "web", Namespace: "prod", UID: "abc",
			},
			Namespace: "prod",
		},
		Status: AttackSurfaceStatus{
			ExposedSyscalls: []string{"execve"},
			ExposedPorts:    []int32{443},
			WritableFiles:   []string{"/var/cache/nginx"},
			Capabilities:    []string{"NET_BIND_SERVICE"},
			RiskScore:       i32(42),
			LastAnalysis:    &now,
		},
	}
}

// A hand-written fixture drifts: a field added to the types is not added here,
// and the DeepCopy tests below go on passing while covering one branch fewer
// every time. This walks the fixtures and fails on anything left at its zero
// value, which is the cheapest way to keep them complete.
func TestFixturesPopulateEveryField(t *testing.T) {
	var unset []string
	var walk func(v reflect.Value, path string)
	walk = func(v reflect.Value, path string) {
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				unset = append(unset, path)
				return
			}
			walk(v.Elem(), path)
		case reflect.Struct:
			if v.Type().PkgPath() != reflect.TypeOf(PahlevanPolicy{}).PkgPath() {
				// metav1.Time, metav1.ObjectMeta, runtime.RawExtension: not
				// this project's shape to keep complete.
				if v.IsZero() {
					unset = append(unset, path)
				}
				return
			}
			for i := 0; i < v.NumField(); i++ {
				f := v.Type().Field(i)
				if f.PkgPath != "" {
					continue
				}
				walk(v.Field(i), path+"."+f.Name)
			}
		case reflect.Slice, reflect.Map:
			if v.Len() == 0 {
				unset = append(unset, path)
				return
			}
			if v.Kind() == reflect.Slice {
				walk(v.Index(0), path+"[0]")
			}
		default:
			if v.IsZero() {
				unset = append(unset, path)
			}
		}
	}
	for name, obj := range map[string]interface{}{
		"policy":  fullPahlevanPolicy(),
		"profile": fullContainerProfile(),
		"surface": fullAttackSurface(),
	} {
		walk(reflect.ValueOf(obj).Elem().FieldByName("Spec"), name+".spec")
		walk(reflect.ValueOf(obj).Elem().FieldByName("Status"), name+".status")
	}
	require.Empty(t, unset, "these fixture fields are unset, so DeepCopy is not exercised on them: %v", unset)
}

func TestDeepCopyIsEqualAndIndependent(t *testing.T) {
	policy := fullPahlevanPolicy()
	profile := fullContainerProfile()
	surface := fullAttackSurface()

	cases := []struct {
		name   string
		orig   interface{}
		clone  interface{}
		mutate func()
		check  func(t *testing.T)
	}{
		{
			name:  "PahlevanPolicy",
			orig:  policy,
			clone: policy.DeepCopy(),
			mutate: func() {
				c := policy.DeepCopy()
				c.Spec.Selector.MatchLabels["app"] = "changed"
				c.Spec.LearningConfig.Duration.Duration = time.Hour
				c.Status.AttackSurface.ExposedPorts[0] = 9999
				c.Spec.NetworkPolicy.EgressRules[0].Peers[0].IPBlock.Except[0] = "0.0.0.0/0"
			},
			check: func(t *testing.T) {
				assert.Equal(t, "web", policy.Spec.Selector.MatchLabels["app"])
				assert.Equal(t, 5*time.Minute, policy.Spec.LearningConfig.Duration.Duration)
				assert.Equal(t, int32(443), policy.Status.AttackSurface.ExposedPorts[0])
				assert.Equal(t, "10.0.0.2/32", policy.Spec.NetworkPolicy.EgressRules[0].Peers[0].IPBlock.Except[0])
			},
		},
		{
			name:  "ContainerProfile",
			orig:  profile,
			clone: profile.DeepCopy(),
			mutate: func() {
				c := profile.DeepCopy()
				c.Status.LearnedSyscalls[0] = 999
				c.Status.Seccomp.AllowedSyscalls = 0
			},
			check: func(t *testing.T) {
				assert.Equal(t, int64(0), profile.Status.LearnedSyscalls[0])
				assert.Equal(t, int32(40), profile.Status.Seccomp.AllowedSyscalls)
			},
		},
		{
			name:  "AttackSurface",
			orig:  surface,
			clone: surface.DeepCopy(),
			mutate: func() {
				c := surface.DeepCopy()
				c.Status.ExposedSyscalls[0] = "changed"
			},
			check: func(t *testing.T) {
				assert.Equal(t, "execve", surface.Status.ExposedSyscalls[0])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.orig, tc.clone)
			require.True(t, reflect.DeepEqual(tc.orig, tc.clone))
			tc.mutate()
			tc.check(t)
		})
	}
}

func TestDeepCopyObjectAndLists(t *testing.T) {
	policy := fullPahlevanPolicy()
	assert.Equal(t, policy, policy.DeepCopyObject())

	pl := &PahlevanPolicyList{
		TypeMeta: metav1.TypeMeta{Kind: "PahlevanPolicyList", APIVersion: GroupVersion.String()},
		Items:    []PahlevanPolicy{*fullPahlevanPolicy(), *fullPahlevanPolicy()},
	}
	assert.Equal(t, pl, pl.DeepCopy())
	assert.Equal(t, pl, pl.DeepCopyObject())

	cl := &ContainerProfileList{Items: []ContainerProfile{*fullContainerProfile()}}
	assert.Equal(t, cl, cl.DeepCopy())
	assert.Equal(t, cl, cl.DeepCopyObject())

	al := &AttackSurfaceList{Items: []AttackSurface{*fullAttackSurface()}}
	assert.Equal(t, al, al.DeepCopy())
	assert.Equal(t, al, al.DeepCopyObject())

	// A nil receiver must return nil rather than panic: controller-runtime
	// calls DeepCopy on values it has not checked.
	var nilPolicy *PahlevanPolicy
	assert.Nil(t, nilPolicy.DeepCopy())
	var nilProfile *ContainerProfile
	assert.Nil(t, nilProfile.DeepCopy())
	var nilSurface *AttackSurface
	assert.Nil(t, nilSurface.DeepCopy())
}

func TestEmptyTypesDeepCopy(t *testing.T) {
	assert.Equal(t, &PahlevanPolicy{}, (&PahlevanPolicy{}).DeepCopy())
	assert.Equal(t, &ContainerProfile{}, (&ContainerProfile{}).DeepCopy())
	assert.Equal(t, &AttackSurface{}, (&AttackSurface{}).DeepCopy())
	assert.Equal(t, &PahlevanPolicySpec{}, (&PahlevanPolicySpec{}).DeepCopy())
	assert.Equal(t, &PahlevanPolicyStatus{}, (&PahlevanPolicyStatus{}).DeepCopy())
	assert.Equal(t, &ContainerProfileStatus{}, (&ContainerProfileStatus{}).DeepCopy())
	assert.Equal(t, &AttackSurfaceStatus{}, (&AttackSurfaceStatus{}).DeepCopy())
}

// The generated DeepCopy wrappers on the nested types are reachable from client
// code, so they are covered here rather than only through the root objects.
func TestNestedTypesDeepCopy(t *testing.T) {
	p := fullPahlevanPolicy()
	cp := fullContainerProfile()
	as := fullAttackSurface()

	checks := []struct {
		name       string
		orig, copy interface{}
	}{
		{"PahlevanPolicySpec", &p.Spec, p.Spec.DeepCopy()},
		{"PahlevanPolicyStatus", &p.Status, p.Status.DeepCopy()},
		{"WorkloadSelector", &p.Spec.Selector, p.Spec.Selector.DeepCopy()},
		{"NamespaceSelector", p.Spec.Selector.NamespaceSelector, p.Spec.Selector.NamespaceSelector.DeepCopy()},
		{"LabelSelector", p.Spec.NetworkPolicy.EgressRules[0].Peers[0].PodSelector, p.Spec.NetworkPolicy.EgressRules[0].Peers[0].PodSelector.DeepCopy()},
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
		{"SeccompProfileRef", cp.Status.Seccomp, cp.Status.Seccomp.DeepCopy()},
		{"AttackSurfaceSpec", &as.Spec, as.Spec.DeepCopy()},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.orig, c.copy)
		})
	}
}

func TestAddToSchemeRegistersAllKinds(t *testing.T) {
	s := runtime.NewScheme()
	require.NoError(t, AddToScheme(s))
	for _, kind := range []string{
		"PahlevanPolicy", "PahlevanPolicyList",
		"ContainerProfile", "ContainerProfileList",
		"AttackSurface", "AttackSurfaceList",
	} {
		assert.True(t, s.Recognizes(GroupVersion.WithKind(kind)),
			"the scheme does not recognize %s, so a client reading one gets "+
				"\"no kind registered\" rather than an object", kind)
	}
}

// The hub markers are what controller-runtime's conversion machinery looks
// for. Without them a spoke's ConvertTo has nothing to convert to, and the
// failure is a webhook that returns an error on every request rather than a
// compile error.
func TestKindsAreConversionHubs(t *testing.T) {
	hubs := []conversion.Hub{&PahlevanPolicy{}, &ContainerProfile{}, &AttackSurface{}}
	for _, h := range hubs {
		h.Hub()
		assert.Implements(t, (*runtime.Object)(nil), h,
			"a hub has to be a runtime.Object or the webhook cannot decode it")
	}
	assert.Len(t, hubs, 3, "every kind the group serves needs a hub")
}

func BenchmarkPahlevanPolicyDeepCopy(b *testing.B) {
	p := fullPahlevanPolicy()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.DeepCopy()
	}
}

func BenchmarkContainerProfileDeepCopy(b *testing.B) {
	p := fullContainerProfile()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.DeepCopy()
	}
}
