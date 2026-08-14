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

package visualization

import (
	"testing"

	"github.com/obsernetics/pahlevan/internal/learner"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }

func resourceMustParse(t *testing.T, s string) resource.Quantity {
	t.Helper()
	return resource.MustParse(s)
}

func newTestAnalyzer(t *testing.T, objs ...client.Object) *AttackSurfaceAnalyzer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to build scheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return NewAttackSurfaceAnalyzer(c, nil, nil)
}

// --- calculateNodeRisk ------------------------------------------------------

func TestCalculateNodeRisk_CleanVsDangerous(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	clean := &AttackSurfaceNode{
		Type:         NodeTypePod,
		ExposedPorts: []*ExposedPort{{Port: 9000, Public: false}},
		Privileges: &PrivilegeProfile{
			RunAsUser: int64Ptr(1000),
		},
		SyscallProfile:    &SyscallProfile{AllowedSyscalls: []uint64{0, 1, 2}},
		FileSystemProfile: &FileSystemProfile{},
	}
	cleanScore := asa.calculateNodeRisk(clean)

	dangerous := &AttackSurfaceNode{
		Type:         NodeTypePod,
		ExposedPorts: []*ExposedPort{{Port: 22, Public: true}}, // public + high-risk (SSH)
		Capabilities: []string{"SYS_ADMIN", "SYS_PTRACE"},
		Privileges: &PrivilegeProfile{
			RunAsUser:                int64Ptr(0), // root
			Privileged:               true,
			AllowPrivilegeEscalation: true,
		},
		SyscallProfile: &SyscallProfile{
			AllowedSyscalls: []uint64{0, 1, 2, 101, 165},
			RiskySyscalls:   []uint64{101, 165}, // ptrace, mount
		},
		FileSystemProfile: &FileSystemProfile{
			WritablePaths:  []string{"/"},
			SensitiveFiles: []*SensitiveFile{{Path: "/secrets"}},
		},
		VulnerabilityCount: 2,
	}
	dangerousScore := asa.calculateNodeRisk(dangerous)

	if cleanScore >= dangerousScore {
		t.Fatalf("expected clean score (%.2f) < dangerous score (%.2f)", cleanScore, dangerousScore)
	}
	if cleanScore < 0 || cleanScore > 10 || dangerousScore < 0 || dangerousScore > 10 {
		t.Fatalf("scores must be within [0,10]: clean=%.2f dangerous=%.2f", cleanScore, dangerousScore)
	}
	// The dangerous node combines privileged+root+escalation (6.0) alone, so it
	// must clamp to the maximum.
	if dangerousScore != 10.0 {
		t.Fatalf("expected dangerous node to clamp to 10.0, got %.2f", dangerousScore)
	}
	if dangerous.CriticalityLevel != CriticalityCritical {
		t.Fatalf("expected dangerous node criticality Critical, got %s", dangerous.CriticalityLevel)
	}
	if clean.CriticalityLevel != CriticalityInfo {
		t.Fatalf("expected clean node criticality Info, got %s (score %.2f)", clean.CriticalityLevel, cleanScore)
	}
}

func TestCalculateNodeRisk_WritableRootMattersMoreThanSubpath(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	base := func(paths []string) *AttackSurfaceNode {
		return &AttackSurfaceNode{
			Type:              NodeTypePod,
			Privileges:        &PrivilegeProfile{RunAsUser: int64Ptr(1000)},
			SyscallProfile:    &SyscallProfile{},
			FileSystemProfile: &FileSystemProfile{WritablePaths: paths},
		}
	}
	rootWritable := asa.calculateNodeRisk(base([]string{"/"}))
	subpathWritable := asa.calculateNodeRisk(base([]string{"/tmp"}))
	if rootWritable <= subpathWritable {
		t.Fatalf("writable root (%.2f) should score higher than a writable subpath (%.2f)", rootWritable, subpathWritable)
	}
}

// --- path scoring -----------------------------------------------------------

func testGraph() *ClusterAttackSurfaceGraph {
	g := &ClusterAttackSurfaceGraph{
		Nodes: map[string]*AttackSurfaceNode{
			"a": {ID: "a", Name: "ingress", Type: NodeTypeIngress, RiskScore: 3.0},
			"b": {ID: "b", Name: "svc", Type: NodeTypeService, RiskScore: 4.0},
			"c": {ID: "c", Name: "db", Type: NodeTypeDatabase, RiskScore: 8.0,
				FileSystemProfile: &FileSystemProfile{SensitiveFiles: []*SensitiveFile{{Path: "/data"}}}},
		},
		Edges: map[string]*AttackSurfaceEdge{
			"a->b": {ID: "a->b", Source: "a", Target: "b", RiskContribution: 0.5},
			"b->c": {ID: "b->c", Source: "b", Target: "c", RiskContribution: 0.5},
		},
	}
	return g
}

func TestCalculatePathRisk_UsesRealNodeAndEdgeData(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := testGraph()

	full := &PathAnalysis{Nodes: []string{"a", "b", "c"}}
	shortHop := &PathAnalysis{Nodes: []string{"a", "b"}}

	riskFull := asa.calculatePathRisk(full, g)
	riskShort := asa.calculatePathRisk(shortHop, g)

	// Reaching the high-risk database endpoint must score higher than stopping
	// at the mid-risk service.
	if riskFull <= riskShort {
		t.Fatalf("path to db (%.2f) should out-score path to svc (%.2f)", riskFull, riskShort)
	}
	if riskFull <= 0 || riskFull > 10 {
		t.Fatalf("path risk out of range: %.2f", riskFull)
	}

	// Manual recomputation of the documented formula for the full path.
	// avgHop = (3+4+8)/3 = 5, endpoint = 8, edgeSum = 1.0, extraHops = 1
	// discount = 1/(1+0.2) = 0.8333...
	// risk = (0.5*8 + 0.5*5)*0.8333 + 1.0 = 6.5*0.8333 + 1 = 6.4166...
	want := (0.5*8.0+0.5*5.0)*(1.0/(1.0+0.2)) + 1.0
	if diff := riskFull - want; diff > 0.001 || diff < -0.001 {
		t.Fatalf("path risk = %.4f, want %.4f", riskFull, want)
	}
}

func TestCalculatePathProbability_DecreasesWithLength(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := testGraph()

	pShort := asa.calculatePathProbability(&PathAnalysis{Nodes: []string{"a", "b"}}, g)
	pLong := asa.calculatePathProbability(&PathAnalysis{Nodes: []string{"a", "b", "c"}}, g)

	if pLong >= pShort {
		t.Fatalf("longer path should be less probable: short=%.3f long=%.3f", pShort, pLong)
	}
	if pShort <= 0 || pShort > 1 || pLong <= 0 || pLong > 1 {
		t.Fatalf("probabilities must be within (0,1]: short=%.3f long=%.3f", pShort, pLong)
	}
}

func TestCalculatePathImpact_HighValueEndpoint(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := testGraph()

	// Endpoint c is a Database (+3) with sensitive files (+1.5) on top of its
	// 8.0 base risk, so it must clamp to 10.
	impact := asa.calculatePathImpact(&PathAnalysis{Nodes: []string{"a", "b", "c"}}, g)
	if impact != 10.0 {
		t.Fatalf("expected database endpoint impact to clamp to 10.0, got %.2f", impact)
	}

	// A service endpoint (no bonus) should reflect its own risk score.
	impactSvc := asa.calculatePathImpact(&PathAnalysis{Nodes: []string{"a", "b"}}, g)
	if impactSvc != 4.0 {
		t.Fatalf("expected service endpoint impact 4.0, got %.2f", impactSvc)
	}
}

// --- prioritization ---------------------------------------------------------

func TestPrioritizeRecommendations_SeverityThenEffort(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	recs := []*RecommendedAction{
		{ID: "low", Priority: "Low", Effort: "Low"},
		{ID: "crit", Priority: "Critical", Effort: "High"},
		{ID: "high-cheap", Priority: "High", Effort: "Low"},
		{ID: "high-expensive", Priority: "High", Effort: "High"},
		{ID: "medium", Priority: "Medium", Effort: "Low"},
	}
	asa.prioritizeRecommendations(recs)

	got := make([]string, len(recs))
	for i, r := range recs {
		got[i] = r.ID
	}
	want := []string{"crit", "high-cheap", "high-expensive", "medium", "low"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prioritization order = %v, want %v", got, want)
		}
	}
}

func TestCalculatePriority_RiskVectorsReachability(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	high := &ExposurePath{
		RiskScore:     8.0,
		Path:          []string{"a", "b"},
		AttackVectors: []*AttackVector{{Type: AttackVectorTypeRemoteExploit}, {Type: AttackVectorTypeLateralMovement}},
	}
	low := &ExposurePath{
		RiskScore:     8.0,
		Path:          []string{"a", "b", "c", "d", "e"}, // more hops => less reachable
		AttackVectors: []*AttackVector{{Type: AttackVectorTypeLateralMovement}},
	}
	if asa.calculatePriority(high) <= asa.calculatePriority(low) {
		t.Fatalf("shorter path with more vectors should have higher priority: high=%.2f low=%.2f",
			asa.calculatePriority(high), asa.calculatePriority(low))
	}
}

// --- compliance -------------------------------------------------------------

func TestAnalyzePolicyCompliance_HardenedIsCompliant(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{}
	container := &v1.Container{
		Name: "app",
		SecurityContext: &v1.SecurityContext{
			RunAsNonRoot:             boolPtr(true),
			RunAsUser:                int64Ptr(1000),
			AllowPrivilegeEscalation: boolPtr(false),
			ReadOnlyRootFilesystem:   boolPtr(true),
			Privileged:               boolPtr(false),
			Capabilities:             &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
		},
		Resources: v1.ResourceRequirements{
			Limits: v1.ResourceList{"cpu": resourceMustParse(t, "100m")},
		},
	}
	res := asa.analyzePolicyCompliance(pod, container)
	if !res.Compliant {
		t.Fatalf("hardened container should be compliant, violations: %v", res.PolicyViolations)
	}
	if res.ComplianceScore != 10.0 {
		t.Fatalf("hardened container should score 10.0, got %.2f", res.ComplianceScore)
	}
}

func TestAnalyzePolicyCompliance_PrivilegedIsPenalized(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{Spec: v1.PodSpec{HostNetwork: true}}
	container := &v1.Container{
		Name: "app",
		SecurityContext: &v1.SecurityContext{
			Privileged:   boolPtr(true),
			RunAsUser:    int64Ptr(0),
			Capabilities: &v1.Capabilities{Add: []v1.Capability{"SYS_ADMIN"}},
		},
	}
	res := asa.analyzePolicyCompliance(pod, container)
	if res.Compliant {
		t.Fatalf("privileged container must not be compliant")
	}
	if res.ComplianceScore >= 5.0 {
		t.Fatalf("privileged container should score low, got %.2f (violations: %v)", res.ComplianceScore, res.PolicyViolations)
	}
	if len(res.PolicyViolations) == 0 {
		t.Fatalf("expected violations to be recorded")
	}
}

// --- syscall exposure -------------------------------------------------------

func TestAnalyzeSyscallExposure_CapabilityDrivesRisk(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{}

	plain := &v1.Container{Name: "plain"}
	plainRes := asa.analyzeSyscallExposure(pod, plain)

	admin := &v1.Container{
		Name: "admin",
		SecurityContext: &v1.SecurityContext{
			Capabilities: &v1.Capabilities{Add: []v1.Capability{"SYS_ADMIN"}},
		},
	}
	adminRes := asa.analyzeSyscallExposure(pod, admin)

	if adminRes.ExposureScore <= plainRes.ExposureScore {
		t.Fatalf("SYS_ADMIN container should have higher exposure: admin=%.2f plain=%.2f",
			adminRes.ExposureScore, plainRes.ExposureScore)
	}
	if !stringsContains(adminRes.RiskySyscalls, "mount") {
		t.Fatalf("SYS_ADMIN should unlock mount as a risky syscall, got %v", adminRes.RiskySyscalls)
	}
	if len(plainRes.RiskySyscalls) != 0 {
		t.Fatalf("plain container should have no risky syscalls, got %v", plainRes.RiskySyscalls)
	}
}

// --- image analysis ---------------------------------------------------------

func TestAnalyzeContainerImage_TaggingHeuristics(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	pinned := asa.analyzeContainerImage("registry.example.com/app@sha256:abc123").RiskScore
	fixed := asa.analyzeContainerImage("registry.example.com/app:1.2.3").RiskScore
	latest := asa.analyzeContainerImage("registry.example.com/app:latest").RiskScore
	implicit := asa.analyzeContainerImage("nginx").RiskScore // no registry host, no tag

	if !(pinned < fixed && fixed < latest) {
		t.Fatalf("expected pinned(%.1f) < fixed(%.1f) < latest(%.1f)", pinned, fixed, latest)
	}
	if implicit <= fixed {
		t.Fatalf("implicit-registry untagged image (%.1f) should be riskier than a fixed-tag qualified one (%.1f)", implicit, fixed)
	}
}

// --- syscall profile fallback ----------------------------------------------

func TestGetPodSyscallProfile_PrivilegedIncludesSensitive(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "app",
					SecurityContext: &v1.SecurityContext{Privileged: boolPtr(true)},
				},
			},
		},
	}
	profile := asa.getPodSyscallProfile(pod)
	if len(profile.RiskySyscalls) == 0 {
		t.Fatalf("privileged pod should expose sensitive syscalls")
	}
	// mount (165) is a sensitive syscall and must be present for a privileged pod.
	found := false
	for _, nr := range profile.RiskySyscalls {
		if nr == 165 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mount (165) among risky syscalls, got %v", profile.RiskySyscalls)
	}
	if len(profile.AllowedSyscalls) <= len(baselineContainerSyscalls) {
		t.Fatalf("privileged pod allowed set should exceed the baseline")
	}
}

func TestGetPodSyscallProfile_UnprivilegedIsBaseline(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{
		Spec: v1.PodSpec{Containers: []v1.Container{{Name: "app"}}},
	}
	profile := asa.getPodSyscallProfile(pod)
	if len(profile.RiskySyscalls) != 0 {
		t.Fatalf("unprivileged pod should have no risky syscalls, got %v", profile.RiskySyscalls)
	}
	if len(profile.AllowedSyscalls) != len(baselineContainerSyscalls) {
		t.Fatalf("unprivileged pod should equal the baseline set, got %d want %d",
			len(profile.AllowedSyscalls), len(baselineContainerSyscalls))
	}
}

// --- network policy coverage ------------------------------------------------

func TestCalculatePolicyCoverage(t *testing.T) {
	workloadRef := learner.WorkloadReference{Namespace: "default", Kind: "Deployment", Name: "web"}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-abc",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "web", Ports: []v1.ContainerPort{{ContainerPort: 8080}, {ContainerPort: 9090}}},
			},
		},
	}
	asa := newTestAnalyzer(t, pod)

	// Full coverage: both directions declared and both observed ports pinned.
	full := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "full", Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{Ports: []netv1.NetworkPolicyPort{portRule(8080), portRule(9090)}},
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{Ports: []netv1.NetworkPolicyPort{portRule(8080), portRule(9090)}},
			},
		},
	}
	fullCov := asa.calculatePolicyCoverage(full, workloadRef)
	if fullCov != 10.0 {
		t.Fatalf("full policy should give coverage 10.0, got %.2f", fullCov)
	}

	// Ingress-only, allow-all (no ports): one direction, zero port coverage.
	// directionCoverage = 0.5, portCoverage = 0 => 10*(0.5*0.5) = 2.5
	ingressAllowAll := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allowall", Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     []netv1.NetworkPolicyIngressRule{{}},
		},
	}
	allowAllCov := asa.calculatePolicyCoverage(ingressAllowAll, workloadRef)
	if allowAllCov != 2.5 {
		t.Fatalf("ingress allow-all should give coverage 2.5, got %.2f", allowAllCov)
	}

	// Partial port coverage: both directions, only one of two ports pinned.
	// directionCoverage = 1.0, portCoverage = 0.5 => 10*(0.5*1 + 0.5*0.5) = 7.5
	partial := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "partial", Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			Ingress:     []netv1.NetworkPolicyIngressRule{{Ports: []netv1.NetworkPolicyPort{portRule(8080)}}},
			Egress:      []netv1.NetworkPolicyEgressRule{{}},
		},
	}
	partialCov := asa.calculatePolicyCoverage(partial, workloadRef)
	if partialCov != 7.5 {
		t.Fatalf("partial policy should give coverage 7.5, got %.2f", partialCov)
	}

	// No rules at all: zero coverage.
	empty := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "default"},
	}
	if cov := asa.calculatePolicyCoverage(empty, workloadRef); cov != 0.0 {
		t.Fatalf("empty policy should give coverage 0.0, got %.2f", cov)
	}
}

func portRule(port int32) netv1.NetworkPolicyPort {
	p := intstr.FromInt32(port)
	return netv1.NetworkPolicyPort{Port: &p}
}
