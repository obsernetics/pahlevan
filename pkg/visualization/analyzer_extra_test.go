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

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/obsernetics/pahlevan/internal/learner"
)

const eps = 1e-9

func approx(t *testing.T, got, want float64, ctx string) {
	t.Helper()
	if d := got - want; d > eps || d < -eps {
		t.Fatalf("%s = %.6f, want %.6f", ctx, got, want)
	}
}

// --- image analysis exact scores -------------------------------------------

func TestAnalyzeContainerImage_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	approx(t, asa.analyzeContainerImage("registry.io/app@sha256:deadbeef").RiskScore, 2.0, "digest-pinned")
	approx(t, asa.analyzeContainerImage("registry.io/app:1.2.3").RiskScore, 3.0, "fixed-tag+host")
	approx(t, asa.analyzeContainerImage("registry.io/app:latest").RiskScore, 5.0, "latest+host")
	approx(t, asa.analyzeContainerImage("nginx").RiskScore, 6.0, "implicit-registry-untagged")
}

// --- syscall exposure fallback ---------------------------------------------

func TestAnalyzeSyscallExposure_PlainBaselineScore(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	res := asa.analyzeSyscallExposure(&v1.Pod{}, &v1.Container{Name: "plain"})
	if len(res.RiskySyscalls) != 0 {
		t.Fatalf("plain container should expose no risky syscalls, got %v", res.RiskySyscalls)
	}
	approx(t, res.ExposureScore, float64(len(res.AllowedSyscalls))*0.05, "plain exposure score")
}

func TestAnalyzeSyscallExposure_DropAllBlocksSensitive(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	c := &v1.Container{
		Name: "hardened",
		SecurityContext: &v1.SecurityContext{
			Capabilities: &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
		},
	}
	res := asa.analyzeSyscallExposure(&v1.Pod{}, c)
	if len(res.BlockedSyscalls) == 0 {
		t.Fatal("dropping ALL should record blocked sensitive syscalls")
	}
}

// --- container network exposure --------------------------------------------

func TestAnalyzeContainerNetworkExposure_ExactScore(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil) // nil client => no public ports
	c := &v1.Container{
		Name:  "app",
		Ports: []v1.ContainerPort{{ContainerPort: 3000}, {ContainerPort: 4000}},
	}
	res := asa.analyzeContainerNetworkExposure(&v1.Pod{}, c)
	if len(res.PublicPorts) != 0 {
		t.Fatalf("no fronting service => no public ports, got %v", res.PublicPorts)
	}
	// two internal ports, neither high-risk: 2*0.5 = 1.0
	approx(t, res.ExposureScore, 1.0, "network exposure score")

	// A high-risk port (22) adds 1.0 on top.
	c2 := &v1.Container{Name: "ssh", Ports: []v1.ContainerPort{{ContainerPort: 22}}}
	res2 := asa.analyzeContainerNetworkExposure(&v1.Pod{}, c2)
	approx(t, res2.ExposureScore, 0.5+1.0, "high-risk network exposure score")
}

// --- filesystem exposure ----------------------------------------------------

func TestAnalyzeFilesystemExposure_ExactScore(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{
		Spec: v1.PodSpec{
			Volumes: []v1.Volume{{Name: "sec", VolumeSource: v1.VolumeSource{Secret: &v1.SecretVolumeSource{}}}},
		},
	}
	c := &v1.Container{
		Name:         "app",
		VolumeMounts: []v1.VolumeMount{{Name: "sec", MountPath: "/etc/sec", ReadOnly: false}},
	}
	res := asa.analyzeFilesystemExposure(pod, c)
	// writable "/" (3.0) + writable "/etc/sec" (0.5) + high-risk secret mount (1.5) = 5.0
	approx(t, res.ExposureScore, 5.0, "filesystem exposure score")
	if len(res.SensitiveFiles) != 1 || res.SensitiveFiles[0].Risk != "high" {
		t.Fatalf("secret mount should be a high-risk sensitive file: %+v", res.SensitiveFiles)
	}

	// A read-only root with a read-only config mount is much cheaper.
	roRoot := &v1.Container{
		Name:            "ro",
		SecurityContext: &v1.SecurityContext{ReadOnlyRootFilesystem: boolPtr(true)},
	}
	resRO := asa.analyzeFilesystemExposure(&v1.Pod{}, roRoot)
	approx(t, resRO.ExposureScore, 0.0, "read-only fs exposure score")
}

// --- security context -------------------------------------------------------

func TestAnalyzeContainerSecurityContext_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	// nil context => every insecure default: 1(nonroot)+2(escalation)+1(rwroot)=4.0
	approx(t, asa.analyzeContainerSecurityContext(&v1.Container{}).RiskScore, 4.0, "nil sc score")

	hardened := &v1.Container{SecurityContext: &v1.SecurityContext{
		RunAsUser:                int64Ptr(1000),
		RunAsNonRoot:             boolPtr(true),
		Privileged:               boolPtr(false),
		AllowPrivilegeEscalation: boolPtr(false),
		ReadOnlyRootFilesystem:   boolPtr(true),
	}}
	approx(t, asa.analyzeContainerSecurityContext(hardened).RiskScore, 0.0, "hardened sc score")

	rootPriv := &v1.Container{SecurityContext: &v1.SecurityContext{
		RunAsUser:  int64Ptr(0),
		Privileged: boolPtr(true),
	}}
	// 3(root)+1(nonroot)+4(priv)+2(escalation)+1(rwroot)=11 -> clamp 10
	approx(t, asa.analyzeContainerSecurityContext(rootPriv).RiskScore, 10.0, "root+priv sc score")
}

// --- resource limits --------------------------------------------------------

func TestAnalyzeResourceLimits_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	none := &v1.Container{}
	approx(t, asa.analyzeResourceLimits(none).RiskScore, 4.0, "no limits")

	cpuOnly := &v1.Container{Resources: v1.ResourceRequirements{
		Limits: v1.ResourceList{"cpu": resourceMustParse(t, "100m")},
	}}
	r := asa.analyzeResourceLimits(cpuOnly)
	approx(t, r.RiskScore, 2.5, "cpu only")
	if !r.HasLimits || r.CPULimit != "100m" {
		t.Fatalf("cpu limit not captured: %+v", r)
	}

	both := &v1.Container{Resources: v1.ResourceRequirements{
		Limits:   v1.ResourceList{"cpu": resourceMustParse(t, "1"), "memory": resourceMustParse(t, "256Mi")},
		Requests: v1.ResourceList{"cpu": resourceMustParse(t, "500m"), "memory": resourceMustParse(t, "128Mi")},
	}}
	rb := asa.analyzeResourceLimits(both)
	approx(t, rb.RiskScore, 1.0, "both limits")
	if rb.MemoryLimit != "256Mi" || rb.MemoryRequest != "128Mi" {
		t.Fatalf("requests/limits not captured: %+v", rb)
	}
}

// --- capabilities -----------------------------------------------------------

func TestAnalyzeContainerCapabilities_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	// No security context => runtime default set.
	approx(t, asa.analyzeContainerCapabilities(&v1.Container{}).RiskScore, 1.0, "default caps")

	dropAll := &v1.Container{SecurityContext: &v1.SecurityContext{
		Capabilities: &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
	}}
	approx(t, asa.analyzeContainerCapabilities(dropAll).RiskScore, 0.0, "drop all")

	addRisky := &v1.Container{SecurityContext: &v1.SecurityContext{
		Capabilities: &v1.Capabilities{Add: []v1.Capability{"SYS_ADMIN"}},
	}}
	res := asa.analyzeContainerCapabilities(addRisky)
	approx(t, res.RiskScore, 1.5, "add risky")
	if len(res.Risky) != 1 || res.Risky[0] != "SYS_ADMIN" {
		t.Fatalf("risky caps not flagged: %+v", res.Risky)
	}

	addBenign := &v1.Container{SecurityContext: &v1.SecurityContext{
		Capabilities: &v1.Capabilities{Add: []v1.Capability{"NOT_A_REAL_CAP"}},
	}}
	approx(t, asa.analyzeContainerCapabilities(addBenign).RiskScore, 0.3, "add benign")
}

func TestIsRiskyCapability(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	if !asa.isRiskyCapability("SYS_ADMIN") {
		t.Error("SYS_ADMIN should be risky")
	}
	if asa.isRiskyCapability("TOTALLY_MADE_UP") {
		t.Error("unknown capability should not be risky")
	}
}

// --- container risk aggregation ---------------------------------------------

func TestCalculateContainerRisk_WeightedSum(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	cs := &ContainerAttackSurface{
		ImageAnalysis:      &ImageSecurityAnalysis{RiskScore: 5.0},
		SecurityContext:    &SecurityContextAnalysis{RiskScore: 4.0},
		CapabilityAnalysis: &CapabilityAnalysis{RiskScore: 1.0},
		ResourceLimits:     &ResourceLimitsAnalysis{RiskScore: 4.0},
		NetworkExposure:    &NetworkExposureAnalysis{ExposureScore: 2.0},
		FileSystemExposure: &FileSystemExposureAnalysis{ExposureScore: 5.0},
	}
	// 5*0.2 + 4*0.3 + 1*0.2 + 4*0.1 + 2*0.1 + 5*0.1 = 1+1.2+0.2+0.4+0.2+0.5 = 3.5
	approx(t, asa.calculateContainerRisk(cs), 3.5, "container risk")

	// Nil sub-analyses contribute nothing.
	approx(t, asa.calculateContainerRisk(&ContainerAttackSurface{}), 0.0, "empty container risk")
}

// --- service exposure risk --------------------------------------------------

func TestCalculateServiceExposureRisk_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	clusterIP := &v1.Service{Spec: v1.ServiceSpec{
		Type:  v1.ServiceTypeClusterIP,
		Ports: []v1.ServicePort{{Port: 80}},
	}}
	// base 2 + clusterIP 1 + 1 port*0.5 = 3.5
	approx(t, asa.calculateServiceExposureRisk(clusterIP), 3.5, "clusterIP risk")

	lb := &v1.Service{Spec: v1.ServiceSpec{
		Type:  v1.ServiceTypeLoadBalancer,
		Ports: []v1.ServicePort{{Port: 22}},
	}}
	// base 2 + LB 4 + 1 port*0.5 + high-risk 22 (+2) = 8.5
	approx(t, asa.calculateServiceExposureRisk(lb), 8.5, "loadbalancer risk")
}

func TestIsHighRiskPort(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	if !asa.isHighRiskPort(22) || !asa.isHighRiskPort(3306) {
		t.Error("22/3306 should be high risk")
	}
	if asa.isHighRiskPort(80) {
		t.Error("80 should not be high risk")
	}
}

// --- network policy effectiveness -------------------------------------------

func TestCalculatePolicyEffectiveness_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)

	// ingress allow-all (no peers, no ports), no egress: 5 + 2 - 3 = 4.0
	allowAll := &netv1.NetworkPolicy{Spec: netv1.NetworkPolicySpec{
		Ingress: []netv1.NetworkPolicyIngressRule{{}},
	}}
	approx(t, asa.calculatePolicyEffectiveness(allowAll), 4.0, "allow-all effectiveness")

	// specific ingress + egress: 5 + 2 + 2 = 9.0
	specific := &netv1.NetworkPolicy{Spec: netv1.NetworkPolicySpec{
		Ingress: []netv1.NetworkPolicyIngressRule{{Ports: []netv1.NetworkPolicyPort{portRule(8080)}}},
		Egress:  []netv1.NetworkPolicyEgressRule{{Ports: []netv1.NetworkPolicyPort{portRule(443)}}},
	}}
	approx(t, asa.calculatePolicyEffectiveness(specific), 9.0, "specific effectiveness")
}

// --- edge risk --------------------------------------------------------------

func TestCalculateEdgeRisk_ExactScores(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := &ClusterAttackSurfaceGraph{Nodes: map[string]*AttackSurfaceNode{
		"hi": {ID: "hi", RiskScore: 9.0},
		"lo": {ID: "lo", RiskScore: 1.0},
	}}
	net := &AttackSurfaceEdge{Type: EdgeTypeNetworkConnection, Source: "hi", Target: "lo"}
	// 0.8 + source>7 (0.2) = 1.0
	approx(t, asa.calculateEdgeRisk(net, g), 1.0, "network edge risk")

	both := &AttackSurfaceEdge{Type: EdgeTypeNetworkConnection, Source: "hi", Target: "hi"}
	approx(t, asa.calculateEdgeRisk(both, g), 1.2, "both-high edge risk")

	dep := &AttackSurfaceEdge{Type: EdgeTypeServiceDependency, Source: "lo", Target: "lo"}
	approx(t, asa.calculateEdgeRisk(dep, g), 0.3, "dependency edge risk")
}

// --- node counting / top factors --------------------------------------------

func TestCountNodesByRiskRange(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	nodes := map[string]*AttackSurfaceNode{
		"a": {RiskScore: 1.0},
		"b": {RiskScore: 4.0},
		"c": {RiskScore: 8.0},
		"d": {RiskScore: 8.5},
	}
	if n := asa.countNodesByRiskRange(nodes, 0, 5); n != 2 {
		t.Errorf("[0,5) count = %d, want 2", n)
	}
	if n := asa.countNodesByRiskRange(nodes, 7, 10); n != 2 {
		t.Errorf("[7,10) count = %d, want 2", n)
	}
}

func TestIdentifyTopRiskFactors(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	nodes := map[string]*AttackSurfaceNode{
		"p": {Privileges: &PrivilegeProfile{Privileged: true}},
		"x": {ExposedPorts: []*ExposedPort{{Port: 80, Public: true}}},
		"v": {VulnerabilityCount: 3},
	}
	factors := asa.identifyTopRiskFactors(nodes)
	want := map[string]bool{"Privileged containers": true, "External exposure": true, "Known vulnerabilities": true}
	if len(factors) != 3 {
		t.Fatalf("expected 3 factors, got %v", factors)
	}
	for _, f := range factors {
		if !want[f] {
			t.Errorf("unexpected factor %q", f)
		}
	}
	if len(asa.identifyTopRiskFactors(map[string]*AttackSurfaceNode{"clean": {}})) != 0 {
		t.Error("clean node should yield no risk factors")
	}
}

// --- criticality / impact / likelihood mapping ------------------------------

func TestRiskToCriticality_Bands(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil) // Low3 Med5 High7 Crit9
	cases := []struct {
		score float64
		want  CriticalityLevel
	}{
		{9.5, CriticalityCritical},
		{8.0, CriticalityHigh},
		{6.0, CriticalityMedium},
		{4.0, CriticalityLow},
		{2.0, CriticalityInfo},
	}
	for _, c := range cases {
		if got := asa.riskToCriticality(c.score); got != c.want {
			t.Errorf("riskToCriticality(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}

	// With no thresholds configured, everything is Info.
	bare := &AttackSurfaceAnalyzer{}
	if got := bare.riskToCriticality(9.9); got != CriticalityInfo {
		t.Errorf("nil-thresholds criticality = %s, want Info", got)
	}
}

func TestScoreToImpactAndLikelihood(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	if asa.scoreToImpact(9.5) != ImpactLevelCritical {
		t.Error("9.5 impact should be critical")
	}
	if asa.scoreToImpact(1.0) != ImpactLevelLow {
		t.Error("1.0 impact should be low")
	}
	if asa.scoreToLikelihood(8.0) != LikelihoodLevelHigh {
		t.Error("8.0 likelihood should be high")
	}
	if asa.scoreToLikelihood(6.0) != LikelihoodLevelMedium {
		t.Error("6.0 likelihood should be medium")
	}
	if asa.scoreToLikelihood(1.0) != LikelihoodLevelLow {
		t.Error("1.0 likelihood should be low")
	}
	approx(t, asa.highRiskThreshold(), 7.0, "default high threshold")
	bare := &AttackSurfaceAnalyzer{}
	approx(t, bare.highRiskThreshold(), 7.0, "fallback high threshold")
}

// --- priority (exact) -------------------------------------------------------

func TestCalculatePriority_Exact(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	p := &ExposurePath{
		RiskScore:     8.0,
		Path:          []string{"a", "b"},
		AttackVectors: []*AttackVector{{}, {}},
	}
	// 8 * (1 + 0.15*2) * 1/(1+0) = 8*1.3 = 10.4
	approx(t, asa.calculatePriority(p), 10.4, "priority")
	approx(t, asa.calculatePriority(nil), 0.0, "nil priority")
}

func TestPriorityAndEffortRank(t *testing.T) {
	if priorityRank("Critical") <= priorityRank("High") || priorityRank("unknown") != 0 {
		t.Error("priorityRank ordering wrong")
	}
	if effortRank("Low") != 1 || effortRank("High") != 3 || effortRank("weird") != 2 {
		t.Error("effortRank mapping wrong")
	}
}

// --- pod-level profile extractors -------------------------------------------

func TestExtractPodPortsAndCapabilities(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{
		Name:  "app",
		Ports: []v1.ContainerPort{{ContainerPort: 8080, Protocol: v1.ProtocolTCP, Name: "http"}},
		SecurityContext: &v1.SecurityContext{
			Capabilities: &v1.Capabilities{Add: []v1.Capability{"NET_ADMIN"}},
		},
	}}}}
	ports := asa.extractPodPorts(pod)
	if len(ports) != 1 || ports[0].Port != 8080 || ports[0].Public {
		t.Fatalf("extractPodPorts wrong: %+v", ports)
	}
	caps := asa.extractPodCapabilities(pod)
	if len(caps) != 1 || caps[0] != "NET_ADMIN" {
		t.Fatalf("extractPodCapabilities wrong: %+v", caps)
	}
}

func TestAnalyzePodPrivileges(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{
		Name: "app",
		SecurityContext: &v1.SecurityContext{
			RunAsUser:  int64Ptr(0),
			Privileged: boolPtr(true),
		},
	}}}}
	p := asa.analyzePodPrivileges(pod)
	if !p.Privileged || p.RunAsUser == nil || *p.RunAsUser != 0 {
		t.Fatalf("expected privileged root profile, got %+v", p)
	}

	clean := asa.analyzePodPrivileges(&v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Name: "x"}}}})
	if clean.Privileged {
		t.Error("clean pod should not be privileged")
	}
}

func TestGetPodNetworkProfile(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{
		Name:  "app",
		Ports: []v1.ContainerPort{{ContainerPort: 8080, Protocol: v1.ProtocolTCP, Name: "http"}},
	}}}}
	np := asa.getPodNetworkProfile(pod)
	if len(np.ExposedPorts) != 1 || len(np.ListeningServices) != 1 {
		t.Fatalf("network profile wrong: %+v", np)
	}
}

func TestGetPodFilesystemProfile(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	pod := &v1.Pod{Spec: v1.PodSpec{
		Volumes: []v1.Volume{{Name: "cfg", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{}}}},
		Containers: []v1.Container{{
			Name:         "app",
			VolumeMounts: []v1.VolumeMount{{Name: "cfg", MountPath: "/cfg", ReadOnly: true}},
			// no readonly root => "/" is writable
		}},
	}}
	fp := asa.getPodFilesystemProfile(pod)
	if !stringsContains(fp.WritablePaths, "/") {
		t.Errorf("expected writable root, got %v", fp.WritablePaths)
	}
	if len(fp.SensitiveFiles) != 1 || fp.SensitiveFiles[0].Type != "config" {
		t.Fatalf("configmap mount should be sensitive: %+v", fp.SensitiveFiles)
	}
}

// --- node recommendations ---------------------------------------------------

func TestGenerateNodeRecommendations(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	node := &AttackSurfaceNode{
		ID:           "n1",
		Name:         "web",
		Privileges:   &PrivilegeProfile{RunAsUser: int64Ptr(0)},
		ExposedPorts: []*ExposedPort{{Port: 80, Public: true}},
	}
	recs := asa.generateNodeRecommendations(node)
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations (root + exposure), got %d", len(recs))
	}

	clean := &AttackSurfaceNode{ID: "n2", Name: "clean", Privileges: &PrivilegeProfile{RunAsUser: int64Ptr(1000)}}
	if len(asa.generateNodeRecommendations(clean)) != 0 {
		t.Error("clean node should have no recommendations")
	}
}

// --- small helpers ----------------------------------------------------------

func TestImageHelpers(t *testing.T) {
	if imageTag("registry:5000/app:1.2.3") != "1.2.3" {
		t.Error("imageTag should ignore registry port")
	}
	if imageTag("registry:5000/app") != "" {
		t.Error("imageTag of untagged qualified image should be empty")
	}
	if imageTag("app:v1") != "v1" {
		t.Error("imageTag of bare tagged image wrong")
	}
	if imageTag("app@sha256:abc") != "" {
		t.Error("digest reference has no tag")
	}
	if !imageHasRegistryHost("registry.io/app") || !imageHasRegistryHost("localhost/app") {
		t.Error("registry host detection wrong (positive)")
	}
	if imageHasRegistryHost("nginx") || imageHasRegistryHost("user/app") {
		t.Error("registry host detection wrong (negative)")
	}
}

func TestCapabilitiesDropAllAndTokenAutomount(t *testing.T) {
	if capabilitiesDropAll(nil) {
		t.Error("nil sc should not drop all")
	}
	if !capabilitiesDropAll(&v1.SecurityContext{Capabilities: &v1.Capabilities{Drop: []v1.Capability{"ALL"}}}) {
		t.Error("drop ALL should be detected")
	}
	if !tokenAutomounted(nil) {
		t.Error("nil pod defaults to automounted")
	}
	if tokenAutomounted(&v1.Pod{Spec: v1.PodSpec{AutomountServiceAccountToken: boolPtr(false)}}) {
		t.Error("explicit false should disable automount")
	}
	if !tokenAutomounted(&v1.Pod{Spec: v1.PodSpec{AutomountServiceAccountToken: boolPtr(true)}}) {
		t.Error("explicit true should enable automount")
	}
}

func TestAppendUniqueAndContains(t *testing.T) {
	s := appendUniqueString([]string{"a"}, "a")
	if len(s) != 1 {
		t.Error("duplicate should not be appended")
	}
	s = appendUniqueString(s, "b")
	if len(s) != 2 || !stringsContains(s, "b") {
		t.Error("new element should be appended")
	}
	if stringsContains(s, "z") {
		t.Error("z not present")
	}
}

func TestSyscallNameAndClassifiers(t *testing.T) {
	if syscallName(999999) != "syscall_999999" {
		t.Errorf("unknown syscall name = %q", syscallName(999999))
	}
	if !isSensitiveSyscall(165) { // mount
		t.Error("mount (165) should be sensitive")
	}
	// isCriticalSyscall exercised regardless of the specific truth value.
	_ = isCriticalSyscall(101)
}

func TestMapLearnerCriticality(t *testing.T) {
	cases := map[learner.CriticalityLevel]CriticalityLevel{
		learner.CriticalityLevel("Critical"): CriticalityCritical,
		learner.CriticalityLevel("high"):     CriticalityHigh,
		learner.CriticalityLevel("Medium"):   CriticalityMedium,
		learner.CriticalityLevel("low"):      CriticalityLow,
		learner.CriticalityLevel("whatever"): CriticalityInfo,
	}
	for in, want := range cases {
		if got := mapLearnerCriticality(in); got != want {
			t.Errorf("mapLearnerCriticality(%q) = %s, want %s", in, got, want)
		}
	}
}

// --- classifyExposureType ---------------------------------------------------

func TestClassifyExposureType(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := &ClusterAttackSurfaceGraph{Nodes: map[string]*AttackSurfaceNode{
		"priv": {Privileges: &PrivilegeProfile{Privileged: true}},
		"data": {FileSystemProfile: &FileSystemProfile{SensitiveFiles: []*SensitiveFile{{Path: "/s"}}}},
		"db":   {Type: NodeTypeDatabase},
		"svc":  {Type: NodeTypeService},
	}}
	if asa.classifyExposureType(g, "priv") != ExposureTypePrivilegeEscalation {
		t.Error("privileged endpoint => privilege escalation")
	}
	if asa.classifyExposureType(g, "data") != ExposureTypeDataAccess {
		t.Error("sensitive-file endpoint => data access")
	}
	if asa.classifyExposureType(g, "db") != ExposureTypeDataAccess {
		t.Error("database endpoint => data access")
	}
	if asa.classifyExposureType(g, "svc") != ExposureTypeLateralMovement {
		t.Error("plain service endpoint => lateral movement")
	}
	if asa.classifyExposureType(g, "missing") != ExposureTypeNetworkIngress {
		t.Error("unknown endpoint => network ingress")
	}
}

// --- attack vectors & mitigation on a real path -----------------------------

func TestIdentifyAttackVectorsAndMitigation(t *testing.T) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := &ClusterAttackSurfaceGraph{
		Nodes: map[string]*AttackSurfaceNode{
			"in": {ID: "in", Name: "ingress", Type: NodeTypeIngress, RiskScore: 3.0,
				ExposedPorts: []*ExposedPort{{Port: 443, Public: true}}},
			"db": {ID: "db", Name: "db", Type: NodeTypeDatabase, RiskScore: 8.0,
				Privileges:        &PrivilegeProfile{RunAsUser: int64Ptr(0)},
				SyscallProfile:    &SyscallProfile{RiskySyscalls: []uint64{165}},
				FileSystemProfile: &FileSystemProfile{WritablePaths: []string{"/"}, SensitiveFiles: []*SensitiveFile{{Path: "/data"}}}},
		},
		Edges: map[string]*AttackSurfaceEdge{
			"in->db": {ID: "in->db", Source: "in", Target: "db", RiskContribution: 0.5},
		},
	}
	path := &PathAnalysis{Nodes: []string{"in", "db"}}
	vectors := asa.identifyAttackVectors(path, g)
	seen := map[AttackVectorType]bool{}
	for _, v := range vectors {
		seen[v.Type] = true
	}
	for _, want := range []AttackVectorType{
		AttackVectorTypeRemoteExploit,
		AttackVectorTypeLateralMovement,
		AttackVectorTypePrivilegeEscalation,
		AttackVectorTypeCredentialAccess,
		AttackVectorTypeDataExfiltration,
	} {
		if !seen[want] {
			t.Errorf("expected attack vector %s", want)
		}
	}

	steps := asa.generateMitigationSteps(path, g)
	if len(steps) == 0 {
		t.Fatal("expected mitigation steps for a dangerous path")
	}
	defenses := asa.pathDefenses(path, g)
	if len(defenses) != len(steps) {
		t.Errorf("defenses (%d) should mirror steps (%d)", len(defenses), len(steps))
	}

	// A single-node path with no weaknesses falls back to the monitoring step.
	empty := asa.generateMitigationSteps(&PathAnalysis{Nodes: []string{"in"}}, g)
	if len(empty) != 1 {
		t.Fatalf("clean single-node path should yield the fallback step, got %v", empty)
	}
}

// --- benchmarks -------------------------------------------------------------

func benchNode() *AttackSurfaceNode {
	return &AttackSurfaceNode{
		Type:         NodeTypePod,
		ExposedPorts: []*ExposedPort{{Port: 22, Public: true}, {Port: 8080, Public: false}},
		Capabilities: []string{"SYS_ADMIN", "NET_ADMIN"},
		Privileges: &PrivilegeProfile{
			RunAsUser:                int64Ptr(0),
			Privileged:               true,
			AllowPrivilegeEscalation: true,
		},
		SyscallProfile: &SyscallProfile{
			AllowedSyscalls: []uint64{0, 1, 2, 3, 4, 5, 101, 165},
			RiskySyscalls:   []uint64{101, 165},
		},
		FileSystemProfile: &FileSystemProfile{
			WritablePaths:  []string{"/", "/tmp"},
			SensitiveFiles: []*SensitiveFile{{Path: "/secrets"}},
		},
		VulnerabilityCount: 2,
	}
}

func BenchmarkCalculateNodeRisk(b *testing.B) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	node := benchNode()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = asa.calculateNodeRisk(node)
	}
}

func BenchmarkCalculatePathRisk(b *testing.B) {
	asa := NewAttackSurfaceAnalyzer(nil, nil, nil)
	g := &ClusterAttackSurfaceGraph{
		Nodes: map[string]*AttackSurfaceNode{
			"a": {ID: "a", Type: NodeTypeIngress, RiskScore: 3.0},
			"b": {ID: "b", Type: NodeTypeService, RiskScore: 4.0},
			"c": {ID: "c", Type: NodeTypeDatabase, RiskScore: 8.0},
		},
		Edges: map[string]*AttackSurfaceEdge{
			"a->b": {Source: "a", Target: "b", RiskContribution: 0.5},
			"b->c": {Source: "b", Target: "c", RiskContribution: 0.5},
		},
	}
	path := &PathAnalysis{Nodes: []string{"a", "b", "c"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = asa.calculatePathRisk(path, g)
	}
}

// --- end-to-end analysis over a fake cluster --------------------------------

func seededClusterAnalyzer(t *testing.T) *AttackSurfaceAnalyzer {
	t.Helper()
	runningPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-abc",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "web"},
			},
		},
		Spec: v1.PodSpec{
			ServiceAccountName: "web-sa",
			HostNetwork:        true,
			Containers: []v1.Container{{
				Name:  "web",
				Image: "registry.io/web:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 8080, Protocol: v1.ProtocolTCP}},
				SecurityContext: &v1.SecurityContext{
					Privileged:   boolPtr(true),
					RunAsUser:    int64Ptr(0),
					Capabilities: &v1.Capabilities{Add: []v1.Capability{"SYS_ADMIN"}},
				},
			}},
		},
		Status: v1.PodStatus{Phase: v1.PodRunning},
	}
	// A pending pod must be ignored by discovery.
	pendingPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-pending", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "web"}}},
		Status:     v1.PodStatus{Phase: v1.PodPending},
	}
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: v1.ServiceSpec{
			Type:     v1.ServiceTypeLoadBalancer,
			Selector: map[string]string{"app": "web"},
			Ports:    []v1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	}
	ingress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web-ing", Namespace: "default"},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{{
				IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{
					Paths: []netv1.HTTPIngressPath{{
						Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{
							Name: "web",
							Port: netv1.ServiceBackendPort{Number: 80},
						}},
					}},
				}},
			}},
		},
	}
	netpol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web-np", Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     []netv1.NetworkPolicyIngressRule{{Ports: []netv1.NetworkPolicyPort{portRule(8080)}}},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "web-admin"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "web-sa", Namespace: "default"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
	}

	return newTestAnalyzer(t, runningPod, pendingPod, svc, ingress, netpol, crb)
}

func TestAnalyzeClusterAttackSurface_EndToEnd(t *testing.T) {
	asa := seededClusterAnalyzer(t)

	graph, err := asa.AnalyzeClusterAttackSurface()
	if err != nil {
		t.Fatalf("AnalyzeClusterAttackSurface: %v", err)
	}
	// pod + service + ingress = 3 nodes (pending pod excluded).
	if len(graph.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d: %v", len(graph.Nodes), keysOf(graph.Nodes))
	}
	if graph.RiskAggregation == nil || graph.RiskAggregation.TotalRiskScore <= 0 {
		t.Fatalf("risk aggregation missing/zero: %+v", graph.RiskAggregation)
	}
	// The privileged root pod must land in the critical band.
	podNode := graph.Nodes["pod-default-web-abc"]
	if podNode == nil {
		t.Fatal("pod node missing")
	}
	if podNode.RiskScore < 9.0 {
		t.Errorf("privileged root pod risk = %.2f, want >= 9.0", podNode.RiskScore)
	}
	// Entry points and exposure paths should be discovered from the ingress.
	if len(graph.ExposurePaths) == 0 {
		t.Error("expected at least one exposure path from the ingress")
	}
}

func TestAnalyzeWorkloadAttackSurface_EndToEnd(t *testing.T) {
	asa := seededClusterAnalyzer(t)
	ref := learner.WorkloadReference{Namespace: "default", Kind: "Deployment", Name: "web"}

	surface, err := asa.AnalyzeWorkloadAttackSurface(ref)
	if err != nil {
		t.Fatalf("AnalyzeWorkloadAttackSurface: %v", err)
	}
	// Both the running and pending pods carry app=web, and container analysis is
	// not phase-filtered, so both containers are analyzed.
	if len(surface.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(surface.Containers))
	}
	if surface.ServiceExposure == nil || !surface.ServiceExposure.LoadBalancer {
		t.Fatalf("expected load-balancer service exposure, got %+v", surface.ServiceExposure)
	}
	if len(surface.NetworkPolicies) != 1 {
		t.Fatalf("expected 1 applicable network policy, got %d", len(surface.NetworkPolicies))
	}
	if surface.RBACAnalysis == nil || !surface.RBACAnalysis.Privileged {
		t.Fatalf("cluster-admin bound SA should be privileged: %+v", surface.RBACAnalysis)
	}
	if surface.OverallRiskScore <= 0 {
		t.Fatalf("overall risk should be positive, got %.2f", surface.OverallRiskScore)
	}
	// A privileged-RBAC risk factor must be recorded.
	foundPriv := false
	for _, f := range surface.TopRisks {
		if f.Type == RiskFactorTypePrivilegedAccess {
			foundPriv = true
		}
	}
	if !foundPriv {
		t.Error("expected a privileged-access risk factor")
	}
}

func TestExportToFormat(t *testing.T) {
	asa := seededClusterAnalyzer(t)
	if _, err := asa.AnalyzeClusterAttackSurface(); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	json, err := asa.ExportToFormat(ExportFormatJSON)
	if err != nil || len(json) == 0 {
		t.Fatalf("JSON export failed: %v", err)
	}
	if b, err := asa.ExportToFormat(ExportFormatMermaid); err != nil || len(b) == 0 {
		t.Fatalf("mermaid export failed: %v", err)
	}
	if _, err := asa.ExportToFormat(ExportFormatGraphQL); err != nil {
		t.Fatalf("graphql export failed: %v", err)
	}
	if _, err := asa.ExportToFormat(ExportFormatCytoscape); err != nil {
		t.Fatalf("cytoscape export failed: %v", err)
	}
	if _, err := asa.ExportToFormat(ExportFormat("bogus")); err == nil {
		t.Fatal("unsupported format should error")
	}
}

func TestGetAttackSurfaceData(t *testing.T) {
	asa := seededClusterAnalyzer(t)
	data, err := asa.GetAttackSurfaceData()
	if err != nil {
		t.Fatalf("GetAttackSurfaceData: %v", err)
	}
	if data.Metadata["analyzer_version"] != "1.0.0" {
		t.Errorf("unexpected metadata: %+v", data.Metadata)
	}
}

func keysOf(m map[string]*AttackSurfaceNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
