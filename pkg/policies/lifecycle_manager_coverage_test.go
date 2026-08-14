package policies

import (
	"context"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func lifecyclePolicy() *policyv1alpha1.PahlevanPolicy {
	return &policyv1alpha1.PahlevanPolicy{
		Spec: policyv1alpha1.PahlevanPolicySpec{
			LearningConfig: policyv1alpha1.LearningConfig{
				LifecycleAware: true,
				Duration:       &metav1.Duration{Duration: time.Hour},
			},
			SelfHealing: policyv1alpha1.SelfHealingConfig{Enabled: true},
		},
	}
}

func TestRegisterWorkloadAndTypes(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "web", Namespace: "default"}
	containers := []string{"main", "init-setup", "istio-proxy"}
	require.NoError(t, lm.RegisterWorkload(ref, containers, lifecyclePolicy()))

	key := lm.getWorkloadKey(ref)
	state := lm.workloadStates[key]
	require.NotNil(t, state)
	assert.Len(t, state.ContainerStates, 3)
	assert.Contains(t, state.InitContainers, "init-setup")
	assert.Contains(t, state.SidecarContainers, "istio-proxy")
	assert.Contains(t, state.MainContainers, "main")
}

func TestDetermineContainerType(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment"}
	assert.Equal(t, ContainerTypeInit, lm.determineContainerType("init-x", ref))
	assert.Equal(t, ContainerTypeSidecar, lm.determineContainerType("envoy", ref))
	assert.Equal(t, ContainerTypeMain, lm.determineContainerType("app", ref))
	// DaemonSet system container -> treated as sidecar.
	assert.Equal(t, ContainerTypeSidecar, lm.determineContainerType("kube-proxy", learner.WorkloadReference{Kind: "DaemonSet"}))
	// Job -> main.
	assert.Equal(t, ContainerTypeMain, lm.determineContainerType("worker", learner.WorkloadReference{Kind: "Job"}))
}

func TestProcessContainerEvent_Transitions(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "web", Namespace: "default"}
	require.NoError(t, lm.RegisterWorkload(ref, []string{"main"}, lifecyclePolicy()))

	// Force initial phase to Initializing so ContainerStarted transitions.
	key := lm.getWorkloadKey(ref)
	lm.workloadStates[key].ContainerStates["main"].CurrentPhase = ContainerPhaseInitializing

	require.NoError(t, lm.ProcessContainerEvent("main", EventTypeContainerStarted, nil))
	assert.Equal(t, ContainerPhaseStarting, lm.workloadStates[key].ContainerStates["main"].CurrentPhase)

	require.NoError(t, lm.ProcessContainerEvent("main", EventTypeContainerHealthy, nil))
	assert.Equal(t, ContainerPhaseRunning, lm.workloadStates[key].ContainerStates["main"].CurrentPhase)

	require.NoError(t, lm.ProcessContainerEvent("main", EventTypeContainerHealthy, map[string]interface{}{"stability_score": 0.9, "cpu_usage": 12.5}))
	assert.Equal(t, ContainerPhaseReady, lm.workloadStates[key].ContainerStates["main"].CurrentPhase)

	// Unknown container.
	assert.Error(t, lm.ProcessContainerEvent("missing", EventTypeContainerStarted, nil))
}

func TestDetermineNewContainerPhase_EventData(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	cs := &ContainerLifecycleState{CurrentPhase: ContainerPhaseStarting}
	// ready_containers triggers Running.
	assert.Equal(t, ContainerPhaseRunning,
		lm.determineNewContainerPhase(cs, EventTypeContainerReady, map[string]interface{}{"ready_containers": 2}))
	// violation -> failed.
	assert.Equal(t, ContainerPhaseFailed,
		lm.determineNewContainerPhase(cs, EventTypeViolationDetected, nil))
	// rollback -> ready.
	assert.Equal(t, ContainerPhaseReady,
		lm.determineNewContainerPhase(cs, EventTypeRollbackTriggered, nil))
	// stability_score triggers Steady from Running.
	cs.CurrentPhase = ContainerPhaseRunning
	assert.Equal(t, ContainerPhaseSteady,
		lm.determineNewContainerPhase(cs, LifecycleEventType("noop"), map[string]interface{}{"stability_score": 0.95}))
}

func TestEventTypeToTrigger(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	assert.Equal(t, TriggerHealthCheck, lm.eventTypeToTrigger(EventTypeContainerHealthy))
	assert.Equal(t, TriggerStabilityReached, lm.eventTypeToTrigger(EventTypeContainerSteady))
	assert.Equal(t, TriggerAutomatic, lm.eventTypeToTrigger(EventTypeContainerStarted))
}

func TestUpdateContainerStateFromEvent(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	cs := &ContainerLifecycleState{}
	lm.updateContainerStateFromEvent(cs, EventTypeContainerStarted, nil)
	assert.False(t, cs.StartTime.IsZero())

	for i := 0; i < 3; i++ {
		lm.updateContainerStateFromEvent(cs, EventTypeContainerReady, nil)
	}
	require.NotNil(t, cs.ReadinessProbe)
	assert.True(t, cs.ReadinessProbe.Stabilized)

	lm.updateContainerStateFromEvent(cs, EventTypeViolationDetected, nil)
	assert.Equal(t, int32(1), cs.ReadinessProbe.FailureCount)

	// Metrics folded in.
	lm.updateContainerStateFromEvent(cs, EventTypeContainerHealthy, map[string]interface{}{
		"stability_score": 0.85, "cpu_usage": 10.0, "memory_usage": 50.0,
	})
	assert.Equal(t, 0.85, cs.StabilityMetrics.OverallScore)
	assert.Equal(t, 10.0, cs.ResourceUsage.CPUUsage.Current)

	// nil container state is a no-op.
	lm.updateContainerStateFromEvent(nil, EventTypeContainerStarted, nil)
}

func TestFloatFromData(t *testing.T) {
	cases := []interface{}{float64(1), float32(2), int(3), int32(4), int64(5)}
	for _, c := range cases {
		_, ok := floatFromData(c)
		assert.True(t, ok)
	}
	_, ok := floatFromData("nope")
	assert.False(t, ok)
}

func TestUpdateWorkloadPhase(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	// nil is a no-op.
	lm.updateWorkloadPhase(nil)

	state := &WorkloadLifecycleState{
		WorkloadRef:       learner.WorkloadReference{Name: "w"},
		MainContainers:    map[string]*ContainerLifecycleState{},
		SidecarContainers: map[string]*ContainerLifecycleState{},
		InitContainers:    map[string]*ContainerLifecycleState{},
	}
	// No containers -> Initializing.
	lm.updateWorkloadPhase(state)
	assert.Equal(t, WorkloadPhaseInitializing, state.CurrentPhase)

	// All steady -> Steady.
	state.MainContainers["a"] = &ContainerLifecycleState{CurrentPhase: ContainerPhaseSteady}
	lm.updateWorkloadPhase(state)
	assert.Equal(t, WorkloadPhaseSteady, state.CurrentPhase)

	// A failed container dominates.
	state.MainContainers["b"] = &ContainerLifecycleState{CurrentPhase: ContainerPhaseFailed}
	lm.updateWorkloadPhase(state)
	assert.Equal(t, WorkloadPhaseFailed, state.CurrentPhase)
}

func TestShouldTriggerPolicyTighteningAndSchedule(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	assert.True(t, lm.shouldTriggerPolicyTightening(nil, ContainerPhaseTransition{To: ContainerPhaseReady}))
	assert.True(t, lm.shouldTriggerPolicyTightening(nil, ContainerPhaseTransition{To: ContainerPhaseSteady}))
	assert.False(t, lm.shouldTriggerPolicyTightening(nil, ContainerPhaseTransition{To: ContainerPhaseRunning}))

	// schedulePolicyTightening: intensity escalates with phase and dedups.
	lm.schedulePolicyTightening("c1", ContainerPhaseTransition{To: ContainerPhaseSteady})
	lm.schedulePolicyTightening("c1", ContainerPhaseTransition{To: ContainerPhaseReady}) // deduped (pending exists)
	pts := lm.policyTighteningScheduler
	pts.mu.Lock()
	tasks := pts.scheduledTightenings["c1"]
	pts.mu.Unlock()
	require.Len(t, tasks, 1)
	assert.Equal(t, IntensityAggressive, tasks[0].Intensity)
}

func TestTightenPolicyAndRunScheduled(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "web", Namespace: "default"}
	require.NoError(t, lm.RegisterWorkload(ref, []string{"main"}, lifecyclePolicy()))
	key := lm.getWorkloadKey(ref)
	cs := lm.workloadStates[key].ContainerStates["main"]
	cs.CurrentPolicy = &GeneratedPolicy{
		Version:       1,
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}, 2: {}, 3: {}, 4: {}}},
		FilePolicy:    &FileEnforcementPolicy{AllowedPaths: map[string]*FileRule{"/etc/a": {AccessModes: []string{"read"}}}},
	}

	require.NoError(t, lm.TightenPolicy("main", TighteningTypeCombined, IntensityModerate))
	// A new policy version was applied and recorded.
	assert.Greater(t, cs.CurrentPolicy.Version, 1)
	require.NotEmpty(t, lm.workloadStates[key].TighteningEvents)

	// runScheduledTightening path.
	require.NoError(t, lm.runScheduledTightening(&ScheduledTighteningTask{ContainerID: "main", TighteningType: TighteningTypeSyscall, Intensity: IntensityGentle}))
	// nil / empty task is a no-op.
	require.NoError(t, lm.runScheduledTightening(nil))
	require.NoError(t, lm.runScheduledTightening(&ScheduledTighteningTask{}))

	// Unknown container/intensity.
	assert.Error(t, lm.TightenPolicy("missing", TighteningTypeCombined, IntensityGentle))
	assert.Error(t, lm.TightenPolicy("main", TighteningTypeCombined, TighteningIntensity("bogus")))
}

func TestAssessCurrentPrivileges(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	// nil policy -> empty privileges.
	empty := lm.assessCurrentPrivileges(&ContainerLifecycleState{})
	assert.Empty(t, empty.Syscalls)

	cs := &ContainerLifecycleState{CurrentPolicy: &GeneratedPolicy{
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}, 2: {}}},
		NetworkPolicy: &NetworkEnforcementPolicy{
			EgressRules:  []*NetworkRule{{Protocol: "tcp", RemoteEndpoint: &EndpointRule{PortRange: &PortRange{Start: 443}}}},
			IngressRules: []*NetworkRule{{Protocol: "tcp", LocalEndpoint: &EndpointRule{PortRange: &PortRange{Start: 8080}}}},
		},
		FilePolicy: &FileEnforcementPolicy{AllowedPaths: map[string]*FileRule{"/etc/a": {AccessModes: []string{"read"}}}},
	}}
	p := lm.assessCurrentPrivileges(cs)
	assert.Len(t, p.Syscalls, 2)
	assert.Len(t, p.NetworkPorts, 2)
	assert.Len(t, p.FilePaths, 1)
}

func TestCalculateTightenedPrivileges_Intensities(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	current := RequiredPrivileges{
		Syscalls:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Capabilities: []string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_SYS_ADMIN"},
		NetworkPorts: []NetworkPortRequirement{{Port: 443}, {Port: 9999}},
		FilePaths:    []FilePathRequirement{{Path: "/etc/x"}, {Path: "/opt/data"}},
	}
	for _, in := range []TighteningIntensity{IntensityGentle, IntensityModerate, IntensityAggressive, IntensityMaximal} {
		out, err := lm.calculateTightenedPrivileges(current, TighteningTypeCombined, in, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(out.Syscalls), len(current.Syscalls))
	}
	// Type-specific: syscall focus.
	out, err := lm.calculateTightenedPrivileges(current, TighteningTypeSyscall, IntensityGentle, nil)
	require.NoError(t, err)
	assert.Equal(t, current.Capabilities, out.Capabilities)

	_, err = lm.calculateTightenedPrivileges(current, TighteningTypeCombined, TighteningIntensity("x"), nil)
	assert.Error(t, err)
}

func TestFilterHelpers(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	// retention >= 1.0 returns input unchanged.
	caps := []string{"CAP_CHOWN", "CAP_X"}
	assert.Equal(t, caps, lm.filterCapabilitiesByUsage(caps, 1.0))

	syscalls := []uint64{1, 2, 3, 999}
	got := lm.filterSyscallsByUsage(syscalls, 0.5)
	assert.LessOrEqual(t, len(got), len(syscalls))
	// essentials retained.
	assert.Contains(t, got, uint64(1))

	ports := []NetworkPortRequirement{{Port: 443}, {Port: 80}, {Port: 12345}}
	assert.LessOrEqual(t, len(lm.filterNetworkPortsByUsage(ports, 0.5)), len(ports))

	paths := []FilePathRequirement{{Path: "/etc/passwd"}, {Path: "/opt/data"}}
	fp := lm.filterFilePathsByUsage(paths, 0.5)
	assert.LessOrEqual(t, len(fp), len(paths))
}

func TestCreateRollbackPlan(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	// High risk -> manual (non-automatic) rollback.
	plan := lm.createRollbackPlan(&ContainerLifecycleState{}, RequiredPrivileges{}, ImpactAssessment{RiskLevel: RiskLevelHigh})
	require.NotNil(t, plan)
	assert.True(t, plan.Enabled)
	assert.False(t, plan.AutomaticRollback)

	// Low risk -> automatic.
	plan = lm.createRollbackPlan(&ContainerLifecycleState{}, RequiredPrivileges{}, ImpactAssessment{RiskLevel: RiskLevelLow})
	assert.True(t, plan.AutomaticRollback)
}

func TestAssessTighteningImpact_RemovesSpecial(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	current := RequiredPrivileges{Syscalls: make([]uint64, 10), Special: []SpecialPrivilege{PrivilegeHostNetwork}}
	next := RequiredPrivileges{Syscalls: make([]uint64, 9)}
	impact := lm.assessTighteningImpact(nil, current, next)
	// Removing a special privilege escalates to high risk.
	assert.Equal(t, RiskLevelHigh, impact.RiskLevel)
	assert.NotEmpty(t, impact.PotentialImpacts)

	// Moderate reduction, no special removed -> medium.
	c2 := RequiredPrivileges{Syscalls: make([]uint64, 10)}
	n2 := RequiredPrivileges{Syscalls: make([]uint64, 4)}
	assert.Equal(t, RiskLevelMedium, lm.assessTighteningImpact(nil, c2, n2).RiskLevel)
}

func TestIsContainerStable(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	assert.False(t, lm.isContainerStable(nil, nil))

	// Too young.
	young := &ContainerLifecycleState{StartTime: time.Now()}
	assert.False(t, lm.isContainerStable(young, nil))

	// Old + high stability score.
	stable := &ContainerLifecycleState{
		StartTime:        time.Now().Add(-10 * time.Minute),
		StabilityMetrics: &StabilityMetrics{OverallScore: 0.9},
	}
	assert.True(t, lm.isContainerStable(stable, nil))

	// Old, steady phase, no score.
	steady := &ContainerLifecycleState{StartTime: time.Now().Add(-10 * time.Minute), CurrentPhase: ContainerPhaseSteady}
	assert.True(t, lm.isContainerStable(steady, nil))
}

func TestDiffSpecialAndPolicyMetrics(t *testing.T) {
	removed := diffSpecialPrivileges(
		[]SpecialPrivilege{PrivilegeHostNetwork, PrivilegePtrace},
		[]SpecialPrivilege{PrivilegePtrace},
	)
	assert.Equal(t, []SpecialPrivilege{PrivilegeHostNetwork}, removed)

	m := policyMetricsFromPrivileges(RequiredPrivileges{
		Syscalls: []uint64{1, 2}, NetworkPorts: []NetworkPortRequirement{{}}, FilePaths: []FilePathRequirement{{}}, Capabilities: []string{"a"},
	})
	assert.Equal(t, 2, m.SyscallCount)
	assert.Equal(t, 1, m.NetworkRuleCount)
}

func TestCalculatePrivilegeLevel_Special(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	assert.Equal(t, PrivilegeLevelPrivileged,
		lm.calculatePrivilegeLevel(RequiredPrivileges{Special: []SpecialPrivilege{PrivilegeDeviceAccess}}))
	assert.Equal(t, PrivilegeLevelElevated,
		lm.calculatePrivilegeLevel(RequiredPrivileges{Special: []SpecialPrivilege{PrivilegePtrace}}))
	assert.Equal(t, PrivilegeLevelReduced,
		lm.calculatePrivilegeLevel(RequiredPrivileges{Syscalls: make([]uint64, 10)}))
	assert.Equal(t, PrivilegeLevelStandard,
		lm.calculatePrivilegeLevel(RequiredPrivileges{Syscalls: make([]uint64, 50)}))
}

func TestSchedulerProcessesDueTasks(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "web", Namespace: "default"}
	require.NoError(t, lm.RegisterWorkload(ref, []string{"main"}, lifecyclePolicy()))
	key := lm.getWorkloadKey(ref)
	lm.workloadStates[key].ContainerStates["main"].CurrentPolicy = &GeneratedPolicy{
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}, 2: {}}},
	}

	pts := lm.policyTighteningScheduler
	pts.mu.Lock()
	pts.scheduledTightenings["main"] = []*ScheduledTighteningTask{{
		ID: "t1", ContainerID: "main", ScheduledTime: time.Now().Add(-time.Minute),
		TighteningType: TighteningTypeSyscall, Intensity: IntensityGentle, Status: TaskStatusPending,
	}}
	pts.mu.Unlock()

	pts.processScheduledTasks()
	// Give the async executeTask goroutine a moment.
	require.Eventually(t, func() bool {
		pts.mu.Lock()
		defer pts.mu.Unlock()
		return pts.scheduledTightenings["main"][0].Status == TaskStatusCompleted
	}, 2*time.Second, 10*time.Millisecond)
}

func TestLifecycleStartStop(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, lm.Start(ctx))
	cancel()
	lm.Stop()
}

// --- benchmarks ---

func BenchmarkTightenPolicy(b *testing.B) {
	lm := NewLifecycleManager(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "web", Namespace: "default"}
	_ = lm.RegisterWorkload(ref, []string{"main"}, lifecyclePolicy())
	key := lm.getWorkloadKey(ref)
	cs := lm.workloadStates[key].ContainerStates["main"]
	allowed := map[uint64]*SyscallRule{}
	for i := uint64(0); i < 200; i++ {
		allowed[i] = &SyscallRule{SyscallNr: i}
	}
	cs.CurrentPolicy = &GeneratedPolicy{SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: allowed}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lm.TightenPolicy("main", TighteningTypeCombined, IntensityModerate)
	}
}

func BenchmarkFilterSyscallsByUsage(b *testing.B) {
	lm := NewLifecycleManager(nil, nil)
	syscalls := make([]uint64, 300)
	for i := range syscalls {
		syscalls[i] = uint64(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lm.filterSyscallsByUsage(syscalls, 0.5)
	}
}
