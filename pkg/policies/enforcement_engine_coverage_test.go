package policies

import (
	"context"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- helpers ---

func selfHealingPolicy() *policyv1alpha1.PahlevanPolicy {
	return &policyv1alpha1.PahlevanPolicy{
		Spec: policyv1alpha1.PahlevanPolicySpec{
			SelfHealing: policyv1alpha1.SelfHealingConfig{
				Enabled:           true,
				RollbackThreshold: 3,
				RollbackWindow:    &metav1.Duration{Duration: 10 * time.Minute},
				RecoveryStrategy:  policyv1alpha1.RecoveryStrategy("Rollback"),
			},
		},
	}
}

// seedLearnerProfile registers a container with the learner and generates an
// (empty but valid) profile so GetProfile succeeds.
func seedLearnerProfile(t *testing.T, containerID string) *learner.SyscallLearner {
	t.Helper()
	sl := learner.NewSyscallLearner(10, 0.7, time.Minute, 5)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "app", Namespace: "default"}
	require.NoError(t, sl.StartLearning(context.Background(), containerID, ref, &policyv1alpha1.PahlevanPolicy{}))
	_, err := sl.GenerateProfile(containerID)
	require.NoError(t, err)
	return sl
}

func fullProfile() *learner.LearningProfile {
	return &learner.LearningProfile{
		ContainerID: "c1",
		AllowedSyscalls: map[uint64]*learner.SyscallProfile{
			0: {SyscallNr: 0, Criticality: learner.CriticalityLow},
			1: {SyscallNr: 1, Criticality: learner.CriticalityLow},
			2: {SyscallNr: 2, Criticality: learner.CriticalityMedium},
		},
		AllowedNetworkFlows: map[string]*learner.NetworkFlowProfile{
			"out/tcp": {Protocol: "tcp", Direction: "outbound"},
			"in/tcp":  {Protocol: "tcp", Direction: "inbound"},
		},
		AllowedFilePaths: map[string]*learner.FileAccessProfile{
			"/etc/app.conf": {PathPattern: "/etc/app.conf", AllowedModes: []string{"read"}, FileTypes: []string{"conf"}, MaxSize: 4096},
			"/var/log/app":  {PathPattern: "/var/log/app", AllowedModes: []string{"read", "write"}},
		},
		SyscallStatistics: learner.SyscallStatistics{TotalCalls: 1500},
		Confidence:        0.9,
	}
}

// --- registration / lifecycle ---

func TestRegisterContainer_WithSelfHealing(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ref := learner.WorkloadReference{Kind: "Deployment", Name: "app", Namespace: "default"}
	require.NoError(t, ee.RegisterContainer("c1", ref, selfHealingPolicy()))

	state, err := ee.GetPolicyState("c1")
	require.NoError(t, err)
	require.NotNil(t, state.SelfHealingState)
	assert.True(t, state.SelfHealingState.Enabled)
	assert.Equal(t, int32(3), state.SelfHealingState.RollbackThreshold)
	assert.Equal(t, 10*time.Minute, state.SelfHealingState.RollbackWindow)
	assert.Equal(t, PhaseInitializing, state.LifecyclePhase)
}

// TestRegisterContainer_SelfHealingNilWindow guards the previous nil-deref bug:
// enabling self-healing without a RollbackWindow must not panic.
func TestRegisterContainer_SelfHealingNilWindow(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	policy := &policyv1alpha1.PahlevanPolicy{
		Spec: policyv1alpha1.PahlevanPolicySpec{
			SelfHealing: policyv1alpha1.SelfHealingConfig{Enabled: true, RollbackThreshold: 2},
		},
	}
	require.NotPanics(t, func() {
		_ = ee.RegisterContainer("c1", learner.WorkloadReference{}, policy)
	})
	state, err := ee.GetPolicyState("c1")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), state.SelfHealingState.RollbackWindow)
}

func TestGetPolicyState_NotFound(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	_, err := ee.GetPolicyState("missing")
	assert.Error(t, err)
}

func TestUnregisterContainer(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{ContainerID: "c1"}
	require.NoError(t, ee.UnregisterContainer("c1"))
	_, err := ee.GetPolicyState("c1")
	assert.Error(t, err)
}

func TestUpdateLifecyclePhase(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{ContainerID: "c1", LifecyclePhase: PhaseStarting}
	require.NoError(t, ee.UpdateLifecyclePhase("c1", PhaseRunning))
	state, _ := ee.GetPolicyState("c1")
	assert.Equal(t, PhaseRunning, state.LifecyclePhase)

	assert.Error(t, ee.UpdateLifecyclePhase("missing", PhaseRunning))
}

func TestProcessViolation_RecordsHistory(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:      "c1",
		SelfHealingState: &SelfHealingState{Enabled: true, RollbackThreshold: 10, RollbackWindow: time.Minute},
	}
	v := &PolicyViolation{
		Timestamp:     time.Now(),
		ViolationType: ViolationTypeSyscall,
		Severity:      ViolationSeverityHigh,
		Details:       ViolationDetails{Resource: "c1", AttemptedAction: "ptrace"},
	}
	require.NoError(t, ee.ProcessViolation(v))
	state, _ := ee.GetPolicyState("c1")
	assert.Len(t, state.ViolationHistory, 1)
	assert.Equal(t, int64(1), state.Statistics.ViolationCount)

	// Unknown container.
	assert.Error(t, ee.ProcessViolation(&PolicyViolation{Details: ViolationDetails{Resource: "missing"}}))
}

// --- policy generation ---

func TestGenerateSyscallPolicy_LearnedAndDangerous(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	profile := fullProfile()
	pol := ee.generateSyscallPolicy(profile, &policyv1alpha1.PahlevanPolicy{})
	require.NotNil(t, pol)
	// Learned syscalls allowed.
	assert.Contains(t, pol.AllowedSyscalls, uint64(0))
	assert.Contains(t, pol.AllowedSyscalls, uint64(2))
	// Dangerous syscalls (e.g. ptrace 101) denied since not learned.
	assert.Contains(t, pol.DeniedSyscalls, uint64(101))
	assert.Equal(t, PolicyActionDeny, pol.DefaultAction)
}

func TestGenerateSyscallPolicy_ExplicitOverrides(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	policy := &policyv1alpha1.PahlevanPolicy{
		Spec: policyv1alpha1.PahlevanPolicySpec{
			SyscallPolicy: &policyv1alpha1.SyscallPolicy{
				AllowedSyscalls: []string{"execve"},
				DeniedSyscalls:  []string{"mount"},
			},
		},
	}
	pol := ee.generateSyscallPolicy(fullProfile(), policy)
	assert.Contains(t, pol.AllowedSyscalls, uint64(59)) // execve
	assert.Contains(t, pol.DeniedSyscalls, uint64(165)) // mount
}

func TestGenerateNetworkPolicy_FromFlows(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	np, err := ee.generateNetworkPolicy(fullProfile(), &policyv1alpha1.PahlevanPolicy{})
	require.NoError(t, err)
	require.NotNil(t, np)
	assert.NotEmpty(t, np.EgressRules)  // includes learned + common DNS
	assert.NotEmpty(t, np.IngressRules) // learned inbound
	assert.Equal(t, PolicyActionDeny, np.DefaultEgressAction)
}

func TestCalculatePolicyStrictnessAndComplexity(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	policy := &GeneratedPolicy{
		SyscallPolicy: &SyscallEnforcementPolicy{
			AllowedSyscalls: map[uint64]*SyscallRule{1: {}, 2: {}},
			DeniedSyscalls:  map[uint64]*SyscallRule{101: {}},
			DefaultAction:   PolicyActionDeny,
		},
		NetworkPolicy: &NetworkEnforcementPolicy{
			DefaultEgressAction:  PolicyActionDeny,
			DefaultIngressAction: PolicyActionDeny,
			EgressRules:          []*NetworkRule{{}, {}},
		},
		FilePolicy: &FileEnforcementPolicy{
			AllowedPaths: map[string]*FileRule{"/a": {}},
		},
	}
	strict := ee.calculatePolicyStrictness(policy)
	assert.Greater(t, strict, 0.5)
	assert.LessOrEqual(t, strict, 1.0)

	complexity := ee.calculatePolicyComplexity(policy)
	assert.GreaterOrEqual(t, complexity, 0.0)
	assert.LessOrEqual(t, complexity, 1.0)
}

func TestCalculatePolicyQuality_NoProfileAndEmptyProfile(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	policy := &GeneratedPolicy{
		ContainerID:   "c1",
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{}, DefaultAction: PolicyActionDeny},
		NetworkPolicy: &NetworkEnforcementPolicy{DefaultEgressAction: PolicyActionDeny},
		FilePolicy:    &FileEnforcementPolicy{AllowedPaths: map[string]*FileRule{}},
	}
	// Manually specified (nil profile).
	q := ee.calculatePolicyQuality(policy, nil)
	assert.Equal(t, 0.7, q.Score)

	// Empty profile must not produce NaN completeness (divide-by-zero guard).
	empty := &learner.LearningProfile{ContainerID: "c1"}
	q2 := ee.calculatePolicyQuality(policy, empty)
	assert.False(t, q2.Completeness != q2.Completeness, "completeness must not be NaN")
	assert.GreaterOrEqual(t, q2.Score, 0.0)
}

// --- eBPF application paths (nil / empty manager return errors) ---

func TestApplyPolicyToEBPF_NilManager(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	err := ee.applyPolicyToEBPF("c1", &GeneratedPolicy{SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}}}})
	assert.Error(t, err)
}

func TestApplyPolicyToEBPF_UnloadedManager(t *testing.T) {
	ee := NewEnforcementEngine(&ebpf.Manager{}, nil)
	policy := &GeneratedPolicy{
		Version:       1,
		SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}}},
		NetworkPolicy: &NetworkEnforcementPolicy{EgressRules: []*NetworkRule{{}}},
		FilePolicy:    &FileEnforcementPolicy{AllowedPaths: map[string]*FileRule{"/a": {}}},
	}
	// Collection not loaded -> error, but exercises the conversion path.
	assert.Error(t, ee.applyPolicyToEBPF("c1", policy))
}

func TestGeneratePolicy_EndToEnd_SeededProfile(t *testing.T) {
	sl := seedLearnerProfile(t, "c1")
	ee := NewEnforcementEngine(nil, sl)
	require.NoError(t, ee.RegisterContainer("c1", learner.WorkloadReference{}, &policyv1alpha1.PahlevanPolicy{}))

	// applyPolicyToEBPF fails (nil manager) but the generation path runs.
	_, err := ee.GeneratePolicy("c1")
	assert.Error(t, err)

	// Unknown container.
	_, err = ee.GeneratePolicy("missing")
	assert.Error(t, err)
}

// --- violation handling & self-healing orchestration ---

func TestHandleViolationAction(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:     "c1",
		EnforcementMode: EnforcementModeMonitoring,
	}
	// Missing violation.
	assert.Error(t, ee.handleViolationAction(&EnforcementAction{ContainerID: "c1"}))

	// High severity -> increaseMonitoring.
	act := &EnforcementAction{
		ContainerID: "c1",
		Violation:   &PolicyViolation{Severity: ViolationSeverityHigh, Timestamp: time.Now()},
	}
	require.NoError(t, ee.handleViolationAction(act))
	assert.Equal(t, EnforcementModeBlocking, ee.containerPolicies["c1"].EnforcementMode)

	// Low severity -> just logs.
	require.NoError(t, ee.handleViolationAction(&EnforcementAction{
		ContainerID: "c1",
		Violation:   &PolicyViolation{Severity: ViolationSeverityLow, Timestamp: time.Now()},
	}))

	// Unknown container.
	assert.Error(t, ee.handleViolationAction(&EnforcementAction{
		ContainerID: "missing",
		Violation:   &PolicyViolation{Severity: ViolationSeverityLow},
	}))
}

func TestHandleCriticalViolation_TightensAfterThreshold(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	now := time.Now()
	state := &ContainerPolicyState{
		ContainerID:     "c1",
		GeneratedPolicy: &GeneratedPolicy{ContainerID: "c1", Version: 1, SyscallPolicy: &SyscallEnforcementPolicy{AllowedSyscalls: map[uint64]*SyscallRule{1: {}}}},
	}
	for i := 0; i < 3; i++ {
		state.ViolationHistory = append(state.ViolationHistory, PolicyViolation{Timestamp: now, Severity: ViolationSeverityCritical})
	}
	ee.containerPolicies["c1"] = state

	// 3 recent critical violations -> tightenPolicy, which fails at eBPF (nil mgr).
	err := ee.handleCriticalViolation("c1", &PolicyViolation{Severity: ViolationSeverityCritical, ViolationType: ViolationTypeSyscall})
	assert.Error(t, err) // eBPF apply fails

	// Below threshold: no tightening, no error.
	ee.containerPolicies["c2"] = &ContainerPolicyState{ContainerID: "c2"}
	require.NoError(t, ee.handleCriticalViolation("c2", &PolicyViolation{Severity: ViolationSeverityCritical}))

	assert.Error(t, ee.handleCriticalViolation("missing", &PolicyViolation{}))
}

func TestPerformSelfHealing_Strategies(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)

	// Not enabled.
	ee.containerPolicies["c0"] = &ContainerPolicyState{ContainerID: "c0"}
	assert.Error(t, ee.performSelfHealing("c0"))

	// rollback strategy triggered via few violations => "none".
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:      "c1",
		SelfHealingState: &SelfHealingState{Enabled: true},
	}
	require.NoError(t, ee.performSelfHealing("c1")) // strategy "none"

	// adjust_thresholds (6-10 violations).
	adj := &ContainerPolicyState{
		ContainerID:      "c2",
		GeneratedPolicy:  &GeneratedPolicy{Confidence: 1.0},
		SelfHealingState: &SelfHealingState{Enabled: true},
	}
	for i := 0; i < 7; i++ {
		adj.ViolationHistory = append(adj.ViolationHistory, PolicyViolation{})
	}
	ee.containerPolicies["c2"] = adj
	require.NoError(t, ee.performSelfHealing("c2"))
	assert.Less(t, ee.containerPolicies["c2"].GeneratedPolicy.Confidence, 1.0)

	assert.Error(t, ee.performSelfHealing("missing"))
}

func TestDetermineSelfHealingStrategy(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	mk := func(n int) *ContainerPolicyState {
		s := &ContainerPolicyState{}
		for i := 0; i < n; i++ {
			s.ViolationHistory = append(s.ViolationHistory, PolicyViolation{})
		}
		return s
	}
	assert.Equal(t, "regenerate_policy", ee.determineSelfHealingStrategy(mk(11)))
	assert.Equal(t, "adjust_thresholds", ee.determineSelfHealingStrategy(mk(6)))
	assert.Equal(t, "none", ee.determineSelfHealingStrategy(mk(1)))
}

func TestShouldTriggerSelfHealing_EE(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	assert.False(t, ee.shouldTriggerSelfHealing(&ContainerPolicyState{}))

	s := &ContainerPolicyState{SelfHealingState: &SelfHealingState{Enabled: true}}
	now := time.Now()
	for i := 0; i < 6; i++ {
		s.ViolationHistory = append(s.ViolationHistory, PolicyViolation{Timestamp: now})
	}
	assert.True(t, ee.shouldTriggerSelfHealing(s))
}

func TestUpdateSelfHealingState_QueuesHeal(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	state := &ContainerPolicyState{
		ContainerID:      "c1",
		SelfHealingState: &SelfHealingState{Enabled: true, RollbackThreshold: 2, RollbackWindow: time.Hour},
	}
	now := time.Now()
	ee.updateSelfHealingState(state, &PolicyViolation{Timestamp: now})
	ee.updateSelfHealingState(state, &PolicyViolation{Timestamp: now})
	assert.Equal(t, int32(2), state.SelfHealingState.ViolationCount)

	// nil self-healing state is a no-op.
	ee.updateSelfHealingState(&ContainerPolicyState{}, &PolicyViolation{})
}

func TestShouldAdaptPolicyForLifecycle(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	assert.True(t, ee.shouldAdaptPolicyForLifecycle(PhaseStarting, PhaseRunning))
	assert.True(t, ee.shouldAdaptPolicyForLifecycle(PhaseRunning, PhaseSteady))
	assert.False(t, ee.shouldAdaptPolicyForLifecycle(PhaseInitializing, PhaseTerminating))
}

func TestRememberPreviousPolicy(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	// No self-healing: no-op.
	ee.rememberPreviousPolicy(&ContainerPolicyState{}, &GeneratedPolicy{})

	cur := &GeneratedPolicy{Version: 1}
	next := &GeneratedPolicy{Version: 2}
	state := &ContainerPolicyState{GeneratedPolicy: cur, SelfHealingState: &SelfHealingState{}}
	ee.rememberPreviousPolicy(state, next)
	assert.Same(t, cur, state.SelfHealingState.PreviousPolicy)
	assert.Same(t, next, state.SelfHealingState.CurrentPolicy)
}

func TestDetermineEnforcementMode(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	// Empty -> default.
	assert.Equal(t, EnforcementModeMonitoring, ee.determineEnforcementMode(&policyv1alpha1.PahlevanPolicy{}))
	// Explicit.
	p := &policyv1alpha1.PahlevanPolicy{Spec: policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementMode("Blocking")},
	}}
	assert.Equal(t, EnforcementModeBlocking, ee.determineEnforcementMode(p))
}

func TestParseSyscallName(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	assert.Equal(t, uint64(101), ee.parseSyscallName("ptrace"))
	assert.Equal(t, uint64(42), ee.parseSyscallName("42"))
	// Unknown -> hashed into range.
	h := ee.parseSyscallName("totally-unknown-syscall")
	assert.Less(t, h, uint64(400))
}

func TestKnownSyscallNumber(t *testing.T) {
	n, ok := knownSyscallNumber("execve")
	assert.True(t, ok)
	assert.Equal(t, uint64(59), n)
	n, ok = knownSyscallNumber(" 200 ")
	assert.True(t, ok)
	assert.Equal(t, uint64(200), n)
	_, ok = knownSyscallNumber("")
	assert.False(t, ok)
	_, ok = knownSyscallNumber("nope")
	assert.False(t, ok)
}

func TestFlowKey(t *testing.T) {
	assert.Equal(t, "outbound/tcp", flowKey("Outbound", "TCP"))
}

func TestEnsureFileRule(t *testing.T) {
	paths := map[string]*FileRule{}
	ensureFileRule(paths, "/a", "read")
	ensureFileRule(paths, "/a", "read", "write") // no duplicate "read"
	require.Contains(t, paths, "/a")
	assert.ElementsMatch(t, []string{"read", "write"}, paths["/a"].AccessModes)
	ensureFileRule(paths, "", "read") // ignored
	assert.Len(t, paths, 1)
}

func TestQueueAndProcessEnforcementAction(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{ContainerID: "c1"}
	// processEnforcementAction routes by type; unknown container generate errors
	// are logged, not returned.
	ee.processEnforcementAction(&EnforcementAction{Type: ActionTypeGeneratePolicy, ContainerID: "missing"})
	ee.processEnforcementAction(&EnforcementAction{Type: ActionTypeUpdatePolicy, ContainerID: "missing"})
	ee.processEnforcementAction(&EnforcementAction{Type: ActionTypeViolation, ContainerID: "c1", Violation: &PolicyViolation{Severity: ViolationSeverityLow, Timestamp: time.Now()}})
	ee.processEnforcementAction(&EnforcementAction{Type: ActionTypeSelfHeal, ContainerID: "missing"})

	// Fill the queue to exercise the drop path.
	for i := 0; i < cap(ee.enforcementQueue); i++ {
		ee.queueEnforcementAction(&EnforcementAction{Type: ActionTypeGeneratePolicy})
	}
	ee.queueEnforcementAction(&EnforcementAction{Type: ActionTypeGeneratePolicy}) // dropped
}

func TestUpdateStatisticsAndPeriodicUpdate(t *testing.T) {
	sl := seedLearnerProfile(t, "c1")
	ee := NewEnforcementEngine(nil, sl)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:      "c1",
		GeneratedPolicy:  &GeneratedPolicy{},
		LastPolicyUpdate: time.Now().Add(-2 * time.Hour),
		ViolationHistory: []PolicyViolation{{}, {}},
	}
	ee.updateStatistics()
	assert.Equal(t, int64(2), ee.containerPolicies["c1"].Statistics.ViolationCount)

	ee.triggerPeriodicPolicyUpdate() // queues a regen for the stale policy
	ee.processSelfHealingActions()   // no self-healing enabled -> no-op
}

func TestAdjustPolicyThresholds(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:     "c1",
		GeneratedPolicy: &GeneratedPolicy{Confidence: 1.0},
	}
	require.NoError(t, ee.adjustPolicyThresholds("c1"))
	assert.InDelta(t, 0.95, ee.containerPolicies["c1"].GeneratedPolicy.Confidence, 0.0001)
}

func TestStartStop(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, ee.Start(ctx))
	cancel()
	ee.Stop()
}

func TestUpdateContainerPolicy(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{ContainerID: "c1", SelfHealingState: &SelfHealingState{}}
	p := &GeneratedPolicy{Version: 5}
	// nil ebpf manager: UpdateContainerPolicy should still update in-memory state
	// or return an error deterministically without panic.
	require.NotPanics(t, func() { _ = ee.UpdateContainerPolicy("c1", p) })
}

// --- benchmarks ---

func BenchmarkCreateTightenedPolicy(b *testing.B) {
	ee := NewEnforcementEngine(nil, nil)
	profile := &learner.LearningProfile{ContainerID: "c1", AllowedSyscalls: map[uint64]*learner.SyscallProfile{}}
	allowed := map[uint64]*SyscallRule{}
	for i := uint64(0); i < 300; i++ {
		profile.AllowedSyscalls[i] = &learner.SyscallProfile{SyscallNr: i}
		allowed[i] = &SyscallRule{SyscallNr: i, Action: PolicyActionAllow}
	}
	allowed[999] = &SyscallRule{SyscallNr: 999, Action: PolicyActionAllow}
	original := &GeneratedPolicy{
		ContainerID:    "c1",
		Version:        1,
		BasedOnProfile: profile,
		SyscallPolicy:  &SyscallEnforcementPolicy{AllowedSyscalls: allowed, DeniedSyscalls: map[uint64]*SyscallRule{}},
	}
	violation := &PolicyViolation{ViolationType: ViolationTypeSyscall, Details: ViolationDetails{AttemptedAction: "999"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ee.createTightenedPolicy(original, violation)
	}
}

func BenchmarkGenerateSyscallPolicy(b *testing.B) {
	ee := NewEnforcementEngine(nil, nil)
	profile := &learner.LearningProfile{ContainerID: "c1", AllowedSyscalls: map[uint64]*learner.SyscallProfile{}}
	for i := uint64(0); i < 300; i++ {
		profile.AllowedSyscalls[i] = &learner.SyscallProfile{SyscallNr: i}
	}
	empty := &policyv1alpha1.PahlevanPolicy{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ee.generateSyscallPolicy(profile, empty)
	}
}
