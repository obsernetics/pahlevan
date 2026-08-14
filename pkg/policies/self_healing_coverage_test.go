package policies

import (
	"context"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registeredSHM(t *testing.T, containerID string) *SelfHealingManager {
	t.Helper()
	shm := NewSelfHealingManager(nil, nil)
	require.NoError(t, shm.initializeComponents())
	require.NoError(t, shm.RegisterContainer(containerID, learner.WorkloadReference{Name: "app", Namespace: "default"},
		&policyv1alpha1.PahlevanPolicy{Spec: policyv1alpha1.PahlevanPolicySpec{
			SelfHealing: policyv1alpha1.SelfHealingConfig{Enabled: true, RecoveryStrategy: policyv1alpha1.RecoveryStrategy("Rollback")},
		}}))
	return shm
}

// TestRegisterAndPerformHealthCheck verifies the previously-broken
// PerformHealthCheck now works: RegisterContainer wires a real HealthChecker.
func TestRegisterAndPerformHealthCheck(t *testing.T) {
	shm := registeredSHM(t, "c1")

	health, err := shm.PerformHealthCheck("c1")
	require.NoError(t, err)
	require.NotNil(t, health)
	assert.Equal(t, HealthLevelHealthy, health.Overall)

	// Crash-loop the container -> critical.
	require.NoError(t, shm.UpdateContainerRuntimeStatus("c1", 10, false))
	health, err = shm.PerformHealthCheck("c1")
	require.NoError(t, err)
	assert.Equal(t, HealthLevelCritical, health.Overall)

	// Unknown container.
	_, err = shm.PerformHealthCheck("missing")
	assert.Error(t, err)
}

func TestGetHealingStateAndUnregister(t *testing.T) {
	shm := registeredSHM(t, "c1")
	state, err := shm.GetHealingState("c1")
	require.NoError(t, err)
	assert.Equal(t, "c1", state.ContainerID)

	require.NoError(t, shm.UnregisterContainer("c1"))
	_, err = shm.GetHealingState("c1")
	assert.Error(t, err)
}

func TestUpdateContainerRuntimeStatus(t *testing.T) {
	shm := registeredSHM(t, "c1")
	require.NoError(t, shm.UpdateContainerRuntimeStatus("c1", 1, false))
	require.NoError(t, shm.UpdateContainerRuntimeStatus("c1", 2, false))
	st, _ := shm.GetHealingState("c1")
	assert.Equal(t, int32(2), st.RestartCount)
	assert.GreaterOrEqual(t, st.ReadinessProbeFailures, 2)

	// Recovery to ready resets readiness failures.
	require.NoError(t, shm.UpdateContainerRuntimeStatus("c1", 2, true))
	st, _ = shm.GetHealingState("c1")
	assert.True(t, st.Ready)

	assert.Error(t, shm.UpdateContainerRuntimeStatus("missing", 0, true))
}

func TestProcessViolation_SH(t *testing.T) {
	shm := registeredSHM(t, "c1")
	// Low severity: recorded, not triggering.
	require.NoError(t, shm.ProcessViolation("c1", &PolicyViolation{Timestamp: time.Now(), Severity: ViolationSeverityLow}))
	st, _ := shm.GetHealingState("c1")
	assert.Len(t, st.ViolationHistory, 1)

	assert.Error(t, shm.ProcessViolation("missing", &PolicyViolation{}))
}

func TestDetermineHealingAction(t *testing.T) {
	shm := registeredSHM(t, "c1")
	state := &HealingState{ContainerID: "c1"}

	// Critical -> emergency.
	assert.Equal(t, ResolutionActionEmergency,
		shm.determineHealingAction(state, &ViolationEvent{Severity: ViolationSeverityCritical}))

	// Emergency mode -> emergency.
	state.EmergencyMode = true
	assert.Equal(t, ResolutionActionEmergency,
		shm.determineHealingAction(state, &ViolationEvent{Severity: ViolationSeverityHigh}))
	state.EmergencyMode = false

	// Many high-severity recent -> emergency.
	now := time.Now()
	for i := 0; i < 4; i++ {
		state.ViolationHistory = append(state.ViolationHistory, &ViolationEvent{Timestamp: now, Severity: ViolationSeverityHigh})
	}
	assert.Equal(t, ResolutionActionEmergency,
		shm.determineHealingAction(state, &ViolationEvent{Severity: ViolationSeverityHigh}))

	// Moderate count with policy history -> relax.
	state2 := &HealingState{
		ContainerID:   "c2",
		PolicyHistory: []*PolicySnapshot{{}, {}},
		ViolationHistory: []*ViolationEvent{
			{Timestamp: now, Severity: ViolationSeverityMedium},
		},
	}
	assert.Equal(t, ResolutionActionRelax,
		shm.determineHealingAction(state2, &ViolationEvent{Severity: ViolationSeverityHigh}))
}

func TestFindRollbackTarget(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	// Insufficient history.
	_, err := shm.findRollbackTarget(&HealingState{})
	assert.Error(t, err)

	p := &GeneratedPolicy{Version: 1}
	state := &HealingState{PolicyHistory: []*PolicySnapshot{{Policy: p}, {Policy: &GeneratedPolicy{Version: 2}}}}
	target, err := shm.findRollbackTarget(state)
	require.NoError(t, err)
	assert.Same(t, p, target)
}

func TestTriggerRollback_NeedsHistory(t *testing.T) {
	shm := registeredSHM(t, "c1")
	// No policy history -> findRollbackTarget errors.
	err := shm.TriggerRollback("c1", "test", RollbackTypeManual)
	assert.Error(t, err)

	// Already in progress.
	st, _ := shm.GetHealingState("c1")
	_ = st
	shm.mu.Lock()
	shm.healingStates["c1"].HealingInProgress = true
	shm.mu.Unlock()
	assert.Error(t, shm.TriggerRollback("c1", "test", RollbackTypeManual))

	assert.Error(t, shm.TriggerRollback("missing", "test", RollbackTypeManual))
}

func TestRelaxPolicy(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	state := &HealingState{ContainerID: "c1"}
	// No current policy -> error.
	assert.Error(t, shm.relaxPolicy(state, &ViolationEvent{}))

	state.CurrentPolicy = &GeneratedPolicy{}
	require.NoError(t, shm.relaxPolicy(state, &ViolationEvent{Details: ViolationDetails{Resource: "/x"}}))
}

func TestHealthLevelToScore(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	assert.Equal(t, 1.0, shm.healthLevelToScore(HealthLevelHealthy))
	assert.Equal(t, 0.7, shm.healthLevelToScore(HealthLevelWarning))
	assert.Equal(t, 0.3, shm.healthLevelToScore(HealthLevelCritical))
	assert.Equal(t, 0.1, shm.healthLevelToScore(HealthLevelFailing))
	assert.Equal(t, 0.5, shm.healthLevelToScore(HealthLevelUnknown))
}

func TestAssessHealth_NilAndReadiness(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	assert.Equal(t, HealthLevelUnknown, shm.assessHealth(nil).Overall)

	// Not ready + restarts -> critical.
	assert.Equal(t, HealthLevelCritical, shm.assessHealth(&HealingState{Ready: false, RestartCount: 3}).Overall)

	// Not ready alone -> warning.
	assert.Equal(t, HealthLevelWarning, shm.assessHealth(&HealingState{Ready: false}).Overall)
}

func TestDetectionHelpers(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)

	// system compromise: many violations.
	comp := &HealingState{}
	for i := 0; i < 101; i++ {
		comp.ViolationHistory = append(comp.ViolationHistory, &ViolationEvent{})
	}
	assert.True(t, shm.detectSystemCompromise("c1", comp))

	// dangerous pattern (syscall/network > 5).
	danger := &HealingState{}
	for i := 0; i < 6; i++ {
		danger.ViolationHistory = append(danger.ViolationHistory, &ViolationEvent{ViolationType: ViolationTypeSyscall})
	}
	assert.True(t, shm.detectSystemCompromise("c1", danger))

	// resource exhaustion.
	assert.False(t, shm.detectResourceExhaustion("c1", &HealingState{}))
	assert.True(t, shm.detectResourceExhaustion("c1", &HealingState{
		HealthStatus:        &HealthStatus{Overall: HealthLevelCritical},
		ConsecutiveFailures: 4,
	}))

	// compromise indicators.
	ind := shm.getCompromiseIndicators(danger)
	assert.NotEmpty(t, ind)
}

func TestAnomalyPatternHelpers(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)

	assert.False(t, shm.hasAnomalousViolationPattern(&HealingState{}))

	// > 10 violations in last hour.
	burst := &HealingState{}
	now := time.Now()
	for i := 0; i < 11; i++ {
		burst.ViolationHistory = append(burst.ViolationHistory, &ViolationEvent{Timestamp: now})
	}
	assert.True(t, shm.hasAnomalousViolationPattern(burst))

	// 3 distinct types in last 5.
	diverse := &HealingState{ViolationHistory: []*ViolationEvent{
		{Timestamp: now.Add(-2 * time.Hour), ViolationType: ViolationTypeSyscall},
		{Timestamp: now.Add(-2 * time.Hour), ViolationType: ViolationTypeNetwork},
		{Timestamp: now.Add(-2 * time.Hour), ViolationType: ViolationTypeFile},
		{Timestamp: now.Add(-2 * time.Hour), ViolationType: ViolationTypeSyscall},
		{Timestamp: now.Add(-2 * time.Hour), ViolationType: ViolationTypeNetwork},
	}}
	assert.True(t, shm.hasAnomalousViolationPattern(diverse))

	assert.False(t, shm.hasResourceAnomalies(&HealingState{}))
	assert.True(t, shm.hasResourceAnomalies(&HealingState{HealthStatus: &HealthStatus{Overall: HealthLevelFailing}}))
}

func TestEvaluateHealthEscalation(t *testing.T) {
	shm := registeredSHM(t, "c1")
	// Healthy resets failures.
	shm.evaluateHealthEscalation("c1", &HealthStatus{Overall: HealthLevelHealthy})
	st, _ := shm.GetHealingState("c1")
	assert.Equal(t, 0, st.ConsecutiveFailures)

	// Critical increments.
	shm.evaluateHealthEscalation("c1", &HealthStatus{Overall: HealthLevelCritical})
	st, _ = shm.GetHealingState("c1")
	assert.Equal(t, 1, st.ConsecutiveFailures)

	// Unknown container is a no-op.
	shm.evaluateHealthEscalation("missing", &HealthStatus{Overall: HealthLevelCritical})
}

func TestCheckEmergencyConditions(t *testing.T) {
	shm := registeredSHM(t, "c1")
	shm.mu.Lock()
	s := shm.healingStates["c1"]
	for i := 0; i < 51; i++ {
		s.ViolationHistory = append(s.ViolationHistory, &ViolationEvent{})
	}
	s.ConsecutiveFailures = 6
	s.EmergencyMode = true
	s.HealthStatus = &HealthStatus{Overall: HealthLevelCritical}
	shm.mu.Unlock()
	require.NotPanics(t, func() { shm.checkEmergencyConditions(context.Background()) })
}

func TestZScoreGetMetadata(t *testing.T) {
	algo := &ZScoreAnomalyAlgorithm{}
	md := algo.GetMetadata()
	assert.Equal(t, "zscore", md.Name)
	assert.Equal(t, 3.0, md.Parameters["threshold"])
}

func TestMeanStdDevAndSeverity(t *testing.T) {
	m, sd := meanStdDev([]float64{2, 4, 6})
	assert.InDelta(t, 4.0, m, 0.0001)
	assert.Greater(t, sd, 0.0)
	m, sd = meanStdDev(nil)
	assert.Equal(t, 0.0, m)
	assert.Equal(t, 0.0, sd)

	assert.Equal(t, ViolationSeverityCritical, zScoreToSeverity(7, 3))
	assert.Equal(t, ViolationSeverityHigh, zScoreToSeverity(5, 3))
	assert.Equal(t, ViolationSeverityMedium, zScoreToSeverity(3.1, 3))
}

func TestRecordAnomaly(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	require.NoError(t, shm.initializeComponents())
	for i := 0; i < 105; i++ {
		shm.recordAnomaly("c1", &Anomaly{Value: float64(i)})
	}
	shm.anomalyDetector.mu.Lock()
	defer shm.anomalyDetector.mu.Unlock()
	assert.LessOrEqual(t, len(shm.anomalyDetector.anomalyHistory["c1"]), 100)

	// nil-safe.
	shm.recordAnomaly("c1", nil)
}

func TestStartStop_SH(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, shm.Start(ctx))
	cancel()
	shm.Stop()
}

// --- benchmarks ---

func BenchmarkDetectAnomalies(b *testing.B) {
	algo := &ZScoreAnomalyAlgorithm{Threshold: 3.0}
	baseline := &Baseline{}
	hist := make([]float64, 0, 60)
	for i := 0; i < 60; i++ {
		hist = append(hist, float64(4+i%3))
	}
	_ = algo.UpdateBaseline(hist, baseline)
	data := []float64{5, 6, 100, 4, 5}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = algo.DetectAnomalies(data, baseline)
	}
}

func BenchmarkAssessHealth(b *testing.B) {
	shm := NewSelfHealingManager(nil, nil)
	state := &HealingState{ContainerID: "c1", Ready: true}
	now := time.Now()
	for i := 0; i < 200; i++ {
		state.ViolationHistory = append(state.ViolationHistory, &ViolationEvent{
			Timestamp: now.Add(-time.Duration(i) * time.Second),
			Severity:  ViolationSeverityMedium,
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = shm.assessHealth(state)
	}
}

func BenchmarkViolationRateSeries(b *testing.B) {
	now := time.Now()
	violations := make([]*ViolationEvent, 0, 500)
	for i := 0; i < 500; i++ {
		violations = append(violations, &ViolationEvent{Timestamp: now.Add(-time.Duration(i) * time.Second)})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = violationRateSeries(violations, time.Minute, 15)
	}
}
