package policies

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssessHealth_FlagsCrashloop verifies the health assessment flags a
// crash-looping container (high restart count) as critical.
func TestAssessHealth_FlagsCrashloop(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)

	state := &HealingState{
		ContainerID:  "c1",
		Ready:        true,
		RestartCount: 10, // crash loop
	}

	health := shm.assessHealth(state)
	require.NotNil(t, health)
	assert.Equal(t, HealthLevelCritical, health.Overall)
}

// TestAssessHealth_HealthyBaseline verifies a stable container is healthy.
func TestAssessHealth_HealthyBaseline(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	state := &HealingState{ContainerID: "c1", Ready: true}
	health := shm.assessHealth(state)
	assert.Equal(t, HealthLevelHealthy, health.Overall)
}

// TestAssessHealth_ViolationSpike flags a burst of recent violations.
func TestAssessHealth_ViolationSpike(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	state := &HealingState{ContainerID: "c1", Ready: true}
	now := time.Now()
	for i := 0; i < 12; i++ {
		state.ViolationHistory = append(state.ViolationHistory, &ViolationEvent{
			Timestamp: now.Add(-time.Duration(i) * time.Second),
			Severity:  ViolationSeverityMedium,
		})
	}
	health := shm.assessHealth(state)
	assert.Equal(t, HealthLevelCritical, health.Overall)
	require.NotNil(t, health.ErrorMetrics)
	assert.Greater(t, health.ErrorMetrics.ErrorCount, int64(0))
}

// TestZScoreAnomalyAlgorithm_FlagsOutlier verifies statistical anomaly detection
// flags a point far from the learned baseline mean/stddev.
func TestZScoreAnomalyAlgorithm_FlagsOutlier(t *testing.T) {
	algo := &ZScoreAnomalyAlgorithm{Threshold: 3.0}
	baseline := &Baseline{}

	// Baseline with some variance around ~5.
	require.NoError(t, algo.UpdateBaseline([]float64{4, 5, 6, 5, 4, 6, 5}, baseline))
	assert.InDelta(t, 5.0, baseline.Mean, 0.5)
	assert.Greater(t, baseline.StandardDev, 0.0)

	// An outlier of 100 must be flagged.
	anomalies, err := algo.DetectAnomalies([]float64{100}, baseline)
	require.NoError(t, err)
	require.Len(t, anomalies, 1)
	assert.Greater(t, anomalies[0].Score, 3.0)
	assert.Equal(t, 100.0, anomalies[0].Value)

	// A normal value must not be flagged.
	anomalies, err = algo.DetectAnomalies([]float64{5}, baseline)
	require.NoError(t, err)
	assert.Empty(t, anomalies)
}

// TestZScoreAnomalyAlgorithm_ZeroVariance handles a constant baseline.
func TestZScoreAnomalyAlgorithm_ZeroVariance(t *testing.T) {
	algo := &ZScoreAnomalyAlgorithm{Threshold: 3.0}
	baseline := &Baseline{}
	require.NoError(t, algo.UpdateBaseline([]float64{1, 1, 1, 1, 1}, baseline))
	assert.Equal(t, 0.0, baseline.StandardDev)

	anomalies, err := algo.DetectAnomalies([]float64{10}, baseline)
	require.NoError(t, err)
	assert.Len(t, anomalies, 1)
}

// TestAnalyzeBehaviorRate flags an upward spike in the current bucket.
func TestAnalyzeBehaviorRate(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	require.NoError(t, shm.initializeComponents())

	now := time.Now()
	state := &HealingState{ContainerID: "c1"}
	// One violation per minute for buckets 2..13 minutes ago (steady baseline).
	for m := 2; m <= 13; m++ {
		state.ViolationHistory = append(state.ViolationHistory, &ViolationEvent{
			Timestamp: now.Add(-time.Duration(m)*time.Minute - 10*time.Second),
		})
	}
	// A spike in the most recent minute.
	for i := 0; i < 15; i++ {
		state.ViolationHistory = append(state.ViolationHistory, &ViolationEvent{
			Timestamp: now.Add(-time.Duration(i) * time.Second),
		})
	}

	anomaly, ok := shm.analyzeBehaviorRate("c1", state)
	require.True(t, ok, "expected the current-minute spike to be flagged")
	assert.Greater(t, anomaly.Value, anomaly.ExpectedValue)
}

func TestViolationRateSeries(t *testing.T) {
	now := time.Now()
	violations := []*ViolationEvent{
		{Timestamp: now.Add(-30 * time.Second)}, // current bucket
		{Timestamp: now.Add(-10 * time.Second)}, // current bucket
		{Timestamp: now.Add(-90 * time.Second)}, // 1 bucket back
	}
	series := violationRateSeries(violations, time.Minute, 5)
	require.Len(t, series, 5)
	assert.Equal(t, 2.0, series[len(series)-1]) // most recent minute
	assert.Equal(t, 1.0, series[len(series)-2])
}

// TestShouldTriggerSelfHealing_Crashloop verifies the decision logic triggers
// on a crash-looping container.
func TestShouldTriggerSelfHealing_Crashloop(t *testing.T) {
	shm := NewSelfHealingManager(nil, nil)
	state := &HealingState{ContainerID: "c1", RestartCount: 6}
	v := &ViolationEvent{Severity: ViolationSeverityHigh, Timestamp: time.Now()}
	assert.True(t, shm.shouldTriggerSelfHealing(state, v))
}
