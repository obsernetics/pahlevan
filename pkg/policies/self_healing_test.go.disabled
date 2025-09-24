package policies

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfHealingManager_NewSelfHealingManager(t *testing.T) {
	shm := NewSelfHealingManager(5, 10*time.Minute, 3, true)

	require.NotNil(t, shm)
	assert.Equal(t, 5, shm.maxRollbackAttempts)
	assert.Equal(t, 10*time.Minute, shm.rollbackWindow)
	assert.Equal(t, 3, shm.violationThreshold)
	assert.True(t, shm.emergencyModeEnabled)
}

func TestSelfHealingState_IsHealthy(t *testing.T) {
	tests := []struct {
		name                string
		state               *SelfHealingState
		expectedHealthy     bool
		expectedDescription string
	}{
		{
			name: "healthy state",
			state: &SelfHealingState{
				RollbackAttempts:    1,
				LastRollbackTime:    time.Now().Add(-1 * time.Hour),
				SuccessfulRollbacks: 5,
				FailedRollbacks:     0,
				EmergencyMode:       false,
			},
			expectedHealthy: true,
		},
		{
			name: "emergency mode",
			state: &SelfHealingState{
				RollbackAttempts:    10,
				LastRollbackTime:    time.Now(),
				SuccessfulRollbacks: 2,
				FailedRollbacks:     8,
				EmergencyMode:       true,
			},
			expectedHealthy: false,
		},
		{
			name: "too many failed rollbacks",
			state: &SelfHealingState{
				RollbackAttempts:    15,
				LastRollbackTime:    time.Now(),
				SuccessfulRollbacks: 1,
				FailedRollbacks:     14,
				EmergencyMode:       false,
			},
			expectedHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthy := tt.state.IsHealthy()
			assert.Equal(t, tt.expectedHealthy, healthy)
		})
	}
}

func TestRollbackAction_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		action  *RollbackAction
		expired bool
	}{
		{
			name: "not expired",
			action: &RollbackAction{
				ScheduledTime: time.Now().Add(1 * time.Hour),
				Timeout:       2 * time.Hour,
			},
			expired: false,
		},
		{
			name: "expired",
			action: &RollbackAction{
				ScheduledTime: time.Now().Add(-3 * time.Hour),
				Timeout:       1 * time.Hour,
			},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired := tt.action.IsExpired()
			assert.Equal(t, tt.expired, expired)
		})
	}
}

func TestEmergencyAction_ShouldExecute(t *testing.T) {
	tests := []struct {
		name           string
		action         *EmergencyAction
		currentSeverity ViolationSeverity
		shouldExecute  bool
	}{
		{
			name: "should execute on critical",
			action: &EmergencyAction{
				Type:             EmergencyActionDisableEnforcement,
				TriggerSeverity:  ViolationSeverityCritical,
				Priority:         ActionPriorityCritical,
			},
			currentSeverity: ViolationSeverityCritical,
			shouldExecute:   true,
		},
		{
			name: "should not execute on lower severity",
			action: &EmergencyAction{
				Type:             EmergencyActionDisableEnforcement,
				TriggerSeverity:  ViolationSeverityCritical,
				Priority:         ActionPriorityCritical,
			},
			currentSeverity: ViolationSeverityHigh,
			shouldExecute:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			should := tt.action.ShouldExecute(tt.currentSeverity)
			assert.Equal(t, tt.shouldExecute, should)
		})
	}
}

func TestRollbackCondition_IsMet(t *testing.T) {
	tests := []struct {
		name      string
		condition *RollbackCondition
		state     *ContainerPolicyState
		met       bool
	}{
		{
			name: "violation count threshold met",
			condition: &RollbackCondition{
				Type:      RollbackConditionViolationCount,
				Threshold: 5,
				Value:     "5",
			},
			state: &ContainerPolicyState{
				ViolationHistory: make([]PolicyViolation, 6),
			},
			met: true,
		},
		{
			name: "violation count threshold not met",
			condition: &RollbackCondition{
				Type:      RollbackConditionViolationCount,
				Threshold: 10,
				Value:     "10",
			},
			state: &ContainerPolicyState{
				ViolationHistory: make([]PolicyViolation, 5),
			},
			met: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			met := tt.condition.IsMet(tt.state)
			assert.Equal(t, tt.met, met)
		})
	}
}

func TestSelfHealingMetrics_UpdateSuccess(t *testing.T) {
	metrics := &SelfHealingMetrics{
		TotalRollbacks:      10,
		SuccessfulRollbacks: 8,
		FailedRollbacks:     2,
		AverageRecoveryTime: 5 * time.Minute,
	}

	metrics.UpdateSuccess(3 * time.Minute)

	assert.Equal(t, 11, metrics.TotalRollbacks)
	assert.Equal(t, 9, metrics.SuccessfulRollbacks)
	assert.Equal(t, 2, metrics.FailedRollbacks)
	// Average should be updated
	expectedAvg := ((5*time.Minute)*8 + 3*time.Minute) / 9
	assert.Equal(t, expectedAvg, metrics.AverageRecoveryTime)
}

func TestSelfHealingMetrics_UpdateFailure(t *testing.T) {
	metrics := &SelfHealingMetrics{
		TotalRollbacks:      10,
		SuccessfulRollbacks: 8,
		FailedRollbacks:     2,
		AverageRecoveryTime: 5 * time.Minute,
		LastRecoveryTime:    time.Now().Add(-1 * time.Hour),
	}

	metrics.UpdateFailure()

	assert.Equal(t, 11, metrics.TotalRollbacks)
	assert.Equal(t, 8, metrics.SuccessfulRollbacks)
	assert.Equal(t, 3, metrics.FailedRollbacks)
}

func TestSelfHealingMetrics_SuccessRate(t *testing.T) {
	tests := []struct {
		name     string
		metrics  *SelfHealingMetrics
		expected float64
	}{
		{
			name: "high success rate",
			metrics: &SelfHealingMetrics{
				TotalRollbacks:      10,
				SuccessfulRollbacks: 8,
			},
			expected: 0.8,
		},
		{
			name: "no rollbacks",
			metrics: &SelfHealingMetrics{
				TotalRollbacks:      0,
				SuccessfulRollbacks: 0,
			},
			expected: 0.0,
		},
		{
			name: "perfect success rate",
			metrics: &SelfHealingMetrics{
				TotalRollbacks:      5,
				SuccessfulRollbacks: 5,
			},
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate := tt.metrics.SuccessRate()
			assert.Equal(t, tt.expected, rate)
		})
	}
}