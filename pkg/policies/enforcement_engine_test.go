package policies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerPolicyState_NewContainerPolicyState(t *testing.T) {
	state := &ContainerPolicyState{
		ContainerID:        "test-container",
		GeneratedPolicy:    nil,
		EnforcementMode:    EnforcementModeMonitoring,
		ViolationHistory:   make([]PolicyViolation, 0),
		SelfHealingState:   nil,
	}

	require.NotNil(t, state)
	assert.Equal(t, "test-container", state.ContainerID)
	assert.Equal(t, EnforcementModeMonitoring, state.EnforcementMode)
	assert.Empty(t, state.ViolationHistory)
}

func TestGlobalEnforcementConfig_Default(t *testing.T) {
	config := &GlobalEnforcementConfig{
		DefaultEnforcementMode:   EnforcementModeMonitoring,
		PolicyGenerationInterval: 300, // 5 minutes
		ViolationThreshold:       10,
		SelfHealingEnabled:       true,
		MetricsEnabled:          true,
	}

	require.NotNil(t, config)
	assert.Equal(t, EnforcementModeMonitoring, config.DefaultEnforcementMode)
	assert.Equal(t, int32(10), config.ViolationThreshold)
	assert.True(t, config.SelfHealingEnabled)
	assert.True(t, config.MetricsEnabled)
}

func TestEnforcementAction_NewEnforcementAction(t *testing.T) {
	action := &EnforcementAction{
		Type:        ActionTypeEnforcePolicy,
		ContainerID: "test-container",
		Policy:      nil,
		Violation:   nil,
		Priority:    ActionPriorityHigh,
	}

	require.NotNil(t, action)
	assert.Equal(t, ActionTypeEnforcePolicy, action.Type)
	assert.Equal(t, "test-container", action.ContainerID)
	assert.Equal(t, ActionPriorityHigh, action.Priority)
}

func TestPolicyAction_String(t *testing.T) {
	tests := []struct {
		action   PolicyAction
		expected string
	}{
		{PolicyActionAllow, "Allow"},
		{PolicyActionDeny, "Deny"},
		{PolicyActionAudit, "Audit"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.action))
		})
	}
}

func TestEnforcementMode_String(t *testing.T) {
	tests := []struct {
		mode     EnforcementMode
		expected string
	}{
		{EnforcementModeOff, "Off"},
		{EnforcementModeMonitoring, "Monitoring"},
		{EnforcementModeBlocking, "Blocking"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.mode))
		})
	}
}