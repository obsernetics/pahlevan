package policies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerPolicyState_NewContainerPolicyState(t *testing.T) {
	state := &ContainerPolicyState{
		ContainerID:    "test-container",
		CurrentPolicy:  nil,
		LastUpdate:     nil,
		ViolationCount: 0,
		SelfHealing:    false,
	}

	require.NotNil(t, state)
	assert.Equal(t, "test-container", state.ContainerID)
	assert.Equal(t, 0, state.ViolationCount)
	assert.False(t, state.SelfHealing)
}

func TestGlobalEnforcementConfig_Default(t *testing.T) {
	config := &GlobalEnforcementConfig{
		DefaultMode:            "monitor",
		LearningWindowDuration: 300, // 5 minutes
		MaxViolationsBeforeBlock: 10,
		SelfHealingEnabled:     true,
		AlertingEnabled:        true,
	}

	require.NotNil(t, config)
	assert.Equal(t, "monitor", config.DefaultMode)
	assert.Equal(t, 300, config.LearningWindowDuration)
	assert.Equal(t, 10, config.MaxViolationsBeforeBlock)
	assert.True(t, config.SelfHealingEnabled)
	assert.True(t, config.AlertingEnabled)
}

func TestEnforcementAction_NewEnforcementAction(t *testing.T) {
	action := &EnforcementAction{
		Type:        "block",
		ContainerID: "test-container",
		PolicyName:  "test-policy",
		Reason:      "Syscall violation",
		Details:     map[string]interface{}{"syscall": "ptrace"},
	}

	require.NotNil(t, action)
	assert.Equal(t, "block", action.Type)
	assert.Equal(t, "test-container", action.ContainerID)
	assert.Equal(t, "test-policy", action.PolicyName)
	assert.Equal(t, "Syscall violation", action.Reason)
	assert.Contains(t, action.Details, "syscall")
}

func TestSyscallEnforcementPolicy_NewSyscallPolicy(t *testing.T) {
	policy := &SyscallEnforcementPolicy{
		AllowedSyscalls: map[uint64]*SyscallRule{
			1: {SyscallNumber: 1, Action: PolicyActionAllow, Priority: 1},
			2: {SyscallNumber: 2, Action: PolicyActionAllow, Priority: 1},
		},
		DeniedSyscalls: map[uint64]*SyscallRule{
			101: {SyscallNumber: 101, Action: PolicyActionDeny, Priority: 10},
		},
		DefaultAction: PolicyActionDeny,
	}

	require.NotNil(t, policy)
	assert.Equal(t, PolicyActionDeny, policy.DefaultAction)
	assert.Len(t, policy.AllowedSyscalls, 2)
	assert.Len(t, policy.DeniedSyscalls, 1)

	// Test allowed syscall
	rule, exists := policy.AllowedSyscalls[1]
	assert.True(t, exists)
	assert.Equal(t, PolicyActionAllow, rule.Action)

	// Test denied syscall
	rule, exists = policy.DeniedSyscalls[101]
	assert.True(t, exists)
	assert.Equal(t, PolicyActionDeny, rule.Action)
}

func TestNetworkEnforcementPolicy_NewNetworkPolicy(t *testing.T) {
	policy := &NetworkEnforcementPolicy{
		AllowedEgressPorts: map[uint16]*PortRule{
			80:  {Port: 80, Protocol: "tcp", Action: PolicyActionAllow},
			443: {Port: 443, Protocol: "tcp", Action: PolicyActionAllow},
		},
		AllowedIngressPorts: map[uint16]*PortRule{
			8080: {Port: 8080, Protocol: "tcp", Action: PolicyActionAllow},
		},
		DefaultAction: PolicyActionDeny,
	}

	require.NotNil(t, policy)
	assert.Equal(t, PolicyActionDeny, policy.DefaultAction)
	assert.Len(t, policy.AllowedEgressPorts, 2)
	assert.Len(t, policy.AllowedIngressPorts, 1)

	// Test egress port
	rule, exists := policy.AllowedEgressPorts[80]
	assert.True(t, exists)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, PolicyActionAllow, rule.Action)
}

func TestFileEnforcementPolicy_NewFilePolicy(t *testing.T) {
	policy := &FileEnforcementPolicy{
		AllowedPaths: map[string]*FileRule{
			"/usr/bin/*": {Pattern: "/usr/bin/*", Action: PolicyActionAllow, Mode: "read"},
			"/tmp/*":     {Pattern: "/tmp/*", Action: PolicyActionAllow, Mode: "write"},
		},
		DeniedPaths: map[string]*FileRule{
			"/etc/passwd": {Pattern: "/etc/passwd", Action: PolicyActionDeny, Mode: "write"},
		},
		DefaultAction: PolicyActionDeny,
	}

	require.NotNil(t, policy)
	assert.Equal(t, PolicyActionDeny, policy.DefaultAction)
	assert.Len(t, policy.AllowedPaths, 2)
	assert.Len(t, policy.DeniedPaths, 1)

	// Test allowed path
	rule, exists := policy.AllowedPaths["/usr/bin/*"]
	assert.True(t, exists)
	assert.Equal(t, "read", rule.Mode)
	assert.Equal(t, PolicyActionAllow, rule.Action)

	// Test denied path
	rule, exists = policy.DeniedPaths["/etc/passwd"]
	assert.True(t, exists)
	assert.Equal(t, "write", rule.Mode)
	assert.Equal(t, PolicyActionDeny, rule.Action)
}

func TestPolicyActionString(t *testing.T) {
	tests := []struct {
		action   PolicyAction
		expected string
	}{
		{PolicyActionAllow, "allow"},
		{PolicyActionDeny, "deny"},
		{PolicyActionAudit, "audit"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.action))
		})
	}
}

func TestSyscallRule_Validate(t *testing.T) {
	rule := &SyscallRule{
		SyscallNumber: 1,
		Action:        PolicyActionAllow,
		Priority:      1,
		Conditions:    []string{"uid=1000"},
	}

	require.NotNil(t, rule)
	assert.Equal(t, uint64(1), rule.SyscallNumber)
	assert.Equal(t, PolicyActionAllow, rule.Action)
	assert.Equal(t, 1, rule.Priority)
	assert.Len(t, rule.Conditions, 1)
}

func TestPortRule_Validate(t *testing.T) {
	rule := &PortRule{
		Port:     80,
		Protocol: "tcp",
		Action:   PolicyActionAllow,
		DestinationIPs: []string{"127.0.0.1", "::1"},
	}

	require.NotNil(t, rule)
	assert.Equal(t, uint16(80), rule.Port)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, PolicyActionAllow, rule.Action)
	assert.Len(t, rule.DestinationIPs, 2)
}

func TestFileRule_Validate(t *testing.T) {
	rule := &FileRule{
		Pattern: "/tmp/*",
		Action:  PolicyActionAllow,
		Mode:    "write",
		MaxSize: 1024,
	}

	require.NotNil(t, rule)
	assert.Equal(t, "/tmp/*", rule.Pattern)
	assert.Equal(t, PolicyActionAllow, rule.Action)
	assert.Equal(t, "write", rule.Mode)
	assert.Equal(t, int64(1024), rule.MaxSize)
}

// Benchmark tests
func BenchmarkSyscallPolicyLookup(b *testing.B) {
	policy := &SyscallEnforcementPolicy{
		AllowedSyscalls: make(map[uint64]*SyscallRule),
		DefaultAction:   PolicyActionDeny,
	}

	// Populate with many syscalls
	for i := uint64(0); i < 1000; i++ {
		policy.AllowedSyscalls[i] = &SyscallRule{
			SyscallNumber: i,
			Action:        PolicyActionAllow,
			Priority:      1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, exists := policy.AllowedSyscalls[uint64(i%1000)]
		_ = exists
	}
}

func BenchmarkNetworkPolicyLookup(b *testing.B) {
	policy := &NetworkEnforcementPolicy{
		AllowedEgressPorts: make(map[uint16]*PortRule),
		DefaultAction:      PolicyActionDeny,
	}

	// Populate with many ports
	for i := uint16(1000); i < 2000; i++ {
		policy.AllowedEgressPorts[i] = &PortRule{
			Port:     i,
			Protocol: "tcp",
			Action:   PolicyActionAllow,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		port := uint16(1000 + (i % 1000))
		_, exists := policy.AllowedEgressPorts[port]
		_ = exists
	}
}