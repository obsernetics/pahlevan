package policies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculatePrivilegeReduction(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)

	prev := RequiredPrivileges{Syscalls: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}
	next := RequiredPrivileges{Syscalls: []uint64{1, 2, 3, 4, 5}}

	assert.InDelta(t, 0.5, lm.calculatePrivilegeReduction(prev, next), 0.0001)

	// No reduction when the sets are equal.
	assert.Equal(t, 0.0, lm.calculatePrivilegeReduction(prev, prev))

	// Empty previous set yields zero (no divide-by-zero).
	assert.Equal(t, 0.0, lm.calculatePrivilegeReduction(RequiredPrivileges{}, next))
}

func TestCalculatePrivilegeLevel(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)

	assert.Equal(t, PrivilegeLevelMinimal, lm.calculatePrivilegeLevel(RequiredPrivileges{}))
	assert.Equal(t, PrivilegeLevelPrivileged,
		lm.calculatePrivilegeLevel(RequiredPrivileges{Special: []SpecialPrivilege{PrivilegeHostNetwork}}))

	many := make([]uint64, 150)
	assert.Equal(t, PrivilegeLevelElevated, lm.calculatePrivilegeLevel(RequiredPrivileges{Syscalls: many}))
}

func TestApplyTightenedPolicy_BuildsPolicy(t *testing.T) {
	lm := NewLifecycleManager(nil, nil) // nil enforcement engine: in-memory only

	cs := &ContainerLifecycleState{ContainerID: "c1"}
	newPriv := RequiredPrivileges{
		Syscalls:     []uint64{1, 2},
		FilePaths:    []FilePathRequirement{{Path: "/etc/app.conf", AccessModes: []string{"read"}}},
		NetworkPorts: []NetworkPortRequirement{{Port: 443, Protocol: "tcp", Direction: "outbound"}},
	}
	event := TighteningEvent{ContainerID: "c1", TighteningType: TighteningTypeCombined}

	require.NoError(t, lm.applyTightenedPolicy(cs, newPriv, event))
	require.NotNil(t, cs.CurrentPolicy)
	assert.Len(t, cs.CurrentPolicy.SyscallPolicy.AllowedSyscalls, 2)
	assert.Len(t, cs.CurrentPolicy.FilePolicy.AllowedPaths, 1)
	assert.Len(t, cs.CurrentPolicy.NetworkPolicy.EgressRules, 1)
	assert.Empty(t, cs.CurrentPolicy.NetworkPolicy.IngressRules)
	assert.Equal(t, PolicyActionDeny, cs.CurrentPolicy.SyscallPolicy.DefaultAction)
	// A history snapshot should be recorded.
	assert.Len(t, cs.PolicyHistory, 1)
}

func TestAssessTighteningImpact_RiskScales(t *testing.T) {
	lm := NewLifecycleManager(nil, nil)

	current := RequiredPrivileges{Syscalls: make([]uint64, 100)}
	// Aggressive reduction -> high risk.
	aggressive := RequiredPrivileges{Syscalls: make([]uint64, 10)}
	impact := lm.assessTighteningImpact(nil, current, aggressive)
	assert.Equal(t, RiskLevelHigh, impact.RiskLevel)
	assert.True(t, impact.Reversibility)

	// Small reduction -> low risk.
	gentle := RequiredPrivileges{Syscalls: make([]uint64, 95)}
	impact = lm.assessTighteningImpact(nil, current, gentle)
	assert.Equal(t, RiskLevelLow, impact.RiskLevel)
}

func TestUpdateUsageMetric(t *testing.T) {
	m := &UsageMetrics{}
	updateUsageMetric(m, 10)
	assert.Equal(t, 10.0, m.Current)
	assert.Equal(t, 10.0, m.Peak)
	updateUsageMetric(m, 20)
	assert.Equal(t, 20.0, m.Current)
	assert.Equal(t, 20.0, m.Peak)
	assert.Equal(t, TrendIncreasing, m.Trend)
}
