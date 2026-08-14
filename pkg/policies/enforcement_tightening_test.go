package policies

import (
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateTightenedPolicy_NarrowsToBaseline verifies that tightening narrows
// the allowed syscall set to the learned baseline and drops the violating call.
func TestCreateTightenedPolicy_NarrowsToBaseline(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)

	profile := &learner.LearningProfile{
		ContainerID: "c1",
		AllowedSyscalls: map[uint64]*learner.SyscallProfile{
			1: {SyscallNr: 1},
			2: {SyscallNr: 2},
			3: {SyscallNr: 3},
		},
		AllowedFilePaths: map[string]*learner.FileAccessProfile{
			"/etc/app.conf": {PathPattern: "/etc/app.conf"},
		},
	}

	original := &GeneratedPolicy{
		ContainerID:    "c1",
		Version:        1,
		Confidence:     0.9,
		BasedOnProfile: profile,
		SyscallPolicy: &SyscallEnforcementPolicy{
			AllowedSyscalls: map[uint64]*SyscallRule{
				1:   {SyscallNr: 1, Action: PolicyActionAllow},
				2:   {SyscallNr: 2, Action: PolicyActionAllow},
				3:   {SyscallNr: 3, Action: PolicyActionAllow},
				999: {SyscallNr: 999, Action: PolicyActionAllow}, // not in baseline
			},
			DeniedSyscalls: map[uint64]*SyscallRule{},
			DefaultAction:  PolicyActionDeny,
		},
		FilePolicy: &FileEnforcementPolicy{
			AllowedPaths: map[string]*FileRule{
				"/etc/app.conf": {PathPattern: "/etc/app.conf", Action: PolicyActionAllow},
				"/root/secret":  {PathPattern: "/root/secret", Action: PolicyActionAllow}, // not in baseline
			},
			DeniedPaths: map[string]*FileRule{},
		},
	}

	violation := &PolicyViolation{
		ViolationType: ViolationTypeSyscall,
		Severity:      ViolationSeverityCritical,
		Details:       ViolationDetails{AttemptedAction: "999"},
	}

	tightened := ee.createTightenedPolicy(original, violation)
	require.NotNil(t, tightened)
	require.NotNil(t, tightened.SyscallPolicy)

	// The allowed set must be strictly narrower than the original.
	assert.Less(t, len(tightened.SyscallPolicy.AllowedSyscalls), len(original.SyscallPolicy.AllowedSyscalls))

	// 999 was both out-of-baseline and the violating syscall: it must be gone
	// from allowed and present in denied.
	_, stillAllowed := tightened.SyscallPolicy.AllowedSyscalls[999]
	assert.False(t, stillAllowed, "violating syscall must not remain allowed")
	_, denied := tightened.SyscallPolicy.DeniedSyscalls[999]
	assert.True(t, denied, "violating syscall must be denied")

	// Baseline syscalls remain.
	for _, nr := range []uint64{1, 2, 3} {
		_, ok := tightened.SyscallPolicy.AllowedSyscalls[nr]
		assert.True(t, ok, "baseline syscall %d should remain allowed", nr)
	}

	// File paths narrowed to baseline (not a simple copy).
	require.NotNil(t, tightened.FilePolicy)
	assert.Contains(t, tightened.FilePolicy.AllowedPaths, "/etc/app.conf")
	assert.NotContains(t, tightened.FilePolicy.AllowedPaths, "/root/secret")

	// Version bumped and confidence reduced.
	assert.Equal(t, original.Version+1, tightened.Version)
	assert.Less(t, tightened.Confidence, original.Confidence)
}

// TestRollbackPolicy_RestoresPrevious verifies rollback restores the previous
// policy and records real statistics.
func TestRollbackPolicy_RestoresPrevious(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)

	prev := &GeneratedPolicy{ContainerID: "c1", Version: 1}
	current := &GeneratedPolicy{ContainerID: "c1", Version: 2}

	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:     "c1",
		GeneratedPolicy: current,
		SelfHealingState: &SelfHealingState{
			Enabled:        true,
			CurrentPolicy:  current,
			PreviousPolicy: prev,
		},
	}

	err := ee.rollbackPolicy("c1")
	require.NoError(t, err)

	state := ee.containerPolicies["c1"]
	assert.Same(t, prev, state.GeneratedPolicy, "generated policy should be restored to previous")
	assert.Same(t, prev, state.SelfHealingState.CurrentPolicy)
	assert.Same(t, current, state.SelfHealingState.PreviousPolicy, "previous<->current should swap")
	assert.Equal(t, int32(1), state.SelfHealingState.RollbackCount)
	assert.Equal(t, int64(1), state.Statistics.SelfHealingActionCount)
	assert.False(t, state.SelfHealingState.LastRollbackTime.IsZero())
}

// TestRollbackPolicy_NoTarget returns an error when there is nothing to restore.
func TestRollbackPolicy_NoTarget(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:      "c1",
		SelfHealingState: &SelfHealingState{Enabled: true},
	}
	err := ee.rollbackPolicy("c1")
	assert.Error(t, err)
}

// TestGenerateFilePolicy_FromProfile ensures the file policy is built from the
// learned profile rather than returned empty.
func TestGenerateFilePolicy_FromProfile(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	profile := &learner.LearningProfile{
		ContainerID: "c1",
		AllowedFilePaths: map[string]*learner.FileAccessProfile{
			"/etc/app.conf": {PathPattern: "/etc/app.conf", AllowedModes: []string{"read"}},
			"/var/log/app":  {PathPattern: "/var/log/app", AllowedModes: []string{"read", "write"}},
		},
	}

	fp, err := ee.generateFilePolicy(profile, &policyv1alpha1.PahlevanPolicy{})
	require.NoError(t, err)
	require.NotNil(t, fp)
	assert.Len(t, fp.AllowedPaths, 2)
	assert.Equal(t, PolicyActionDeny, fp.DefaultAction)
	require.Contains(t, fp.AllowedPaths, "/var/log/app")
	assert.ElementsMatch(t, []string{"read", "write"}, fp.AllowedPaths["/var/log/app"].AccessModes)
}

// TestIncreaseMonitoring_EscalatesMode verifies the enforcement posture is
// escalated toward blocking.
func TestIncreaseMonitoring_EscalatesMode(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	ee.containerPolicies["c1"] = &ContainerPolicyState{
		ContainerID:     "c1",
		EnforcementMode: EnforcementModeMonitoring,
	}

	require.NoError(t, ee.increaseMonitoring("c1"))
	assert.Equal(t, EnforcementModeBlocking, ee.containerPolicies["c1"].EnforcementMode)
	assert.Equal(t, int64(1), ee.containerPolicies["c1"].Statistics.EnforcementActionCount)
}

func TestViolationToPriority(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)
	assert.Equal(t, ActionPriorityCritical, ee.violationToPriority(ViolationSeverityCritical))
	assert.Equal(t, ActionPriorityHigh, ee.violationToPriority(ViolationSeverityHigh))
	assert.Equal(t, ActionPriorityMedium, ee.violationToPriority(ViolationSeverityMedium))
	assert.Equal(t, ActionPriorityLow, ee.violationToPriority(ViolationSeverityLow))
}

func TestViolationSyscallNr(t *testing.T) {
	ee := NewEnforcementEngine(nil, nil)

	nr, ok := ee.violationSyscallNr(&PolicyViolation{ViolationType: ViolationTypeSyscall, Details: ViolationDetails{AttemptedAction: "ptrace"}})
	assert.True(t, ok)
	assert.Equal(t, uint64(101), nr)

	nr, ok = ee.violationSyscallNr(&PolicyViolation{ViolationType: ViolationTypeSyscall, Details: ViolationDetails{AttemptedAction: "42"}})
	assert.True(t, ok)
	assert.Equal(t, uint64(42), nr)

	_, ok = ee.violationSyscallNr(&PolicyViolation{ViolationType: ViolationTypeNetwork})
	assert.False(t, ok)

	_ = time.Now()
}
