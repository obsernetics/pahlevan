package policies

import (
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerPolicyState_CompleteValidation(t *testing.T) {
	tests := []struct {
		name  string
		state *ContainerPolicyState
		valid bool
	}{
		{
			name: "complete valid state",
			state: &ContainerPolicyState{
				ContainerID:      "valid-container-123",
				EnforcementMode:  EnforcementModeMonitoring,
				LifecyclePhase:   PhaseRunning,
				ViolationHistory: make([]PolicyViolation, 0),
				Statistics: EnforcementStatistics{
					ViolationCount:         0,
					EnforcementActionCount: 0,
					PolicyGenerationCount:  100,
					LastViolationTime:      time.Now(),
				},
			},
			valid: true,
		},
		{
			name: "state with violations",
			state: &ContainerPolicyState{
				ContainerID:     "container-with-violations",
				EnforcementMode: EnforcementModeBlocking,
				LifecyclePhase:  PhaseSteady,
				ViolationHistory: []PolicyViolation{
					{
						ViolationType: ViolationTypeSyscall,
						Severity:      ViolationSeverityHigh,
						Details:       ViolationDetails{Resource: "syscall", AttemptedAction: "ptrace"},
						Timestamp:     time.Now(),
						Context: ViolationContext{ProcessName: "ptrace", ProcessID: 1234},
					},
				},
				Statistics: EnforcementStatistics{
					ViolationCount: 1,
					EnforcementActionCount: 1,
					PolicyGenerationCount:  99,
					LastViolationTime:      time.Now(),
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid {
				assert.NotEmpty(t, tt.state.ContainerID)
				assert.NotEqual(t, EnforcementModeOff, tt.state.EnforcementMode)
			}
		})
	}
}

func TestGeneratedPolicy_PolicyGeneration(t *testing.T) {
	tests := []struct {
		name     string
		profile  *learner.LearningProfile
		expected *GeneratedPolicy
	}{
		{
			name: "comprehensive policy generation",
			profile: &learner.LearningProfile{
				ContainerID: "web-server",
				ObservedSyscalls: map[uint64]*learner.SyscallStatistics{
					1:   {SyscallNumber: 1, TotalCalls: 100, UniquePids: 1},   // read
					2:   {SyscallNumber: 2, TotalCalls: 80, UniquePids: 1},    // write
					22:  {SyscallNumber: 22, TotalCalls: 50, UniquePids: 1},   // pipe
					142: {SyscallNumber: 142, TotalCalls: 10, UniquePids: 1},  // setgid - privileged
				},
				NetworkConnections: []*learner.NetworkConnection{
					{
						Protocol:   "tcp",
						LocalPort:  8080,
						RemoteAddr: "0.0.0.0",
						RemotePort: 0,
						State:      "LISTEN",
					},
					{
						Protocol:   "tcp",
						LocalPort:  0,
						RemoteAddr: "192.168.1.1",
						RemotePort: 443,
						State:      "ESTABLISHED",
					},
				},
				FileAccesses: []*learner.FileAccess{
					{
						Path: "/var/log/app.log",
						Mode: "write",
					},
					{
						Path: "/etc/config.json",
						Mode: "read",
					},
					{
						Path: "/tmp/upload.txt",
						Mode: "write",
					},
				},
			},
			expected: &GeneratedPolicy{
				SyscallPolicy: &SyscallEnforcementPolicy{
					AllowedSyscalls: map[uint64]*SyscallRule{
						1:  {SyscallNr: 1, Action: PolicyActionAllow},
						2:  {SyscallNr: 2, Action: PolicyActionAllow},
						22: {SyscallNr: 22, Action: PolicyActionAllow},
					},
					DeniedSyscalls: map[uint64]*SyscallRule{
						142: {SyscallNr: 142, Action: PolicyActionDeny},
					},
					DefaultAction: PolicyActionDeny,
				},
				NetworkPolicy: &NetworkEnforcementPolicy{
					AllowedIngressPorts: map[uint16]*PortRule{
						8080: {Port: 8080, Protocol: "tcp", Action: PolicyActionAllow},
					},
					AllowedEgressPorts: map[uint16]*PortRule{
						443: {Port: 443, Protocol: "tcp", Action: PolicyActionAllow},
					},
					DefaultAction: PolicyActionDeny,
				},
				FilePolicy: &FileEnforcementPolicy{
					AllowedPaths: map[string]*FileRule{
						"/var/log/*": {Pattern: "/var/log/*", Action: PolicyActionAllow, Mode: "write"},
						"/etc/*":     {Pattern: "/etc/*", Action: PolicyActionAllow, Mode: "read"},
						"/tmp/*":     {Pattern: "/tmp/*", Action: PolicyActionAllow, Mode: "write"},
					},
					DefaultAction: PolicyActionDeny,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := generatePolicyFromProfile(tt.profile)

			require.NotNil(t, policy)
			require.NotNil(t, policy.SyscallPolicy)
			require.NotNil(t, policy.NetworkPolicy)
			require.NotNil(t, policy.FilePolicy)

			// Verify syscall policy
			assert.Equal(t, PolicyActionDeny, policy.SyscallPolicy.DefaultAction)
			assert.True(t, len(policy.SyscallPolicy.AllowedSyscalls) > 0)

			// Verify network policy
			assert.Equal(t, PolicyActionDeny, policy.NetworkPolicy.DefaultAction)

			// Verify file policy
			assert.Equal(t, PolicyActionDeny, policy.FilePolicy.DefaultAction)
		})
	}
}

func TestPolicyActions_Validation(t *testing.T) {
	tests := []struct {
		name   string
		action PolicyAction
		valid  bool
	}{
		{"allow action", PolicyActionAllow, true},
		{"deny action", PolicyActionDeny, true},
		{"alert action", PolicyActionAlert, true},
		{"audit action", PolicyActionAudit, true},
		{"kill action", PolicyActionKill, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, isPolicyActionValid(tt.action))
		})
	}
}

func TestViolationSeverity_Escalation(t *testing.T) {
	tests := []struct {
		name            string
		severity        ViolationSeverity
		shouldEscalate  bool
		escalateDelay   time.Duration
	}{
		{
			name:           "critical violation immediate escalation",
			severity:       ViolationSeverityCritical,
			shouldEscalate: true,
			escalateDelay:  0,
		},
		{
			name:           "high violation quick escalation",
			severity:       ViolationSeverityHigh,
			shouldEscalate: true,
			escalateDelay:  5 * time.Minute,
		},
		{
			name:           "medium violation delayed escalation",
			severity:       ViolationSeverityMedium,
			shouldEscalate: true,
			escalateDelay:  15 * time.Minute,
		},
		{
			name:           "low violation no escalation",
			severity:       ViolationSeverityLow,
			shouldEscalate: false,
			escalateDelay:  time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violation := &PolicyViolation{
				ViolationType: ViolationTypeSyscall,
				Severity:      tt.severity,
				Details:       ViolationDetails{Resource: "test", AttemptedAction: "test_action"},
				Timestamp:     time.Now().Add(-tt.escalateDelay),
				Context:       ViolationContext{ProcessName: "test", ProcessID: 1234},
			}

			shouldEscalate := violation.ShouldEscalate(time.Now())
			assert.Equal(t, tt.shouldEscalate, shouldEscalate)
		})
	}
}

func TestEnforcementMode_Transitions(t *testing.T) {
	tests := []struct {
		name        string
		from        EnforcementMode
		to          EnforcementMode
		allowed     bool
		description string
	}{
		{
			name:        "off to learning",
			from:        EnforcementModeOff,
			to:          EnforcementModeLearning,
			allowed:     true,
			description: "Starting learning phase",
		},
		{
			name:        "learning to monitoring",
			from:        EnforcementModeLearning,
			to:          EnforcementModeMonitoring,
			allowed:     true,
			description: "Transitioning to monitoring after learning",
		},
		{
			name:        "monitoring to blocking",
			from:        EnforcementModeMonitoring,
			to:          EnforcementModeBlocking,
			allowed:     true,
			description: "Enabling enforcement",
		},
		{
			name:        "blocking to monitoring",
			from:        EnforcementModeBlocking,
			to:          EnforcementModeMonitoring,
			allowed:     true,
			description: "Emergency rollback",
		},
		{
			name:        "blocking to off illegal",
			from:        EnforcementModeBlocking,
			to:          EnforcementModeOff,
			allowed:     false,
			description: "Direct disable not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := isEnforcementModeTransitionAllowed(tt.from, tt.to)
			assert.Equal(t, tt.allowed, allowed, tt.description)
		})
	}
}

func TestWorkloadLifecyclePhases(t *testing.T) {
	tests := []struct {
		name     string
		phase    WorkloadLifecyclePhase
		expected map[string]bool
	}{
		{
			name:  "initializing phase capabilities",
			phase: PhaseInitializing,
			expected: map[string]bool{
				"canLearn":       true,
				"canEnforce":     false,
				"canSelfHeal":    false,
				"requiresPolicy": false,
			},
		},
		{
			name:  "running phase capabilities",
			phase: PhaseRunning,
			expected: map[string]bool{
				"canLearn":       true,
				"canEnforce":     true,
				"canSelfHeal":    true,
				"requiresPolicy": true,
			},
		},
		{
			name:  "steady phase capabilities",
			phase: PhaseSteady,
			expected: map[string]bool{
				"canLearn":       false,
				"canEnforce":     true,
				"canSelfHeal":    true,
				"requiresPolicy": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capabilities := getPhaseCapabilities(tt.phase)
			for capability, expected := range tt.expected {
				actual := capabilities[capability]
				assert.Equal(t, expected, actual, "capability %s", capability)
			}
		})
	}
}

func TestPolicyRule_RateLimiting(t *testing.T) {
	tests := []struct {
		name        string
		rule        *SyscallRule
		requests    []time.Time
		expectAllow bool
	}{
		{
			name: "within rate limit",
			rule: &SyscallRule{
				SyscallNr: 1,
				Action:    PolicyActionAllow,
				RateLimit: &RateLimit{
					Requests: 10,
					Window:   time.Minute,
				},
			},
			requests:    make([]time.Time, 5), // 5 requests < 10 limit
			expectAllow: true,
		},
		{
			name: "exceeding rate limit",
			rule: &SyscallRule{
				SyscallNr: 1,
				Action:    PolicyActionAllow,
				RateLimit: &RateLimit{
					Requests: 5,
					Window:   time.Minute,
				},
			},
			requests:    make([]time.Time, 10), // 10 requests > 5 limit
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			for i := range tt.requests {
				tt.requests[i] = now.Add(-time.Duration(i) * time.Second)
			}

			allowed := tt.rule.CheckRateLimit(tt.requests, now)
			assert.Equal(t, tt.expectAllow, allowed)
		})
	}
}

// Helper functions for testing
func generatePolicyFromProfile(profile *learner.LearningProfile) *GeneratedPolicy {
	syscallPolicy := &SyscallEnforcementPolicy{
		AllowedSyscalls: make(map[uint64]*SyscallRule),
		DeniedSyscalls:  make(map[uint64]*SyscallRule),
		DefaultAction:   PolicyActionDeny,
	}

	// Generate syscall rules based on observed syscalls
	for syscallNum, stats := range profile.ObservedSyscalls {
		rule := &SyscallRule{
			SyscallNr: syscallNum,
			Action:    PolicyActionAllow,
		}

		// Mark privileged syscalls as denied
		if isPrivilegedSyscall(syscallNum) {
			rule.Action = PolicyActionDeny
			syscallPolicy.DeniedSyscalls[syscallNum] = rule
		} else {
			syscallPolicy.AllowedSyscalls[syscallNum] = rule
		}
	}

	networkPolicy := &NetworkEnforcementPolicy{
		AllowedEgressPorts:  make(map[uint16]*PortRule),
		AllowedIngressPorts: make(map[uint16]*PortRule),
		DefaultAction:       PolicyActionDeny,
	}

	// Generate network rules
	for _, conn := range profile.NetworkConnections {
		rule := &PortRule{
			Port:     conn.LocalPort,
			Protocol: conn.Protocol,
			Action:   PolicyActionAllow,
		}

		if conn.State == "LISTEN" {
			networkPolicy.AllowedIngressPorts[conn.LocalPort] = rule
		} else {
			networkPolicy.AllowedEgressPorts[conn.RemotePort] = rule
		}
	}

	filePolicy := &FileEnforcementPolicy{
		AllowedPaths:  make(map[string]*FileRule),
		DefaultAction: PolicyActionDeny,
	}

	// Generate file rules
	for _, access := range profile.FileAccesses {
		pattern := getPathPattern(access.Path)
		rule := &FileRule{
			Pattern: pattern,
			Action:  PolicyActionAllow,
			Mode:    access.Mode,
		}
		filePolicy.AllowedPaths[pattern] = rule
	}

	return &GeneratedPolicy{
		SyscallPolicy: syscallPolicy,
		NetworkPolicy: networkPolicy,
		FilePolicy:    filePolicy,
	}
}

func isPolicyActionValid(action PolicyAction) bool {
	validActions := []PolicyAction{
		PolicyActionAllow,
		PolicyActionDeny,
		PolicyActionAlert,
		PolicyActionAudit,
		PolicyActionKill,
	}

	for _, valid := range validActions {
		if action == valid {
			return true
		}
	}
	return false
}

func (pv *PolicyViolation) ShouldEscalate(now time.Time) bool {
	elapsed := now.Sub(pv.Timestamp)

	switch pv.Severity {
	case ViolationSeverityCritical:
		return true // Immediate escalation
	case ViolationSeverityHigh:
		return elapsed > 5*time.Minute
	case ViolationSeverityMedium:
		return elapsed > 15*time.Minute
	case ViolationSeverityLow:
		return false // No escalation for low severity
	default:
		return false
	}
}

func isEnforcementModeTransitionAllowed(from, to EnforcementMode) bool {
	allowedTransitions := map[EnforcementMode][]EnforcementMode{
		EnforcementModeOff: {
			EnforcementModeLearning,
			EnforcementModeMonitoring,
		},
		EnforcementModeLearning: {
			EnforcementModeMonitoring,
			EnforcementModeOff,
		},
		EnforcementModeMonitoring: {
			EnforcementModeBlocking,
			EnforcementModeOff,
		},
		EnforcementModeBlocking: {
			EnforcementModeMonitoring, // Emergency rollback only
		},
	}

	allowed := allowedTransitions[from]
	for _, mode := range allowed {
		if mode == to {
			return true
		}
	}
	return false
}

func getPhaseCapabilities(phase WorkloadLifecyclePhase) map[string]bool {
	capabilities := map[WorkloadLifecyclePhase]map[string]bool{
		PhaseInitializing: {
			"canLearn":       true,
			"canEnforce":     false,
			"canSelfHeal":    false,
			"requiresPolicy": false,
		},
		PhaseStarting: {
			"canLearn":       true,
			"canEnforce":     false,
			"canSelfHeal":    false,
			"requiresPolicy": false,
		},
		PhaseRunning: {
			"canLearn":       true,
			"canEnforce":     true,
			"canSelfHeal":    true,
			"requiresPolicy": true,
		},
		PhaseSteady: {
			"canLearn":       false,
			"canEnforce":     true,
			"canSelfHeal":    true,
			"requiresPolicy": true,
		},
	}

	return capabilities[phase]
}

func (sr *SyscallRule) CheckRateLimit(requests []time.Time, now time.Time) bool {
	if sr.RateLimit == nil {
		return true // No rate limit
	}

	// Count requests within the window
	windowStart := now.Add(-sr.RateLimit.Window)
	validRequests := 0

	for _, reqTime := range requests {
		if reqTime.After(windowStart) {
			validRequests++
		}
	}

	return validRequests <= sr.RateLimit.Requests
}

func isPrivilegedSyscall(syscallNum uint64) bool {
	privilegedSyscalls := []uint64{
		142, // setgid
		146, // setuid
		155, // pivot_root
		159, // adjtimex
		165, // mount
		166, // umount
		169, // reboot
		172, // iopl
		173, // ioperm
	}

	for _, privileged := range privilegedSyscalls {
		if syscallNum == privileged {
			return true
		}
	}
	return false
}

func getPathPattern(path string) string {
	// Simple pattern generation - in real implementation would be more sophisticated
	if len(path) > 0 && path[0] == '/' {
		parts := []string{"/var/log/*", "/etc/*", "/tmp/*", "/usr/*"}
		for _, pattern := range parts {
			if len(pattern) > 2 && len(path) > len(pattern)-1 {
				prefix := pattern[:len(pattern)-1] // Remove *
				if path[:len(prefix)] == prefix {
					return pattern
				}
			}
		}
	}
	return path
}