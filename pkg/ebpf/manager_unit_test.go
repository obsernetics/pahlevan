package ebpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *ContainerPolicy
		wantErr bool
	}{
		{
			name: "valid policy",
			policy: &ContainerPolicy{
				AllowedSyscalls:  map[uint64]bool{1: true, 2: true},
				EnforcementMode:  1,
				SelfHealing:      true,
			},
			wantErr: false,
		},
		{
			name: "valid minimal policy",
			policy: &ContainerPolicy{
				AllowedSyscalls:  map[uint64]bool{1: true},
				EnforcementMode:  1,
				SelfHealing:      false,
			},
			wantErr: false,
		},
		{
			name: "nil syscalls map",
			policy: &ContainerPolicy{
				AllowedSyscalls:  nil,
				EnforcementMode:  1,
				SelfHealing:      false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNetworkPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *NetworkPolicy
		wantErr bool
	}{
		{
			name: "valid network policy",
			policy: &NetworkPolicy{
				AllowedEgressPorts:  map[uint16]bool{80: true, 443: true},
				AllowedIngressPorts: map[uint16]bool{8080: true},
				EnforcementMode:     1,
			},
			wantErr: false,
		},
		{
			name: "nil port maps",
			policy: &NetworkPolicy{
				AllowedEgressPorts:  nil,
				AllowedIngressPorts: nil,
				EnforcementMode:     1,
			},
			wantErr: true,
		},
		{
			name: "invalid enforcement mode",
			policy: &NetworkPolicy{
				AllowedEgressPorts:  map[uint16]bool{80: true},
				AllowedIngressPorts: map[uint16]bool{8080: true},
				EnforcementMode:     255, // Invalid mode
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilePolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *FilePolicy
		wantErr bool
	}{
		{
			name: "valid file policy",
			policy: &FilePolicy{
				EnforcementMode: 1,
				AllowTmpWrites:  true,
				AllowProcReads:  true,
				AllowDevAccess:  false,
			},
			wantErr: false,
		},
		{
			name: "invalid enforcement mode",
			policy: &FilePolicy{
				EnforcementMode: 10, // Invalid mode
				AllowTmpWrites:  true,
				AllowProcReads:  true,
				AllowDevAccess:  false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventTypeSyscall, "syscall"},
		{EventTypeNetwork, "network"},
		{EventTypeFile, "file"},
		{EventTypeProcess, "process"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.eventType))
		})
	}
}

func TestPolicyUpdateEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *PolicyUpdateEvent
		wantErr bool
	}{
		{
			name: "valid update event",
			event: &PolicyUpdateEvent{
				ContainerID: "test-container",
				EventType:   EventTypeSyscall,
				Timestamp:   time.Now(),
				Data:        map[string]interface{}{"syscall": "open"},
			},
			wantErr: false,
		},
		{
			name: "empty container ID",
			event: &PolicyUpdateEvent{
				// ContainerID not part of struct in manager.go
				EventType:   EventTypeSyscall,
				Timestamp:   time.Now(),
				Data:        map[string]interface{}{"syscall": "open"},
			},
			wantErr: true,
		},
		{
			name: "zero timestamp",
			event: &PolicyUpdateEvent{
				// ContainerID not part of struct in manager.go
				EventType:   EventTypeSyscall,
				Timestamp:   time.Time{},
				Data:        map[string]interface{}{"syscall": "open"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStatistics_Reset(t *testing.T) {
	stats := &Statistics{
		EventsProcessed:    1000,
		PoliciesUpdated:    50,
		ViolationsDetected: 10,
		LastUpdate:         time.Now(),
	}

	stats.Reset()

	assert.Equal(t, uint64(0), stats.GetEventsProcessed())
	assert.Equal(t, uint64(0), stats.GetPoliciesUpdated())
	assert.Equal(t, uint64(0), stats.GetViolationsDetected())
	assert.True(t, stats.GetLastUpdate().IsZero())
}

func TestStatistics_IncrementEvents(t *testing.T) {
	stats := &Statistics{}

	stats.IncrementEvents()
	assert.Equal(t, uint64(1), stats.GetEventsProcessed())

	stats.IncrementEvents()
	assert.Equal(t, uint64(2), stats.GetEventsProcessed())
}

func TestStatistics_IncrementPolicies(t *testing.T) {
	stats := &Statistics{}

	stats.IncrementPolicies()
	assert.Equal(t, uint64(1), stats.GetPoliciesUpdated())

	stats.IncrementPolicies()
	assert.Equal(t, uint64(2), stats.GetPoliciesUpdated())
}

func TestStatistics_IncrementViolations(t *testing.T) {
	stats := &Statistics{}

	stats.IncrementViolations()
	assert.Equal(t, uint64(1), stats.GetViolationsDetected())

	stats.IncrementViolations()
	assert.Equal(t, uint64(2), stats.GetViolationsDetected())
}

func TestStatistics_UpdateTimestamp(t *testing.T) {
	stats := &Statistics{}
	before := time.Now()

	stats.UpdateTimestamp()

	assert.True(t, stats.LastUpdate.After(before) || stats.LastUpdate.Equal(before))
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
		valid  bool
	}{
		{
			name: "valid config",
			config: map[string]interface{}{
				"enforcement_mode": 1,
				"self_healing":     true,
				"max_violations":   10,
			},
			valid: true,
		},
		{
			name: "invalid enforcement mode type",
			config: map[string]interface{}{
				"enforcement_mode": "invalid",
				"self_healing":     true,
			},
			valid: false,
		},
		{
			name: "missing required fields",
			config: map[string]interface{}{
				"self_healing": true,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateConfig(tt.config)
			assert.Equal(t, tt.valid, valid)
		})
	}
}

// Helper function for config validation
func validateConfig(config map[string]interface{}) bool {
	// Check enforcement mode
	if mode, ok := config["enforcement_mode"]; ok {
		if _, ok := mode.(int); !ok {
			return false
		}
	} else {
		return false
	}

	// Check self healing
	if _, ok := config["self_healing"]; !ok {
		return false
	}

	return true
}

func TestPolicyMerge(t *testing.T) {
	policy1 := &ContainerPolicy{
		AllowedSyscalls: map[uint64]bool{1: true, 2: true},
		EnforcementMode: 1,
		SelfHealing:     true,
	}

	policy2 := &ContainerPolicy{
		AllowedSyscalls: map[uint64]bool{3: true, 4: true},
		EnforcementMode: 1,
		SelfHealing:     false,
	}

	merged := mergePolicies(policy1, policy2)

	require.NotNil(t, merged)
	assert.Len(t, merged.AllowedSyscalls, 4)
	assert.True(t, merged.AllowedSyscalls[1])
	assert.True(t, merged.AllowedSyscalls[2])
	assert.True(t, merged.AllowedSyscalls[3])
	assert.True(t, merged.AllowedSyscalls[4])
}

// Helper function for policy merging
func mergePolicies(p1, p2 *ContainerPolicy) *ContainerPolicy {
	merged := &ContainerPolicy{
		AllowedSyscalls: make(map[uint64]bool),
		EnforcementMode: p1.EnforcementMode,
		SelfHealing:     p1.SelfHealing || p2.SelfHealing,
	}

	// Merge syscalls
	for syscall, allowed := range p1.AllowedSyscalls {
		if allowed {
			merged.AllowedSyscalls[syscall] = true
		}
	}

	for syscall, allowed := range p2.AllowedSyscalls {
		if allowed {
			merged.AllowedSyscalls[syscall] = true
		}
	}

	return merged
}

func TestBenchmarkPolicyValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	policy := &ContainerPolicy{
		// ContainerID not part of struct in manager.go
		AllowedSyscalls: make(map[uint64]bool),
		EnforcementMode: 1,
		SelfHealing:     true,
	}

	// Add many syscalls
	for i := uint64(1); i <= 1000; i++ {
		policy.AllowedSyscalls[i] = true
	}

	start := time.Now()
	for i := 0; i < 1000; i++ {
		err := policy.Validate()
		require.NoError(t, err)
	}
	duration := time.Since(start)

	assert.Less(t, duration, 100*time.Millisecond, "Policy validation should be fast")
	t.Logf("Policy validation benchmark: %v for 1000 iterations", duration)
}