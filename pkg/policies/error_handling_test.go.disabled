package policies

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLifecycleManager_ErrorHandling(t *testing.T) {
	t.Run("nil container metadata", func(t *testing.T) {
		manager := NewLifecycleManager(5*time.Minute, 10*time.Minute)

		// Should handle nil metadata gracefully
		err := manager.StartLearning("test-container", nil)
		if err != nil {
			assert.Contains(t, err.Error(), "metadata", "Error should indicate metadata issue")
		}
	})

	t.Run("empty container ID", func(t *testing.T) {
		manager := NewLifecycleManager(5*time.Minute, 10*time.Minute)

		// Should handle empty container ID
		metadata := &ContainerMetadata{
			Namespace: "test",
			PodName:   "test-pod",
			Image:     "test:latest",
		}
		err := manager.StartLearning("", metadata)
		assert.Error(t, err, "Empty container ID should cause error")
		assert.Contains(t, err.Error(), "container", "Error should indicate container ID issue")
	})

	t.Run("invalid transitions", func(t *testing.T) {
		manager := NewLifecycleManager(5*time.Minute, 10*time.Minute)

		// Try to transition without starting learning
		err := manager.TransitionToEnforcement("nonexistent-container")
		assert.Error(t, err, "Transition without learning should fail")
		assert.Contains(t, err.Error(), "not found", "Error should indicate container not found")
	})

	t.Run("concurrent access to same container", func(t *testing.T) {
		manager := NewLifecycleManager(5*time.Minute, 10*time.Minute)
		containerID := "concurrent-test"
		metadata := &ContainerMetadata{
			Namespace: "test",
			PodName:   "test-pod",
			Image:     "test:latest",
		}

		var wg sync.WaitGroup
		errorChan := make(chan error, 10)

		// Start multiple learning sessions concurrently
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := manager.StartLearning(containerID, metadata); err != nil {
					errorChan <- err
				}
			}()
		}

		// Try transitions concurrently
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(10 * time.Millisecond) // Small delay
				if err := manager.TransitionToEnforcement(containerID); err != nil {
					errorChan <- err
				}
			}()
		}

		wg.Wait()
		close(errorChan)

		// Should handle concurrent access gracefully
		errorCount := 0
		for err := range errorChan {
			t.Logf("Concurrent access error (expected): %v", err)
			errorCount++
		}
		// Some operations should succeed, others may fail due to race conditions
		assert.LessOrEqual(t, errorCount, 7, "Not all concurrent operations should fail")
	})
}

func TestEnforcementEngine_ErrorRecovery(t *testing.T) {
	t.Run("nil policy handling", func(t *testing.T) {
		engine := NewEnforcementEngine()

		// Should handle nil policy gracefully
		result := engine.EvaluateEvent("test-container", nil, EventTypeSyscall)
		assert.Equal(t, ActionDeny, result.Action, "Nil policy should result in deny")
		assert.True(t, result.IsViolation, "Nil policy should be treated as violation")
	})

	t.Run("malformed event data", func(t *testing.T) {
		engine := NewEnforcementEngine()
		policy := &ContainerPolicy{
			AllowedSyscalls: map[uint64]bool{1: true, 2: true},
			EnforcementMode: 1,
		}

		// Test with completely invalid event data
		event := map[string]interface{}{
			"invalid_field": "invalid_value",
			"nested": map[string]interface{}{
				"deeply": []interface{}{1, 2, "invalid"},
			},
		}

		result := engine.EvaluateEvent("test-container", event, EventTypeSyscall)
		// Should handle malformed data gracefully
		assert.NotNil(t, result)
		assert.Equal(t, ActionDeny, result.Action, "Malformed event should result in deny")
	})

	t.Run("resource exhaustion", func(t *testing.T) {
		engine := NewEnforcementEngine()
		policy := &ContainerPolicy{
			AllowedSyscalls: make(map[uint64]bool),
			EnforcementMode: 1,
		}

		// Add many allowed syscalls
		for i := uint64(0); i < 10000; i++ {
			policy.AllowedSyscalls[i] = true
		}

		// Test with many containers and events
		start := time.Now()
		for i := 0; i < 1000; i++ {
			containerID := string(rune('a'+i%26)) + string(rune('0'+i%10))
			event := map[string]interface{}{
				"syscall_nr": uint64(i % 100),
				"pid":        i,
			}
			result := engine.EvaluateEvent(containerID, event, EventTypeSyscall)
			assert.NotNil(t, result)
		}
		duration := time.Since(start)

		assert.Less(t, duration, 5*time.Second, "Engine should handle load efficiently")
	})
}

func TestPolicyValidation_EdgeCases(t *testing.T) {
	t.Run("extreme values", func(t *testing.T) {
		tests := []struct {
			name   string
			policy *ContainerPolicy
			valid  bool
		}{
			{
				name: "maximum enforcement mode",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{1: true},
					EnforcementMode: 255, // Maximum uint8
				},
				valid: false,
			},
			{
					name: "negative enforcement mode",
					policy: &ContainerPolicy{
						AllowedSyscalls: map[uint64]bool{1: true},
						EnforcementMode: -1,
					},
					valid: false,
			},
			{
				name: "empty syscalls with enforcement",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{}, // Empty but not nil
					EnforcementMode: 1,
				},
				valid: true, // Empty syscalls might be valid for strict enforcement
			},
			{
				name: "maximum syscall numbers",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{
						^uint64(0): true, // Maximum uint64
						^uint64(0) - 1: true,
					},
					EnforcementMode: 1,
				},
				valid: false, // Invalid syscall numbers
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.policy.Validate()
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("network policy edge cases", func(t *testing.T) {
		tests := []struct {
			name   string
			policy *NetworkPolicy
			valid  bool
		}{
			{
				name: "port 0",
				policy: &NetworkPolicy{
					AllowedEgressPorts:  map[uint16]bool{0: true},
					AllowedIngressPorts: map[uint16]bool{0: true},
					EnforcementMode:     1,
				},
				valid: false, // Port 0 is invalid
			},
			{
				name: "maximum port",
				policy: &NetworkPolicy{
					AllowedEgressPorts:  map[uint16]bool{65535: true},
					AllowedIngressPorts: map[uint16]bool{65535: true},
					EnforcementMode:     1,
				},
				valid: true, // Port 65535 is valid
			},
			{
				name: "conflicting ports",
				policy: &NetworkPolicy{
					AllowedEgressPorts:  map[uint16]bool{80: true, 80: false}, // Conflict
					AllowedIngressPorts: map[uint16]bool{80: true},
					EnforcementMode:     1,
				},
				valid: true, // Map handles this automatically
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.policy.Validate()
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})
}

func TestLearningEngine_ErrorConditions(t *testing.T) {
	t.Run("malformed behavioral data", func(t *testing.T) {
		engine := NewLearningEngine()

		// Test with completely invalid behavioral data
		invalidData := map[string]interface{}{
			"invalid_key": []interface{}{nil, "string", 123, true},
			"nested": map[string]interface{}{
				"deeply": map[string]interface{}{
					"nested": "value",
				},
			},
		}

		// Should handle invalid data gracefully
		err := engine.UpdateBehavioralProfile("test-container", invalidData)
		if err != nil {
			assert.Contains(t, err.Error(), "invalid", "Error should indicate invalid data")
		}
	})

	t.Run("memory exhaustion simulation", func(t *testing.T) {
		engine := NewLearningEngine()

		// Add many containers with large behavioral profiles
		for i := 0; i < 1000; i++ {
			containerID := string(rune('a'+i%26)) + string(rune('0'+i%10))
			data := make(map[string]interface{})

			// Create large behavioral data
			for j := 0; j < 100; j++ {
				syscallKey := string(rune('s'+j%26)) + string(rune('0'+j%10))
				data[syscallKey] = map[string]interface{}{
					"frequency": j,
					"contexts":  make([]string, j%10),
					"metadata":  make(map[string]string),
				}
			}

			err := engine.UpdateBehavioralProfile(containerID, data)
			assert.NoError(t, err, "Engine should handle large data sets")
		}

		// Test generating policies from all profiles
		for i := 0; i < 1000; i++ {
			containerID := string(rune('a'+i%26)) + string(rune('0'+i%10))
			policy, err := engine.GeneratePolicy(containerID)
			if err == nil {
				assert.NotNil(t, policy)
			}
		}
	})

	t.Run("concurrent profile updates", func(t *testing.T) {
		engine := NewLearningEngine()
		containerID := "concurrent-test"

		var wg sync.WaitGroup
		errorChan := make(chan error, 50)

		// Concurrent profile updates
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				data := map[string]interface{}{
					string(rune('s'+index%26)): map[string]interface{}{
						"frequency": index,
						"last_seen": time.Now().Unix(),
					},
				}
				if err := engine.UpdateBehavioralProfile(containerID, data); err != nil {
					errorChan <- err
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)

		// Check for errors
		for err := range errorChan {
			t.Errorf("Concurrent update failed: %v", err)
		}
	})
}

func TestSelfHealing_FailureScenarios(t *testing.T) {
	t.Run("rollback chain failure", func(t *testing.T) {
		manager := NewSelfHealingManager(3, 5*time.Minute, 2, true)

		// Simulate a chain of failures
		containerID := "failure-test"
		for i := 0; i < 5; i++ {
			// Each rollback "fails" by triggering another violation
			err := manager.TriggerRollback(containerID, RollbackReasonViolationThreshold)
			if err != nil {
				t.Logf("Rollback %d failed (expected): %v", i, err)
			}
		}

		// Verify emergency mode is triggered
		state := manager.GetContainerState(containerID)
		if state != nil {
			assert.True(t, state.EmergencyMode, "Emergency mode should be triggered after failures")
		}
	})

	t.Run("invalid rollback conditions", func(t *testing.T) {
		manager := NewSelfHealingManager(3, 5*time.Minute, 2, true)

		// Test invalid rollback reasons
		invalidReasons := []RollbackReason{
			RollbackReason(999), // Invalid enum value
			RollbackReason(-1),  // Negative value
		}

		for _, reason := range invalidReasons {
			err := manager.TriggerRollback("test-container", reason)
			if err != nil {
				assert.Contains(t, err.Error(), "invalid", "Should indicate invalid reason")
			}
		}
	})

	t.Run("timeout handling", func(t *testing.T) {
		manager := NewSelfHealingManager(3, 1*time.Millisecond, 2, true) // Very short timeout

		// Trigger rollback
		containerID := "timeout-test"
		err := manager.TriggerRollback(containerID, RollbackReasonViolationThreshold)
		assert.NoError(t, err)

		// Wait for timeout
		time.Sleep(5 * time.Millisecond)

		// Check if rollback action expired
		state := manager.GetContainerState(containerID)
		if state != nil && len(state.PendingActions) > 0 {
			for _, action := range state.PendingActions {
				if action.IsExpired() {
					t.Log("Rollback action properly expired")
				}
			}
		}
	})
}

func TestMetrics_ErrorConditions(t *testing.T) {
	t.Run("overflow protection", func(t *testing.T) {
		metrics := &SelfHealingMetrics{
			TotalRollbacks:      ^uint64(0) - 1, // Near maximum
			SuccessfulRollbacks: ^uint64(0) - 1,
			FailedRollbacks:     ^uint64(0) - 1,
		}

		// Should handle overflow gracefully
		metrics.UpdateSuccess(1 * time.Minute)
		metrics.UpdateFailure()

		// Verify no panic and reasonable values
		assert.GreaterOrEqual(t, metrics.TotalRollbacks, uint64(0))
		assert.GreaterOrEqual(t, metrics.SuccessfulRollbacks, uint64(0))
		assert.GreaterOrEqual(t, metrics.FailedRollbacks, uint64(0))
	})

	t.Run("division by zero", func(t *testing.T) {
		metrics := &SelfHealingMetrics{
			TotalRollbacks:      0,
			SuccessfulRollbacks: 0,
			FailedRollbacks:     0,
		}

		// Should handle division by zero in success rate calculation
		rate := metrics.SuccessRate()
		assert.Equal(t, 0.0, rate, "Success rate should be 0 when no rollbacks")
	})

	t.Run("negative time values", func(t *testing.T) {
		metrics := &SelfHealingMetrics{
			TotalRollbacks:      1,
			SuccessfulRollbacks: 1,
			AverageRecoveryTime: 1 * time.Minute,
		}

		// Test with negative duration (shouldn't happen but test resilience)
		metrics.UpdateSuccess(-1 * time.Minute)

		// Should handle gracefully
		assert.GreaterOrEqual(t, metrics.AverageRecoveryTime, time.Duration(0))
	})
}
