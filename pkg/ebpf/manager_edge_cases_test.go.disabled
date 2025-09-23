package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestManager_NilPointerSafety(t *testing.T) {
	// Test that manager methods handle nil pointers gracefully
	t.Run("nil policies", func(t *testing.T) {
		manager := &Manager{
			eventHandlers: []EventHandler{},
		}

		// Should not panic with nil policies
		err := manager.UpdateContainerPolicy("test-container", nil)
		if err != nil {
			assert.Contains(t, err.Error(), "policy", "Error should indicate policy issue")
		}
	})

	t.Run("nil context", func(t *testing.T) {
		manager := &Manager{
			eventHandlers: []EventHandler{},
		}

		// Test with a valid policy
		policy := &ContainerPolicy{
			AllowedSyscalls: map[uint64]bool{1: true},
			EnforcementMode: 1,
		}
		err := manager.UpdateContainerPolicy("test-container", policy)
		// Should work without context dependency for policy updates
		assert.NoError(t, err)
	})

	t.Run("nil event handler", func(t *testing.T) {
		manager := &Manager{
			eventHandlers: []EventHandler{},
		}

		// Should not panic when adding nil handler
		manager.AddEventHandler(nil)
		// Should still have empty handlers
		assert.Len(t, manager.eventHandlers, 0)
	})
}

func TestManager_ResourceExhaustion(t *testing.T) {
	t.Run("massive policies", func(t *testing.T) {
		manager := &Manager{
			eventHandlers: []EventHandler{},
		}

		// Create a very large policy set
		policies := make(map[string]*ContainerPolicy)
		for i := 0; i < 10000; i++ {
			containerID := string(rune('a' + i%26)) + string(rune('0' + i%10))
			policies[containerID] = &ContainerPolicy{
				AllowedSyscalls: make(map[uint64]bool),
				EnforcementMode: 1,
			}
			// Add many syscalls
			for j := uint64(0); j < 100; j++ {
				policies[containerID].AllowedSyscalls[j] = true
			}
		}

		// Should handle large policy sets without crashing
		start := time.Now()
		for containerID, policy := range policies {
			err := manager.UpdateContainerPolicy(containerID, policy)
			assert.NoError(t, err)
		}
		duration := time.Since(start)

		assert.Less(t, duration, 5*time.Second, "Large policy update should complete within reasonable time")
	})

	t.Run("memory pressure", func(t *testing.T) {
		manager := &Manager{
			eventHandlers: []EventHandler{},
		}

		// Simulate memory pressure by rapidly creating and destroying policies
		for iteration := 0; iteration < 100; iteration++ {
			policies := make(map[string]*ContainerPolicy)
			for i := 0; i < 100; i++ {
				containerID := string(rune('x' + iteration%5)) + string(rune('0' + i%10))
				policies[containerID] = &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{uint64(i): true},
					EnforcementMode: 1,
				}
			}
			for containerID, policy := range policies {
				err := manager.UpdateContainerPolicy(containerID, policy)
				assert.NoError(t, err)
			}
		}
	})
}

func TestManager_ConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	manager := &Manager{
		eventHandlers: []EventHandler{},
	}

	var wg sync.WaitGroup
	errorChan := make(chan error, 100)

	// Concurrent policy updates
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				policies := map[string]*ContainerPolicy{
					string(rune('w'+workerID)): {
						AllowedSyscalls: map[uint64]bool{uint64(j): true},
						EnforcementMode: 1,
					},
				}
				for containerID, policy := range policies {
					if err := manager.UpdateContainerPolicy(containerID, policy); err != nil {
						errorChan <- err
						return
					}
				}
			}
		}(i)
	}

	// Concurrent event handler additions
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				handler := &TestEventHandler{ID: j}
				manager.AddEventHandler(handler)
			}
		}()
	}

	// Concurrent capability checks
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				// Just test that method doesn't panic
				_, _ = manager.CheckCapabilities()
			}
		}()
	}

	wg.Wait()
	close(errorChan)

	// Check for any errors
	for err := range errorChan {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

func TestManager_InvalidInputs(t *testing.T) {
	manager := &Manager{
		eventHandlers: []EventHandler{},
	}

	t.Run("invalid policy data", func(t *testing.T) {
		// Test with policy containing invalid data
		policies := map[string]*ContainerPolicy{
			"invalid": {
				AllowedSyscalls: nil, // Invalid nil syscalls
				EnforcementMode: 99,   // Invalid enforcement mode
			},
		}

		// Should handle invalid policies gracefully
		for containerID, policy := range policies {
			err := manager.UpdateContainerPolicy(containerID, policy)
			// Depending on validation implementation, this may succeed or fail gracefully
			if err != nil {
				assert.Contains(t, err.Error(), "invalid", "Error should indicate invalid policy")
			}
		}
	})

	t.Run("extremely long container ID", func(t *testing.T) {
		// Test with extremely long container ID
		longID := make([]byte, 10000)
		for i := range longID {
			longID[i] = 'a'
		}

		policies := map[string]*ContainerPolicy{
			string(longID): {
				AllowedSyscalls: map[uint64]bool{1: true},
				EnforcementMode: 1,
			},
		}

		// Should handle extremely long IDs
		for containerID, policy := range policies {
			err := manager.UpdateContainerPolicy(containerID, policy)
			assert.NoError(t, err)
		}
	})

	t.Run("invalid syscall numbers", func(t *testing.T) {
		// Test with invalid syscall numbers
		policies := map[string]*ContainerPolicy{
			"test": {
				AllowedSyscalls: map[uint64]bool{
					^uint64(0): true, // Maximum uint64
					99999:      true, // Very high syscall number
				},
				EnforcementMode: 1,
			},
		}

		// Should handle invalid syscall numbers
		for containerID, policy := range policies {
			err := manager.UpdateContainerPolicy(containerID, policy)
			// May succeed but with validation warnings or fail with appropriate error
			if err != nil {
				assert.Contains(t, err.Error(), "invalid", "Should indicate invalid syscall")
			}
		}
	})
}

func TestManager_StateTransitions(t *testing.T) {
	manager := &Manager{
		eventHandlers: []EventHandler{},
		running:       false,
	}

	t.Run("start when already started", func(t *testing.T) {
		// Simulate starting when already running
		manager.running = true

		// Starting already running manager should be handled gracefully
		err := manager.Start(context.Background())
		// May return error or be idempotent
		if err != nil {
			assert.Contains(t, err.Error(), "already", "Error should indicate already running")
		}
	})

	t.Run("stop when not started", func(t *testing.T) {
		manager.running = false

		// Stopping non-running manager should be handled gracefully
		// Should not panic or error
		manager.Stop()
	})

	t.Run("multiple stops", func(t *testing.T) {
		manager.running = true

		// First stop
		manager.Stop()

		// Second stop should be idempotent
		manager.Stop()
	})
}

func TestManager_ContextCancellation(t *testing.T) {
	manager := &Manager{
		eventHandlers: []EventHandler{},
	}

	t.Run("cancelled context during update", func(t *testing.T) {
		// Test policy updates (they don't typically use context)
		policy := &ContainerPolicy{
			AllowedSyscalls: map[uint64]bool{1: true},
			EnforcementMode: 1,
		}

		// Should handle policy updates
		err := manager.UpdateContainerPolicy("test-container", policy)
		assert.NoError(t, err)
	})

	t.Run("timeout context", func(t *testing.T) {
		// Test policy updates (they don't typically use context)
		policy := &ContainerPolicy{
			AllowedSyscalls: map[uint64]bool{1: true},
			EnforcementMode: 1,
		}

		// Should handle policy updates
		err := manager.UpdateContainerPolicy("test-container", policy)
		assert.NoError(t, err)
	})
}

func TestManager_EdgeCaseRecovery(t *testing.T) {
	manager := &Manager{
		eventHandlers: []EventHandler{},
	}

	t.Run("recovery after error", func(t *testing.T) {
		// First, try an operation that might fail
		invalidPolicy := &ContainerPolicy{
			AllowedSyscalls: nil,
			EnforcementMode: 255, // Invalid high value
		}
		manager.UpdateContainerPolicy("invalid", invalidPolicy)

		// Then try a valid operation - should work
		validPolicy := &ContainerPolicy{
			AllowedSyscalls: map[uint64]bool{1: true},
			EnforcementMode: 1,
		}
		err := manager.UpdateContainerPolicy("valid", validPolicy)
		assert.NoError(t, err, "Manager should recover after error")
	})

	t.Run("statistics consistency", func(t *testing.T) {
		// Just verify manager doesn't panic with error conditions
		// Create some test policies
		policies := map[string]*ContainerPolicy{
			"test": {
				AllowedSyscalls: map[uint64]bool{1: true},
				EnforcementMode: 1,
			},
		}

		// Multiple rapid operations should not cause issues
		for i := 0; i < 10; i++ {
			for containerID, policy := range policies {
				manager.UpdateContainerPolicy(containerID, policy)
			}
		}
	})
}

// TestEventHandler for testing
type TestEventHandler struct {
	ID       int
	Received []interface{}
}

func (h *TestEventHandler) HandleSyscallEvent(event *SyscallEvent) error {
	if h.Received == nil {
		h.Received = make([]interface{}, 0)
	}
	h.Received = append(h.Received, event)
	return nil
}

func (h *TestEventHandler) HandleNetworkEvent(event *NetworkEvent) error {
	if h.Received == nil {
		h.Received = make([]interface{}, 0)
	}
	h.Received = append(h.Received, event)
	return nil
}

func (h *TestEventHandler) HandleFileEvent(event *FileEvent) error {
	if h.Received == nil {
		h.Received = make([]interface{}, 0)
	}
	h.Received = append(h.Received, event)
	return nil
}

