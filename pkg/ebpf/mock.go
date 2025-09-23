//go:build testing
// +build testing

/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockManager provides a mock implementation of the eBPF manager for testing
type MockManager struct {
	mu                  sync.RWMutex
	isLoaded            bool
	containerPolicies   map[string]*ContainerPolicy
	eventHandlers       []EventHandler
	config              *ProgramConfig
	simulateEvents      bool
	eventGeneration     chan struct{}
	stopEventGeneration chan struct{}
}

// NewMockManager creates a new mock eBPF manager
func NewMockManager() *MockManager {
	return &MockManager{
		containerPolicies:   make(map[string]*ContainerPolicy),
		eventHandlers:       make([]EventHandler, 0),
		eventGeneration:     make(chan struct{}),
		stopEventGeneration: make(chan struct{}),
	}
}

// LoadPrograms simulates loading eBPF programs
func (m *MockManager) LoadPrograms(config *ProgramConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isLoaded {
		return fmt.Errorf("programs already loaded")
	}

	m.config = config
	m.isLoaded = true

	// Start mock event generation if enabled
	if m.simulateEvents {
		go m.generateMockEvents()
	}

	return nil
}

// UpdateContainerPolicy simulates updating container policy
func (m *MockManager) UpdateContainerPolicy(containerID string, policy *ContainerPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLoaded {
		return fmt.Errorf("programs not loaded")
	}

	// Store the policy in memory
	m.containerPolicies[containerID] = policy

	return nil
}

// RemoveContainerPolicy simulates removing container policy
func (m *MockManager) RemoveContainerPolicy(containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLoaded {
		return fmt.Errorf("programs not loaded")
	}

	delete(m.containerPolicies, containerID)
	return nil
}

// RegisterEventHandler registers an event handler
func (m *MockManager) RegisterEventHandler(handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// GetStats returns mock statistics
func (m *MockManager) GetStats() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.isLoaded {
		return nil, fmt.Errorf("programs not loaded")
	}

	stats := map[string]interface{}{
		"loaded":             m.isLoaded,
		"mock":               true,
		"container_policies": len(m.containerPolicies),
		"event_handlers":     len(m.eventHandlers),
		"simulate_events":    m.simulateEvents,
	}

	return stats, nil
}

// Close simulates closing the eBPF manager
func (m *MockManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLoaded {
		return nil
	}

	// Stop event generation
	if m.simulateEvents {
		close(m.stopEventGeneration)
	}

	m.isLoaded = false
	m.containerPolicies = make(map[string]*ContainerPolicy)
	m.eventHandlers = make([]EventHandler, 0)

	return nil
}

// IsLoaded returns whether the mock programs are loaded
func (m *MockManager) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLoaded
}

// SetSimulateEvents enables or disables mock event generation
func (m *MockManager) SetSimulateEvents(simulate bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulateEvents = simulate
}

// generateMockEvents generates mock eBPF events for testing
func (m *MockManager) generateMockEvents() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	eventCounter := 0

	for {
		select {
		case <-m.stopEventGeneration:
			return
		case <-ticker.C:
			m.generateSampleEvents(eventCounter)
			eventCounter++
		}
	}
}

// generateSampleEvents generates sample syscall, network, and file events
func (m *MockManager) generateSampleEvents(counter int) {
	m.mu.RLock()
	handlers := make([]EventHandler, len(m.eventHandlers))
	copy(handlers, m.eventHandlers)
	policies := make(map[string]*ContainerPolicy)
	for k, v := range m.containerPolicies {
		policies[k] = v
	}
	m.mu.RUnlock()

	if len(handlers) == 0 {
		return
	}

	now := time.Now()
	containerID := fmt.Sprintf("mock-container-%d", counter%3)

	// Generate mock syscall event
	syscallEvent := &SyscallEvent{
		PID:         uint32(1000 + counter),
		TGID:        uint32(1000 + counter),
		SyscallNr:   uint64(counter % 300), // Mock syscall numbers
		Timestamp:   now,
		ContainerID: containerID,
		Phase:       EventPhaseLearning,
		Action:      EventActionAllow,
	}

	// Check if this syscall should be blocked based on policy
	if policy, exists := policies[containerID]; exists {
		for _, blocked := range policy.BlockedSyscalls {
			if blocked == syscallEvent.SyscallNr {
				syscallEvent.Action = EventActionBlock
				break
			}
		}
	}

	// Generate mock network event
	networkEvent := &NetworkEvent{
		PID:         uint32(1000 + counter),
		TGID:        uint32(1000 + counter),
		SourceIP:    0xC0A80101, // 192.168.1.1
		DestIP:      0x08080808, // 8.8.8.8
		SourcePort:  uint16(8080 + counter%1000),
		DestPort:    80,
		Protocol:    6, // TCP
		Timestamp:   now,
		ContainerID: containerID,
		Direction:   NetworkDirectionOutbound,
		Action:      EventActionAllow,
	}

	// Generate mock file event
	fileEvent := &FileEvent{
		PID:         uint32(1000 + counter),
		TGID:        uint32(1000 + counter),
		Filename:    fmt.Sprintf("/tmp/mock-file-%d", counter),
		Operation:   FileOperationOpen,
		Flags:       0x2, // O_RDWR
		Mode:        0644,
		Timestamp:   now,
		ContainerID: containerID,
		Action:      EventActionAllow,
	}

	// Send events to all handlers
	for _, handler := range handlers {
		go func(h EventHandler) {
			if err := h.HandleSyscallEvent(syscallEvent); err != nil {
				// Log error in real implementation
			}
			if err := h.HandleNetworkEvent(networkEvent); err != nil {
				// Log error in real implementation
			}
			if err := h.HandleFileEvent(fileEvent); err != nil {
				// Log error in real implementation
			}
		}(handler)
	}
}

// GetContainerPolicy returns the policy for a container (testing helper)
func (m *MockManager) GetContainerPolicy(containerID string) (*ContainerPolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, exists := m.containerPolicies[containerID]
	return policy, exists
}

// GetContainerPolicies returns all container policies (testing helper)
func (m *MockManager) GetContainerPolicies() map[string]*ContainerPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ContainerPolicy)
	for k, v := range m.containerPolicies {
		result[k] = v
	}
	return result
}

// TriggerEvent manually triggers an event for testing
func (m *MockManager) TriggerEvent(event interface{}) error {
	m.mu.RLock()
	handlers := make([]EventHandler, len(m.eventHandlers))
	copy(handlers, m.eventHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		switch e := event.(type) {
		case *SyscallEvent:
			go handler.HandleSyscallEvent(e)
		case *NetworkEvent:
			go handler.HandleNetworkEvent(e)
		case *FileEvent:
			go handler.HandleFileEvent(e)
		default:
			return fmt.Errorf("unknown event type: %T", event)
		}
	}

	return nil
}

// SimulateViolation simulates a policy violation for testing
func (m *MockManager) SimulateViolation(containerID string, violationType string) error {
	m.mu.RLock()
	handlers := make([]EventHandler, len(m.eventHandlers))
	copy(handlers, m.eventHandlers)
	m.mu.RUnlock()

	now := time.Now()

	switch violationType {
	case "syscall":
		event := &SyscallEvent{
			PID:         1234,
			TGID:        1234,
			SyscallNr:   999, // Unusual syscall number
			Timestamp:   now,
			ContainerID: containerID,
			Phase:       EventPhaseEnforcing,
			Action:      EventActionBlock,
		}
		for _, handler := range handlers {
			go handler.HandleSyscallEvent(event)
		}

	case "network":
		event := &NetworkEvent{
			PID:         1234,
			TGID:        1234,
			SourceIP:    0xC0A80101,
			DestIP:      0xAC100001, // 172.16.0.1 - potentially suspicious
			SourcePort:  8080,
			DestPort:    22, // SSH port
			Protocol:    6,
			Timestamp:   now,
			ContainerID: containerID,
			Direction:   NetworkDirectionOutbound,
			Action:      EventActionBlock,
		}
		for _, handler := range handlers {
			go handler.HandleNetworkEvent(event)
		}

	case "file":
		event := &FileEvent{
			PID:         1234,
			TGID:        1234,
			Filename:    "/etc/passwd", // Sensitive file
			Operation:   FileOperationWrite,
			Flags:       0x2,
			Mode:        0644,
			Timestamp:   now,
			ContainerID: containerID,
			Action:      EventActionBlock,
		}
		for _, handler := range handlers {
			go handler.HandleFileEvent(event)
		}

	default:
		return fmt.Errorf("unknown violation type: %s", violationType)
	}

	return nil
}

// MockManagerInterface defines the interface for mock manager specific methods
type MockManagerInterface interface {
	Manager
	SetSimulateEvents(bool)
	GetContainerPolicy(string) (*ContainerPolicy, bool)
	GetContainerPolicies() map[string]*ContainerPolicy
	TriggerEvent(interface{}) error
	SimulateViolation(string, string) error
}

// Verify that MockManager implements both Manager and MockManagerInterface
var (
	_ Manager              = (*MockManager)(nil)
	_ MockManagerInterface = (*MockManager)(nil)
)
