package ebpf

import (
	"fmt"
	"sync"
	"time"
)

// eBPF manager types

// Note: ContainerPolicy, NetworkPolicy, and FilePolicy are defined in manager.go
// to avoid duplication.

type EventType string

const (
	EventTypeSyscall EventType = "syscall"
	EventTypeNetwork EventType = "network"
	EventTypeFile    EventType = "file"
	EventTypeProcess EventType = "process"
)

type PolicyUpdateEvent struct {
	ContainerID string
	EventType   EventType
	Timestamp   time.Time
	Data        map[string]interface{}
}

type Statistics struct {
	mu                 sync.RWMutex
	EventsProcessed    uint64
	PoliciesUpdated    uint64
	ViolationsDetected uint64
	LastUpdate         time.Time
}

// Methods for policy types are defined in manager.go alongside the type definitions

func (pue *PolicyUpdateEvent) Validate() error {
	if pue.ContainerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if pue.Timestamp.IsZero() {
		return fmt.Errorf("timestamp cannot be zero")
	}
	return nil
}

func (s *Statistics) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EventsProcessed = 0
	s.PoliciesUpdated = 0
	s.ViolationsDetected = 0
	s.LastUpdate = time.Time{}
}

func (s *Statistics) IncrementEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EventsProcessed++
	s.lastUpdateNoLock()
}

func (s *Statistics) IncrementPolicies() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PoliciesUpdated++
	s.lastUpdateNoLock()
}

func (s *Statistics) IncrementViolations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ViolationsDetected++
	s.lastUpdateNoLock()
}

func (s *Statistics) UpdateTimestamp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUpdate = time.Now()
}

// lastUpdateNoLock updates timestamp without acquiring the lock
// Should only be called when the caller already holds the lock
func (s *Statistics) lastUpdateNoLock() {
	s.LastUpdate = time.Now()
}

// Thread-safe getters
func (s *Statistics) GetEventsProcessed() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.EventsProcessed
}

func (s *Statistics) GetPoliciesUpdated() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PoliciesUpdated
}

func (s *Statistics) GetViolationsDetected() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ViolationsDetected
}

func (s *Statistics) GetLastUpdate() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastUpdate
}