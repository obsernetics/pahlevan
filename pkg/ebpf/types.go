package ebpf

import (
	"fmt"
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
	s.EventsProcessed = 0
	s.PoliciesUpdated = 0
	s.ViolationsDetected = 0
	s.LastUpdate = time.Time{}
}

func (s *Statistics) IncrementEvents() {
	s.EventsProcessed++
	s.UpdateTimestamp()
}

func (s *Statistics) IncrementPolicies() {
	s.PoliciesUpdated++
	s.UpdateTimestamp()
}

func (s *Statistics) IncrementViolations() {
	s.ViolationsDetected++
	s.UpdateTimestamp()
}

func (s *Statistics) UpdateTimestamp() {
	s.LastUpdate = time.Now()
}