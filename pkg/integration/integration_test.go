package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/learner"
	"github.com/obsernetics/pahlevan/pkg/observability"
)

// MockEBPFManager implements a mock eBPF manager for integration testing
type MockEBPFManager struct {
	mock.Mock
	running      bool
	eventsChan   chan interface{}
	handlers     []ebpf.EventHandler
	capabilities *ebpf.SystemCapabilities
}

func NewMockEBPFManager() *MockEBPFManager {
	return &MockEBPFManager{
		eventsChan: make(chan interface{}, 100),
		capabilities: &ebpf.SystemCapabilities{
			HasEBPFSupport:       true,
			HasTracepointSupport: true,
			HasTCSupport:         true,
			KernelVersion:        "5.4.0-test",
		},
	}
}

func (m *MockEBPFManager) Start(ctx context.Context) error {
	args := m.Called(ctx)
	m.running = true
	return args.Error(0)
}

func (m *MockEBPFManager) Stop() {
	m.Called()
	m.running = false
	close(m.eventsChan)
}

func (m *MockEBPFManager) AddEventHandler(handler ebpf.EventHandler) {
	m.Called(handler)
	m.handlers = append(m.handlers, handler)
}

func (m *MockEBPFManager) GetCapabilities() *ebpf.SystemCapabilities {
	m.Called()
	return m.capabilities
}

func (m *MockEBPFManager) SimulateSyscallEvent(event *ebpf.SyscallEvent) {
	for _, handler := range m.handlers {
		go handler.HandleSyscallEvent(event)
	}
}

func (m *MockEBPFManager) SimulateNetworkEvent(event *ebpf.NetworkEvent) {
	for _, handler := range m.handlers {
		go handler.HandleNetworkEvent(event)
	}
}

func (m *MockEBPFManager) SimulateFileEvent(event *ebpf.FileEvent) {
	for _, handler := range m.handlers {
		go handler.HandleFileEvent(event)
	}
}

// MockLearningEngine implements a mock learning engine for integration testing
type MockLearningEngine struct {
	mock.Mock
	mu       sync.Mutex
	profiles map[string]*learner.LearningProfile
}

func NewMockLearningEngine() *MockLearningEngine {
	return &MockLearningEngine{
		profiles: make(map[string]*learner.LearningProfile),
	}
}

func (m *MockLearningEngine) HandleSyscallEvent(event *ebpf.SyscallEvent) error {
	args := m.Called(event)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Simulate adding to learning profile
	profile, exists := m.profiles[event.ContainerID]
	if !exists {
		profile = &learner.LearningProfile{
			ContainerID:      event.ContainerID,
			ObservedSyscalls: make(map[uint64]*learner.SyscallStatistics),
			StartTime:        time.Now(),
		}
		m.profiles[event.ContainerID] = profile
	}

	// Mock syscall learning
	stats, exists := profile.ObservedSyscalls[event.SyscallNr]
	if !exists {
		stats = &learner.SyscallStatistics{
			SyscallNumber: event.SyscallNr,
			TotalCalls:    0,
			UniquePids:    0,
			PidSet:        make(map[int]bool),
			Arguments:     make(map[string]uint64),
		}
		profile.ObservedSyscalls[event.SyscallNr] = stats
	}

	stats.TotalCalls++
	if !stats.PidSet[int(event.PID)] {
		stats.PidSet[int(event.PID)] = true
		stats.UniquePids++
	}
	stats.LastSeen = time.Now()

	return args.Error(0)
}

func (m *MockLearningEngine) HandleNetworkEvent(event *ebpf.NetworkEvent) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockLearningEngine) HandleFileEvent(event *ebpf.FileEvent) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockLearningEngine) HandleProcessEvent(event *ebpf.ProcessEvent) error {
	return nil
}

func (m *MockLearningEngine) HandleCapabilityEvent(event *ebpf.CapabilityEvent) error {
	return nil
}

// syscallCount is the part of a SyscallStatistics these tests assert on.
// Copying only the scalars keeps the snapshot below free of the statistics'
// internal maps, which the handler goroutines keep writing.
type syscallCount struct {
	totalCalls uint64
	uniquePids int
}

// profileSnapshot is a lock-safe copy of a learning profile.
type profileSnapshot struct {
	exists      bool
	containerID string
	syscalls    map[uint64]syscallCount
}

// snapshot copies a container's profile under the same lock the handler
// goroutines write with.
//
// The tests used to sleep a fixed interval and then read
// profile.ObservedSyscalls straight off the pointer GetProfile returns, which
// is a data race against any handler that had not finished - the sleep hid it
// rather than removed it.
func (m *MockLearningEngine) snapshot(containerID string) profileSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	profile, ok := m.profiles[containerID]
	if !ok {
		return profileSnapshot{}
	}
	out := profileSnapshot{
		exists:      true,
		containerID: profile.ContainerID,
		syscalls:    make(map[uint64]syscallCount, len(profile.ObservedSyscalls)),
	}
	for nr, st := range profile.ObservedSyscalls {
		out.syscalls[nr] = syscallCount{totalCalls: st.TotalCalls, uniquePids: st.UniquePids}
	}
	return out
}

// awaitProfile polls until a container's recorded syscalls satisfy done, and
// returns that snapshot. The handlers run as goroutines, so the tests have to
// wait for them; polling returns as soon as the events have landed instead of
// always paying a fixed sleep.
func (m *MockLearningEngine) awaitProfile(t *testing.T, containerID string, done func(profileSnapshot) bool) profileSnapshot {
	t.Helper()
	var got profileSnapshot
	require.Eventually(t, func() bool {
		got = m.snapshot(containerID)
		return done(got)
	}, 5*time.Second, time.Millisecond,
		"the learning engine never reached the expected state for %s (last seen: %+v)", containerID, &got)
	return got
}

func (m *MockLearningEngine) GetProfile(containerID string) *learner.LearningProfile {
	args := m.Called(containerID)
	if args.Get(0) != nil {
		return args.Get(0).(*learner.LearningProfile)
	}
	// The event handlers write this map from the agent's goroutines, so the
	// read needs the same lock they take.
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.profiles[containerID]
}

// MockObservabilityManager implements a mock observability manager
type MockObservabilityManager struct {
	mock.Mock
	mu      sync.Mutex
	metrics map[string]*observability.SecurityMetrics
	alerts  []*observability.Alert
}

func NewMockObservabilityManager() *MockObservabilityManager {
	return &MockObservabilityManager{
		metrics: make(map[string]*observability.SecurityMetrics),
		alerts:  make([]*observability.Alert, 0),
	}
}

func (m *MockObservabilityManager) RecordViolation(containerID string, violation interface{}) {
	m.Called(containerID, violation)

	m.mu.Lock()
	defer m.mu.Unlock()

	if metrics, exists := m.metrics[containerID]; exists {
		if metrics.ViolationCounts == nil {
			metrics.ViolationCounts = make(map[string]uint64)
		}
		metrics.ViolationCounts["total"]++
	} else {
		m.metrics[containerID] = &observability.SecurityMetrics{
			ViolationCounts: map[string]uint64{"total": 1},
			LastUpdate:      time.Now(),
		}
	}
}

func (m *MockObservabilityManager) CreateAlert(alertType observability.AlertType, message string) {
	m.Called(alertType, message)

	alert := &observability.Alert{
		Type:      alertType,
		Message:   message,
		Timestamp: time.Now(),
		Severity:  observability.SeverityMedium,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, alert)
}

func (m *MockObservabilityManager) GetMetrics(containerID string) *observability.SecurityMetrics {
	m.Called(containerID)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.metrics[containerID]
}

// Integration Tests

// Helper function to setup common mock expectations
func setupCommonMocks(ebpfManager *MockEBPFManager, learningEngine *MockLearningEngine, obsManager *MockObservabilityManager) {
	ebpfManager.On("Start", mock.Anything).Return(nil)
	ebpfManager.On("Stop").Return(nil).Maybe()
	ebpfManager.On("AddEventHandler", mock.Anything).Return()
	learningEngine.On("HandleSyscallEvent", mock.Anything).Return(nil)
	learningEngine.On("GetProfile", mock.Anything).Return(nil).Maybe()
	obsManager.On("RecordViolation", mock.Anything, mock.Anything).Return().Maybe()
	obsManager.On("GetMetrics", mock.Anything).Return(nil).Maybe()
}

func TestPahlevanSystemIntegration(t *testing.T) {
	// Create mock components
	ebpfManager := NewMockEBPFManager()
	learningEngine := NewMockLearningEngine()
	obsManager := NewMockObservabilityManager()

	// Setup expectations
	setupCommonMocks(ebpfManager, learningEngine, obsManager)

	// Test system initialization
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start eBPF manager
	err := ebpfManager.Start(ctx)
	require.NoError(t, err)

	// Add learning engine as event handler
	ebpfManager.AddEventHandler(learningEngine)

	// Simulate learning phase
	containerID := "test-container-123"

	// Generate sample syscall events for learning
	syscallEvents := []*ebpf.SyscallEvent{
		{PID: 1234, SyscallNr: 1, ContainerID: containerID, Timestamp: uint64(time.Now().UnixNano())},  // read
		{PID: 1234, SyscallNr: 2, ContainerID: containerID, Timestamp: uint64(time.Now().UnixNano())},  // write
		{PID: 1234, SyscallNr: 3, ContainerID: containerID, Timestamp: uint64(time.Now().UnixNano())},  // open
		{PID: 1235, SyscallNr: 1, ContainerID: containerID, Timestamp: uint64(time.Now().UnixNano())},  // read from different PID
		{PID: 1235, SyscallNr: 59, ContainerID: containerID, Timestamp: uint64(time.Now().UnixNano())}, // execve
	}

	// Simulate events during learning phase
	for _, event := range syscallEvents {
		ebpfManager.SimulateSyscallEvent(event)
	}

	// Verify learning occurred. The five handlers are goroutines, so wait for
	// the last of them to land - read seen from a second PID is the final
	// thing to become true - rather than sleeping 10ms per event and hoping.
	profile := learningEngine.awaitProfile(t, containerID, func(p profileSnapshot) bool {
		return len(p.syscalls) == 4 && p.syscalls[1].totalCalls == 2
	})
	require.True(t, profile.exists)
	assert.Equal(t, containerID, profile.containerID)
	assert.Contains(t, profile.syscalls, uint64(1))  // read
	assert.Contains(t, profile.syscalls, uint64(2))  // write
	assert.Contains(t, profile.syscalls, uint64(3))  // open
	assert.Contains(t, profile.syscalls, uint64(59)) // execve

	// Verify syscall statistics
	readStats := profile.syscalls[1]
	assert.Equal(t, uint64(2), readStats.totalCalls) // Called by both PIDs
	assert.Equal(t, 2, readStats.uniquePids)         // Two different PIDs

	// Cleanup
	ebpfManager.Stop()

	// Verify all mocks were called as expected
	ebpfManager.AssertExpectations(t)
	learningEngine.AssertExpectations(t)
}

func TestLearningToEnforcementTransition(t *testing.T) {
	// Create mock components
	ebpfManager := NewMockEBPFManager()
	learningEngine := NewMockLearningEngine()
	obsManager := NewMockObservabilityManager()

	// Setup expectations
	setupCommonMocks(ebpfManager, learningEngine, obsManager)
	obsManager.On("CreateAlert", mock.Anything, mock.Anything).Return()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start system
	err := ebpfManager.Start(ctx)
	require.NoError(t, err)
	ebpfManager.AddEventHandler(learningEngine)

	containerID := "production-container"

	// Phase 1: Learning phase - train on normal behavior
	normalSyscalls := []uint64{1, 2, 3, 4, 5} // read, write, open, close, stat
	for _, syscallNr := range normalSyscalls {
		for i := 0; i < 10; i++ { // Multiple calls to establish pattern
			event := &ebpf.SyscallEvent{
				PID:         uint32(1000 + i),
				SyscallNr:   syscallNr,
				ContainerID: containerID,
				Timestamp:   uint64(time.Now().UnixNano()),
			}
			ebpfManager.SimulateSyscallEvent(event)
		}
	}

	// Wait for learning to complete: poll for the profile the handlers build,
	// which returns as soon as every event has landed.
	profile := learningEngine.awaitProfile(t, containerID, func(p profileSnapshot) bool {
		return len(p.syscalls) == len(normalSyscalls)
	})
	require.True(t, profile.exists)
	assert.Len(t, profile.syscalls, len(normalSyscalls))

	// Phase 2: Enforcement phase - detect policy violations
	// Simulate a suspicious syscall that wasn't seen during learning
	suspiciousSyscall := &ebpf.SyscallEvent{
		PID:         2000,
		SyscallNr:   42, // ptrace - typically suspicious
		ContainerID: containerID,
		Timestamp:   uint64(time.Now().UnixNano()),
	}

	// This would normally trigger a policy violation in a real system
	ebpfManager.SimulateSyscallEvent(suspiciousSyscall)
	obsManager.RecordViolation(containerID, "Unexpected syscall: ptrace")
	obsManager.CreateAlert(observability.AlertTypeViolation, "Suspicious syscall detected")

	// Verify violation was recorded
	metrics := obsManager.GetMetrics(containerID)
	assert.NotNil(t, metrics)
	assert.Contains(t, metrics.ViolationCounts, "total")
	assert.Equal(t, uint64(1), metrics.ViolationCounts["total"])

	// Cleanup
	ebpfManager.Stop()

	// Verify expectations
	ebpfManager.AssertExpectations(t)
	learningEngine.AssertExpectations(t)
	obsManager.AssertExpectations(t)
}

func TestMultiContainerScenario(t *testing.T) {
	// Test scenario with multiple containers running simultaneously
	ebpfManager := NewMockEBPFManager()
	learningEngine := NewMockLearningEngine()
	obsManager := NewMockObservabilityManager()

	// Setup expectations
	setupCommonMocks(ebpfManager, learningEngine, obsManager)
	learningEngine.On("HandleNetworkEvent", mock.Anything).Return(nil)
	learningEngine.On("HandleFileEvent", mock.Anything).Return(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start system
	err := ebpfManager.Start(ctx)
	require.NoError(t, err)
	ebpfManager.AddEventHandler(learningEngine)

	// Define multiple containers with different behavior patterns
	containers := map[string][]uint64{
		"web-server":   {1, 2, 3, 41, 42},   // read, write, open, socket, connect
		"database":     {1, 2, 3, 4, 5, 17}, // read, write, open, close, stat, getcwd
		"worker-queue": {1, 2, 59, 60, 61},  // read, write, execve, exit, wait4
	}

	// Simulate events from multiple containers
	for containerID, syscalls := range containers {
		for _, syscallNr := range syscalls {
			event := &ebpf.SyscallEvent{
				PID:         1000,
				SyscallNr:   syscallNr,
				ContainerID: containerID,
				Timestamp:   uint64(time.Now().UnixNano()),
			}
			ebpfManager.SimulateSyscallEvent(event)

			// Also simulate some network events for web-server
			if containerID == "web-server" {
				networkEvent := &ebpf.NetworkEvent{
					PID:         1000,
					SrcPort:     8080,
					DstPort:     443,
					ContainerID: containerID,
					Timestamp:   uint64(time.Now().UnixNano()),
				}
				ebpfManager.SimulateNetworkEvent(networkEvent)
			}

			// Simulate file events for database
			if containerID == "database" {
				fileEvent := &ebpf.FileEvent{
					PID:         1000,
					Path:        "/var/lib/db/data.db",
					ContainerID: containerID,
					Timestamp:   uint64(time.Now().UnixNano()),
				}
				ebpfManager.SimulateFileEvent(fileEvent)
			}
		}
	}

	// Verify each container has its own learning profile. Waiting per container
	// for exactly the syscalls it should have seen returns as soon as the
	// handler goroutines have run, instead of sleeping a fixed 100ms.
	for containerID, expectedSyscalls := range containers {
		want := expectedSyscalls
		profile := learningEngine.awaitProfile(t, containerID, func(p profileSnapshot) bool {
			for _, nr := range want {
				if _, ok := p.syscalls[nr]; !ok {
					return false
				}
			}
			return p.exists
		})
		require.True(t, profile.exists, "Profile should exist for container %s", containerID)
		assert.Equal(t, containerID, profile.containerID)

		for _, syscallNr := range want {
			assert.Contains(t, profile.syscalls, syscallNr,
				"Container %s should have observed syscall %d", containerID, syscallNr)
		}
	}

	// Cleanup
	ebpfManager.Stop()

	// Verify expectations
	ebpfManager.AssertExpectations(t)
	learningEngine.AssertExpectations(t)
	obsManager.AssertExpectations(t)
}

func TestSystemUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	// Test system behavior under high load
	ebpfManager := NewMockEBPFManager()
	learningEngine := NewMockLearningEngine()
	obsManager := NewMockObservabilityManager()

	// Setup expectations for high volume
	setupCommonMocks(ebpfManager, learningEngine, obsManager)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start system
	err := ebpfManager.Start(ctx)
	require.NoError(t, err)
	ebpfManager.AddEventHandler(learningEngine)

	// Generate high volume of events
	eventCount := 10000
	containerCount := 10
	syscallTypes := []uint64{1, 2, 3, 4, 5, 59, 60}

	start := time.Now()

	for i := 0; i < eventCount; i++ {
		containerID := "load-test-container-" + string(rune('A'+i%containerCount))
		syscallNr := syscallTypes[i%len(syscallTypes)]

		event := &ebpf.SyscallEvent{
			PID:         uint32(1000 + i%100),
			SyscallNr:   syscallNr,
			ContainerID: containerID,
			Timestamp:   uint64(time.Now().UnixNano()),
		}

		ebpfManager.SimulateSyscallEvent(event)
	}

	duration := time.Since(start)
	eventsPerSecond := float64(eventCount) / duration.Seconds()

	// Performance assertions
	assert.Less(t, duration, 5*time.Second, "Should process %d events within 5 seconds", eventCount)
	assert.Greater(t, eventsPerSecond, 1000.0, "Should process at least 1000 events per second")

	t.Logf("Processed %d events in %v (%.2f events/sec)", eventCount, duration, eventsPerSecond)

	// Verify profiles were created for all containers
	for i := 0; i < containerCount; i++ {
		containerID := "load-test-container-" + string(rune('A'+i))
		profile := learningEngine.GetProfile(containerID)
		assert.NotNil(t, profile, "Profile should exist for container %s", containerID)
	}

	// Cleanup
	ebpfManager.Stop()

	// Verify expectations
	ebpfManager.AssertExpectations(t)
	learningEngine.AssertExpectations(t)
}
