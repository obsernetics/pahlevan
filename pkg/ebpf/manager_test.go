package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	manager, err := NewManager()

	// Note: This might fail on systems without eBPF support
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}

	require.NoError(t, err)
	require.NotNil(t, manager)

	// Check that basic fields are initialized
	assert.NotNil(t, manager.stopCh)
	assert.NotNil(t, manager.syscallEventCounter)
	assert.NotNil(t, manager.networkEventCounter)
	assert.NotNil(t, manager.fileEventCounter)
	assert.NotNil(t, manager.enforcementCounter)
	assert.NotNil(t, manager.capabilities)
	assert.NotNil(t, manager.capabilityChecker)

	// Clean up
	manager.Close()
}

func TestManager_GetCapabilities(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}
	defer manager.Close()

	caps := manager.GetCapabilities()
	require.NotNil(t, caps)
	assert.NotEmpty(t, caps.KernelVersion)
}

func TestManager_CheckCapabilities(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}
	defer manager.Close()

	caps, err := manager.CheckCapabilities()
	require.NoError(t, err)
	require.NotNil(t, caps)
	assert.NotEmpty(t, caps.KernelVersion)
}

func TestManager_AddEventHandler(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}
	defer manager.Close()

	// Create a mock event handler
	handler := &mockEventHandler{}

	// Add the handler
	manager.AddEventHandler(handler)

	// Verify it was added (we can't directly access the slice, but we can test it doesn't panic)
	assert.NotPanics(t, func() {
		manager.AddEventHandler(handler)
	})
}

func TestManager_StartStop(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}
	defer manager.Close()

	// Test starting without loaded programs should fail
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	// This should fail because we haven't loaded programs
	assert.Error(t, err)

	// Test stopping when not running
	assert.NotPanics(t, func() {
		manager.Stop()
	})
}

func TestManager_UpdatePolicies(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF: %v", err)
	}
	defer manager.Close()

	containerID := "test-container"

	// Test updating container policy without loaded collection
	containerPolicy := &ContainerPolicy{
		AllowedSyscalls:  map[uint64]bool{1: true, 2: true},
		LastUpdate:       time.Now(),
		LearningWindowMs: 5000,
		EnforcementMode:  1,
		SelfHealing:      true,
	}

	err = manager.UpdateContainerPolicy(containerID, containerPolicy)
	assert.Error(t, err, "Should fail when syscall collection not loaded")

	// Test updating network policy without loaded collection
	networkPolicy := &NetworkPolicy{
		AllowedEgressPorts:  map[uint16]bool{80: true, 443: true},
		AllowedIngressPorts: map[uint16]bool{8080: true},
		LastUpdate:          time.Now(),
		EnforcementMode:     1,
	}

	err = manager.UpdateNetworkPolicy(containerID, networkPolicy)
	assert.Error(t, err, "Should fail when network collection not loaded")

	// Test updating file policy without loaded collection
	filePolicy := &FilePolicy{
		AllowedPaths:    []string{"/usr", "/lib"},
		EnforcementMode: 1,
		AllowTmpWrites:  true,
		AllowProcReads:  true,
		AllowDevAccess:  false,
		LastUpdate:      time.Now(),
	}

	err = manager.UpdateFilePolicy(containerID, filePolicy)
	assert.Error(t, err, "Should fail when file collection not loaded")
}

// Mock event handler for testing
type mockEventHandler struct {
	syscallEvents []*SyscallEvent
	networkEvents []*NetworkEvent
	fileEvents    []*FileEvent
}

func (m *mockEventHandler) HandleSyscallEvent(event *SyscallEvent) error {
	m.syscallEvents = append(m.syscallEvents, event)
	return nil
}

func (m *mockEventHandler) HandleNetworkEvent(event *NetworkEvent) error {
	m.networkEvents = append(m.networkEvents, event)
	return nil
}

func (m *mockEventHandler) HandleFileEvent(event *FileEvent) error {
	m.fileEvents = append(m.fileEvents, event)
	return nil
}

func TestEventStructures(t *testing.T) {
	// Test SyscallEvent
	syscallEvent := &SyscallEvent{
		PID:         1234,
		TGID:        1234,
		UID:         1000,
		GID:         1000,
		SyscallNr:   1,
		Timestamp:   uint64(time.Now().UnixNano()),
		Comm:        "test-process",
		ContainerID: "test-container",
		Phase:       1,
		Action:      0,
	}
	assert.Equal(t, uint32(1234), syscallEvent.PID)
	assert.Equal(t, "test-process", syscallEvent.Comm)

	// Test NetworkEvent
	networkEvent := &NetworkEvent{
		PID:         1234,
		TGID:        1234,
		SrcIP:       0x7f000001, // 127.0.0.1
		DstIP:       0x08080808, // 8.8.8.8
		SrcPort:     12345,
		DstPort:     80,
		Protocol:    6, // TCP
		Direction:   1, // Outgoing
		Action:      0, // Allow
		Timestamp:   uint64(time.Now().UnixNano()),
		ContainerID: "test-container",
	}
	assert.Equal(t, uint16(80), networkEvent.DstPort)
	assert.Equal(t, uint8(6), networkEvent.Protocol)

	// Test FileEvent
	fileEvent := &FileEvent{
		PID:         1234,
		TGID:        1234,
		UID:         1000,
		GID:         1000,
		Timestamp:   uint64(time.Now().UnixNano()),
		SyscallNr:   2, // open
		Flags:       0,
		Mode:        0644,
		Action:      0,
		Comm:        "test-process",
		ContainerID: "test-container",
		Path:        "/tmp/test-file",
	}
	assert.Equal(t, "/tmp/test-file", fileEvent.Path)
	assert.Equal(t, uint32(2), fileEvent.SyscallNr)
}

func TestPolicyStructures(t *testing.T) {
	// Test ContainerPolicy
	containerPolicy := &ContainerPolicy{
		AllowedSyscalls:  map[uint64]bool{1: true, 2: true, 3: false},
		LastUpdate:       time.Now(),
		LearningWindowMs: 5000,
		EnforcementMode:  1,
		SelfHealing:      true,
	}
	assert.True(t, containerPolicy.AllowedSyscalls[1])
	assert.False(t, containerPolicy.AllowedSyscalls[3])
	assert.True(t, containerPolicy.SelfHealing)

	// Test NetworkPolicy
	networkPolicy := &NetworkPolicy{
		AllowedEgressPorts:  map[uint16]bool{80: true, 443: true},
		AllowedIngressPorts: map[uint16]bool{8080: true, 3000: true},
		AllowedEgressIPs:    []uint32{0x08080808, 0x08080404}, // 8.8.8.8, 8.8.4.4
		AllowedIngressIPs:   []uint32{0x7f000001},             // 127.0.0.1
		LastUpdate:          time.Now(),
		EnforcementMode:     1,
	}
	assert.True(t, networkPolicy.AllowedEgressPorts[80])
	assert.True(t, networkPolicy.AllowedIngressPorts[8080])
	assert.Len(t, networkPolicy.AllowedEgressIPs, 2)

	// Test FilePolicy
	filePolicy := &FilePolicy{
		AllowedPaths:    []string{"/usr", "/lib", "/bin"},
		EnforcementMode: 1,
		AllowTmpWrites:  true,
		AllowProcReads:  true,
		AllowDevAccess:  false,
		LastUpdate:      time.Now(),
	}
	assert.Contains(t, filePolicy.AllowedPaths, "/usr")
	assert.True(t, filePolicy.AllowTmpWrites)
	assert.False(t, filePolicy.AllowDevAccess)
}