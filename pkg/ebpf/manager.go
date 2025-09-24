package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/metric"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" SyscallMonitor ../../bpf/syscall_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" NetworkMonitor ../../bpf/network_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" FileMonitor ../../bpf/file_monitor.c

type Manager struct {
	mu                  sync.RWMutex
	syscallSpecs        *ebpf.CollectionSpec
	networkSpecs        *ebpf.CollectionSpec
	fileSpecs           *ebpf.CollectionSpec
	syscallCollection   *ebpf.Collection
	networkCollection   *ebpf.Collection
	fileCollection      *ebpf.Collection
	syscallLinks        []link.Link
	networkLinks        []link.Link
	fileLinks           []link.Link
	eventReader         *ringbuf.Reader
	networkEventReader  *ringbuf.Reader
	fileEventReader     *ringbuf.Reader
	eventHandlers       []EventHandler
	running             bool
	stopCh              chan struct{}
	syscallEventCounter prometheus.Counter
	networkEventCounter prometheus.Counter
	fileEventCounter    prometheus.Counter
	enforcementCounter  prometheus.Counter
	otelSyscallCounter  metric.Int64Counter
	otelNetworkCounter  metric.Int64Counter
	otelFileCounter     metric.Int64Counter
	capabilities        *SystemCapabilities
	capabilityChecker   *CapabilityChecker
}

type EventHandler interface {
	HandleSyscallEvent(event *SyscallEvent) error
	HandleNetworkEvent(event *NetworkEvent) error
	HandleFileEvent(event *FileEvent) error
}

type SyscallEvent struct {
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	SyscallNr   uint64
	Timestamp   uint64
	Comm        string
	ContainerID string
	Phase       uint8
	Action      uint8
}

type NetworkEvent struct {
	PID         uint32
	TGID        uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Direction   uint8
	Action      uint8
	Timestamp   uint64
	ContainerID string
}

type FileEvent struct {
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	Timestamp   uint64
	SyscallNr   uint32
	Flags       uint32
	Mode        uint16
	Action      uint8
	Comm        string
	ContainerID string
	Path        string
}

type ContainerPolicy struct {
	AllowedSyscalls  map[uint64]bool
	LastUpdate       time.Time
	LearningWindowMs uint32
	EnforcementMode  uint8
	SelfHealing      bool
}

type NetworkPolicy struct {
	AllowedEgressPorts  map[uint16]bool
	AllowedIngressPorts map[uint16]bool
	AllowedEgressIPs    []uint32
	AllowedIngressIPs   []uint32
	LastUpdate          time.Time
	EnforcementMode     uint8
}

type FilePolicy struct {
	AllowedPaths    []string
	EnforcementMode uint8
	AllowTmpWrites  bool
	AllowProcReads  bool
	AllowDevAccess  bool
	LastUpdate      time.Time
}

func NewManager() (*Manager, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %v", err)
	}

	// Initialize Prometheus metrics
	syscallEventCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_syscall_events_total",
		Help: "Total number of syscall events processed",
	})

	networkEventCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_network_events_total",
		Help: "Total number of network events processed",
	})

	fileEventCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_file_events_total",
		Help: "Total number of file events processed",
	})

	enforcementCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_enforcement_actions_total",
		Help: "Total number of enforcement actions taken",
	})

	prometheus.MustRegister(syscallEventCounter, networkEventCounter, fileEventCounter, enforcementCounter)

	// Initialize capability checker and check system capabilities
	capabilityChecker := NewCapabilityChecker()
	capabilities, err := capabilityChecker.CheckSystemCapabilities()
	if err != nil {
		return nil, fmt.Errorf("failed to check system capabilities: %v", err)
	}

	return &Manager{
		stopCh:              make(chan struct{}),
		syscallEventCounter: syscallEventCounter,
		networkEventCounter: networkEventCounter,
		fileEventCounter:    fileEventCounter,
		enforcementCounter:  enforcementCounter,
		capabilities:        capabilities,
		capabilityChecker:   capabilityChecker,
	}, nil
}

func (m *Manager) LoadPrograms() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check required capabilities
	if err := m.capabilities.RequireFeature("ebpf"); err != nil {
		return fmt.Errorf("eBPF support check failed: %v", err)
	}

	// Load syscall monitor (requires tracepoint support)
	if !m.capabilities.HasTracepointSupport {
		return fmt.Errorf("syscall monitoring requires tracepoint support which is not available on this system. Please ensure debugfs is mounted and kernel has tracepoint support")
	}

	syscallSpecs, err := LoadSyscallMonitor()
	if err != nil {
		return fmt.Errorf("failed to load syscall monitor specs: %v", err)
	}
	m.syscallSpecs = syscallSpecs

	syscallColl, err := ebpf.NewCollection(syscallSpecs)
	if err != nil {
		return fmt.Errorf("failed to create syscall collection: %v", err)
	}
	m.syscallCollection = syscallColl

	// Load network monitor (may require TC support for some features)
	networkSpecs, err := LoadNetworkMonitor()
	if err != nil {
		if !m.capabilities.HasTCSupport {
			return fmt.Errorf("network monitoring failed to load and TC (traffic control) support is not available. Please install iproute2 package and ensure you have root privileges. Error: %v", err)
		}
		return fmt.Errorf("failed to load network monitor specs: %v", err)
	}
	m.networkSpecs = networkSpecs

	networkColl, err := ebpf.NewCollection(networkSpecs)
	if err != nil {
		if !m.capabilities.HasTCSupport {
			return fmt.Errorf("network monitoring collection creation failed and TC support is not available. Network monitoring will be limited. Error: %v", err)
		}
		return fmt.Errorf("failed to create network collection: %v", err)
	}
	m.networkCollection = networkColl

	// Load file monitor (requires tracepoint support)
	if !m.capabilities.HasTracepointSupport {
		return fmt.Errorf("file monitoring requires tracepoint support which is not available on this system")
	}

	fileSpecs, err := LoadFileMonitor()
	if err != nil {
		return fmt.Errorf("failed to load file monitor specs: %v", err)
	}
	m.fileSpecs = fileSpecs

	fileColl, err := ebpf.NewCollection(fileSpecs)
	if err != nil {
		return fmt.Errorf("failed to create file collection: %v", err)
	}
	m.fileCollection = fileColl

	return nil
}

func (m *Manager) AttachPrograms() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Attach syscall tracepoints
	syscallTracepoints := []string{
		"sys_enter_openat",
		"sys_enter_read",
		"sys_enter_write",
		"sys_enter_execve",
		"sys_enter_clone",
		"sys_enter_fork",
		"sys_enter_socket",
		"sys_enter_connect",
		"sys_enter_bind",
	}

	for _, tp := range syscallTracepoints {
		prog := m.syscallCollection.Programs[fmt.Sprintf("trace_%s", tp)]
		if prog == nil {
			continue
		}

		l, err := link.Tracepoint("syscalls", tp, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach tracepoint %s: %v", tp, err)
		}
		m.syscallLinks = append(m.syscallLinks, l)
	}

	// Attach file monitor tracepoints
	fileTracepoints := []string{
		"sys_enter_openat",
		"sys_enter_open",
		"sys_enter_creat",
		"sys_enter_unlink",
		"sys_enter_unlinkat",
		"sys_enter_mkdir",
		"sys_enter_mkdirat",
		"sys_enter_rmdir",
	}

	for _, tp := range fileTracepoints {
		prog := m.fileCollection.Programs[fmt.Sprintf("trace_file_%s", tp)]
		if prog == nil {
			prog = m.fileCollection.Programs[fmt.Sprintf("trace_file_%s", tp[11:])] // Remove sys_enter_ prefix
		}
		if prog == nil {
			continue
		}

		l, err := link.Tracepoint("syscalls", tp, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach file tracepoint %s: %v", tp, err)
		}
		m.fileLinks = append(m.fileLinks, l)
	}

	// Setup event readers
	if err := m.setupEventReaders(); err != nil {
		return fmt.Errorf("failed to setup event readers: %v", err)
	}

	return nil
}

func (m *Manager) setupEventReaders() error {
	// Syscall events
	eventsMap := m.syscallCollection.Maps["events"]
	if eventsMap != nil {
		reader, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			return fmt.Errorf("failed to create syscall event reader: %v", err)
		}
		m.eventReader = reader
	}

	// Network events
	networkEventsMap := m.networkCollection.Maps["network_events"]
	if networkEventsMap != nil {
		reader, err := ringbuf.NewReader(networkEventsMap)
		if err != nil {
			return fmt.Errorf("failed to create network event reader: %v", err)
		}
		m.networkEventReader = reader
	}

	// File events
	fileEventsMap := m.fileCollection.Maps["file_events"]
	if fileEventsMap != nil {
		reader, err := ringbuf.NewReader(fileEventsMap)
		if err != nil {
			return fmt.Errorf("failed to create file event reader: %v", err)
		}
		m.fileEventReader = reader
	}

	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("manager is already running")
	}
	m.running = true
	m.mu.Unlock()

	// Attach programs
	if err := m.AttachPrograms(); err != nil {
		return fmt.Errorf("failed to attach programs: %v", err)
	}

	// Start event processing goroutines
	go m.processSyscallEvents(ctx)
	go m.processNetworkEvents(ctx)
	go m.processFileEvents(ctx)

	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	close(m.stopCh)
	m.running = false

	// Close event readers
	if m.eventReader != nil {
		m.eventReader.Close()
	}
	if m.networkEventReader != nil {
		m.networkEventReader.Close()
	}
	if m.fileEventReader != nil {
		m.fileEventReader.Close()
	}

	// Detach all links
	for _, l := range m.syscallLinks {
		l.Close()
	}
	for _, l := range m.networkLinks {
		l.Close()
	}
	for _, l := range m.fileLinks {
		l.Close()
	}

	// Close collections
	if m.syscallCollection != nil {
		m.syscallCollection.Close()
	}
	if m.networkCollection != nil {
		m.networkCollection.Close()
	}
	if m.fileCollection != nil {
		m.fileCollection.Close()
	}
}

func (m *Manager) Close() {
	m.Stop()
}

func (m *Manager) AddEventHandler(handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// GetCapabilities returns the system capabilities detected during initialization
func (m *Manager) GetCapabilities() *SystemCapabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.capabilities
}

// CheckCapabilities re-checks system capabilities
func (m *Manager) CheckCapabilities() (*SystemCapabilities, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	capabilities, err := m.capabilityChecker.CheckSystemCapabilities()
	if err != nil {
		return nil, err
	}
	m.capabilities = capabilities
	return capabilities, nil
}

func (m *Manager) UpdateContainerPolicy(containerID string, policy *ContainerPolicy) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.syscallCollection == nil {
		return fmt.Errorf("syscall collection not loaded")
	}

	policyMap := m.syscallCollection.Maps["container_policies"]
	if policyMap == nil {
		return fmt.Errorf("container_policies map not found")
	}

	// Convert Go policy to eBPF format
	ebpfPolicy := convertToEBPFPolicy(policy)
	return policyMap.Put([]byte(containerID), ebpfPolicy)
}

func (m *Manager) UpdateNetworkPolicy(containerID string, policy *NetworkPolicy) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.networkCollection == nil {
		return fmt.Errorf("network collection not loaded")
	}

	policyMap := m.networkCollection.Maps["network_policies"]
	if policyMap == nil {
		return fmt.Errorf("network_policies map not found")
	}

	// Convert Go policy to eBPF format
	ebpfPolicy := convertToEBPFNetworkPolicy(policy)
	return policyMap.Put([]byte(containerID), ebpfPolicy)
}

func (m *Manager) UpdateFilePolicy(containerID string, policy *FilePolicy) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.fileCollection == nil {
		return fmt.Errorf("file collection not loaded")
	}

	policyMap := m.fileCollection.Maps["file_policies"]
	if policyMap == nil {
		return fmt.Errorf("file_policies map not found")
	}

	// Convert Go policy to eBPF format
	ebpfPolicy := convertToEBPFFilePolicy(policy)
	return policyMap.Put([]byte(containerID), ebpfPolicy)
}

func (m *Manager) processSyscallEvents(ctx context.Context) {
	if m.eventReader == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
			record, err := m.eventReader.Read()
			if err != nil {
				continue
			}

			event := parseSyscallEvent(record.RawSample)
			if event != nil {
				m.syscallEventCounter.Inc()
				if m.otelSyscallCounter != nil {
					m.otelSyscallCounter.Add(ctx, 1)
				}

				// Notify handlers
				m.mu.RLock()
				for _, handler := range m.eventHandlers {
					go func(h EventHandler, e *SyscallEvent) {
						_ = h.HandleSyscallEvent(e)
					}(handler, event)
				}
				m.mu.RUnlock()
			}
		}
	}
}

func (m *Manager) processNetworkEvents(ctx context.Context) {
	if m.networkEventReader == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
			record, err := m.networkEventReader.Read()
			if err != nil {
				continue
			}

			event := parseNetworkEvent(record.RawSample)
			if event != nil {
				m.networkEventCounter.Inc()
				if m.otelNetworkCounter != nil {
					m.otelNetworkCounter.Add(ctx, 1)
				}

				// Notify handlers
				m.mu.RLock()
				for _, handler := range m.eventHandlers {
					go func(h EventHandler, e *NetworkEvent) {
						_ = h.HandleNetworkEvent(e)
					}(handler, event)
				}
				m.mu.RUnlock()
			}
		}
	}
}

func (m *Manager) processFileEvents(ctx context.Context) {
	if m.fileEventReader == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
			record, err := m.fileEventReader.Read()
			if err != nil {
				continue
			}

			event := parseFileEvent(record.RawSample)
			if event != nil {
				m.fileEventCounter.Inc()
				if m.otelFileCounter != nil {
					m.otelFileCounter.Add(ctx, 1)
				}

				// Notify handlers
				m.mu.RLock()
				for _, handler := range m.eventHandlers {
					go func(h EventHandler, e *FileEvent) {
						_ = h.HandleFileEvent(e)
					}(handler, event)
				}
				m.mu.RUnlock()
			}
		}
	}
}

// Helper functions for converting between Go and eBPF data structures

// EBPFContainerPolicy represents the eBPF container_policy struct layout
type EBPFContainerPolicy struct {
	ContainerID      uint32    // container_id
	LearningMode     uint32    // learning_mode (1 = learning, 0 = enforcement)
	AllowedSyscalls  [64]uint64 // allowed_syscalls bitmap for syscalls 0-4095
	ViolationCount   uint32    // violation_count
	LastUpdateNs     uint64    // last_update_ns
}

func convertToEBPFPolicy(policy *ContainerPolicy) *EBPFContainerPolicy {
	ebpfPolicy := &EBPFContainerPolicy{
		ContainerID:      0, // Will be set by caller as map key
		LearningMode:     0, // 0 = enforcement mode by default
		ViolationCount:   0,
		LastUpdateNs:     uint64(policy.LastUpdate.UnixNano()),
	}

	// Convert enforcement mode
	if policy.EnforcementMode == 0 { // Assuming 0 = monitoring/learning
		ebpfPolicy.LearningMode = 1
	}

	// Convert syscall map to bitmap
	for syscallNr, allowed := range policy.AllowedSyscalls {
		if allowed && syscallNr < 4096 { // eBPF supports 0-4095
			wordIdx := syscallNr / 64
			bitIdx := syscallNr % 64
			if wordIdx < 64 {
				ebpfPolicy.AllowedSyscalls[wordIdx] |= (1 << bitIdx)
			}
		}
	}

	return ebpfPolicy
}

// EBPFConnectionPolicy represents the eBPF connection_policy struct layout
type EBPFConnectionPolicy struct {
	ContainerID            uint32     // container_id
	AllowedDestinations    [256]uint32 // allowed_destinations (IP addresses)
	AllowedPorts          [64]uint16  // allowed_ports
	LearningMode          uint32     // learning_mode (1 = learning, 0 = enforcement)
	LastUpdateNs          uint64     // last_update_ns
}

func convertToEBPFNetworkPolicy(policy *NetworkPolicy) *EBPFConnectionPolicy {
	ebpfPolicy := &EBPFConnectionPolicy{
		ContainerID:   0, // Will be set by caller as map key
		LearningMode:  0, // 0 = enforcement mode by default
		LastUpdateNs:  uint64(policy.LastUpdate.UnixNano()),
	}

	// Convert enforcement mode
	if policy.EnforcementMode == 0 { // Assuming 0 = monitoring/learning
		ebpfPolicy.LearningMode = 1
	}

	// Convert allowed IPs (both egress and ingress)
	destIdx := 0
	for _, ip := range policy.AllowedEgressIPs {
		if destIdx < 256 {
			ebpfPolicy.AllowedDestinations[destIdx] = ip
			destIdx++
		}
	}
	for _, ip := range policy.AllowedIngressIPs {
		if destIdx < 256 {
			ebpfPolicy.AllowedDestinations[destIdx] = ip
			destIdx++
		}
	}

	// Convert allowed ports (both egress and ingress)
	portIdx := 0
	for port := range policy.AllowedEgressPorts {
		if portIdx < 64 {
			ebpfPolicy.AllowedPorts[portIdx] = port
			portIdx++
		}
	}
	for port := range policy.AllowedIngressPorts {
		if portIdx < 64 {
			ebpfPolicy.AllowedPorts[portIdx] = port
			portIdx++
		}
	}

	return ebpfPolicy
}

// EBPFFileAccessPolicy represents the eBPF file_access_policy struct layout
type EBPFFileAccessPolicy struct {
	ContainerID   uint32        // container_id
	LearningMode  uint32        // learning_mode (1 = learning, 0 = enforcement)
	AllowedPaths  [1024][64]byte // allowed_paths (char array)
	PathCount     uint32        // path_count (number of valid paths)
	LastUpdateNs  uint64        // last_update_ns
}

func convertToEBPFFilePolicy(policy *FilePolicy) *EBPFFileAccessPolicy {
	ebpfPolicy := &EBPFFileAccessPolicy{
		ContainerID:   0, // Will be set by caller as map key
		LearningMode:  0, // 0 = enforcement mode by default
		PathCount:     0,
		LastUpdateNs:  uint64(policy.LastUpdate.UnixNano()),
	}

	// Convert enforcement mode
	if policy.EnforcementMode == 0 { // Assuming 0 = monitoring/learning
		ebpfPolicy.LearningMode = 1
	}

	// Convert allowed paths to fixed-size char arrays
	for i, path := range policy.AllowedPaths {
		if i >= 1024 { // eBPF limit
			break
		}

		// Copy path to fixed-size array (max 63 chars + null terminator)
		pathBytes := []byte(path)
		copyLen := len(pathBytes)
		if copyLen >= 64 {
			copyLen = 63 // Leave space for null terminator
		}

		copy(ebpfPolicy.AllowedPaths[i][:copyLen], pathBytes)
		ebpfPolicy.AllowedPaths[i][copyLen] = 0 // Null terminator
		ebpfPolicy.PathCount++
	}

	return ebpfPolicy
}

func parseSyscallEvent(data []byte) *SyscallEvent {
	// Parse raw eBPF syscall_event struct data
	if len(data) < 32 { // Minimum size for syscall_event struct
		return nil
	}

	event := &SyscallEvent{}

	// Parse eBPF syscall_event struct layout:
	// __u32 pid; __u32 tid; __u32 syscall_nr; __u64 timestamp_ns; char comm[16]; __u32 container_id;
	offset := 0

	// Parse PID (uint32)
	event.PID = uint32(data[offset]) | uint32(data[offset+1])<<8 |
	           uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	offset += 4

	// Parse TID (uint32) - note Go SyscallEvent has TGID but eBPF has tid
	event.TGID = uint32(data[offset]) | uint32(data[offset+1])<<8 |
	            uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	offset += 4

	// Parse syscall_nr (uint32 in eBPF, but uint64 in Go)
	event.SyscallNr = uint64(uint32(data[offset]) | uint32(data[offset+1])<<8 |
	                 uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24)
	offset += 4

	// Parse timestamp_ns (uint64)
	event.Timestamp = uint64(data[offset]) | uint64(data[offset+1])<<8 |
	                 uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
	                 uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 |
	                 uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56
	offset += 8

	// Parse comm (char[16]) - find null terminator
	commBytes := make([]byte, 0, 16)
	for i := 0; i < 16 && offset+i < len(data); i++ {
		if data[offset+i] == 0 {
			break
		}
		commBytes = append(commBytes, data[offset+i])
	}
	event.Comm = string(commBytes)
	offset += 16

	// Parse container_id (uint32) - convert to string
	if offset+4 <= len(data) {
		containerID := uint32(data[offset]) | uint32(data[offset+1])<<8 |
		              uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
		event.ContainerID = fmt.Sprintf("%d", containerID)
	}

	return event
}

func parseNetworkEvent(data []byte) *NetworkEvent {
	if len(data) < 32 { // Minimum size for network event
		return &NetworkEvent{}
	}

	event := &NetworkEvent{}

	// Parse binary data using encoding/binary
	offset := 0

	// Parse PID (4 bytes)
	event.PID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse TGID (4 bytes)
	event.TGID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse SrcIP (4 bytes)
	event.SrcIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse DstIP (4 bytes)
	event.DstIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse SrcPort (2 bytes)
	event.SrcPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Parse DstPort (2 bytes)
	event.DstPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Parse Protocol (1 byte)
	if offset < len(data) {
		event.Protocol = data[offset]
		offset++
	}

	// Parse Direction (1 byte)
	if offset < len(data) {
		event.Direction = data[offset]
		offset++
	}

	// Parse Action (1 byte)
	if offset < len(data) {
		event.Action = data[offset]
		offset++
	}

	// Skip padding byte
	offset++

	// Parse Timestamp (8 bytes)
	if offset+8 <= len(data) {
		event.Timestamp = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	// Container ID would be determined from PID namespace or passed separately
	event.ContainerID = fmt.Sprintf("container-%d", event.PID)

	return event
}

func parseFileEvent(data []byte) *FileEvent {
	if len(data) < 40 { // Minimum size for file event
		return &FileEvent{}
	}

	event := &FileEvent{}
	offset := 0

	// Parse PID (4 bytes)
	event.PID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse TGID (4 bytes)
	event.TGID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse UID (4 bytes)
	event.UID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse GID (4 bytes)
	event.GID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse Timestamp (8 bytes)
	event.Timestamp = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	// Parse SyscallNr (4 bytes)
	event.SyscallNr = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse Flags (4 bytes)
	event.Flags = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse Mode (2 bytes)
	event.Mode = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Parse Action (1 byte)
	if offset < len(data) {
		event.Action = data[offset]
		offset++
	}

	// Skip padding byte
	offset++

	// Parse Comm (null-terminated string, up to 16 bytes)
	commEnd := offset + 16
	if commEnd > len(data) {
		commEnd = len(data)
	}

	for i := offset; i < commEnd; i++ {
		if data[i] == 0 {
			event.Comm = string(data[offset:i])
			break
		}
		if i == commEnd-1 {
			event.Comm = string(data[offset:commEnd])
		}
	}
	offset = commEnd

	// Parse Path (remaining bytes, null-terminated)
	if offset < len(data) {
		pathData := data[offset:]
		for i, b := range pathData {
			if b == 0 {
				event.Path = string(pathData[:i])
				break
			}
			if i == len(pathData)-1 {
				event.Path = string(pathData)
			}
		}
	}

	// Container ID would be determined from PID namespace
	event.ContainerID = fmt.Sprintf("container-%d", event.PID)

	return event
}

// Validation methods for policy types
func (cp *ContainerPolicy) Validate() error {
	if cp.AllowedSyscalls == nil {
		return fmt.Errorf("allowed syscalls map cannot be nil")
	}
	if cp.EnforcementMode > 3 {
		return fmt.Errorf("invalid enforcement mode: %d", cp.EnforcementMode)
	}
	return nil
}

func (np *NetworkPolicy) Validate() error {
	if np.AllowedEgressPorts == nil || np.AllowedIngressPorts == nil {
		return fmt.Errorf("port maps cannot be nil")
	}
	if np.EnforcementMode > 3 {
		return fmt.Errorf("invalid enforcement mode: %d", np.EnforcementMode)
	}
	return nil
}

func (fp *FilePolicy) Validate() error {
	if fp.EnforcementMode > 3 {
		return fmt.Errorf("invalid enforcement mode: %d", fp.EnforcementMode)
	}
	return nil
}
