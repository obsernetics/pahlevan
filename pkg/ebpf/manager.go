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
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/metric"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Package-level counters are registered exactly once with the default registry.
// Registering per-Manager (as the previous code did) panicked with
// "duplicate metrics collector registration" whenever a second Manager was
// constructed (e.g. across tests or multiple watchers).
var (
	syscallEventCounterVec = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_syscall_events_total",
		Help: "Total number of syscall events processed",
	})
	networkEventCounterVec = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_network_events_total",
		Help: "Total number of network events processed",
	})
	fileEventCounterVec = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_file_events_total",
		Help: "Total number of file events processed",
	})
	enforcementCounterVec = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pahlevan_enforcement_actions_total",
		Help: "Total number of enforcement actions taken",
	})
)

// SyscallMonitor is CO-RE (uses bpf/vmlinux.h); the others are being migrated to
// CO-RE in a later step and still compile against kernel uapi headers.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" SyscallMonitor ../../bpf/syscall_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" NetworkMonitor ../../bpf/network_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" FileMonitor ../../bpf/file_monitor.c

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
	CgroupID    uint64 // real attribution key from bpf_get_current_cgroup_id()
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
	CgroupID    uint64 // real attribution key from bpf_get_current_cgroup_id()
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

	// Use the package-level, registered-once counters.
	syscallEventCounter := syscallEventCounterVec
	networkEventCounter := networkEventCounterVec
	fileEventCounter := fileEventCounterVec
	enforcementCounter := enforcementCounterVec

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

	// The syscall monitor is REQUIRED — it is the core observation program.
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

	// The file (LSM) and network monitors are BEST-EFFORT: a kernel without the
	// bpf LSM (file) or without the still-migrating network program should still
	// run the agent in a degraded, syscall-only mode rather than fail outright.
	if fileSpecs, ferr := LoadFileMonitor(); ferr == nil {
		if fileColl, cerr := ebpf.NewCollection(fileSpecs); cerr == nil {
			m.fileSpecs = fileSpecs
			m.fileCollection = fileColl
		} else {
			log.Log.V(0).Info("file monitor unavailable; continuing without file observation", "error", cerr.Error())
		}
	} else {
		log.Log.V(0).Info("file monitor spec unavailable; continuing without file observation", "error", ferr.Error())
	}

	if netSpecs, nerr := LoadNetworkMonitor(); nerr == nil {
		if netColl, cerr := ebpf.NewCollection(netSpecs); cerr == nil {
			m.networkSpecs = netSpecs
			m.networkCollection = netColl
		} else {
			log.Log.V(0).Info("network monitor unavailable; continuing without network observation", "error", cerr.Error())
		}
	} else {
		log.Log.V(0).Info("network monitor spec unavailable; continuing without network observation", "error", nerr.Error())
	}

	return nil
}

func (m *Manager) AttachPrograms() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The syscall collection is required; network/file are best-effort and may be
	// nil in degraded mode. Guard against a misordered Start()/AttachPrograms().
	if m.syscallCollection == nil {
		return fmt.Errorf("cannot attach: eBPF programs not loaded (call LoadPrograms first)")
	}

	// Attach the single raw tracepoint on sys_enter. One program observes every
	// syscall (vs a hand-picked handful of tracepoints), which is what the
	// learner needs; per-(cgroup,syscall) dedup happens in-kernel.
	if prog := m.syscallCollection.Programs["handle_sys_enter"]; prog != nil {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: prog,
		})
		if err != nil {
			return fmt.Errorf("failed to attach raw_tracepoint sys_enter: %v", err)
		}
		m.syscallLinks = append(m.syscallLinks, l)
	}

	// Attach the file monitor via the BPF LSM file_open hook. This sees the
	// resolved struct file (full path via bpf_d_path) and, in a later phase, can
	// DENY by returning -EPERM — something tracepoints cannot do. Requires a
	// kernel booted with the bpf LSM active (lsm=...,bpf).
	if m.fileCollection != nil {
		if prog := m.fileCollection.Programs["file_open"]; prog != nil {
			l, err := link.AttachLSM(link.LSMOptions{Program: prog})
			if err != nil {
				// Degrade gracefully: without the bpf LSM active, keep running with
				// syscall observation rather than failing the whole data plane.
				log.Log.V(0).Info("lsm/file_open attach failed; file enforcement/observation disabled (enable with lsm=...,bpf)", "error", err.Error())
			} else {
				m.fileLinks = append(m.fileLinks, l)
			}
		}
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

	// Network events (best-effort; nil in degraded mode).
	if m.networkCollection != nil {
		if networkEventsMap := m.networkCollection.Maps["network_events"]; networkEventsMap != nil {
			reader, err := ringbuf.NewReader(networkEventsMap)
			if err != nil {
				log.Log.V(0).Info("network event reader unavailable", "error", err.Error())
			} else {
				m.networkEventReader = reader
			}
		}
	}

	// File events (best-effort; nil in degraded mode).
	if m.fileCollection != nil {
		if fileEventsMap := m.fileCollection.Maps["file_events"]; fileEventsMap != nil {
			reader, err := ringbuf.NewReader(fileEventsMap)
			if err != nil {
				return fmt.Errorf("failed to create file event reader: %v", err)
			}
			m.fileEventReader = reader
		}
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

// EventReader interface for reading events from eBPF programs
type EventReader interface {
	Read() (*EventRecord, error)
}

// EventRecord represents a raw event record from eBPF
type EventRecord struct {
	RawSample []byte
}

// processEvents handles event processing for different event types
func (m *Manager) processEvents(ctx context.Context, eventType string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
			var rawSample []byte
			var err error

			switch eventType {
			case "syscall":
				if m.eventReader == nil {
					return
				}
				record, e := m.eventReader.Read()
				if e != nil {
					continue
				}
				rawSample = record.RawSample
				err = e
			case "network":
				if m.networkEventReader == nil {
					return
				}
				record, e := m.networkEventReader.Read()
				if e != nil {
					continue
				}
				rawSample = record.RawSample
				err = e
			case "file":
				if m.fileEventReader == nil {
					return
				}
				record, e := m.fileEventReader.Read()
				if e != nil {
					continue
				}
				rawSample = record.RawSample
				err = e
			default:
				return
			}

			if err != nil {
				continue
			}

			m.handleEventRecord(ctx, eventType, rawSample)
		}
	}
}

// handleEventRecord processes a single event record based on type
func (m *Manager) handleEventRecord(ctx context.Context, eventType string, rawSample []byte) {
	switch eventType {
	case "syscall":
		if event := parseSyscallEvent(rawSample); event != nil {
			m.syscallEventCounter.Inc()
			if m.otelSyscallCounter != nil {
				m.otelSyscallCounter.Add(ctx, 1)
			}
			m.notifyHandlers(func(h EventHandler) { _ = h.HandleSyscallEvent(event) })
		}
	case "network":
		if event := parseNetworkEvent(rawSample); event != nil {
			m.networkEventCounter.Inc()
			if m.otelNetworkCounter != nil {
				m.otelNetworkCounter.Add(ctx, 1)
			}
			m.notifyHandlers(func(h EventHandler) { _ = h.HandleNetworkEvent(event) })
		}
	case "file":
		if event := parseFileEvent(rawSample); event != nil {
			m.fileEventCounter.Inc()
			if m.otelFileCounter != nil {
				m.otelFileCounter.Add(ctx, 1)
			}
			m.notifyHandlers(func(h EventHandler) { _ = h.HandleFileEvent(event) })
		}
	}
}

// notifyHandlers safely notifies all event handlers
func (m *Manager) notifyHandlers(notify func(EventHandler)) {
	m.mu.RLock()
	handlers := make([]EventHandler, len(m.eventHandlers))
	copy(handlers, m.eventHandlers)
	m.mu.RUnlock()

	for _, handler := range handlers {
		go notify(handler)
	}
}

// Wrapper functions for backward compatibility
func (m *Manager) processSyscallEvents(ctx context.Context) {
	m.processEvents(ctx, "syscall")
}

func (m *Manager) processNetworkEvents(ctx context.Context) {
	m.processEvents(ctx, "network")
}

func (m *Manager) processFileEvents(ctx context.Context) {
	m.processEvents(ctx, "file")
}

// Helper functions for converting between Go and eBPF data structures

// EBPFContainerPolicy represents the eBPF container_policy struct layout
type EBPFContainerPolicy struct {
	ContainerID     uint32     // container_id
	LearningMode    uint32     // learning_mode (1 = learning, 0 = enforcement)
	AllowedSyscalls [64]uint64 // allowed_syscalls bitmap for syscalls 0-4095
	ViolationCount  uint32     // violation_count
	LastUpdateNs    uint64     // last_update_ns
}

func convertToEBPFPolicy(policy *ContainerPolicy) *EBPFContainerPolicy {
	ebpfPolicy := &EBPFContainerPolicy{
		ContainerID:    0, // Will be set by caller as map key
		LearningMode:   0, // 0 = enforcement mode by default
		ViolationCount: 0,
		LastUpdateNs:   uint64(policy.LastUpdate.UnixNano()),
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
	ContainerID         uint32      // container_id
	AllowedDestinations [256]uint32 // allowed_destinations (IP addresses)
	AllowedPorts        [64]uint16  // allowed_ports
	LearningMode        uint32      // learning_mode (1 = learning, 0 = enforcement)
	LastUpdateNs        uint64      // last_update_ns
}

func convertToEBPFNetworkPolicy(policy *NetworkPolicy) *EBPFConnectionPolicy {
	ebpfPolicy := &EBPFConnectionPolicy{
		ContainerID:  0, // Will be set by caller as map key
		LearningMode: 0, // 0 = enforcement mode by default
		LastUpdateNs: uint64(policy.LastUpdate.UnixNano()),
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
	ContainerID  uint32         // container_id
	LearningMode uint32         // learning_mode (1 = learning, 0 = enforcement)
	AllowedPaths [1024][64]byte // allowed_paths (char array)
	PathCount    uint32         // path_count (number of valid paths)
	LastUpdateNs uint64         // last_update_ns
}

func convertToEBPFFilePolicy(policy *FilePolicy) *EBPFFileAccessPolicy {
	ebpfPolicy := &EBPFFileAccessPolicy{
		ContainerID:  0, // Will be set by caller as map key
		LearningMode: 0, // 0 = enforcement mode by default
		PathCount:    0,
		LastUpdateNs: uint64(policy.LastUpdate.UnixNano()),
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

// parseSyscallEvent decodes the CO-RE `struct syscall_event` emitted by
// bpf/syscall_monitor.c (see that file for the authoritative layout):
//
//	__u64 cgroup_id; __u64 timestamp_ns; __u64 syscall_nr;
//	__u32 pid; __u32 tid; __u32 uid; __u32 gid; __u8 comm[16];  // 56 bytes
func parseSyscallEvent(data []byte) *SyscallEvent {
	const size = 8 + 8 + 8 + 4 + 4 + 4 + 4 + 16 // 56
	if len(data) < size {
		return nil
	}

	event := &SyscallEvent{
		CgroupID:  binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		SyscallNr: binary.LittleEndian.Uint64(data[16:24]),
		PID:       binary.LittleEndian.Uint32(data[24:28]),
		UID:       binary.LittleEndian.Uint32(data[32:36]),
		GID:       binary.LittleEndian.Uint32(data[36:40]),
	}
	// eBPF `pid` is the userspace TGID; expose it as both for now.
	event.TGID = event.PID

	comm := data[40:56]
	if i := indexZero(comm); i >= 0 {
		comm = comm[:i]
	}
	event.Comm = string(comm)

	// Until pod attribution (pkg/attribution) resolves cgroup->pod, surface the
	// cgroup id as the container identifier.
	event.ContainerID = fmt.Sprintf("cgroup:%d", event.CgroupID)

	return event
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
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
	// CO-RE `struct file_event` from bpf/file_monitor.c:
	//   __u64 cgroup_id; __u64 timestamp_ns; __u32 pid; __u32 uid; __u32 gid;
	//   __u32 flags; __u8 comm[16]; __u8 path[128];   // 176 bytes
	const size = 8 + 8 + 4 + 4 + 4 + 4 + 16 + 128
	if len(data) < size {
		return nil
	}
	event := &FileEvent{
		CgroupID:  binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		PID:       binary.LittleEndian.Uint32(data[16:20]),
		UID:       binary.LittleEndian.Uint32(data[20:24]),
		GID:       binary.LittleEndian.Uint32(data[24:28]),
		Flags:     binary.LittleEndian.Uint32(data[28:32]),
	}
	event.TGID = event.PID
	comm := data[32:48]
	if i := indexZero(comm); i >= 0 {
		comm = comm[:i]
	}
	event.Comm = string(comm)
	path := data[48:176]
	if i := indexZero(path); i >= 0 {
		path = path[:i]
	}
	event.Path = string(path)
	event.ContainerID = fmt.Sprintf("cgroup:%d", event.CgroupID)
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

// FnvPathHash computes the FNV-1a hash that bpf/file_monitor.c uses to key its
// in-kernel file block list. Userspace inserts this hash into the file_blocked
// map to DENY opens of the given path in-kernel.
func FnvPathHash(path string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(path); i++ {
		h ^= uint64(path[i])
		h *= 1099511628211
	}
	return h
}

// SetFileEnforcement flips a cgroup between learning and enforcing for the file
// allow-list. In enforcing mode, opens of paths not in the learned allow-set are
// denied in-kernel. Absent from the mode map == learning (the default).
func (m *Manager) SetFileEnforcement(cgroupID uint64, enforce bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.fileCollection == nil {
		return fmt.Errorf("file monitor not loaded (bpf LSM unavailable?)")
	}
	fm := m.fileCollection.Maps["file_mode"]
	if fm == nil {
		return fmt.Errorf("file_mode map not found")
	}
	if enforce {
		return fm.Put(cgroupID, uint8(1))
	}
	// Learning: remove the entry so the default (learn) applies. Ignore ENOENT.
	_ = fm.Delete(cgroupID)
	return nil
}

// LearnedFileCount returns the number of (cgroup,path) entries currently in the
// file allow-set (diagnostics / profile sizing). Returns 0 if unavailable.
func (m *Manager) LearnedFileCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.fileCollection == nil {
		return 0
	}
	fm := m.fileCollection.Maps["file_allowed"]
	if fm == nil {
		return 0
	}
	var k uint64
	var v uint8
	n := 0
	it := fm.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	return n
}
