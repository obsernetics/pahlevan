package ebpf

import (
	"context"
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
					go handler.HandleSyscallEvent(event)
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
					go handler.HandleNetworkEvent(event)
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
					go handler.HandleFileEvent(event)
				}
				m.mu.RUnlock()
			}
		}
	}
}

// Helper functions for converting between Go and eBPF data structures
func convertToEBPFPolicy(policy *ContainerPolicy) interface{} {
	// Implementation would convert Go policy struct to eBPF-compatible format
	// This is a placeholder - actual implementation would match the eBPF struct layout
	return policy
}

func convertToEBPFNetworkPolicy(policy *NetworkPolicy) interface{} {
	// Implementation would convert Go network policy struct to eBPF-compatible format
	return policy
}

func convertToEBPFFilePolicy(policy *FilePolicy) interface{} {
	// Implementation would convert Go file policy struct to eBPF-compatible format
	return policy
}

func parseSyscallEvent(data []byte) *SyscallEvent {
	// Implementation would parse raw eBPF event data into Go struct
	// This is a placeholder - actual implementation would use unsafe pointers or binary encoding
	return &SyscallEvent{}
}

func parseNetworkEvent(data []byte) *NetworkEvent {
	// Implementation would parse raw eBPF event data into Go struct
	return &NetworkEvent{}
}

func parseFileEvent(data []byte) *FileEvent {
	// Implementation would parse raw eBPF event data into Go struct
	return &FileEvent{}
}
