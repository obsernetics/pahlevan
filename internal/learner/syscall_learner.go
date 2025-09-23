package learner

import (
	"context"
	"fmt"
	"sync"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"go.opentelemetry.io/otel/metric"
)

// SyscallLearner implements adaptive syscall learning and baseline profiling
type SyscallLearner struct {
	mu                    sync.RWMutex
	containers            map[string]*ContainerLearningState
	learningProfiles      map[string]*LearningProfile
	baselineThreshold     int
	confidenceThreshold   float64
	learningWindowSize    time.Duration
	minObservations       int
	phaseTransitionDelay  time.Duration
	syscallCounter        metric.Int64Counter
	learningProgressGauge metric.Float64Gauge
	baselineQuality       metric.Float64Gauge
}

// ContainerLearningState tracks the learning state for a container
type ContainerLearningState struct {
	ContainerID         string
	WorkloadRef         WorkloadReference
	Phase               LearningPhase
	StartTime           time.Time
	LastActivity        time.Time
	LearningWindow      time.Duration
	SyscallObservations map[uint64]*SyscallObservation
	NetworkFlows        map[string]*NetworkFlowObservation
	FileAccess          map[string]*FileAccessObservation
	PolicyRef           *policyv1alpha1.PahlevanPolicy
	LifecycleEvents     []LifecycleEvent
	Statistics          LearningStatistics
	Confidence          float64
}

// WorkloadReference identifies the workload
type WorkloadReference struct {
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
	UID        string
}

// LearningPhase represents the current learning phase
type LearningPhase string

const (
	PhaseInitializing     LearningPhase = "Initializing"
	PhaseBootstrap        LearningPhase = "Bootstrap"   // Learning during container init
	PhaseRuntime          LearningPhase = "Runtime"     // Learning during normal operation
	PhaseStabilizing      LearningPhase = "Stabilizing" // Waiting for stability
	PhaseProfileGenerated LearningPhase = "ProfileGenerated"
	PhaseTransitioning    LearningPhase = "Transitioning" // Moving to enforcement
)

// SyscallObservation tracks syscall usage patterns
type SyscallObservation struct {
	SyscallNr   uint64
	Count       int64
	FirstSeen   time.Time
	LastSeen    time.Time
	Contexts    map[string]int64 // Process context -> count
	Arguments   map[string]int64 // Argument patterns -> count
	ReturnCodes map[int64]int64  // Return codes -> count
	Frequency   float64          // Calls per minute
	Criticality CriticalityLevel
	Confidence  float64
}

// NetworkFlowObservation tracks network flow patterns
type NetworkFlowObservation struct {
	Protocol      string
	Direction     string
	RemoteAddress string
	RemotePort    int32
	LocalPort     int32
	Count         int64
	FirstSeen     time.Time
	LastSeen      time.Time
	BytesTotal    int64
	PacketsTotal  int64
	Confidence    float64
}

// FileAccessObservation tracks file access patterns
type FileAccessObservation struct {
	Path        string
	AccessModes map[string]int64 // read, write, execute -> count
	FirstSeen   time.Time
	LastSeen    time.Time
	FileType    string
	Permissions uint32
	Frequency   float64
	Confidence  float64
}

// LifecycleEvent tracks container lifecycle events
type LifecycleEvent struct {
	Timestamp time.Time
	Event     LifecycleEventType
	Phase     string
	Metadata  map[string]string
}

// LifecycleEventType defines lifecycle event types
type LifecycleEventType string

const (
	EventContainerStarted   LifecycleEventType = "ContainerStarted"
	EventInitCompleted      LifecycleEventType = "InitCompleted"
	EventApplicationStarted LifecycleEventType = "ApplicationStarted"
	EventHealthCheckPassed  LifecycleEventType = "HealthCheckPassed"
	EventApplicationSteady  LifecycleEventType = "ApplicationSteady"
	EventContainerStopping  LifecycleEventType = "ContainerStopping"
)

// CriticalityLevel defines syscall criticality
type CriticalityLevel string

const (
	CriticalityLow      CriticalityLevel = "Low"
	CriticalityMedium   CriticalityLevel = "Medium"
	CriticalityHigh     CriticalityLevel = "High"
	CriticalityCritical CriticalityLevel = "Critical"
)

// LearningStatistics provides learning statistics
type LearningStatistics struct {
	TotalSyscalls      int64
	UniqueSyscalls     int
	TotalNetworkFlows  int64
	UniqueNetworkFlows int
	TotalFileAccess    int64
	UniqueFileAccess   int
	LearningProgress   float64
	StabilityScore     float64
	Confidence         float64
}

// LearningProfile represents the learned baseline profile
type LearningProfile struct {
	ContainerID      string
	WorkloadRef      WorkloadReference
	GeneratedAt      time.Time
	LearningDuration time.Duration

	// Syscall profile
	AllowedSyscalls   map[uint64]*SyscallProfile
	SyscallStatistics SyscallStatistics

	// Network profile
	AllowedNetworkFlows map[string]*NetworkFlowProfile
	NetworkStatistics   NetworkStatistics

	// File access profile
	AllowedFilePaths map[string]*FileAccessProfile
	FileStatistics   FileStatistics

	// Quality metrics
	Quality        ProfileQuality
	Confidence     float64
	StabilityScore float64

	// Lifecycle information
	LifecyclePhases []string
	CriticalPaths   []string
}

// SyscallProfile represents a learned syscall pattern
type SyscallProfile struct {
	SyscallNr          uint64
	Name               string
	Frequency          float64
	Criticality        CriticalityLevel
	AllowedContexts    []string
	ArgumentPatterns   []string
	TypicalReturnCodes []int64
	Confidence         float64
}

// NetworkFlowProfile represents a learned network flow pattern
type NetworkFlowProfile struct {
	Protocol        string
	Direction       string
	RemoteEndpoints []string
	PortRanges      []PortRange
	MaxConnections  int32
	MaxBandwidth    int64
	Confidence      float64
}

// FileAccessProfile represents a learned file access pattern
type FileAccessProfile struct {
	PathPattern  string
	AllowedModes []string
	FileTypes    []string
	MaxSize      int64
	Confidence   float64
}

// PortRange defines a range of ports
type PortRange struct {
	Start int32
	End   int32
}

// Statistics structures
type SyscallStatistics struct {
	TotalCalls       int64
	UniqueSyscalls   int
	AverageFrequency float64
	TopSyscalls      []uint64
}

type NetworkStatistics struct {
	TotalFlows     int64
	UniqueFlows    int
	TotalBytes     int64
	AverageLatency time.Duration
}

type FileStatistics struct {
	TotalAccess    int64
	UniqueFiles    int
	ReadWriteRatio float64
	TopDirectories []string
}

// ProfileQuality represents the quality of learned profile
type ProfileQuality struct {
	Score           float64
	Completeness    float64
	Stability       float64
	Coverage        float64
	Accuracy        float64
	Recommendations []string
}

func NewSyscallLearner(
	baselineThreshold int,
	confidenceThreshold float64,
	learningWindowSize time.Duration,
	minObservations int,
) *SyscallLearner {
	return &SyscallLearner{
		containers:           make(map[string]*ContainerLearningState),
		learningProfiles:     make(map[string]*LearningProfile),
		baselineThreshold:    baselineThreshold,
		confidenceThreshold:  confidenceThreshold,
		learningWindowSize:   learningWindowSize,
		minObservations:      minObservations,
		phaseTransitionDelay: 30 * time.Second,
	}
}

func (sl *SyscallLearner) StartLearning(ctx context.Context, containerID string, workloadRef WorkloadReference, policy *policyv1alpha1.PahlevanPolicy) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Initialize learning state
	state := &ContainerLearningState{
		ContainerID:         containerID,
		WorkloadRef:         workloadRef,
		Phase:               PhaseInitializing,
		StartTime:           time.Now(),
		LastActivity:        time.Now(),
		LearningWindow:      sl.learningWindowSize,
		SyscallObservations: make(map[uint64]*SyscallObservation),
		NetworkFlows:        make(map[string]*NetworkFlowObservation),
		FileAccess:          make(map[string]*FileAccessObservation),
		PolicyRef:           policy,
		LifecycleEvents:     make([]LifecycleEvent, 0),
		Statistics:          LearningStatistics{},
		Confidence:          0.0,
	}

	// Apply learning configuration from policy
	if policy.Spec.LearningConfig.WindowSize != nil {
		state.LearningWindow = policy.Spec.LearningConfig.WindowSize.Duration
	}

	sl.containers[containerID] = state

	// Record lifecycle event
	state.LifecycleEvents = append(state.LifecycleEvents, LifecycleEvent{
		Timestamp: time.Now(),
		Event:     EventContainerStarted,
		Phase:     string(PhaseInitializing),
		Metadata:  map[string]string{"workload": fmt.Sprintf("%s/%s", workloadRef.Namespace, workloadRef.Name)},
	})

	// Transition to bootstrap phase
	go sl.schedulePhaseTransition(containerID, PhaseBootstrap, 5*time.Second)

	return nil
}

func (sl *SyscallLearner) ProcessSyscallEvent(event *ebpf.SyscallEvent) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[event.ContainerID]
	if !exists {
		return fmt.Errorf("container not found in learning state: %s", event.ContainerID)
	}

	// Update last activity
	state.LastActivity = time.Now()

	// Get or create syscall observation
	obs, exists := state.SyscallObservations[event.SyscallNr]
	if !exists {
		obs = &SyscallObservation{
			SyscallNr:   event.SyscallNr,
			Count:       0,
			FirstSeen:   time.Now(),
			Contexts:    make(map[string]int64),
			Arguments:   make(map[string]int64),
			ReturnCodes: make(map[int64]int64),
			Criticality: sl.assessSyscallCriticality(event.SyscallNr),
		}
		state.SyscallObservations[event.SyscallNr] = obs
	}

	// Update observation
	obs.Count++
	obs.LastSeen = time.Now()
	obs.Contexts[event.Comm]++

	// Update statistics
	state.Statistics.TotalSyscalls++
	state.Statistics.UniqueSyscalls = len(state.SyscallObservations)

	// Calculate frequency and confidence
	duration := time.Since(obs.FirstSeen)
	if duration.Minutes() > 0 {
		obs.Frequency = float64(obs.Count) / duration.Minutes()
	}
	obs.Confidence = sl.calculateSyscallConfidence(obs)

	// Update learning progress
	sl.updateLearningProgress(state)

	// Check for phase transitions
	sl.checkPhaseTransition(state)

	// Update metrics
	if sl.syscallCounter != nil {
		sl.syscallCounter.Add(context.Background(), 1)
	}

	return nil
}

func (sl *SyscallLearner) ProcessNetworkEvent(event *ebpf.NetworkEvent) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[event.ContainerID]
	if !exists {
		return fmt.Errorf("container not found in learning state: %s", event.ContainerID)
	}

	// Create flow key
	flowKey := fmt.Sprintf("%s:%d-%s:%d-%d",
		sl.ipToString(event.SrcIP), event.SrcPort,
		sl.ipToString(event.DstIP), event.DstPort,
		event.Protocol)

	// Get or create flow observation
	flow, exists := state.NetworkFlows[flowKey]
	if !exists {
		flow = &NetworkFlowObservation{
			Protocol:      sl.protocolToString(event.Protocol),
			Direction:     sl.directionToString(event.Direction),
			RemoteAddress: sl.ipToString(event.DstIP),
			RemotePort:    int32(event.DstPort),
			LocalPort:     int32(event.SrcPort),
			Count:         0,
			FirstSeen:     time.Now(),
		}
		state.NetworkFlows[flowKey] = flow
	}

	// Update flow
	flow.Count++
	flow.LastSeen = time.Now()
	flow.Confidence = sl.calculateNetworkFlowConfidence(flow)

	// Update statistics
	state.Statistics.TotalNetworkFlows++
	state.Statistics.UniqueNetworkFlows = len(state.NetworkFlows)

	return nil
}

func (sl *SyscallLearner) ProcessFileEvent(event *ebpf.FileEvent) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[event.ContainerID]
	if !exists {
		return fmt.Errorf("container not found in learning state: %s", event.ContainerID)
	}

	// Get or create file access observation
	access, exists := state.FileAccess[event.Path]
	if !exists {
		access = &FileAccessObservation{
			Path:        event.Path,
			AccessModes: make(map[string]int64),
			FirstSeen:   time.Now(),
			FileType:    sl.detectFileType(event.Path),
			Permissions: event.Flags,
		}
		state.FileAccess[event.Path] = access
	}

	// Update access patterns
	mode := sl.flagsToAccessMode(event.Flags)
	access.AccessModes[mode]++
	access.LastSeen = time.Now()
	access.Confidence = sl.calculateFileAccessConfidence(access)

	// Update statistics
	state.Statistics.TotalFileAccess++
	state.Statistics.UniqueFileAccess = len(state.FileAccess)

	return nil
}

func (sl *SyscallLearner) RecordLifecycleEvent(containerID string, event LifecycleEventType, metadata map[string]string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[containerID]
	if !exists {
		return fmt.Errorf("container not found in learning state: %s", containerID)
	}

	lifecycleEvent := LifecycleEvent{
		Timestamp: time.Now(),
		Event:     event,
		Phase:     string(state.Phase),
		Metadata:  metadata,
	}

	state.LifecycleEvents = append(state.LifecycleEvents, lifecycleEvent)

	// Trigger phase transitions based on lifecycle events
	switch event {
	case EventInitCompleted:
		go sl.schedulePhaseTransition(containerID, PhaseRuntime, sl.phaseTransitionDelay)
	case EventApplicationSteady:
		go sl.schedulePhaseTransition(containerID, PhaseStabilizing, sl.phaseTransitionDelay)
	}

	return nil
}

func (sl *SyscallLearner) GenerateProfile(containerID string) (*LearningProfile, error) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	state, exists := sl.containers[containerID]
	if !exists {
		return nil, fmt.Errorf("container not found in learning state: %s", containerID)
	}

	profile := &LearningProfile{
		ContainerID:         containerID,
		WorkloadRef:         state.WorkloadRef,
		GeneratedAt:         time.Now(),
		LearningDuration:    time.Since(state.StartTime),
		AllowedSyscalls:     make(map[uint64]*SyscallProfile),
		AllowedNetworkFlows: make(map[string]*NetworkFlowProfile),
		AllowedFilePaths:    make(map[string]*FileAccessProfile),
	}

	// Generate syscall profiles
	for syscallNr, obs := range state.SyscallObservations {
		if obs.Confidence >= sl.confidenceThreshold {
			profile.AllowedSyscalls[syscallNr] = &SyscallProfile{
				SyscallNr:   syscallNr,
				Name:        sl.syscallNumberToName(syscallNr),
				Frequency:   obs.Frequency,
				Criticality: obs.Criticality,
				Confidence:  obs.Confidence,
			}
		}
	}

	// Generate network flow profiles
	for flowKey, flow := range state.NetworkFlows {
		if flow.Confidence >= sl.confidenceThreshold {
			profile.AllowedNetworkFlows[flowKey] = &NetworkFlowProfile{
				Protocol:   flow.Protocol,
				Direction:  flow.Direction,
				Confidence: flow.Confidence,
			}
		}
	}

	// Generate file access profiles
	for path, access := range state.FileAccess {
		if access.Confidence >= sl.confidenceThreshold {
			allowedModes := make([]string, 0, len(access.AccessModes))
			for mode := range access.AccessModes {
				allowedModes = append(allowedModes, mode)
			}

			profile.AllowedFilePaths[path] = &FileAccessProfile{
				PathPattern:  path,
				AllowedModes: allowedModes,
				FileTypes:    []string{access.FileType},
				Confidence:   access.Confidence,
			}
		}
	}

	// Calculate profile quality
	profile.Quality = sl.calculateProfileQuality(state, profile)
	profile.Confidence = state.Confidence
	profile.StabilityScore = state.Statistics.StabilityScore

	// Generate lifecycle phases
	phases := make(map[string]bool)
	for _, event := range state.LifecycleEvents {
		phases[event.Phase] = true
	}
	profile.LifecyclePhases = make([]string, 0, len(phases))
	for phase := range phases {
		profile.LifecyclePhases = append(profile.LifecyclePhases, phase)
	}

	// Store profile
	sl.learningProfiles[containerID] = profile

	return profile, nil
}

func (sl *SyscallLearner) GetLearningState(containerID string) (*ContainerLearningState, error) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	state, exists := sl.containers[containerID]
	if !exists {
		return nil, fmt.Errorf("container not found in learning state: %s", containerID)
	}

	// Return a copy to avoid race conditions
	stateCopy := *state
	return &stateCopy, nil
}

func (sl *SyscallLearner) GetProfile(containerID string) (*LearningProfile, error) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	profile, exists := sl.learningProfiles[containerID]
	if !exists {
		return nil, fmt.Errorf("profile not found for container: %s", containerID)
	}

	return profile, nil
}

func (sl *SyscallLearner) StopLearning(containerID string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[containerID]
	if !exists {
		return fmt.Errorf("container not found in learning state: %s", containerID)
	}

	// Record stop event
	state.LifecycleEvents = append(state.LifecycleEvents, LifecycleEvent{
		Timestamp: time.Now(),
		Event:     EventContainerStopping,
		Phase:     string(state.Phase),
	})

	// Generate final profile if not already done
	if state.Phase != PhaseProfileGenerated {
		_, err := sl.GenerateProfile(containerID)
		if err != nil {
			return fmt.Errorf("failed to generate final profile: %v", err)
		}
	}

	delete(sl.containers, containerID)
	return nil
}

// Helper methods

func (sl *SyscallLearner) schedulePhaseTransition(containerID string, newPhase LearningPhase, delay time.Duration) {
	time.Sleep(delay)

	sl.mu.Lock()
	defer sl.mu.Unlock()

	state, exists := sl.containers[containerID]
	if !exists {
		return
	}

	state.Phase = newPhase
	sl.updateLearningProgress(state)
}

func (sl *SyscallLearner) checkPhaseTransition(state *ContainerLearningState) {
	switch state.Phase {
	case PhaseBootstrap:
		if len(state.SyscallObservations) >= sl.minObservations {
			go sl.schedulePhaseTransition(state.ContainerID, PhaseRuntime, sl.phaseTransitionDelay)
		}
	case PhaseRuntime:
		if time.Since(state.StartTime) >= state.LearningWindow {
			go sl.schedulePhaseTransition(state.ContainerID, PhaseStabilizing, sl.phaseTransitionDelay)
		}
	case PhaseStabilizing:
		if state.Statistics.StabilityScore >= 0.8 {
			go sl.schedulePhaseTransition(state.ContainerID, PhaseProfileGenerated, sl.phaseTransitionDelay)
		}
	}
}

func (sl *SyscallLearner) updateLearningProgress(state *ContainerLearningState) {
	// Calculate learning progress based on various factors
	timeProgress := float64(time.Since(state.StartTime)) / float64(state.LearningWindow)
	if timeProgress > 1.0 {
		timeProgress = 1.0
	}

	observationProgress := float64(len(state.SyscallObservations)) / float64(sl.baselineThreshold)
	if observationProgress > 1.0 {
		observationProgress = 1.0
	}

	stabilityProgress := state.Statistics.StabilityScore

	// Weighted average
	state.Statistics.LearningProgress = (timeProgress*0.4 + observationProgress*0.3 + stabilityProgress*0.3)

	// Update confidence
	state.Confidence = sl.calculateOverallConfidence(state)

	// Update metrics
	if sl.learningProgressGauge != nil {
		sl.learningProgressGauge.Record(context.Background(), state.Statistics.LearningProgress)
	}
}

func (sl *SyscallLearner) assessSyscallCriticality(syscallNr uint64) CriticalityLevel {
	// Map syscall numbers to criticality levels
	criticalSyscalls := map[uint64]CriticalityLevel{
		// Process control
		59: CriticalityCritical, // execve
		56: CriticalityCritical, // clone
		57: CriticalityHigh,     // fork
		60: CriticalityHigh,     // exit

		// File operations
		2:   CriticalityMedium, // open
		257: CriticalityMedium, // openat
		3:   CriticalityLow,    // close
		0:   CriticalityLow,    // read
		1:   CriticalityLow,    // write

		// Network operations
		41: CriticalityHigh,   // socket
		42: CriticalityHigh,   // connect
		43: CriticalityMedium, // accept
		49: CriticalityMedium, // bind
		50: CriticalityMedium, // listen
	}

	if level, exists := criticalSyscalls[syscallNr]; exists {
		return level
	}

	return CriticalityLow
}

func (sl *SyscallLearner) calculateSyscallConfidence(obs *SyscallObservation) float64 {
	// Base confidence on observation count and frequency stability
	countFactor := float64(obs.Count) / 100.0
	if countFactor > 1.0 {
		countFactor = 1.0
	}

	frequencyStability := 0.5 // Placeholder for frequency stability calculation

	return (countFactor + frequencyStability) / 2.0
}

func (sl *SyscallLearner) calculateNetworkFlowConfidence(flow *NetworkFlowObservation) float64 {
	// Similar confidence calculation for network flows
	countFactor := float64(flow.Count) / 50.0
	if countFactor > 1.0 {
		countFactor = 1.0
	}

	return countFactor
}

func (sl *SyscallLearner) calculateFileAccessConfidence(access *FileAccessObservation) float64 {
	// Calculate confidence based on access patterns
	totalAccess := int64(0)
	for _, count := range access.AccessModes {
		totalAccess += count
	}

	countFactor := float64(totalAccess) / 20.0
	if countFactor > 1.0 {
		countFactor = 1.0
	}

	return countFactor
}

func (sl *SyscallLearner) calculateOverallConfidence(state *ContainerLearningState) float64 {
	if len(state.SyscallObservations) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, obs := range state.SyscallObservations {
		totalConfidence += obs.Confidence
	}

	return totalConfidence / float64(len(state.SyscallObservations))
}

func (sl *SyscallLearner) calculateProfileQuality(state *ContainerLearningState, profile *LearningProfile) ProfileQuality {
	// Calculate various quality metrics
	completeness := float64(len(profile.AllowedSyscalls)) / float64(len(state.SyscallObservations))
	stability := state.Statistics.StabilityScore
	coverage := sl.calculateCoverage(state)
	accuracy := sl.calculateAccuracy(state)

	score := (completeness + stability + coverage + accuracy) / 4.0

	recommendations := sl.generateRecommendations(state, profile)

	return ProfileQuality{
		Score:           score,
		Completeness:    completeness,
		Stability:       stability,
		Coverage:        coverage,
		Accuracy:        accuracy,
		Recommendations: recommendations,
	}
}

func (sl *SyscallLearner) calculateCoverage(state *ContainerLearningState) float64 {
	// Placeholder implementation
	return 0.8
}

func (sl *SyscallLearner) calculateAccuracy(state *ContainerLearningState) float64 {
	// Placeholder implementation
	return 0.9
}

func (sl *SyscallLearner) generateRecommendations(state *ContainerLearningState, profile *LearningProfile) []string {
	recommendations := make([]string, 0)

	if state.Statistics.LearningProgress < 0.8 {
		recommendations = append(recommendations, "Consider extending learning window for better coverage")
	}

	if len(profile.AllowedSyscalls) > 100 {
		recommendations = append(recommendations, "High number of syscalls detected - consider workload optimization")
	}

	return recommendations
}

// Utility functions
func (sl *SyscallLearner) ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

func (sl *SyscallLearner) protocolToString(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", proto)
	}
}

func (sl *SyscallLearner) directionToString(dir uint8) string {
	switch dir {
	case 0:
		return "ingress"
	case 1:
		return "egress"
	default:
		return "unknown"
	}
}

func (sl *SyscallLearner) detectFileType(path string) string {
	// Simple file type detection based on path
	if len(path) > 4 {
		ext := path[len(path)-4:]
		switch ext {
		case ".so", ".dll":
			return "library"
		case ".bin", ".exe":
			return "executable"
		case ".log":
			return "log"
		case ".tmp":
			return "temporary"
		}
	}

	if path[0:4] == "/tmp" || path[0:8] == "/var/tmp" {
		return "temporary"
	}
	if path[0:5] == "/proc" {
		return "procfs"
	}
	if path[0:4] == "/dev" {
		return "device"
	}

	return "regular"
}

func (sl *SyscallLearner) flagsToAccessMode(flags uint32) string {
	if flags&0x2 != 0 {
		return "write"
	}
	if flags&0x1 != 0 {
		return "read"
	}
	return "read"
}

func (sl *SyscallLearner) syscallNumberToName(nr uint64) string {
	// Map common syscall numbers to names
	names := map[uint64]string{
		0:   "read",
		1:   "write",
		2:   "open",
		3:   "close",
		41:  "socket",
		42:  "connect",
		56:  "clone",
		57:  "fork",
		59:  "execve",
		60:  "exit",
		257: "openat",
	}

	if name, exists := names[nr]; exists {
		return name
	}

	return fmt.Sprintf("syscall_%d", nr)
}
