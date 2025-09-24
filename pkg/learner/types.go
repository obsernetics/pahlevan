package learner

import "time"

// Learning engine types and structures

type LearningEngine struct {
	learningWindow      time.Duration
	confidenceThreshold float64
	maxSamples          int
	profiles            map[string]*LearningProfile
}

type LearningProfile struct {
	ContainerID        string
	ObservedSyscalls   map[uint64]*SyscallStatistics
	NetworkConnections []*NetworkConnection
	FileAccesses       []*FileAccess
	ProcessHierarchy   []*ProcessInfo
	StartTime          time.Time
}

type SyscallStatistics struct {
	SyscallNumber uint64
	TotalCalls    uint64
	UniquePids    int
	LastSeen      time.Time
	Arguments     map[string]uint64
	PidSet        map[int]bool
}

type SyscallEvent struct {
	SyscallNumber uint64
	PID           int
	Timestamp     time.Time
	Arguments     []uint64
	ReturnValue   int64
	Duration      time.Duration
}

type NetworkConnection struct {
	Protocol    string
	LocalAddr   string
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string
	ProcessInfo *ProcessInfo
	Timestamp   time.Time
}

type FileAccess struct {
	Path        string
	Mode        string
	ProcessInfo *ProcessInfo
	Timestamp   time.Time
	Size        int64
}

type ProcessInfo struct {
	PID     int
	PPID    int
	Command string
	User    string
}

type WorkloadReference struct {
	Namespace string
	PodName   string
	Container string
}

type WorkloadLifecycle struct {
	CurrentPhase WorkloadPhase
	StartTime    time.Time
}

type WorkloadPhase string

const (
	PhaseInitializing WorkloadPhase = "Initializing"
	PhaseStarting     WorkloadPhase = "Starting"
	PhaseRunning      WorkloadPhase = "Running"
	PhaseSteady       WorkloadPhase = "Steady"
)

type BehaviorPattern struct {
	Type           PatternType
	Frequency      int
	Confidence     float64
	LastObserved   time.Time
	StabilityScore float64
}

type PatternType string

const (
	PatternTypeSyscallSequence PatternType = "SyscallSequence"
	PatternTypeNetworkAccess   PatternType = "NetworkAccess"
	PatternTypeFileAccess      PatternType = "FileAccess"
)

type AnomalyDetector struct {
	BaseLine           map[uint64]float64
	DeviationThreshold float64
	MinSamples         int
}

type CriticalityLevel string

const (
	CriticalityLow      CriticalityLevel = "Low"
	CriticalityMedium   CriticalityLevel = "Medium"
	CriticalityHigh     CriticalityLevel = "High"
	CriticalityCritical CriticalityLevel = "Critical"
)

// Constructor functions
func NewLearningEngine(window time.Duration, threshold float64, maxSamples int) *LearningEngine {
	return &LearningEngine{
		learningWindow:      window,
		confidenceThreshold: threshold,
		maxSamples:          maxSamples,
		profiles:            make(map[string]*LearningProfile),
	}
}

// LearningProfile methods
func (lp *LearningProfile) AddSyscall(event *SyscallEvent) {
	if lp.ObservedSyscalls == nil {
		lp.ObservedSyscalls = make(map[uint64]*SyscallStatistics)
	}

	stats, exists := lp.ObservedSyscalls[event.SyscallNumber]
	if !exists {
		stats = &SyscallStatistics{
			SyscallNumber: event.SyscallNumber,
			Arguments:     make(map[string]uint64),
			PidSet:        make(map[int]bool),
		}
		lp.ObservedSyscalls[event.SyscallNumber] = stats
	}

	stats.UpdateStatistics(event)
}

func (lp *LearningProfile) AddNetworkConnection(conn *NetworkConnection) {
	lp.NetworkConnections = append(lp.NetworkConnections, conn)
}

func (lp *LearningProfile) AddFileAccess(access *FileAccess) {
	lp.FileAccesses = append(lp.FileAccesses, access)
}

func (lp *LearningProfile) FindProcess(pid int) *ProcessInfo {
	for _, proc := range lp.ProcessHierarchy {
		if proc.PID == pid {
			return proc
		}
	}
	return nil
}

func (lp *LearningProfile) GetSyscallFrequency() map[uint64]float64 {
	frequency := make(map[uint64]float64)
	elapsed := time.Since(lp.StartTime).Hours()
	if elapsed == 0 {
		elapsed = 1
	}

	for syscall, stats := range lp.ObservedSyscalls {
		frequency[syscall] = float64(stats.TotalCalls) / elapsed
	}
	return frequency
}

func (lp *LearningProfile) IsLearningComplete(window time.Duration, confidence float64, minSamples int) bool {
	if time.Since(lp.StartTime) < window {
		return false
	}

	totalCalls := 0
	for _, stats := range lp.ObservedSyscalls {
		totalCalls += int(stats.TotalCalls)
	}

	return totalCalls >= minSamples
}

// SyscallStatistics methods
func (ss *SyscallStatistics) UpdateStatistics(event *SyscallEvent) {
	ss.TotalCalls++
	ss.LastSeen = event.Timestamp

	if !ss.PidSet[event.PID] {
		ss.PidSet[event.PID] = true
		ss.UniquePids++
	}
}

// WorkloadLifecycle methods
func (wl *WorkloadLifecycle) CanTransitionTo(phase WorkloadPhase) bool {
	transitions := map[WorkloadPhase][]WorkloadPhase{
		PhaseInitializing: {PhaseStarting},
		PhaseStarting:     {PhaseRunning},
		PhaseRunning:      {PhaseSteady},
		PhaseSteady:       {},
	}

	allowed := transitions[wl.CurrentPhase]
	for _, allowedPhase := range allowed {
		if allowedPhase == phase {
			return true
		}
	}
	return false
}

// BehaviorPattern methods
func (bp *BehaviorPattern) IsStable() bool {
	return bp.Confidence > 0.8 && bp.StabilityScore > 0.8 && bp.Frequency > 10
}

// AnomalyDetector methods
func (ad *AnomalyDetector) DetectAnomaly(frequencies map[uint64]float64) bool {
	for syscall, freq := range frequencies {
		baseline, exists := ad.BaseLine[syscall]
		if exists {
			deviation := (freq - baseline) / baseline
			if deviation > ad.DeviationThreshold {
				return true
			}
		}
	}
	return false
}
