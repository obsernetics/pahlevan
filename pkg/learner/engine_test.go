package learner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLearningEngine_NewLearningEngine(t *testing.T) {
	engine := NewLearningEngine(5*time.Minute, 0.95, 100)

	require.NotNil(t, engine)
	assert.Equal(t, 5*time.Minute, engine.learningWindow)
	assert.Equal(t, 0.95, engine.confidenceThreshold)
	assert.Equal(t, 100, engine.maxSamples)
	assert.NotNil(t, engine.profiles)
}

func TestLearningProfile_AddSyscall(t *testing.T) {
	tests := []struct {
		name            string
		initialSyscalls map[uint64]*SyscallStatistics
		event           *SyscallEvent
		expectedCount   int
		expectedCalls   uint64
		expectedPids    int
	}{
		{
			name:            "new syscall to empty profile",
			initialSyscalls: nil, // Test nil map initialization
			event: &SyscallEvent{
				SyscallNumber: 1,
				PID:           1234,
				Timestamp:     time.Now(),
				Arguments:     []uint64{1, 2, 3},
				ReturnValue:   0,
				Duration:      100 * time.Microsecond,
			},
			expectedCount: 1,
			expectedCalls: 1,
			expectedPids:  1,
		},
		{
			name:            "new syscall to existing profile",
			initialSyscalls: make(map[uint64]*SyscallStatistics),
			event: &SyscallEvent{
				SyscallNumber: 2,
				PID:           1234,
				Timestamp:     time.Now(),
				Arguments:     []uint64{1, 2, 3},
				ReturnValue:   0,
				Duration:      100 * time.Microsecond,
			},
			expectedCount: 1,
			expectedCalls: 1,
			expectedPids:  1,
		},
		{
			name: "existing syscall update",
			initialSyscalls: map[uint64]*SyscallStatistics{
				1: {
					SyscallNumber: 1,
					TotalCalls:    5,
					Arguments:     make(map[string]uint64),
					PidSet:        map[int]bool{1000: true},
					UniquePids:    1,
				},
			},
			event: &SyscallEvent{
				SyscallNumber: 1,
				PID:           1234, // Different PID
				Timestamp:     time.Now(),
				Arguments:     []uint64{1, 2, 3},
				ReturnValue:   0,
				Duration:      100 * time.Microsecond,
			},
			expectedCount: 1,
			expectedCalls: 6,
			expectedPids:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &LearningProfile{
				ContainerID:      "test-container",
				ObservedSyscalls: tt.initialSyscalls,
				StartTime:        time.Now(),
			}

			profile.AddSyscall(tt.event)

			assert.Len(t, profile.ObservedSyscalls, tt.expectedCount)
			stats := profile.ObservedSyscalls[tt.event.SyscallNumber]
			require.NotNil(t, stats)
			assert.Equal(t, tt.event.SyscallNumber, stats.SyscallNumber)
			assert.Equal(t, tt.expectedCalls, stats.TotalCalls)
			assert.Equal(t, tt.expectedPids, stats.UniquePids)
		})
	}
}

func TestLearningProfile_AddNetworkConnection(t *testing.T) {
	profile := &LearningProfile{
		ContainerID:        "test-container",
		NetworkConnections: make([]*NetworkConnection, 0),
		StartTime:          time.Now(),
	}

	connection := &NetworkConnection{
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.1.1",
		RemotePort: 80,
		State:      "ESTABLISHED",
		ProcessInfo: &ProcessInfo{
			PID:     1234,
			Command: "nginx",
			User:    "www-data",
		},
		Timestamp: time.Now(),
	}

	profile.AddNetworkConnection(connection)

	assert.Len(t, profile.NetworkConnections, 1)
	assert.Equal(t, "tcp", profile.NetworkConnections[0].Protocol)
	assert.Equal(t, uint16(8080), profile.NetworkConnections[0].LocalPort)
}

func TestLearningProfile_AddFileAccess(t *testing.T) {
	profile := &LearningProfile{
		ContainerID:  "test-container",
		FileAccesses: make([]*FileAccess, 0),
		StartTime:    time.Now(),
	}

	fileAccess := &FileAccess{
		Path: "/tmp/test.txt",
		Mode: "write",
		ProcessInfo: &ProcessInfo{
			PID:     1234,
			Command: "vim",
			User:    "user",
		},
		Timestamp: time.Now(),
		Size:      1024,
	}

	profile.AddFileAccess(fileAccess)

	assert.Len(t, profile.FileAccesses, 1)
	assert.Equal(t, "/tmp/test.txt", profile.FileAccesses[0].Path)
	assert.Equal(t, "write", profile.FileAccesses[0].Mode)
}

func TestSyscallStatistics_UpdateStatistics(t *testing.T) {
	stats := &SyscallStatistics{
		SyscallNumber: 1,
		TotalCalls:    5,
		UniquePids:    2,
		LastSeen:      time.Now().Add(-1 * time.Hour),
		Arguments:     make(map[string]uint64),
		PidSet:        map[int]bool{100: true, 200: true},
	}

	event := &SyscallEvent{
		SyscallNumber: 1,
		PID:           300,
		Timestamp:     time.Now(),
		Arguments:     []uint64{1, 2, 3},
		ReturnValue:   0,
	}

	stats.UpdateStatistics(event)

	assert.Equal(t, uint64(6), stats.TotalCalls)
	assert.Equal(t, 3, stats.UniquePids)
	assert.True(t, stats.PidSet[300])
	assert.True(t, stats.LastSeen.After(time.Now().Add(-1*time.Minute)))
}

func TestWorkloadLifecycle_TransitionPhase(t *testing.T) {
	tests := []struct {
		name        string
		current     WorkloadPhase
		next        WorkloadPhase
		shouldAllow bool
	}{
		{
			name:        "init to starting",
			current:     PhaseInitializing,
			next:        PhaseStarting,
			shouldAllow: true,
		},
		{
			name:        "starting to running",
			current:     PhaseStarting,
			next:        PhaseRunning,
			shouldAllow: true,
		},
		{
			name:        "running to steady",
			current:     PhaseRunning,
			next:        PhaseSteady,
			shouldAllow: true,
		},
		{
			name:        "invalid transition",
			current:     PhaseInitializing,
			next:        PhaseSteady,
			shouldAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifecycle := &WorkloadLifecycle{
				CurrentPhase: tt.current,
				StartTime:    time.Now().Add(-1 * time.Hour),
			}

			allowed := lifecycle.CanTransitionTo(tt.next)
			assert.Equal(t, tt.shouldAllow, allowed)
		})
	}
}

func TestBehaviorPattern_IsStable(t *testing.T) {
	tests := []struct {
		name     string
		pattern  *BehaviorPattern
		expected bool
	}{
		{
			name: "stable pattern",
			pattern: &BehaviorPattern{
				Type:           PatternTypeSyscallSequence,
				Frequency:      100,
				Confidence:     0.95,
				LastObserved:   time.Now(),
				StabilityScore: 0.9,
			},
			expected: true,
		},
		{
			name: "unstable pattern",
			pattern: &BehaviorPattern{
				Type:           PatternTypeSyscallSequence,
				Frequency:      5,
				Confidence:     0.3,
				LastObserved:   time.Now().Add(-1 * time.Hour),
				StabilityScore: 0.2,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stable := tt.pattern.IsStable()
			assert.Equal(t, tt.expected, stable)
		})
	}
}

func TestAnomalyDetection_DetectAnomaly(t *testing.T) {
	detector := &AnomalyDetector{
		BaseLine:           make(map[uint64]float64),
		DeviationThreshold: 2.0,
		MinSamples:         10,
	}

	// Establish baseline
	for i := 0; i < 100; i++ {
		detector.BaseLine[1] = 50.0 // Average syscall 1 frequency
	}

	tests := []struct {
		name          string
		syscallFreq   map[uint64]float64
		expectAnomaly bool
	}{
		{
			name:          "normal behavior",
			syscallFreq:   map[uint64]float64{1: 52.0},
			expectAnomaly: false,
		},
		{
			name:          "anomalous behavior",
			syscallFreq:   map[uint64]float64{1: 200.0},
			expectAnomaly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anomaly := detector.DetectAnomaly(tt.syscallFreq)
			assert.Equal(t, tt.expectAnomaly, anomaly)
		})
	}
}

func TestCriticalityLevel_String(t *testing.T) {
	tests := []struct {
		level    CriticalityLevel
		expected string
	}{
		{CriticalityLow, "Low"},
		{CriticalityMedium, "Medium"},
		{CriticalityHigh, "High"},
		{CriticalityCritical, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.level))
		})
	}
}

func TestProcessHierarchy_FindProcess(t *testing.T) {
	profile := &LearningProfile{
		ProcessHierarchy: []*ProcessInfo{
			{PID: 1, PPID: 0, Command: "init", User: "root"},
			{PID: 100, PPID: 1, Command: "systemd", User: "root"},
			{PID: 1234, PPID: 100, Command: "nginx", User: "www-data"},
		},
	}

	process := profile.FindProcess(1234)
	require.NotNil(t, process)
	assert.Equal(t, 1234, process.PID)
	assert.Equal(t, "nginx", process.Command)

	notFound := profile.FindProcess(9999)
	assert.Nil(t, notFound)
}

func TestLearningProfile_GetSyscallFrequency(t *testing.T) {
	tests := []struct {
		name         string
		profile      *LearningProfile
		expectedLen  int
		validateFunc func(t *testing.T, frequency map[uint64]float64)
	}{
		{
			name: "normal frequency calculation",
			profile: &LearningProfile{
				ContainerID: "test-container",
				ObservedSyscalls: map[uint64]*SyscallStatistics{
					1: {SyscallNumber: 1, TotalCalls: 100, UniquePids: 1},
					2: {SyscallNumber: 2, TotalCalls: 50, UniquePids: 1},
					3: {SyscallNumber: 3, TotalCalls: 25, UniquePids: 1},
				},
				StartTime: time.Now().Add(-1 * time.Hour),
			},
			expectedLen: 3,
			validateFunc: func(t *testing.T, frequency map[uint64]float64) {
				assert.InDelta(t, 100.0, frequency[1], 0.1)
				assert.InDelta(t, 50.0, frequency[2], 0.1)
				assert.InDelta(t, 25.0, frequency[3], 0.1)
			},
		},
		{
			name: "very short elapsed time edge case",
			profile: &LearningProfile{
				ContainerID: "test-container",
				ObservedSyscalls: map[uint64]*SyscallStatistics{
					1: {SyscallNumber: 1, TotalCalls: 100, UniquePids: 1},
					2: {SyscallNumber: 2, TotalCalls: 50, UniquePids: 1},
				},
				StartTime: time.Now().Add(-1 * time.Nanosecond), // Very short time
			},
			expectedLen: 2,
			validateFunc: func(t *testing.T, frequency map[uint64]float64) {
				// With very short elapsed time, frequencies should be very high
				assert.Greater(t, frequency[1], 1000.0)     // Much higher than normal
				assert.Greater(t, frequency[2], 500.0)      // Much higher than normal
				assert.True(t, frequency[1] > frequency[2]) // Relative ratio maintained
			},
		},
		{
			name: "empty syscalls map",
			profile: &LearningProfile{
				ContainerID:      "test-container",
				ObservedSyscalls: map[uint64]*SyscallStatistics{},
				StartTime:        time.Now().Add(-2 * time.Hour),
			},
			expectedLen: 0,
			validateFunc: func(t *testing.T, frequency map[uint64]float64) {
				assert.Empty(t, frequency)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frequency := tt.profile.GetSyscallFrequency()
			assert.Len(t, frequency, tt.expectedLen)
			tt.validateFunc(t, frequency)
		})
	}
}

func TestLearningProfile_IsLearningComplete(t *testing.T) {
	tests := []struct {
		name     string
		profile  *LearningProfile
		window   time.Duration
		expected bool
	}{
		{
			name: "learning complete",
			profile: &LearningProfile{
				StartTime: time.Now().Add(-6 * time.Minute),
				ObservedSyscalls: map[uint64]*SyscallStatistics{
					1: {TotalCalls: 100},
					2: {TotalCalls: 50},
				},
			},
			window:   5 * time.Minute,
			expected: true,
		},
		{
			name: "learning not complete",
			profile: &LearningProfile{
				StartTime: time.Now().Add(-3 * time.Minute),
				ObservedSyscalls: map[uint64]*SyscallStatistics{
					1: {TotalCalls: 10},
				},
			},
			window:   5 * time.Minute,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			complete := tt.profile.IsLearningComplete(tt.window, 0.8, 20)
			assert.Equal(t, tt.expected, complete)
		})
	}
}

func TestBenchmarkLearningProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	profile := &LearningProfile{
		ContainerID:      "benchmark-container",
		ObservedSyscalls: make(map[uint64]*SyscallStatistics),
		StartTime:        time.Now(),
	}

	start := time.Now()

	// Simulate adding many syscalls
	for i := 0; i < 10000; i++ {
		event := &SyscallEvent{
			SyscallNumber: uint64(i % 300), // 300 different syscalls
			PID:           1234,
			Timestamp:     time.Now(),
			Arguments:     []uint64{1, 2, 3},
		}
		profile.AddSyscall(event)
	}

	duration := time.Since(start)
	assert.Less(t, duration, 1*time.Second, "Learning profile updates should be fast")
	t.Logf("Added 10000 syscalls in %v", duration)
}
