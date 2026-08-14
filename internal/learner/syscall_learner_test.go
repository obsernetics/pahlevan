package learner

import (
	"context"
	"fmt"
	"testing"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestLearner() *SyscallLearner {
	// confidenceThreshold 0 so every observation is promoted into a profile.
	return NewSyscallLearner(10, 0.0, time.Minute, 3)
}

func testWorkloadRef() WorkloadReference {
	return WorkloadReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "web",
		Namespace:  "default",
		UID:        "uid-123",
	}
}

func startContainer(t *testing.T, sl *SyscallLearner, id string) {
	t.Helper()
	if err := sl.StartLearning(context.Background(), id, testWorkloadRef(), nil); err != nil {
		t.Fatalf("StartLearning(%s) failed: %v", id, err)
	}
}

func TestNewSyscallLearner(t *testing.T) {
	sl := NewSyscallLearner(50, 0.7, 2*time.Minute, 5)
	if sl == nil {
		t.Fatal("expected non-nil learner")
	}
	if sl.baselineThreshold != 50 || sl.confidenceThreshold != 0.7 {
		t.Fatalf("unexpected config: %+v", sl)
	}
	if sl.containers == nil || sl.learningProfiles == nil {
		t.Fatal("maps not initialized")
	}
	if sl.phaseTransitionDelay != 30*time.Second {
		t.Fatalf("unexpected phaseTransitionDelay: %v", sl.phaseTransitionDelay)
	}
}

func TestStartLearning_NilAndPolicy(t *testing.T) {
	sl := newTestLearner()

	// nil policy must not panic and should use the default window.
	startContainer(t, sl, "c-nil")
	state, err := sl.GetLearningState("c-nil")
	if err != nil {
		t.Fatalf("GetLearningState: %v", err)
	}
	if state.Phase != PhaseInitializing {
		t.Fatalf("expected Initializing, got %s", state.Phase)
	}
	if state.LearningWindow != time.Minute {
		t.Fatalf("expected default window, got %v", state.LearningWindow)
	}
	if len(state.LifecycleEvents) == 0 || state.LifecycleEvents[0].Event != EventContainerStarted {
		t.Fatalf("expected ContainerStarted lifecycle event, got %+v", state.LifecycleEvents)
	}

	// Policy with a window override should be honoured.
	win := metav1.Duration{Duration: 5 * time.Minute}
	policy := &policyv1alpha1.PahlevanPolicy{
		Spec: policyv1alpha1.PahlevanPolicySpec{
			LearningConfig: policyv1alpha1.LearningConfig{WindowSize: &win},
		},
	}
	if err := sl.StartLearning(context.Background(), "c-pol", testWorkloadRef(), policy); err != nil {
		t.Fatalf("StartLearning with policy: %v", err)
	}
	state, _ = sl.GetLearningState("c-pol")
	if state.LearningWindow != 5*time.Minute {
		t.Fatalf("expected policy window, got %v", state.LearningWindow)
	}
}

func TestProcessSyscallEvent(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	// Unknown container -> error.
	if err := sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "missing", SyscallNr: 1}); err == nil {
		t.Fatal("expected error for unknown container")
	}

	// Feed the same syscall many times to build up count/confidence.
	for i := 0; i < 120; i++ {
		if err := sl.ProcessSyscallEvent(&ebpf.SyscallEvent{
			ContainerID: "c1",
			SyscallNr:   59, // execve -> Critical
			Comm:        "app",
		}); err != nil {
			t.Fatalf("ProcessSyscallEvent: %v", err)
		}
	}
	// A second distinct syscall.
	if err := sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "c1", SyscallNr: 0, Comm: "app"}); err != nil {
		t.Fatalf("ProcessSyscallEvent: %v", err)
	}

	state, err := sl.GetLearningState("c1")
	if err != nil {
		t.Fatalf("GetLearningState: %v", err)
	}
	if state.Statistics.TotalSyscalls != 121 {
		t.Fatalf("expected 121 total syscalls, got %d", state.Statistics.TotalSyscalls)
	}
	if state.Statistics.UniqueSyscalls != 2 {
		t.Fatalf("expected 2 unique syscalls, got %d", state.Statistics.UniqueSyscalls)
	}
	obs := state.SyscallObservations[59]
	if obs == nil || obs.Count != 120 {
		t.Fatalf("expected 120 observations for execve, got %+v", obs)
	}
	if obs.Criticality != CriticalityCritical {
		t.Fatalf("expected Critical criticality for execve, got %s", obs.Criticality)
	}
	if obs.Contexts["app"] != 120 {
		t.Fatalf("expected 120 'app' contexts, got %d", obs.Contexts["app"])
	}
	if obs.Confidence <= 0 {
		t.Fatalf("expected positive confidence, got %f", obs.Confidence)
	}
}

func TestProcessNetworkEvent(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	if err := sl.ProcessNetworkEvent(&ebpf.NetworkEvent{ContainerID: "missing"}); err == nil {
		t.Fatal("expected error for unknown container")
	}

	ev := &ebpf.NetworkEvent{
		ContainerID: "c1",
		SrcIP:       0x0A000001, // 10.0.0.1
		DstIP:       0x08080808, // 8.8.8.8
		SrcPort:     12345,
		DstPort:     53,
		Protocol:    17, // udp
		Direction:   1,  // egress
	}
	for i := 0; i < 60; i++ {
		if err := sl.ProcessNetworkEvent(ev); err != nil {
			t.Fatalf("ProcessNetworkEvent: %v", err)
		}
	}
	state, _ := sl.GetLearningState("c1")
	if state.Statistics.UniqueNetworkFlows != 1 {
		t.Fatalf("expected 1 unique flow, got %d", state.Statistics.UniqueNetworkFlows)
	}
	if state.Statistics.TotalNetworkFlows != 60 {
		t.Fatalf("expected 60 total flows, got %d", state.Statistics.TotalNetworkFlows)
	}
	for _, flow := range state.NetworkFlows {
		if flow.Protocol != "udp" || flow.Direction != "egress" {
			t.Fatalf("unexpected flow decode: %+v", flow)
		}
		if flow.RemoteAddress != "8.8.8.8" {
			t.Fatalf("unexpected remote addr: %s", flow.RemoteAddress)
		}
		if flow.Confidence <= 0 {
			t.Fatalf("expected positive confidence, got %f", flow.Confidence)
		}
	}
}

func TestProcessFileEvent(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	if err := sl.ProcessFileEvent(&ebpf.FileEvent{ContainerID: "missing"}); err == nil {
		t.Fatal("expected error for unknown container")
	}

	for i := 0; i < 25; i++ {
		if err := sl.ProcessFileEvent(&ebpf.FileEvent{
			ContainerID: "c1",
			Path:        "/etc/config.log",
			Flags:       0x2, // write
		}); err != nil {
			t.Fatalf("ProcessFileEvent: %v", err)
		}
	}
	state, _ := sl.GetLearningState("c1")
	if state.Statistics.UniqueFileAccess != 1 {
		t.Fatalf("expected 1 unique file, got %d", state.Statistics.UniqueFileAccess)
	}
	access := state.FileAccess["/etc/config.log"]
	if access == nil {
		t.Fatal("missing file access observation")
	}
	if access.AccessModes["write"] != 25 {
		t.Fatalf("expected 25 writes, got %d", access.AccessModes["write"])
	}
	if access.FileType != "log" {
		t.Fatalf("expected log file type, got %s", access.FileType)
	}
}

func TestRecordLifecycleEvent(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	if err := sl.RecordLifecycleEvent("missing", EventInitCompleted, nil); err == nil {
		t.Fatal("expected error for unknown container")
	}

	if err := sl.RecordLifecycleEvent("c1", EventInitCompleted, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("RecordLifecycleEvent: %v", err)
	}
	if err := sl.RecordLifecycleEvent("c1", EventApplicationSteady, nil); err != nil {
		t.Fatalf("RecordLifecycleEvent: %v", err)
	}
	state, _ := sl.GetLearningState("c1")
	// Start + two recorded events.
	if len(state.LifecycleEvents) != 3 {
		t.Fatalf("expected 3 lifecycle events, got %d", len(state.LifecycleEvents))
	}
}

func TestGenerateProfile(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	if _, err := sl.GenerateProfile("missing"); err == nil {
		t.Fatal("expected error for unknown container")
	}

	for i := 0; i < 30; i++ {
		_ = sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "c1", SyscallNr: 59, Comm: "app"})
		_ = sl.ProcessNetworkEvent(&ebpf.NetworkEvent{ContainerID: "c1", DstIP: 0x08080808, DstPort: 443, Protocol: 6, Direction: 1})
		_ = sl.ProcessFileEvent(&ebpf.FileEvent{ContainerID: "c1", Path: "/var/log/app.log", Flags: 0x1})
	}
	_ = sl.RecordLifecycleEvent("c1", EventInitCompleted, nil)

	profile, err := sl.GenerateProfile("c1")
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if profile.ContainerID != "c1" {
		t.Fatalf("unexpected container id: %s", profile.ContainerID)
	}
	if len(profile.AllowedSyscalls) != 1 {
		t.Fatalf("expected 1 allowed syscall, got %d", len(profile.AllowedSyscalls))
	}
	sp := profile.AllowedSyscalls[59]
	if sp == nil || sp.Name != "execve" {
		t.Fatalf("expected execve profile, got %+v", sp)
	}
	if len(profile.AllowedNetworkFlows) != 1 {
		t.Fatalf("expected 1 network flow, got %d", len(profile.AllowedNetworkFlows))
	}
	if len(profile.AllowedFilePaths) != 1 {
		t.Fatalf("expected 1 file path, got %d", len(profile.AllowedFilePaths))
	}
	if profile.Quality.Score < 0 {
		t.Fatalf("unexpected quality score: %f", profile.Quality.Score)
	}
	if len(profile.LifecyclePhases) == 0 {
		t.Fatal("expected lifecycle phases")
	}

	// GenerateProfile stores the profile, retrievable via GetProfile.
	got, err := sl.GetProfile("c1")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got != profile {
		t.Fatal("GetProfile returned a different profile instance")
	}
}

func TestGenerateProfile_HighConfidenceThresholdFiltersOut(t *testing.T) {
	// With an impossibly high threshold, no observation is promoted.
	sl := NewSyscallLearner(10, 2.0, time.Minute, 3)
	startContainer(t, sl, "c1")
	for i := 0; i < 5; i++ {
		_ = sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "c1", SyscallNr: 1, Comm: "app"})
	}
	profile, err := sl.GenerateProfile("c1")
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if len(profile.AllowedSyscalls) != 0 {
		t.Fatalf("expected no syscalls promoted, got %d", len(profile.AllowedSyscalls))
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	sl := newTestLearner()
	if _, err := sl.GetProfile("nope"); err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestGetLearningState_NotFound(t *testing.T) {
	sl := newTestLearner()
	if _, err := sl.GetLearningState("nope"); err == nil {
		t.Fatal("expected error for missing state")
	}
}

func TestStopLearning(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")
	for i := 0; i < 5; i++ {
		_ = sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "c1", SyscallNr: 1, Comm: "app"})
	}

	if err := sl.StopLearning("c1"); err != nil {
		t.Fatalf("StopLearning: %v", err)
	}
	// State removed; a generated profile persists.
	if _, err := sl.GetLearningState("c1"); err == nil {
		t.Fatal("expected state removed after StopLearning")
	}
	if _, err := sl.GetProfile("c1"); err != nil {
		t.Fatalf("expected profile to persist after StopLearning: %v", err)
	}

	// Stopping a missing container errors.
	if err := sl.StopLearning("c1"); err == nil {
		t.Fatal("expected error stopping already-stopped container")
	}
}

func TestSchedulePhaseTransition(t *testing.T) {
	sl := newTestLearner()
	startContainer(t, sl, "c1")

	// Direct call with no delay is deterministic.
	sl.schedulePhaseTransition("c1", PhaseRuntime, 0)
	state, _ := sl.GetLearningState("c1")
	if state.Phase != PhaseRuntime {
		t.Fatalf("expected Runtime phase, got %s", state.Phase)
	}
	// Missing container is a no-op (must not panic).
	sl.schedulePhaseTransition("missing", PhaseRuntime, 0)
}

func TestAssessSyscallCriticality(t *testing.T) {
	sl := newTestLearner()
	cases := map[uint64]CriticalityLevel{
		59:   CriticalityCritical,
		56:   CriticalityCritical,
		57:   CriticalityHigh,
		41:   CriticalityHigh,
		2:    CriticalityMedium,
		0:    CriticalityLow,
		9999: CriticalityLow, // unknown -> low
	}
	for nr, want := range cases {
		if got := sl.assessSyscallCriticality(nr); got != want {
			t.Errorf("criticality(%d)=%s want %s", nr, got, want)
		}
	}
}

func TestDetectFileType(t *testing.T) {
	sl := newTestLearner()
	cases := map[string]string{
		"":                 "regular",
		"/tmp":             "temporary", // short path used to panic
		"/dev":             "device",
		"/proc":            "procfs",
		"/var/tmp/x":       "temporary",
		"/lib/libc.so":     "library",
		"/bin/app.bin":     "executable",
		"/var/log/app.log": "log",
		"/data/file.tmp":   "temporary",
		"/home/user/file":  "regular",
		"ab":               "regular", // shorter than 4, no prefix match
	}
	for path, want := range cases {
		if got := sl.detectFileType(path); got != want {
			t.Errorf("detectFileType(%q)=%s want %s", path, got, want)
		}
	}
}

func TestUtilityConversions(t *testing.T) {
	sl := newTestLearner()

	if got := sl.ipToString(0x01020304); got != "1.2.3.4" {
		t.Errorf("ipToString=%s", got)
	}
	if got := sl.protocolToString(6); got != "tcp" {
		t.Errorf("protocol tcp=%s", got)
	}
	if got := sl.protocolToString(17); got != "udp" {
		t.Errorf("protocol udp=%s", got)
	}
	if got := sl.protocolToString(99); got != "proto-99" {
		t.Errorf("protocol unknown=%s", got)
	}
	if got := sl.directionToString(0); got != "ingress" {
		t.Errorf("dir 0=%s", got)
	}
	if got := sl.directionToString(1); got != "egress" {
		t.Errorf("dir 1=%s", got)
	}
	if got := sl.directionToString(9); got != "unknown" {
		t.Errorf("dir unknown=%s", got)
	}
	if got := sl.flagsToAccessMode(0x2); got != "write" {
		t.Errorf("flags write=%s", got)
	}
	if got := sl.flagsToAccessMode(0x1); got != "read" {
		t.Errorf("flags read=%s", got)
	}
	if got := sl.flagsToAccessMode(0x0); got != "read" {
		t.Errorf("flags default=%s", got)
	}
	if got := sl.syscallNumberToName(59); got != "execve" {
		t.Errorf("name execve=%s", got)
	}
	if got := sl.syscallNumberToName(4242); got != "syscall_4242" {
		t.Errorf("name unknown=%s", got)
	}
}

func TestConfidenceCalculations(t *testing.T) {
	sl := newTestLearner()

	// Frequency stability: fewer than 2 observations is low.
	low := &SyscallObservation{Count: 1}
	if s := sl.calculateSyscallFrequencyStability(low); s != 0.1 {
		t.Errorf("expected 0.1 stability, got %f", s)
	}
	// Same first/last seen => moderate stability.
	now := time.Now()
	pt := &SyscallObservation{Count: 5, FirstSeen: now, LastSeen: now}
	if s := sl.calculateSyscallFrequencyStability(pt); s != 0.3 {
		t.Errorf("expected 0.3 stability, got %f", s)
	}
	// Spread over time yields a bounded [0,1] stability.
	spread := &SyscallObservation{Count: 50, FirstSeen: now.Add(-time.Minute), LastSeen: now, Frequency: 50}
	if s := sl.calculateSyscallFrequencyStability(spread); s < 0 || s > 1 {
		t.Errorf("stability out of range: %f", s)
	}

	// Network + file confidence saturate to 1.
	if c := sl.calculateNetworkFlowConfidence(&NetworkFlowObservation{Count: 1000}); c != 1.0 {
		t.Errorf("expected saturated network confidence, got %f", c)
	}
	fa := &FileAccessObservation{AccessModes: map[string]int64{"read": 1000}}
	if c := sl.calculateFileAccessConfidence(fa); c != 1.0 {
		t.Errorf("expected saturated file confidence, got %f", c)
	}

	// Overall confidence of an empty state is zero.
	empty := &ContainerLearningState{SyscallObservations: map[uint64]*SyscallObservation{}}
	if c := sl.calculateOverallConfidence(empty); c != 0.0 {
		t.Errorf("expected zero overall confidence, got %f", c)
	}
}

func TestAccuracyAndCoverageEmpty(t *testing.T) {
	sl := newTestLearner()
	empty := &ContainerLearningState{SyscallObservations: map[uint64]*SyscallObservation{}}
	if c := sl.calculateCoverage(empty); c != 0.0 {
		t.Errorf("expected zero coverage, got %f", c)
	}
	if a := sl.calculateAccuracy(empty); a != 0.0 {
		t.Errorf("expected zero accuracy, got %f", a)
	}
}

func TestAccuracyWithReturnCodesAndArgs(t *testing.T) {
	sl := newTestLearner()
	state := &ContainerLearningState{
		SyscallObservations: map[uint64]*SyscallObservation{
			1: {
				SyscallNr:   1,
				Count:       10,
				Confidence:  0.9,
				ReturnCodes: map[int64]int64{0: 8, -1: 2},
				Arguments:   map[string]int64{"a": 1, "b": 1, "c": 1},
				Contexts:    map[string]int64{"app": 10},
			},
		},
	}
	a := sl.calculateAccuracy(state)
	if a <= 0 || a > 1 {
		t.Fatalf("accuracy out of range: %f", a)
	}
	c := sl.calculateCoverage(state)
	if c <= 0 || c > 1 {
		t.Fatalf("coverage out of range: %f", c)
	}
}

func TestUpdateLearningProgress_ZeroDivisorsGuarded(t *testing.T) {
	// Zero baseline threshold and window must not produce NaN/Inf progress.
	sl := NewSyscallLearner(0, 0.0, 0, 0)
	state := &ContainerLearningState{
		StartTime:           time.Now(),
		LearningWindow:      0,
		SyscallObservations: map[uint64]*SyscallObservation{1: {Confidence: 0.5}},
	}
	sl.updateLearningProgress(state)
	p := state.Statistics.LearningProgress
	if p != p { // NaN check
		t.Fatal("learning progress is NaN")
	}
	if p < 0 || p > 1 {
		t.Fatalf("learning progress out of range: %f", p)
	}
}

// --- Benchmarks -------------------------------------------------------------

func BenchmarkProcessSyscallEvent(b *testing.B) {
	// High minObservations so the bootstrap transition never spawns goroutines.
	sl := NewSyscallLearner(10, 0.0, time.Minute, 1_000_000)
	if err := sl.StartLearning(context.Background(), "bench", testWorkloadRef(), nil); err != nil {
		b.Fatalf("StartLearning: %v", err)
	}
	ev := &ebpf.SyscallEvent{ContainerID: "bench", SyscallNr: 59, Comm: "app"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sl.ProcessSyscallEvent(ev); err != nil {
			b.Fatalf("ProcessSyscallEvent: %v", err)
		}
	}
}

func BenchmarkProcessSyscallEvent_ManyDistinct(b *testing.B) {
	sl := NewSyscallLearner(10, 0.0, time.Minute, 1_000_000)
	_ = sl.StartLearning(context.Background(), "bench", testWorkloadRef(), nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sl.ProcessSyscallEvent(&ebpf.SyscallEvent{
			ContainerID: "bench",
			SyscallNr:   uint64(i % 400),
			Comm:        "app",
		})
	}
}

func BenchmarkGenerateProfile(b *testing.B) {
	sl := NewSyscallLearner(10, 0.0, time.Minute, 1_000_000)
	_ = sl.StartLearning(context.Background(), "bench", testWorkloadRef(), nil)
	for i := 0; i < 300; i++ {
		_ = sl.ProcessSyscallEvent(&ebpf.SyscallEvent{ContainerID: "bench", SyscallNr: uint64(i % 100), Comm: "app"})
		_ = sl.ProcessNetworkEvent(&ebpf.NetworkEvent{ContainerID: "bench", DstIP: uint32(i), DstPort: uint16(i % 1000), Protocol: 6})
		_ = sl.ProcessFileEvent(&ebpf.FileEvent{ContainerID: "bench", Path: fmt.Sprintf("/var/log/f-%d.log", i%50), Flags: 0x1})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sl.GenerateProfile("bench"); err != nil {
			b.Fatalf("GenerateProfile: %v", err)
		}
	}
}
