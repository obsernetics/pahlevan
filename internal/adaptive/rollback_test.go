package adaptive

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// --- helpers -----------------------------------------------------------------

const (
	testNS      = "prod"
	testPodName = "web-abc"
	testPodUID  = "pod-uid-xyz"
)

// rollbackScheme builds a fake client that knows both the Pahlevan CRDs and
// core/v1, so pod reads and Event writes both work.
func rollbackClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := newRuntimeScheme(t)
	return fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&policyv1alpha1.ContainerProfile{}).
		WithObjects(objs...).
		Build()
}

// testPod builds a pod whose single container has the given runtime health.
func testPod(restarts int32, ready bool, waitingReason string) *corev1.Pod {
	cs := corev1.ContainerStatus{
		Name:         "app",
		RestartCount: restarts,
		Ready:        ready,
	}
	if waitingReason != "" {
		cs.State.Waiting = &corev1.ContainerStateWaiting{Reason: waitingReason}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testPodName, Namespace: testNS, UID: types.UID(testPodUID)},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{cs}},
	}
}

// enforcingController returns a controller with cgroup 42 already enforcing,
// its baseline captured from the pod currently stored in the client.
func enforcingController(t *testing.T, cl client.Client, base time.Time) (*Controller, *fakeEnforcer) {
	t.Helper()
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil,
		fakePoliciesMeta{window: time.Minute, blocking: true, ok: true, ns: testNS, name: testPodName, metaOK: true})
	c.Client = cl
	c.Node = "node-1"
	c.now = func() time.Time { return base }

	c.mu.Lock()
	st := c.track(42)
	st.ref.PodUID = testPodUID
	st.ref.ContainerID = "abcdef0123456789"
	c.mu.Unlock()

	// Elapse the learning window and reconcile: cgroup 42 goes enforcing.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	if !enf.enforced[42] {
		t.Fatal("setup: expected cgroup 42 to be enforcing")
	}
	return c, enf
}

func phaseOf(t *testing.T, c *Controller, id uint64) Phase {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state[id].phase
}

func warningEvents(t *testing.T, cl client.Client) []corev1.Event {
	t.Helper()
	var list corev1.EventList
	if err := cl.List(context.Background(), &list); err != nil {
		t.Fatalf("list events: %v", err)
	}
	return list.Items
}

// --- denial accounting --------------------------------------------------------

func TestNoteDenial_OnlyCountsWhileEnforcing(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})

	// Learning: denial flags are counted as denials, never as learned behaviour,
	// and never inflate the enforcing denial counter.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 1, Path: "/etc/shadow", Flags: DeniedFlag})
	c.mu.Lock()
	if got := len(c.state[1].files); got != 0 {
		t.Errorf("denied file must not be learned, got %d learned files", got)
	}
	if got := c.state[1].denials; got != 0 {
		t.Errorf("denials while learning = %d, want 0", got)
	}
	c.state[1].phase = PhaseEnforcing
	c.mu.Unlock()

	// Enforcing: each denial bit increments the counter, once per event type.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 1, Path: "/etc/shadow", Flags: DeniedFlag})
	_ = c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 1, Filename: "/bin/sh", Flags: DeniedFlag})
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 1, DstIP: 1, DstPort: 80, Direction: DeniedDirection})
	_ = c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 1, Capability: 21, Flags: DeniedFlag})

	c.mu.Lock()
	got := c.state[1].denials
	c.mu.Unlock()
	if got != 4 {
		t.Errorf("denials = %d, want 4 (file, exec, network, capability)", got)
	}
}

func TestHandleEvents_AllowedEventsDoNotCountAsDenials(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})
	c.mu.Lock()
	c.track(3).phase = PhaseEnforcing
	c.mu.Unlock()

	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 3, Path: "/etc/hosts", Flags: 0})
	_ = c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 3, Filename: "/bin/ls", Flags: 0x40000000})
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 3, DstIP: 1, DstPort: 443, Direction: 1})
	_ = c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 3, Capability: 1, Flags: 0})

	c.mu.Lock()
	got := c.state[3].denials
	c.mu.Unlock()
	if got != 0 {
		t.Errorf("allowed events counted as denials: %d", got)
	}
}

// --- pure distress evaluation --------------------------------------------------

func TestCaptureBaseline(t *testing.T) {
	if b := CaptureBaseline(nil); b.Restarts != nil || b.Ready != nil {
		t.Errorf("nil pod should yield an empty baseline, got %+v", b)
	}
	b := CaptureBaseline(testPod(2, true, ""))
	if b.Restarts["app"] != 2 {
		t.Errorf("Restarts[app] = %d, want 2", b.Restarts["app"])
	}
	if !b.Ready["app"] {
		t.Error("Ready[app] should be true")
	}
}

func TestEvaluatePodDistress(t *testing.T) {
	healthy := CaptureBaseline(testPod(2, true, ""))

	tests := []struct {
		name string
		pod  *corev1.Pod
		base ContainerBaseline
		want bool
	}{
		{"nil pod is not distress", nil, healthy, false},
		{"unchanged pod is healthy", testPod(2, true, ""), healthy, false},
		{"restart count increased", testPod(3, true, ""), healthy, true},
		{"crashloopbackoff", testPod(2, true, "CrashLoopBackOff"), healthy, true},
		{"readiness flipped false", testPod(2, false, ""), healthy, true},
		{"other waiting reason is not distress", testPod(2, true, "ContainerCreating"), healthy, false},
		{"restart count lower than baseline is not distress", testPod(1, true, ""), healthy, false},
		{"crashloop is distress even with an empty baseline", testPod(0, true, "CrashLoopBackOff"), ContainerBaseline{}, true},
		{"unknown container name is ignored", testPod(9, false, ""), CaptureBaseline(testPod(0, true, "")), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := EvaluatePodDistress(tc.pod, tc.base)
			if got != tc.want {
				t.Fatalf("distressed = %v (%q), want %v", got, reason, tc.want)
			}
			if got && reason == "" {
				t.Error("distress must come with a reason")
			}
			if !got && reason != "" {
				t.Errorf("no distress but got reason %q", reason)
			}
		})
	}
}

func TestEvaluatePodDistress_BaselineWithoutContainer(t *testing.T) {
	// A container that is not in the baseline at all (e.g. added after the
	// transition) must not be judged on restarts or readiness.
	base := ContainerBaseline{Restarts: map[string]int32{}, Ready: map[string]bool{}}
	if reason, got := EvaluatePodDistress(testPod(7, false, ""), base); got {
		t.Errorf("unknown container should not be distress, got %q", reason)
	}
}

// --- rollback triggers ---------------------------------------------------------

func TestRollback_TriggersOnDenialRate(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, enf := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 3

	// Two denials: below threshold, still enforcing.
	for i := 0; i < 2; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	}
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()
	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("rolled back below the denial threshold")
	}

	// Third denial crosses the threshold.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseLearning {
		t.Fatal("expected rollback to Learning after crossing the denial threshold")
	}
	// The whole point: the enforcement setters were called with false.
	if enf.enforced[42] || enf.netEnforced[42] || enf.execEnforced[42] || enf.capEnforced[42] {
		t.Errorf("rollback must clear every enforcement bit, got file=%v net=%v exec=%v cap=%v",
			enf.enforced[42], enf.netEnforced[42], enf.execEnforced[42], enf.capEnforced[42])
	}

	snap := c.Snapshot()
	if len(snap) != 1 || snap[0].Rollbacks != 1 {
		t.Fatalf("expected 1 recorded rollback, got %+v", snap)
	}
	// The learning window restarts, but the container's true first-seen time
	// must not be rewritten by the rollback.
	if !snap[0].FirstSeen.Equal(base) {
		t.Errorf("FirstSeen = %v, want the original %v", snap[0].FirstSeen, base)
	}
	c.mu.Lock()
	learningSince := c.state[42].learningSince
	c.mu.Unlock()
	if !learningSince.After(base) {
		t.Errorf("learningSince = %v, should have restarted after the rollback", learningSince)
	}
	if snap[0].LastRollbackReason == "" || snap[0].LastRollback.IsZero() {
		t.Errorf("rollback reason/time not recorded: %+v", snap[0])
	}
	if snap[0].Denials != 0 {
		t.Errorf("denial counter should reset on rollback, got %d", snap[0].Denials)
	}

	// A Warning Event must be visible on the pod.
	evs := warningEvents(t, cl)
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 rollback event, got %d", len(evs))
	}
	if evs[0].Reason != "EnforcementRolledBack" || evs[0].Type != corev1.EventTypeWarning {
		t.Errorf("unexpected event: reason=%q type=%q", evs[0].Reason, evs[0].Type)
	}
	if evs[0].InvolvedObject.Name != testPodName || evs[0].InvolvedObject.Kind != "Pod" {
		t.Errorf("event not attached to the pod: %+v", evs[0].InvolvedObject)
	}
	if evs[0].Message == "" {
		t.Error("rollback event must explain itself")
	}
}

func TestRollback_TriggersOnPodDistress(t *testing.T) {
	distressCases := []struct {
		name string
		pod  *corev1.Pod
	}{
		{"restart", testPod(1, true, "")},
		{"crashloop", testPod(0, true, "CrashLoopBackOff")},
		{"unready", testPod(0, false, "")},
	}
	for _, tc := range distressCases {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Unix(1700000000, 0)
			cl := rollbackClient(t, testPod(0, true, ""))
			c, enf := enforcingController(t, cl, base)

			// No denials at all: the pod-health signal alone must roll back.
			// Pod status is a subresource, so it must be written through Status().
			if err := cl.Status().Update(context.Background(), tc.pod); err != nil {
				t.Fatalf("update pod status: %v", err)
			}
			c.now = func() time.Time { return base.Add(3 * time.Minute) }
			c.Reconcile()

			if phaseOf(t, c, 42) != PhaseLearning {
				t.Fatal("expected rollback on pod distress")
			}
			if enf.enforced[42] {
				t.Error("file enforcement still on after distress rollback")
			}
			if len(warningEvents(t, cl)) != 1 {
				t.Error("expected a rollback event")
			}
		})
	}
}

func TestRollback_HealthyEnforcingContainerIsNotRolledBack(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, enf := enforcingController(t, cl, base)

	// Healthy pod, a couple of denials well below the threshold.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/tmp/x", Flags: DeniedFlag})
	for i := 1; i <= 5; i++ {
		c.now = func() time.Time { return base.Add(time.Duration(2+i) * time.Minute) }
		c.Reconcile()
	}

	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("healthy container must stay enforcing")
	}
	if !enf.enforced[42] {
		t.Error("file enforcement should still be on")
	}
	if len(warningEvents(t, cl)) != 0 {
		t.Error("no rollback event should be emitted for a healthy container")
	}
}

func TestRollback_NotEvaluatedOutsideObservationWindow(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1

	// A denial arriving long after the transition is normal enforcement doing
	// its job, not evidence of a bad baseline.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	c.now = func() time.Time { return base.Add(2*time.Minute + 2*c.Rollback.ObservationWindow) }
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("denials past the observation window must not roll back enforcement")
	}
}

func TestRollback_DisabledByZeroObservationWindow(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.ObservationWindow = 0

	for i := 0; i < 50; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	}
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("rollback must be disabled when ObservationWindow is zero")
	}
}

func TestRollback_DenialTriggerDisabledByZeroThreshold(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 0

	for i := 0; i < 50; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	}
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("a zero DenialThreshold must disable the denial trigger")
	}
}

// --- cooldown and attempt cap ---------------------------------------------------

func TestRollback_CooldownPreventsFlapping(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, enf := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1
	c.Rollback.Cooldown = 10 * time.Minute

	now := base.Add(3 * time.Minute)
	c.now = func() time.Time { return now }
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	c.Reconcile()
	if phaseOf(t, c, 42) != PhaseLearning {
		t.Fatal("setup: expected a rollback")
	}
	rolledBackAt := now

	// The learning window (1m) has elapsed, but the 10m cooldown has not: the
	// container must NOT be re-enforced.
	for _, d := range []time.Duration{2 * time.Minute, 5 * time.Minute, 9 * time.Minute} {
		now = rolledBackAt.Add(d)
		c.Reconcile()
		if phaseOf(t, c, 42) != PhaseLearning {
			t.Fatalf("re-enforced %s after rollback, inside the 10m cooldown", d)
		}
		if enf.enforced[42] {
			t.Fatalf("enforcement re-enabled %s after rollback", d)
		}
	}

	// Past the cooldown it may try again.
	now = rolledBackAt.Add(11 * time.Minute)
	c.Reconcile()
	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("expected a second enforce attempt once the cooldown expired")
	}
	if !enf.enforced[42] {
		t.Error("file enforcement should be back on for the second attempt")
	}
}

func TestRollback_CooldownGrowsWithEachRollback(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1
	c.Rollback.Cooldown = time.Minute
	c.Rollback.MaxAttempts = 0 // unlimited, so we can observe the backoff

	now := base.Add(3 * time.Minute)
	c.now = func() time.Time { return now }

	holds := make([]time.Duration, 0, 3)
	for i := 0; i < 3; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
		c.Reconcile()
		c.mu.Lock()
		st := c.state[42]
		if st.phase != PhaseLearning {
			c.mu.Unlock()
			t.Fatalf("rollback %d did not happen", i+1)
		}
		holds = append(holds, st.holdUntil.Sub(now))
		c.mu.Unlock()
		// Jump past the cooldown so the next attempt can start.
		now = now.Add(holds[i] + time.Minute)
		c.Reconcile() // re-enforces
	}

	if !(holds[0] < holds[1] && holds[1] < holds[2]) {
		t.Errorf("cooldown must grow with each rollback, got %v", holds)
	}
	if holds[0] != time.Minute || holds[1] != 2*time.Minute || holds[2] != 3*time.Minute {
		t.Errorf("cooldown backoff = %v, want 1m/2m/3m", holds)
	}
}

func TestRollback_AttemptCapIsHonored(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, enf := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1
	c.Rollback.Cooldown = time.Minute
	c.Rollback.MaxAttempts = 3

	now := base.Add(3 * time.Minute)
	c.now = func() time.Time { return now }

	// Attempt 1 already happened in enforcingController. Fail it, then fail the
	// two attempts that follow.
	for i := 0; i < 3; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
		c.Reconcile()
		if phaseOf(t, c, 42) != PhaseLearning {
			t.Fatalf("rollback %d did not happen", i+1)
		}
		now = now.Add(time.Hour) // well past any cooldown
		c.Reconcile()
	}

	// The cap is reached: the container stays in learning forever, monitor only.
	if phaseOf(t, c, 42) != PhaseLearning {
		t.Fatal("container must stop being re-enforced once the attempt cap is reached")
	}
	if enf.enforced[42] {
		t.Error("enforcement must stay off past the attempt cap")
	}
	snap := c.Snapshot()
	if snap[0].Attempts != 3 {
		t.Errorf("Attempts = %d, want exactly 3 (the cap)", snap[0].Attempts)
	}
	if snap[0].Rollbacks != 3 {
		t.Errorf("Rollbacks = %d, want 3", snap[0].Rollbacks)
	}

	// Reconciling repeatedly past the cap changes nothing and logs only once.
	for i := 0; i < 5; i++ {
		now = now.Add(time.Hour)
		c.Reconcile()
	}
	if c.Snapshot()[0].Attempts != 3 {
		t.Error("attempt cap leaked on repeated reconciles")
	}
}

func TestRollback_UnlimitedAttemptsWhenMaxAttemptsIsZero(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1
	c.Rollback.Cooldown = 0 // no cooldown, so re-enforcement is immediate
	c.Rollback.MaxAttempts = 0

	now := base.Add(3 * time.Minute)
	c.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
		c.Reconcile() // roll back
		now = now.Add(2 * time.Minute)
		c.Reconcile() // re-enforce
	}
	if got := c.Snapshot()[0].Attempts; got != 6 {
		t.Errorf("Attempts = %d, want 6 (1 initial + 5 retries, uncapped)", got)
	}
}

// --- persistence ---------------------------------------------------------------

func TestPersistProfile_ReportsRollbackState(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 2

	// Before any rollback, the profile reports one attempt and no rollbacks.
	cp := &policyv1alpha1.ContainerProfile{}
	key := types.NamespacedName{Namespace: testNS, Name: "pod-" + testPodUID + "-abcdef012345"}
	if err := cl.Get(context.Background(), key, cp); err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if cp.Status.EnforcementAttempts != 1 || cp.Status.RollbackCount != 0 {
		t.Errorf("attempts/rollbacks = %d/%d, want 1/0", cp.Status.EnforcementAttempts, cp.Status.RollbackCount)
	}
	if cp.Status.EnforcingSince == nil || !cp.Status.EnforcingSince.Time.Equal(base.Add(2*time.Minute)) {
		t.Errorf("EnforcingSince = %v, want the real transition time %v", cp.Status.EnforcingSince, base.Add(2*time.Minute))
	}

	// Trigger a rollback and re-read.
	rolledBackAt := base.Add(3 * time.Minute)
	c.now = func() time.Time { return rolledBackAt }
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow", Flags: DeniedFlag})
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/gshadow", Flags: DeniedFlag})
	c.Reconcile()

	if err := cl.Get(context.Background(), key, cp); err != nil {
		t.Fatalf("get profile after rollback: %v", err)
	}
	if cp.Status.Phase != string(PhaseLearning) {
		t.Errorf("Phase = %q, want Learning after rollback", cp.Status.Phase)
	}
	if cp.Status.RollbackCount != 1 {
		t.Errorf("RollbackCount = %d, want 1", cp.Status.RollbackCount)
	}
	if cp.Status.LastRollbackTime == nil || !cp.Status.LastRollbackTime.Time.Equal(rolledBackAt) {
		t.Errorf("LastRollbackTime = %v, want %v", cp.Status.LastRollbackTime, rolledBackAt)
	}
	if cp.Status.LastRollbackReason == "" {
		t.Error("LastRollbackReason must be recorded on the CR")
	}
	if cp.Status.EnforcingSince != nil {
		t.Error("EnforcingSince must be cleared once the container is back to learning")
	}
	if cp.Status.DenialCount != 0 {
		t.Errorf("DenialCount = %d, want 0 after rollback", cp.Status.DenialCount)
	}
}

// --- degraded environments -------------------------------------------------------

func TestRollback_NoClientMeansNoHealthSignal(t *testing.T) {
	// Without a client the controller cannot read pods, so pod distress can never
	// fire; the denial trigger must still work and must not panic on the Event.
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil,
		fakePoliciesMeta{window: 0, blocking: true, ok: true, ns: testNS, name: testPodName, metaOK: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	c.Rollback.DenialThreshold = 1

	c.mu.Lock()
	c.track(8).ref.PodUID = testPodUID
	c.mu.Unlock()
	c.Reconcile()
	if !enf.enforced[8] {
		t.Fatal("setup: expected enforcement")
	}

	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 8, Path: "/x", Flags: DeniedFlag})
	c.now = func() time.Time { return base.Add(time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 8) != PhaseLearning {
		t.Fatal("denial-driven rollback must work without a client")
	}
	if enf.enforced[8] {
		t.Error("enforcement not cleared")
	}
}

func TestRollback_UnresolvablePodSkipsEventAndHealthCheck(t *testing.T) {
	// PodMeta not ok: fetchPod and emitRollbackEvent must both no-op cleanly.
	cl := rollbackClient(t)
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePoliciesMeta{window: 0, blocking: true, ok: true, metaOK: false})
	c.Client = cl
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	c.Rollback.DenialThreshold = 1

	c.mu.Lock()
	c.track(11).ref.PodUID = testPodUID
	c.mu.Unlock()
	c.Reconcile()

	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 11, Path: "/x", Flags: DeniedFlag})
	c.now = func() time.Time { return base.Add(time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 11) != PhaseLearning {
		t.Fatal("expected rollback")
	}
	if len(warningEvents(t, cl)) != 0 {
		t.Error("no event should be emitted for an unresolvable pod")
	}
}

func TestRollback_MissingPodIsNotDistress(t *testing.T) {
	// PodMeta resolves but the pod is gone from the API: fetchPod returns nil and
	// the container must be left alone rather than rolled back.
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)

	if err := cl.Delete(context.Background(), testPod(0, true, "")); err != nil {
		t.Fatalf("delete pod: %v", err)
	}
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseEnforcing {
		t.Fatal("an unreadable pod must not be treated as distress")
	}
}

func TestRollback_EnforcerErrorsDoNotStopTheRollback(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cl := rollbackClient(t, testPod(0, true, ""))
	c, _ := enforcingController(t, cl, base)
	c.Rollback.DenialThreshold = 1

	// Swap in an enforcer that fails every call: the rollback must still attempt
	// all four setters and still return the container to learning.
	fe := &failingEnforcer{}
	c.enforcer = fe

	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/x", Flags: DeniedFlag})
	c.now = func() time.Time { return base.Add(3 * time.Minute) }
	c.Reconcile()

	if phaseOf(t, c, 42) != PhaseLearning {
		t.Fatal("rollback must complete even when the enforcer errors")
	}
	if fe.file != 1 || fe.net != 1 || fe.exec != 1 || fe.capa != 1 {
		t.Errorf("all four setters must be attempted, got file=%d net=%d exec=%d cap=%d",
			fe.file, fe.net, fe.exec, fe.capa)
	}
}

func TestMaybeEnforce_FileEnforcementErrorAbortsTheTransition(t *testing.T) {
	fe := &failingEnforcer{}
	c := NewController(logr.Discard(), fe, nil, fakePolicies{window: 0, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 4, SyscallNr: 1})
	c.Reconcile()

	if phaseOf(t, c, 4) != PhaseLearning {
		t.Fatal("a failed file-enforcement write must not mark the container enforcing")
	}
	if fe.net != 0 || fe.exec != 0 || fe.capa != 0 {
		t.Error("the transition must abort before the best-effort setters")
	}
	if c.Snapshot()[0].Attempts != 0 {
		t.Error("a failed transition must not consume an attempt")
	}
}

func TestMaybeEnforce_BestEffortSetterErrorsStillEnforce(t *testing.T) {
	// File enforcement succeeds; the other three fail because the kernel lacks
	// BPF LSM. The container is still enforcing on the signal that worked.
	pe := &partialEnforcer{}
	c := NewController(logr.Discard(), pe, nil, fakePolicies{window: 0, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 6, SyscallNr: 1})
	c.Reconcile()

	if phaseOf(t, c, 6) != PhaseEnforcing {
		t.Fatal("file enforcement alone should still put the container in enforcing")
	}
	if pe.net != 1 || pe.exec != 1 || pe.capa != 1 {
		t.Errorf("all best-effort setters must be attempted, got net=%d exec=%d cap=%d", pe.net, pe.exec, pe.capa)
	}
}

func TestHandleEvents_IgnoreCgroupZeroAndLearnExecsAndCaps(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})

	for _, err := range []error{
		c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 0, Filename: "/bin/sh"}),
		c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 0, Capability: 1}),
		c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 0, Path: "/x"}),
		c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 0, SyscallNr: 1}),
	} {
		if err != nil {
			t.Fatalf("cgroup 0 must be ignored without error: %v", err)
		}
	}
	c.mu.Lock()
	n := len(c.state)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("cgroup 0 must not be tracked, got %d entries", n)
	}

	// Learning records executables and capabilities.
	_ = c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 12, Filename: "/bin/sh"})
	_ = c.HandleProcessEvent(&ebpf.ProcessEvent{CgroupID: 12, Filename: ""}) // empty is ignored
	_ = c.HandleCapabilityEvent(&ebpf.CapabilityEvent{CgroupID: 12, Capability: 21})
	c.mu.Lock()
	execs, caps := len(c.state[12].execs), len(c.state[12].caps)
	c.mu.Unlock()
	if execs != 1 || caps != 1 {
		t.Errorf("learned execs/caps = %d/%d, want 1/1", execs, caps)
	}
}

func TestDefaultRollbackConfig(t *testing.T) {
	cfg := DefaultRollbackConfig()
	if cfg.ObservationWindow <= 0 || cfg.DenialThreshold <= 0 || cfg.Cooldown <= 0 || cfg.MaxAttempts <= 0 {
		t.Fatalf("defaults must enable rollback with finite retries: %+v", cfg)
	}
	if cfg.Cooldown <= cfg.ObservationWindow {
		t.Error("cooldown should outlast the observation window so a retry cannot immediately re-fail")
	}
	// NewController must install the defaults, since the node agent never sets them.
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})
	if c.Rollback != cfg {
		t.Errorf("NewController Rollback = %+v, want %+v", c.Rollback, cfg)
	}
}
