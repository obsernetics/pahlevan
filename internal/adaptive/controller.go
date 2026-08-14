// Package adaptive implements Pahlevan's core learn->enforce control loop that
// runs inside the node agent.
//
// It consumes the eBPF event stream, attributes each event to a Kubernetes pod
// via the cgroup id, and drives each matched container through a learning window
// and then into in-kernel enforcement - with no hand-written rules. This is the
// behaviour that distinguishes Pahlevan from Falco (alert-only, manual rules) and
// Tetragon (manual TracingPolicy).
package adaptive

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

// Phase is the lifecycle phase of a container under a policy.
type Phase string

const (
	PhaseLearning  Phase = "Learning"
	PhaseEnforcing Phase = "Enforcing"
)

// Enforcer is the subset of the eBPF manager the controller needs. Kept small so
// the loop is testable without a live kernel.
type Enforcer interface {
	SetFileEnforcement(cgroupID uint64, enforce bool) error
	SetNetworkEnforcement(cgroupID uint64, enforce bool) error
	SetExecEnforcement(cgroupID uint64, enforce bool) error
	SetCapabilityEnforcement(cgroupID uint64, enforce bool) error
}

// PolicyResolver decides, for a given cgroup, whether a policy applies and how
// long its learning window is. The agent supplies a real implementation backed by
// pod labels + PahlevanPolicy selectors; tests supply a fake.
type PolicyResolver interface {
	// Resolve returns (learningWindow, blocking, ok). ok=false means no policy
	// governs this cgroup yet (keep observing, don't enforce).
	Resolve(cgroupID uint64, ref attribution.ContainerRef) (window time.Duration, blocking bool, ok bool)
	// PodMeta resolves a pod UID to its namespace and name (ok=false if unknown).
	PodMeta(podUID string) (namespace, name string, ok bool)
}

// Denial markers set by the eBPF data plane. The contract is defined once, next
// to the wire format it describes, and aliased here so this package keeps
// reading naturally. Duplicating the literals invited the two halves to drift.
const (
	DeniedFlag      = ebpf.DeniedFlag
	DeniedDirection = ebpf.DeniedDirection
)

// RollbackConfig tunes health-driven rollback out of enforcement. A container
// that starts failing right after Pahlevan flips it to enforcing is, far more
// often than not, failing *because* of an incomplete learned baseline. Rolling
// back to learning is what makes the "self-healing" claim true.
type RollbackConfig struct {
	// ObservationWindow is how long after the enforce transition the controller
	// watches the container for distress. Past this window the baseline is
	// considered settled and rollback is no longer evaluated. Zero or negative
	// disables health-driven rollback entirely.
	ObservationWindow time.Duration

	// DenialThreshold is the number of in-kernel denials observed within
	// ObservationWindow that triggers a rollback. Because the count is bounded
	// by the window, this is a denial rate. Zero or negative disables the
	// denial-driven trigger (pod distress can still trigger).
	DenialThreshold int

	// Cooldown is the extra learning time imposed after a rollback, before the
	// container may be considered for enforcement again. It is multiplied by the
	// rollback count, so repeated failures back off linearly and cannot flap.
	Cooldown time.Duration

	// MaxAttempts caps how many times a single container may be transitioned to
	// enforcing. Once reached the container stays in learning (monitor only)
	// rather than being flipped back and forth forever. Zero or negative means
	// unlimited.
	MaxAttempts int
}

// DefaultRollbackConfig returns the rollback settings the node agent runs with.
// They are deliberately conservative: react inside the first few minutes, when
// a bad baseline shows up, and give up after a few attempts instead of flapping.
func DefaultRollbackConfig() RollbackConfig {
	return RollbackConfig{
		ObservationWindow: 5 * time.Minute,
		DenialThreshold:   10,
		Cooldown:          10 * time.Minute,
		MaxAttempts:       3,
	}
}

// ContainerBaseline records the per-container runtime health of a pod at the
// instant it transitioned to enforcing. Distress is judged relative to this, so
// a pod that was already crash-looping before Pahlevan touched it does not get
// blamed on enforcement.
type ContainerBaseline struct {
	// Restarts is the restart count per container name at the transition.
	Restarts map[string]int32
	// Ready is the readiness per container name at the transition.
	Ready map[string]bool
}

// CaptureBaseline snapshots a pod's per-container restart counts and readiness.
// A nil pod yields a zero baseline, which EvaluatePodDistress treats as
// "nothing known", so an unreadable pod never triggers a rollback on its own.
func CaptureBaseline(pod *corev1.Pod) ContainerBaseline {
	b := ContainerBaseline{}
	if pod == nil {
		return b
	}
	b.Restarts = make(map[string]int32, len(pod.Status.ContainerStatuses))
	b.Ready = make(map[string]bool, len(pod.Status.ContainerStatuses))
	for _, cs := range pod.Status.ContainerStatuses {
		b.Restarts[cs.Name] = cs.RestartCount
		b.Ready[cs.Name] = cs.Ready
	}
	return b
}

// EvaluatePodDistress reports whether a pod has deteriorated relative to the
// baseline captured when it began enforcing. It returns a human-readable reason
// suitable for a Kubernetes Event.
//
// Distress is any of:
//   - a container restarted since the transition,
//   - a container is waiting in CrashLoopBackOff,
//   - a container that was ready at the transition is no longer ready.
//
// It is a pure function so the decision is testable without a cluster.
func EvaluatePodDistress(pod *corev1.Pod, base ContainerBaseline) (string, bool) {
	if pod == nil {
		return "", false
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && w.Reason == "CrashLoopBackOff" {
			return fmt.Sprintf("container %q entered CrashLoopBackOff after enforcement began", cs.Name), true
		}
		if base.Restarts != nil {
			if was, known := base.Restarts[cs.Name]; known && cs.RestartCount > was {
				return fmt.Sprintf("container %q restarted after enforcement began (%d -> %d)", cs.Name, was, cs.RestartCount), true
			}
		}
		if base.Ready != nil {
			if wasReady, known := base.Ready[cs.Name]; known && wasReady && !cs.Ready {
				return fmt.Sprintf("container %q became not ready after enforcement began", cs.Name), true
			}
		}
	}
	return "", false
}

type cgState struct {
	cgroupID uint64
	// firstSeen is when this cgroup was first observed. It never moves, so the
	// reported profile age stays honest across rollbacks.
	firstSeen time.Time
	// learningSince is when the current learning window opened. It equals
	// firstSeen until a rollback restarts learning.
	learningSince time.Time
	phase         Phase
	ref           attribution.ContainerRef
	syscalls      map[uint64]struct{}
	files         map[string]struct{}
	dests         map[string]struct{}
	execs         map[string]struct{}
	caps          map[uint32]struct{}

	// Enforcement health tracking.
	enforcingSince     time.Time
	denials            int
	attempts           int
	rollbacks          int
	lastRollback       time.Time
	lastRollbackReason string
	// holdUntil is the earliest time a new enforce attempt may be made. Set on
	// rollback to impose the cooldown.
	holdUntil time.Time
	// baseline is the pod's runtime health at the last enforce transition.
	baseline ContainerBaseline
	// capLogged keeps the attempt-cap message to one line per container.
	capLogged bool
}

// noteDenial records an in-kernel denial. Only denials observed while the
// container is enforcing are meaningful: they are the ones caused by the
// baseline Pahlevan just installed. Callers must hold c.mu.
func (st *cgState) noteDenial() {
	if st.phase == PhaseEnforcing {
		st.denials++
	}
}

// Controller tracks per-cgroup learning state and flips cgroups to enforcement
// when their learning window closes. It implements ebpf.EventHandler.
type Controller struct {
	log      logr.Logger
	enforcer Enforcer
	resolver *attribution.Resolver
	policies PolicyResolver
	now      func() time.Time

	// SeccompDir, when set, is where per-workload seccomp profiles generated from
	// the learned syscall set are written on the enforce transition (for use as a
	// pod localhostProfile). Empty disables seccomp profile emission.
	SeccompDir string

	// Client, when set, is used to persist a ContainerProfile CR per learned
	// container (the inspectable baseline). Node labels the profile's origin.
	Client client.Client
	Node   string

	// Rollback tunes health-driven rollback out of enforcement. NewController
	// installs DefaultRollbackConfig; set ObservationWindow to zero to disable.
	Rollback RollbackConfig

	// Metrics, when set, receives the policy-plane series: transitions,
	// rollbacks, denials, learning progress and the learned attack surface.
	// Nil disables recording entirely, which is what the unit tests use.
	Metrics *metrics.Manager

	mu    sync.Mutex
	state map[uint64]*cgState
}

// NewController builds an adaptive controller.
func NewController(log logr.Logger, enforcer Enforcer, resolver *attribution.Resolver, policies PolicyResolver) *Controller {
	return &Controller{
		log:      log,
		enforcer: enforcer,
		resolver: resolver,
		policies: policies,
		now:      time.Now,
		state:    make(map[uint64]*cgState),
		Rollback: DefaultRollbackConfig(),
	}
}

func (c *Controller) track(cgroupID uint64) *cgState {
	st, ok := c.state[cgroupID]
	if !ok {
		ref := attribution.ContainerRef{}
		if c.resolver != nil {
			if r, found := c.resolver.Lookup(cgroupID); found {
				ref = r
			}
		}
		now := c.now()
		st = &cgState{
			cgroupID:      cgroupID,
			firstSeen:     now,
			learningSince: now,
			phase:         PhaseLearning,
			ref:           ref,
			syscalls:      make(map[uint64]struct{}),
			files:         make(map[string]struct{}),
			dests:         make(map[string]struct{}),
			execs:         make(map[string]struct{}),
			caps:          make(map[uint32]struct{}),
		}
		c.state[cgroupID] = st
	}
	return st
}

// HandleSyscallEvent records an observed syscall for the cgroup's learning set.
func (c *Controller) HandleSyscallEvent(e *ebpf.SyscallEvent) error {
	if e.CgroupID == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(e.CgroupID)
	if st.phase == PhaseLearning {
		st.syscalls[e.SyscallNr] = struct{}{}
	}
	return nil
}

// HandleFileEvent records an observed file path for the cgroup's learning set.
func (c *Controller) HandleFileEvent(e *ebpf.FileEvent) error {
	if e.CgroupID == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(e.CgroupID)
	if e.Flags&DeniedFlag != 0 {
		c.recordDenial(st)
		return nil
	}
	if st.phase == PhaseLearning && e.Path != "" {
		st.files[e.Path] = struct{}{}
	}
	return nil
}

// HandleNetworkEvent records an observed egress destination for the learning set.
func (c *Controller) HandleNetworkEvent(e *ebpf.NetworkEvent) error {
	if e.CgroupID == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(e.CgroupID)
	if e.Direction&DeniedDirection != 0 {
		c.recordDenial(st)
		return nil
	}
	if st.phase == PhaseLearning {
		st.dests[netKey(e.DstIP, e.DstPort)] = struct{}{}
	}
	return nil
}

func netKey(ip uint32, port uint16) string {
	return fmt.Sprintf("%d:%d", ip, port)
}

// HandleProcessEvent records an observed executable for the cgroup's learning set.
func (c *Controller) HandleProcessEvent(e *ebpf.ProcessEvent) error {
	if e.CgroupID == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(e.CgroupID)
	if e.Flags&DeniedFlag != 0 {
		c.recordDenial(st)
		return nil
	}
	if st.phase == PhaseLearning && e.Filename != "" {
		st.execs[e.Filename] = struct{}{}
	}
	return nil
}

// HandleCapabilityEvent records an observed capability for the learning set.
func (c *Controller) HandleCapabilityEvent(e *ebpf.CapabilityEvent) error {
	if e.CgroupID == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(e.CgroupID)
	if e.Flags&DeniedFlag != 0 {
		c.recordDenial(st)
		return nil
	}
	if st.phase == PhaseLearning {
		st.caps[e.Capability] = struct{}{}
	}
	return nil
}

// metricLabels builds the label set for a tracked container. PodMeta is
// consulted only when a recorder is actually attached, so the nil-Metrics path
// stays free. Callers must hold c.mu.
func (c *Controller) metricLabels(st *cgState) metrics.MetricLabels {
	l := metrics.MetricLabels{
		ContainerID: st.ref.ContainerID,
		Phase:       string(st.phase),
	}
	if ns, name, ok := c.policies.PodMeta(st.ref.PodUID); ok {
		l.Namespace, l.PodName = ns, name
	}
	return l
}

// recordDenial notes an in-kernel denial on both the container state and the
// policy-plane metrics. Callers must hold c.mu.
func (c *Controller) recordDenial(st *cgState) {
	st.noteDenial()
	if c.Metrics != nil && st.phase == PhaseEnforcing {
		c.Metrics.RecordPolicyViolation(c.metricLabels(st))
	}
}

// Profile is a snapshot of what a container learned, plus how its enforcement
// attempts have gone.
type Profile struct {
	CgroupID  uint64
	Ref       attribution.ContainerRef
	Phase     Phase
	Syscalls  []uint64
	Files     []string
	FirstSeen time.Time

	// EnforcingSince is the time of the current enforce transition (zero while
	// learning).
	EnforcingSince time.Time
	// Denials is the number of in-kernel denials seen since that transition.
	Denials int
	// Attempts is how many times this container has been flipped to enforcing.
	Attempts int
	// Rollbacks is how many of those attempts were rolled back.
	Rollbacks int
	// LastRollback / LastRollbackReason describe the most recent rollback.
	LastRollback       time.Time
	LastRollbackReason string
}

// Snapshot returns the current per-cgroup learned profiles (for status/CRD sync).
func (c *Controller) Snapshot() []Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Profile, 0, len(c.state))
	for id, st := range c.state {
		p := Profile{
			CgroupID:           id,
			Ref:                st.ref,
			Phase:              st.phase,
			FirstSeen:          st.firstSeen,
			EnforcingSince:     st.enforcingSince,
			Denials:            st.denials,
			Attempts:           st.attempts,
			Rollbacks:          st.rollbacks,
			LastRollback:       st.lastRollback,
			LastRollbackReason: st.lastRollbackReason,
		}
		for s := range st.syscalls {
			p.Syscalls = append(p.Syscalls, s)
		}
		for f := range st.files {
			p.Files = append(p.Files, f)
		}
		out = append(out, p)
	}
	return out
}

// Reconcile evaluates every tracked cgroup once. Containers still learning whose
// window has elapsed and whose policy is blocking are flipped to enforcing;
// containers already enforcing are checked for distress and rolled back if the
// baseline turns out to be wrong. Exposed for tests; Run calls it on a ticker.
func (c *Controller) Reconcile() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, st := range c.state {
		switch st.phase {
		case PhaseLearning:
			c.maybeEnforce(id, st)
		case PhaseEnforcing:
			c.maybeRollback(id, st)
		}
	}
	// Persist/refresh the inspectable ContainerProfile for every tracked container.
	for _, st := range c.state {
		c.persistProfile(st)
	}
	c.recordFleetMetrics()
}

// recordEnforceTransition publishes what a container learned at the moment the
// kernel starts enforcing it. This is the only point where the learned set is
// final, so it is where the attack-surface gauges are meaningful. Callers must
// hold c.mu.
func (c *Controller) recordEnforceTransition(st *cgState, learned time.Duration) {
	if c.Metrics == nil {
		return
	}
	labels := c.metricLabels(st)
	c.Metrics.RecordEnforcementAction(labels, "enforce")
	c.Metrics.RecordContainerLearningDuration(labels, learned)

	// The privilege reduction is the point of the tool: the fraction of the
	// syscall table the workload will no longer be permitted to call. Reported
	// against the generated seccomp allow-list, which is the enforced artifact.
	if total := seccomp.KnownSyscallCount(); total > 0 {
		allowed := float64(len(st.syscalls))
		c.Metrics.UpdatePrivilegeReductionRatio(labels, 1-allowed/float64(total))
	}
	c.Metrics.UpdateExposedSyscalls(labels, "learned", float64(len(st.syscalls)))
	c.Metrics.UpdateWritablePaths(labels, "learned", float64(len(st.files)))
	c.Metrics.UpdateCapabilities(labels, "learned", float64(len(st.caps)))
}

// recordFleetMetrics publishes the per-node aggregates. Called once per
// reconcile rather than per event, so the cost is bounded by the tick.
// Callers must hold c.mu.
func (c *Controller) recordFleetMetrics() {
	if c.Metrics == nil {
		return
	}
	var learning, enforcing float64
	for _, st := range c.state {
		switch st.phase {
		case PhaseLearning:
			learning++
		case PhaseEnforcing:
			enforcing++
		}
	}
	c.Metrics.UpdateContainerCounts(float64(len(c.state)), learning, enforcing)

	// Learning progress is the share of tracked containers that have made it
	// all the way to enforcing. A fleet stuck at 0 means learning windows are
	// not elapsing or no policy is blocking, which is worth alerting on.
	progress := float64(0)
	if len(c.state) > 0 {
		progress = enforcing / float64(len(c.state))
	}
	c.Metrics.UpdateLearningProgress(metrics.MetricLabels{}, progress)
}

// maybeEnforce flips a learning container to enforcing when its window has
// elapsed, its policy is blocking, it is not in a post-rollback cooldown, and it
// has attempts left. Callers must hold c.mu.
func (c *Controller) maybeEnforce(id uint64, st *cgState) {
	window, blocking, ok := c.policies.Resolve(id, st.ref)
	if !ok || !blocking {
		return
	}
	now := c.now()
	if now.Sub(st.learningSince) < window {
		return
	}
	if now.Before(st.holdUntil) {
		// Post-rollback cooldown: keep learning, do not flap back to enforcing.
		return
	}
	if c.Rollback.MaxAttempts > 0 && st.attempts >= c.Rollback.MaxAttempts {
		if !st.capLogged {
			st.capLogged = true
			c.log.Info("enforcement attempt cap reached; container stays in learning (monitor only)",
				"cgroup", id, "pod", st.ref.PodUID, "attempts", st.attempts,
				"maxAttempts", c.Rollback.MaxAttempts, "lastRollbackReason", st.lastRollbackReason)
		}
		return
	}
	if err := c.enforcer.SetFileEnforcement(id, true); err != nil {
		c.log.Error(err, "failed to enable file enforcement", "cgroup", id)
		return
	}
	if err := c.enforcer.SetNetworkEnforcement(id, true); err != nil {
		// File enforcement is on; network is best-effort (needs bpf LSM too).
		c.log.V(1).Info("network enforcement unavailable", "cgroup", id, "error", err.Error())
	}
	if err := c.enforcer.SetExecEnforcement(id, true); err != nil {
		c.log.V(1).Info("exec enforcement unavailable", "cgroup", id, "error", err.Error())
	}
	if err := c.enforcer.SetCapabilityEnforcement(id, true); err != nil {
		c.log.V(1).Info("capability enforcement unavailable", "cgroup", id, "error", err.Error())
	}
	st.phase = PhaseEnforcing
	st.enforcingSince = now
	st.attempts++
	st.denials = 0
	st.baseline = CaptureBaseline(c.fetchPod(st))
	c.writeSeccompProfile(st)
	c.recordEnforceTransition(st, now.Sub(st.learningSince))
	c.log.Info("container transitioned to enforcing",
		"cgroup", id, "pod", st.ref.PodUID, "attempt", st.attempts,
		"syscalls", len(st.syscalls), "files", len(st.files), "dests", len(st.dests), "execs", len(st.execs), "caps", len(st.caps))
}

// maybeRollback checks a recently-enforcing container for signs that the learned
// baseline is wrong, and rolls enforcement back if so. Callers must hold c.mu.
//
// Only the ObservationWindow immediately after the transition is examined: that
// is the interval in which a breakage is attributable to enforcement. Past it
// the baseline is treated as settled, so a container that is fine for an hour
// and then legitimately gets denied is not un-enforced by an attacker's noise.
func (c *Controller) maybeRollback(id uint64, st *cgState) {
	cfg := c.Rollback
	if cfg.ObservationWindow <= 0 {
		return
	}
	elapsed := c.now().Sub(st.enforcingSince)
	if elapsed < 0 || elapsed > cfg.ObservationWindow {
		return
	}
	reason := ""
	switch {
	case cfg.DenialThreshold > 0 && st.denials >= cfg.DenialThreshold:
		reason = fmt.Sprintf("%d in-kernel denials within %s of enforcement (threshold %d)",
			st.denials, elapsed.Round(time.Second), cfg.DenialThreshold)
	default:
		if r, distressed := EvaluatePodDistress(c.fetchPod(st), st.baseline); distressed {
			reason = r
		}
	}
	if reason == "" {
		return
	}
	c.rollback(id, st, reason)
}

// rollback returns a container to learning: it clears every enforcement bit in
// the eBPF maps, restarts the learning window behind a cooldown, and records why
// on both the log and a Kubernetes Event. Callers must hold c.mu.
func (c *Controller) rollback(id uint64, st *cgState, reason string) {
	// Every setter is attempted even if an earlier one fails: leaving a
	// container half-enforcing is strictly worse than a noisy log.
	if err := c.enforcer.SetFileEnforcement(id, false); err != nil {
		c.log.Error(err, "failed to disable file enforcement during rollback", "cgroup", id)
	}
	if err := c.enforcer.SetNetworkEnforcement(id, false); err != nil {
		c.log.Error(err, "failed to disable network enforcement during rollback", "cgroup", id)
	}
	if err := c.enforcer.SetExecEnforcement(id, false); err != nil {
		c.log.Error(err, "failed to disable exec enforcement during rollback", "cgroup", id)
	}
	if err := c.enforcer.SetCapabilityEnforcement(id, false); err != nil {
		c.log.Error(err, "failed to disable capability enforcement during rollback", "cgroup", id)
	}

	now := c.now()
	st.phase = PhaseLearning
	st.rollbacks++
	st.lastRollback = now
	st.lastRollbackReason = reason
	st.denials = 0
	st.enforcingSince = time.Time{}
	st.baseline = ContainerBaseline{}
	// Restart the learning window and hold off the next attempt. The cooldown
	// grows with each rollback so a container that keeps failing backs off
	// instead of flapping. firstSeen deliberately stays put.
	st.learningSince = now
	if c.Rollback.Cooldown > 0 {
		st.holdUntil = now.Add(time.Duration(st.rollbacks) * c.Rollback.Cooldown)
	}

	if c.Metrics != nil {
		labels := c.metricLabels(st)
		c.Metrics.RecordRollbackAction(labels)
		// A rollback IS the self-healing action; they are counted separately
		// because the second is the headline number and the first is the
		// mechanism, and a future healing action may not be a rollback.
		c.Metrics.RecordSelfHealingAction(labels)
	}

	c.log.Info("rolled back enforcement to learning",
		"cgroup", id, "pod", st.ref.PodUID, "reason", reason,
		"rollbacks", st.rollbacks, "attempts", st.attempts, "holdUntil", st.holdUntil)
	c.emitRollbackEvent(st, reason)
}

// fetchPod reads the pod backing a tracked cgroup. Returns nil when there is no
// client, no resolvable pod, or the read fails: callers must treat nil as
// "no health signal", never as "unhealthy". Callers must hold c.mu.
func (c *Controller) fetchPod(st *cgState) *corev1.Pod {
	if c.Client == nil || st.ref.PodUID == "" {
		return nil
	}
	ns, name, ok := c.policies.PodMeta(st.ref.PodUID)
	if !ok || ns == "" || name == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pod := &corev1.Pod{}
	if err := c.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, pod); err != nil {
		c.log.V(1).Info("failed to read pod for enforcement health check", "pod", name, "error", err.Error())
		return nil
	}
	return pod
}

// emitRollbackEvent records a Warning Event on the pod so the rollback is
// visible to whoever is looking at the workload, not just in agent logs.
// The agent's own client is used (it already has events create/patch), so this
// works without wiring a recorder through the binary. Callers must hold c.mu.
func (c *Controller) emitRollbackEvent(st *cgState, reason string) {
	if c.Client == nil || st.ref.PodUID == "" {
		return
	}
	ns, name, ok := c.policies.PodMeta(st.ref.PodUID)
	if !ok || ns == "" || name == "" {
		return
	}
	now := metav1.NewTime(c.now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.pahlevan-rollback.%x", name, c.now().UnixNano()),
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "pahlevan",
			},
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  ns,
			Name:       name,
			UID:        types.UID(st.ref.PodUID),
		},
		Reason: "EnforcementRolledBack",
		Message: fmt.Sprintf(
			"Pahlevan returned this container to learning: %s. The learned baseline was incomplete; enforcement is off and relearning has started.",
			reason),
		Type:                corev1.EventTypeWarning,
		Source:              corev1.EventSource{Component: "pahlevan-agent", Host: c.Node},
		FirstTimestamp:      now,
		LastTimestamp:       now,
		EventTime:           metav1.MicroTime{Time: c.now()},
		Count:               1,
		ReportingController: "pahlevan-agent",
		ReportingInstance:   c.Node,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Client.Create(ctx, ev); err != nil && !apierrors.IsAlreadyExists(err) {
		c.log.V(1).Info("failed to emit rollback event", "pod", name, "error", err.Error())
	}
}

// writeSeccompProfile generates a seccomp profile from the container's learned
// syscall set and writes it to SeccompDir (best-effort). The file can then be
// referenced as a pod localhostProfile so future pods start already confined.
func (c *Controller) writeSeccompProfile(st *cgState) {
	if c.SeccompDir == "" || len(st.syscalls) == 0 {
		return
	}
	syscalls := make([]uint64, 0, len(st.syscalls))
	for s := range st.syscalls {
		syscalls = append(syscalls, s)
	}
	prof, skipped := seccomp.Generate(syscalls)
	data, err := prof.JSON()
	if err != nil {
		c.log.Error(err, "failed to render seccomp profile")
		return
	}
	name := st.ref.PodUID
	if name == "" {
		name = fmt.Sprintf("cgroup-%d", st.firstSeen.UnixNano())
	}
	if err := os.MkdirAll(c.SeccompDir, 0o755); err != nil {
		c.log.Error(err, "failed to create seccomp dir", "dir", c.SeccompDir)
		return
	}
	path := filepath.Join(c.SeccompDir, "pahlevan-"+name+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		c.log.Error(err, "failed to write seccomp profile", "path", path)
		return
	}
	c.log.Info("wrote learned seccomp profile", "path", path, "allowed", len(prof.Syscalls[0].Names), "skippedUnknown", skipped)
}

// persistProfile upserts a ContainerProfile CR reflecting the container's learned
// baseline and phase. Best-effort: skips when no client is set or the pod isn't
// resolved yet. Uses server-side apply so it creates or converges.
func (c *Controller) persistProfile(st *cgState) {
	if c.Client == nil || st.ref.PodUID == "" {
		return
	}
	ns, podName, ok := c.policies.PodMeta(st.ref.PodUID)
	if !ok || ns == "" {
		return
	}
	syscalls := make([]int64, 0, len(st.syscalls))
	for s := range st.syscalls {
		syscalls = append(syscalls, int64(s))
	}
	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	files := make([]string, 0, len(st.files))
	for f := range st.files {
		files = append(files, f)
	}
	sort.Strings(files)
	dests := make([]string, 0, len(st.dests))
	for d := range st.dests {
		dests = append(dests, d)
	}
	sort.Strings(dests)
	execs := make([]string, 0, len(st.execs))
	for e := range st.execs {
		execs = append(execs, e)
	}
	sort.Strings(execs)

	now := metav1.Now()
	cp := &policyv1alpha1.ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policyv1alpha1.GroupVersion.String(),
			Kind:       "ContainerProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileName(st.ref),
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "pahlevan",
				"pahlevan.io/pod-uid":       st.ref.PodUID,
			},
		},
		Spec: policyv1alpha1.ContainerProfileSpec{
			PodName:     podName,
			Namespace:   ns,
			ContainerID: st.ref.ContainerID,
			CgroupID:    int64(st.cgroupID),
			Node:        c.Node,
		},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:                      string(st.phase),
			LearnedSyscalls:            syscalls,
			LearnedFiles:               files,
			LearnedNetworkDestinations: dests,
			LearnedExecutables:         execs,
			SyscallCount:               int32(len(syscalls)),
			FileCount:                  int32(len(files)),
			NetworkCount:               int32(len(dests)),
			FirstSeen:                  &metav1.Time{Time: st.firstSeen},
			LastUpdated:                &now,
			EnforcementAttempts:        int32(st.attempts),
			RollbackCount:              int32(st.rollbacks),
			LastRollbackReason:         st.lastRollbackReason,
			DenialCount:                int32(st.denials),
		},
	}
	if st.phase == PhaseEnforcing && !st.enforcingSince.IsZero() {
		cp.Status.EnforcingSince = &metav1.Time{Time: st.enforcingSince}
	}
	if !st.lastRollback.IsZero() {
		cp.Status.LastRollbackTime = &metav1.Time{Time: st.lastRollback}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Client.Patch(ctx, cp, client.Apply,
		client.FieldOwner("pahlevan-agent"), client.ForceOwnership); err != nil {
		c.log.V(1).Info("failed to persist ContainerProfile", "pod", podName, "error", err.Error())
	}
}

func profileName(ref attribution.ContainerRef) string {
	// Stable, DNS-safe name per pod (+container when known).
	name := "pod-" + ref.PodUID
	if len(ref.ContainerID) >= 12 {
		name += "-" + ref.ContainerID[:12]
	}
	return name
}

// Run drives Reconcile on an interval until ctx is cancelled.
func (c *Controller) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Reconcile()
			if c.resolver != nil {
				_ = c.resolver.Refresh()
			}
		}
	}
}
