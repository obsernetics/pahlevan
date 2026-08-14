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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
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

type cgState struct {
	cgroupID  uint64
	firstSeen time.Time
	phase     Phase
	ref       attribution.ContainerRef
	syscalls  map[uint64]struct{}
	files     map[string]struct{}
	dests     map[string]struct{}
	execs     map[string]struct{}
	caps      map[uint32]struct{}
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
		st = &cgState{
			cgroupID:  cgroupID,
			firstSeen: c.now(),
			phase:     PhaseLearning,
			ref:       ref,
			syscalls:  make(map[uint64]struct{}),
			files:     make(map[string]struct{}),
			dests:     make(map[string]struct{}),
			execs:     make(map[string]struct{}),
			caps:      make(map[uint32]struct{}),
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
	if st.phase == PhaseLearning {
		st.caps[e.Capability] = struct{}{}
	}
	return nil
}

// Profile is a snapshot of what a container learned.
type Profile struct {
	CgroupID  uint64
	Ref       attribution.ContainerRef
	Phase     Phase
	Syscalls  []uint64
	Files     []string
	FirstSeen time.Time
}

// Snapshot returns the current per-cgroup learned profiles (for status/CRD sync).
func (c *Controller) Snapshot() []Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Profile, 0, len(c.state))
	for id, st := range c.state {
		p := Profile{CgroupID: id, Ref: st.ref, Phase: st.phase, FirstSeen: st.firstSeen}
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

// Reconcile evaluates every tracked cgroup once: any container still learning
// whose window has elapsed and whose policy is blocking is flipped to enforcing.
// Exposed for tests; Run calls it on a ticker.
func (c *Controller) Reconcile() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, st := range c.state {
		if st.phase != PhaseLearning {
			continue
		}
		window, blocking, ok := c.policies.Resolve(id, st.ref)
		if !ok || !blocking {
			continue
		}
		if c.now().Sub(st.firstSeen) < window {
			continue
		}
		if err := c.enforcer.SetFileEnforcement(id, true); err != nil {
			c.log.Error(err, "failed to enable file enforcement", "cgroup", id)
			continue
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
		c.writeSeccompProfile(st)
		c.log.Info("container transitioned to enforcing",
			"cgroup", id, "pod", st.ref.PodUID,
			"syscalls", len(st.syscalls), "files", len(st.files), "dests", len(st.dests), "execs", len(st.execs), "caps", len(st.caps))
	}
	// Persist/refresh the inspectable ContainerProfile for every tracked container.
	for _, st := range c.state {
		c.persistProfile(st)
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
			CgroupID:    st.cgroupID,
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
		},
	}
	if st.phase == PhaseEnforcing {
		cp.Status.EnforcingSince = &now
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
