package adaptive

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// allowRecorder gives the enforcer fakes the allow-set surface and records
// what was seeded, so tests can assert the operator's overrides reached the
// kernel rather than just that enforcement was switched on.
type allowRecorder struct {
	files map[string]bool
	execs map[string]bool
	caps  map[uint32]bool
	dests map[string]bool
	err   error
}

func (a *allowRecorder) AllowFilePath(_ uint64, path string, allowed bool) error {
	if a.files == nil {
		a.files = map[string]bool{}
	}
	a.files[path] = allowed
	return a.err
}

func (a *allowRecorder) AllowExecPath(_ uint64, path string, allowed bool) error {
	if a.execs == nil {
		a.execs = map[string]bool{}
	}
	a.execs[path] = allowed
	return a.err
}

func (a *allowRecorder) AllowCapability(_ uint64, capability uint32, allowed bool) error {
	if a.caps == nil {
		a.caps = map[uint32]bool{}
	}
	a.caps[capability] = allowed
	return a.err
}

func (a *allowRecorder) AllowNetworkDestination(_ uint64, ip net.IP, port uint16, allowed bool) error {
	if a.dests == nil {
		a.dests = map[string]bool{}
	}
	a.dests[net.JoinHostPort(ip.String(), fmt.Sprint(port))] = allowed
	return a.err
}

type fakeEnforcer struct {
	allowRecorder
	enforced     map[uint64]bool
	netEnforced  map[uint64]bool
	execEnforced map[uint64]bool
	capEnforced  map[uint64]bool
}

func (f *fakeEnforcer) SetFileEnforcement(cgroupID uint64, enforce bool) error {
	if f.enforced == nil {
		f.enforced = map[uint64]bool{}
	}
	f.enforced[cgroupID] = enforce
	return nil
}

func (f *fakeEnforcer) SetNetworkEnforcement(cgroupID uint64, enforce bool) error {
	if f.netEnforced == nil {
		f.netEnforced = map[uint64]bool{}
	}
	f.netEnforced[cgroupID] = enforce
	return nil
}

func (f *fakeEnforcer) SetExecEnforcement(cgroupID uint64, enforce bool) error {
	if f.execEnforced == nil {
		f.execEnforced = map[uint64]bool{}
	}
	f.execEnforced[cgroupID] = enforce
	return nil
}

func (f *fakeEnforcer) SetCapabilityEnforcement(cgroupID uint64, enforce bool) error {
	if f.capEnforced == nil {
		f.capEnforced = map[uint64]bool{}
	}
	f.capEnforced[cgroupID] = enforce
	return nil
}

// failingEnforcer fails every call and counts the attempts, so tests can assert
// that a rollback still tries every setter and still completes.
type failingEnforcer struct {
	allowRecorder
	file, net, exec, capa int
}

func (f *failingEnforcer) SetFileEnforcement(uint64, bool) error {
	f.file++
	return errEnforce
}

func (f *failingEnforcer) SetNetworkEnforcement(uint64, bool) error {
	f.net++
	return errEnforce
}

func (f *failingEnforcer) SetExecEnforcement(uint64, bool) error {
	f.exec++
	return errEnforce
}

func (f *failingEnforcer) SetCapabilityEnforcement(uint64, bool) error {
	f.capa++
	return errEnforce
}

var errEnforce = errors.New("enforcement map update failed")

// partialEnforcer models a kernel without BPF LSM: the file (fentry-based) path
// works, the LSM-backed ones do not.
type partialEnforcer struct {
	allowRecorder
	net, exec, capa int
}

func (f *partialEnforcer) SetFileEnforcement(uint64, bool) error { return nil }

func (f *partialEnforcer) SetNetworkEnforcement(uint64, bool) error {
	f.net++
	return errEnforce
}

func (f *partialEnforcer) SetExecEnforcement(uint64, bool) error {
	f.exec++
	return errEnforce
}

func (f *partialEnforcer) SetCapabilityEnforcement(uint64, bool) error {
	f.capa++
	return errEnforce
}

type fakePolicies struct {
	window      time.Duration
	gracePeriod time.Duration
	blocking    bool
	ok          bool
	overrides   Overrides
	// selfHealing mirrors spec.selfHealing. It defaults to enabled because
	// that is what most tests here are exercising; the disabled case has its
	// own tests in rollback_test.go.
	selfHealingDisabled bool
	rollbackThreshold   int
	rollbackWindow      time.Duration
}

func (p fakePolicies) Resolve(uint64, attribution.ContainerRef) (Decision, bool) {
	mode := ModeMonitoring
	if p.blocking {
		mode = ModeBlocking
	}
	return Decision{
		PolicyName:  "test",
		Mode:        mode,
		Window:      p.window,
		GracePeriod: p.gracePeriod,
		Overrides:   p.overrides,
		SelfHealing: SelfHealingDecision{
			Enabled:   !p.selfHealingDisabled,
			Threshold: p.rollbackThreshold,
			Window:    p.rollbackWindow,
		},
	}, p.ok
}

func TestController_LearnThenEnforce(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{window: time.Minute, blocking: true, ok: true})

	// Control the clock.
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// Observe some behaviour for cgroup 42.
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 42, SyscallNr: 257})
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/hostname"})

	// Before the window elapses, no enforcement.
	c.Reconcile()
	if enf.enforced[42] {
		t.Fatal("enforcement enabled before learning window elapsed")
	}

	// Advance past the window.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	c.Reconcile()
	if !enf.enforced[42] {
		t.Fatal("expected enforcement to be enabled after the learning window")
	}

	// After enforcing, new observations are not added to the learning set.
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 42, Path: "/etc/shadow"})
	snap := c.Snapshot()
	if len(snap) != 1 || snap[0].Phase != PhaseEnforcing {
		t.Fatalf("expected 1 enforcing profile, got %+v", snap)
	}
	for _, f := range snap[0].Files {
		if f == "/etc/shadow" {
			t.Error("post-enforcement file must not be added to the learned set")
		}
	}
}

func TestController_NonBlockingPolicyStaysLearning(t *testing.T) {
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{window: 0, blocking: false, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base.Add(time.Hour) }
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 7, SyscallNr: 1})
	c.Reconcile()
	if enf.enforced[7] {
		t.Fatal("monitor-only (non-blocking) policy must never enforce")
	}
}

func TestController_WritesSeccompProfileOnEnforce(t *testing.T) {
	dir := t.TempDir()
	enf := &fakeEnforcer{}
	c := NewController(logr.Discard(), enf, nil, fakePolicies{window: 0, blocking: true, ok: true})
	c.SeccompDir = dir
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// Learn read(0)/write(1)/openat(257) for a cgroup with a pod UID.
	c.mu.Lock()
	st := c.track(99)
	st.ref.PodUID = "pod-abc"
	c.mu.Unlock()
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 99, SyscallNr: 0})
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 99, SyscallNr: 1})
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 99, SyscallNr: 257})

	c.now = func() time.Time { return base.Add(time.Minute) }
	c.Reconcile()

	path := dir + "/pahlevan-pod-abc.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected seccomp profile at %s: %v", path, err)
	}
	for _, want := range []string{"SCMP_ACT_ERRNO", "openat", "SCMP_ACT_ALLOW"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func (p fakePolicies) PodMeta(string) (string, string, bool) { return "", "", false }

// switchablePolicies lets a test change the governing mode between reconciles,
// which is how an operator editing a PahlevanPolicy actually behaves.
type switchablePolicies struct {
	window time.Duration
	mode   Mode
	ok     bool
}

func (p *switchablePolicies) Resolve(uint64, attribution.ContainerRef) (Decision, bool) {
	return Decision{
		PolicyName:  "switchable",
		Mode:        p.mode,
		Window:      p.window,
		SelfHealing: SelfHealingDecision{Enabled: true},
	}, p.ok
}

func (p *switchablePolicies) PodMeta(string) (string, string, bool) { return "", "", false }

// orderedEnforcer records the sequence of calls so a test can assert that
// allow-set seeding happens before enforcement is switched on.
type orderedEnforcer struct {
	calls []string
}

func (o *orderedEnforcer) SetFileEnforcement(_ uint64, enforce bool) error {
	if enforce {
		o.calls = append(o.calls, "enforce:file")
	}
	return nil
}
func (o *orderedEnforcer) SetNetworkEnforcement(uint64, bool) error    { return nil }
func (o *orderedEnforcer) SetExecEnforcement(uint64, bool) error       { return nil }
func (o *orderedEnforcer) SetCapabilityEnforcement(uint64, bool) error { return nil }

func (o *orderedEnforcer) AllowFilePath(_ uint64, path string, _ bool) error {
	o.calls = append(o.calls, "seed:"+path)
	return nil
}
func (o *orderedEnforcer) AllowExecPath(uint64, string, bool) error   { return nil }
func (o *orderedEnforcer) AllowCapability(uint64, uint32, bool) error { return nil }
func (o *orderedEnforcer) AllowNetworkDestination(uint64, net.IP, uint16, bool) error {
	return nil
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

var assertAnError = errors.New("allow-set write failed")

// readOnlyProfile returns the single generated seccomp profile in dir.
func readOnlyProfile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read seccomp dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one profile, got %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return string(data)
}
