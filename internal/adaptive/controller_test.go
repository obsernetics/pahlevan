package adaptive

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

type fakeEnforcer struct {
	enforced map[uint64]bool
}

func (f *fakeEnforcer) SetFileEnforcement(cgroupID uint64, enforce bool) error {
	if f.enforced == nil {
		f.enforced = map[uint64]bool{}
	}
	f.enforced[cgroupID] = enforce
	return nil
}

type fakePolicies struct {
	window   time.Duration
	blocking bool
	ok       bool
}

func (p fakePolicies) Resolve(uint64, attribution.ContainerRef) (time.Duration, bool, bool) {
	return p.window, p.blocking, p.ok
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
