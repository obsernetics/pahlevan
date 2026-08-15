package adaptive

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// benchController builds a controller pre-loaded with n learning cgroups, each
// having learned a handful of syscalls/files, and a blocking policy whose window
// has already elapsed so every Reconcile evaluates the enforce transition.
func benchController(n int, elapsed bool) *Controller {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	if elapsed {
		c.now = func() time.Time { return base.Add(time.Hour) }
	} else {
		c.now = func() time.Time { return base }
	}
	for i := 0; i < n; i++ {
		id := uint64(i + 1)
		_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: id, SyscallNr: uint64(i % 300)})
		_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: id, SyscallNr: 1})
		_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: id, Path: "/etc/hostname"})
		_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: id, DstIP: uint32(i), DstPort: 443})
		// Reset the learning clock so the window is (or isn't) elapsed
		// deterministically.
		c.mu.Lock()
		c.state[id].firstSeen = base
		c.state[id].learningSince = base
		c.mu.Unlock()
	}
	return c
}

func BenchmarkReconcile_LearningWindowOpen(b *testing.B) {
	c := benchController(500, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Reconcile()
	}
}

func BenchmarkReconcile_ManyCgroupsEnforcing(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Fresh controller each iteration since enforce transition is one-shot.
		c := benchController(500, true)
		b.StartTimer()
		c.Reconcile()
	}
}

func BenchmarkHandleSyscallEvent(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	ev := &ebpf.SyscallEvent{CgroupID: 1, SyscallNr: 257}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleSyscallEvent(ev)
	}
}

// enforcingBenchController returns a controller with cgroup 1 already enforcing,
// so the denial-accounting branch added to the event handlers is exercised.
func enforcingBenchController() *Controller {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	c.mu.Lock()
	c.track(1).phase = PhaseEnforcing
	c.mu.Unlock()
	return c
}

func BenchmarkHandleFileEvent_Allowed(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	ev := &ebpf.FileEvent{CgroupID: 1, Path: "/etc/hostname"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleFileEvent(ev)
	}
}

func BenchmarkHandleFileEvent_Denied(b *testing.B) {
	c := enforcingBenchController()
	ev := &ebpf.FileEvent{CgroupID: 1, Path: "/etc/shadow", Flags: DeniedFlag}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleFileEvent(ev)
	}
}

func BenchmarkHandleNetworkEvent_Denied(b *testing.B) {
	c := enforcingBenchController()
	ev := &ebpf.NetworkEvent{CgroupID: 1, DstIP: 0x08080808, DstPort: 443, Direction: DeniedDirection}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleNetworkEvent(ev)
	}
}

func BenchmarkHandleProcessEvent_Denied(b *testing.B) {
	c := enforcingBenchController()
	ev := &ebpf.ProcessEvent{CgroupID: 1, Filename: "/bin/sh", Flags: DeniedFlag}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleProcessEvent(ev)
	}
}

func BenchmarkHandleCapabilityEvent_Denied(b *testing.B) {
	c := enforcingBenchController()
	ev := &ebpf.CapabilityEvent{CgroupID: 1, Capability: 21, Flags: DeniedFlag}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleCapabilityEvent(ev)
	}
}

// BenchmarkReconcile_ManyCgroupsEnforcing_HealthCheck measures the added
// per-reconcile rollback evaluation for containers that are enforcing and still
// inside their observation window. There is no client here, so it measures the
// pure decision path (the pod read is a cached Get in the agent).
func BenchmarkReconcile_EnforcingHealthCheck(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	c.mu.Lock()
	for i := 0; i < 500; i++ {
		st := c.track(uint64(i + 1))
		st.phase = PhaseEnforcing
		st.enforcingSince = base
	}
	c.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Reconcile()
	}
}

// BenchmarkRollback measures the rollback itself: four enforcement-map writes
// plus the state reset. No client, so no API traffic is included.
func BenchmarkRollback(b *testing.B) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePolicies{window: time.Minute, blocking: true, ok: true})
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.track(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.phase = PhaseEnforcing
		c.rollback(1, st, "benchmark")
	}
}
