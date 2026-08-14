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
		// Reset firstSeen so the window is (or isn't) elapsed deterministically.
		c.mu.Lock()
		c.state[id].firstSeen = base
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
