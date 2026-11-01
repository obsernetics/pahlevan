package export

import (
	"testing"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// exactDepthAncestry returns ebpf.AncestryDepth ancestors so the handler
// treats the event as possibly truncated and attempts to extend it.
func exactDepthAncestry(oldestPID uint32, oldestComm string) []ebpf.Ancestor {
	a := make([]ebpf.Ancestor, ebpf.AncestryDepth)
	for i := range a {
		a[i] = ebpf.Ancestor{PID: 900 + uint32(i), Comm: "mid"}
	}
	a[len(a)-1] = ebpf.Ancestor{PID: oldestPID, Comm: oldestComm}
	return a
}

func TestExtendAncestryGoesPastCapturedDepth(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{})

	// Record the chain older than what any single event will carry:
	// root(1) -> grandparent(10) -> oldestCaptured(20).
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 1, Comm: "root", Filename: "/sbin/init",
	}); err != nil {
		t.Fatalf("seed root: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 10, PPID: 1, Comm: "grandparent", ParentComm: "root",
		Filename: "/usr/sbin/grandparent",
	}); err != nil {
		t.Fatalf("seed grandparent: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 20, PPID: 10, Comm: "oldestCaptured", ParentComm: "grandparent",
		Filename: "/usr/bin/oldestCaptured",
	}); err != nil {
		t.Fatalf("seed oldestCaptured: %v", err)
	}

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 999, PPID: 900, Comm: "curl", Filename: "/usr/bin/curl",
		Ancestry: exactDepthAncestry(20, "oldestCaptured"),
	}); err != nil {
		t.Fatalf("leaf exec: %v", err)
	}

	got := sink.all()
	leaf := got[len(got)-1]
	if leaf.Exec == nil {
		t.Fatal("leaf event has no Exec")
	}
	if len(leaf.Exec.Ancestry) != ebpf.AncestryDepth+2 {
		t.Fatalf("Ancestry length = %d, want %d (captured + 2 extended)",
			len(leaf.Exec.Ancestry), ebpf.AncestryDepth+2)
	}
	extended := leaf.Exec.Ancestry[ebpf.AncestryDepth:]
	want := []AncestorInfo{{PID: 10, Comm: "grandparent"}, {PID: 1, Comm: "root"}}
	if extended[0] != want[0] || extended[1] != want[1] {
		t.Fatalf("extended ancestry = %+v, want %+v", extended, want)
	}
	wantChain := "root -> grandparent -> oldestCaptured -> mid -> mid -> mid -> curl"
	if leaf.Exec.AncestryChain != wantChain {
		t.Fatalf("AncestryChain = %q, want %q", leaf.Exec.AncestryChain, wantChain)
	}
}

func TestExtendAncestryStopsBeforeCapturedDepth(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{})

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 1, Comm: "root", Filename: "/sbin/init",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Only two ancestors captured: shorter than ebpf.AncestryDepth, so the
	// handler must not attempt to extend it even though pid 1 is recorded.
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 50, PPID: 5, Comm: "sh", Filename: "/bin/sh",
		Ancestry: []ebpf.Ancestor{{PID: 5, Comm: "mid"}, {PID: 1, Comm: "root"}},
	}); err != nil {
		t.Fatalf("leaf exec: %v", err)
	}

	got := sink.all()
	leaf := got[len(got)-1]
	if len(leaf.Exec.Ancestry) != 2 {
		t.Fatalf("Ancestry length = %d, want 2 (unextended)", len(leaf.Exec.Ancestry))
	}
}

func TestExtendAncestryDisabledBySize(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{AncestryCacheSize: -1})

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 20, PPID: 10, Comm: "oldestCaptured", ParentComm: "grandparent",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 999, PPID: 900, Comm: "curl", Filename: "/usr/bin/curl",
		Ancestry: exactDepthAncestry(20, "oldestCaptured"),
	}); err != nil {
		t.Fatalf("leaf exec: %v", err)
	}

	got := sink.all()
	leaf := got[len(got)-1]
	if len(leaf.Exec.Ancestry) != ebpf.AncestryDepth {
		t.Fatalf("Ancestry length = %d, want %d with the cache disabled",
			len(leaf.Exec.Ancestry), ebpf.AncestryDepth)
	}
}

func TestExtendAncestryPIDReuseStopsTheWalk(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{})

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 20, PPID: 10, Comm: "oldestCaptured", ParentComm: "grandparent",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// pid 10 execs again as something unrelated before the leaf event
	// arrives; the cached link from pid 20 must not be trusted past pid 10.
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 10, PPID: 1, Comm: "unrelated", ParentComm: "root",
	}); err != nil {
		t.Fatalf("reuse: %v", err)
	}

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 999, PPID: 900, Comm: "curl", Filename: "/usr/bin/curl",
		Ancestry: exactDepthAncestry(20, "oldestCaptured"),
	}); err != nil {
		t.Fatalf("leaf exec: %v", err)
	}

	got := sink.all()
	leaf := got[len(got)-1]
	if len(leaf.Exec.Ancestry) != ebpf.AncestryDepth+1 {
		t.Fatalf("Ancestry length = %d, want %d (one trustworthy extra hop)",
			len(leaf.Exec.Ancestry), ebpf.AncestryDepth+1)
	}
	extra := leaf.Exec.Ancestry[ebpf.AncestryDepth]
	if extra.PID != 10 || extra.Comm != "grandparent" {
		t.Fatalf("extra ancestor = %+v, want {10 grandparent} (the identity pid 20 itself recorded)", extra)
	}
}

func TestExtendAncestryNoExecDoesNothing(t *testing.T) {
	h := newTestHandler(&captureSink{}, HandlerOptions{})
	// Must not panic on an event carrying no Exec block.
	h.extendAncestry(&Event{}, &ebpf.ProcessEvent{CgroupID: 1, PID: 1, Comm: "init"})
}

// The post-exploitation signal in postex.go walks an event's ancestry
// looking for a request-serving process. With the server five hops back -
// one past what a single exec event ever captures - the signal only fires
// once the lineage cache has extended the chain far enough to reach it.
func TestExtendAncestryFeedsThePostExploitationSignal(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{})

	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 1, Comm: "nginx", Filename: "/usr/sbin/nginx",
	}); err != nil {
		t.Fatalf("seed nginx: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 20, PPID: 1, Comm: "oldestCaptured", ParentComm: "nginx",
	}); err != nil {
		t.Fatalf("seed oldestCaptured: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{
		CgroupID: 7, PID: 999, PPID: 900, Comm: "sh", Filename: "/bin/sh",
		Ancestry: exactDepthAncestry(20, "oldestCaptured"),
	}); err != nil {
		t.Fatalf("leaf exec: %v", err)
	}

	got := sink.all()
	leaf := got[len(got)-1]
	if !leaf.HasSignal(SignalServerSpawnedShell) {
		t.Fatalf("signals = %v, want %q once nginx is reachable through the extended ancestry",
			leaf.Signals, SignalServerSpawnedShell)
	}
}
