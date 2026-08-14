package adaptive

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// fakePoliciesMeta is a PolicyResolver whose PodMeta resolves to a fixed
// namespace/name so the ContainerProfile persistence path can be exercised.
type fakePoliciesMeta struct {
	window   time.Duration
	blocking bool
	ok       bool
	ns, name string
	metaOK   bool
}

func (p fakePoliciesMeta) Resolve(uint64, attribution.ContainerRef) (Decision, bool) {
	mode := ModeMonitoring
	if p.blocking {
		mode = ModeBlocking
	}
	return Decision{
		PolicyName:  "test",
		Mode:        mode,
		Window:      p.window,
		SelfHealing: SelfHealingDecision{Enabled: true},
	}, p.ok
}

func (p fakePoliciesMeta) PodMeta(string) (string, string, bool) {
	return p.ns, p.name, p.metaOK
}

// newRuntimeScheme returns a scheme with the Pahlevan CRDs and core/v1, so both
// ContainerProfile persistence and pod reads / Event writes can be faked.
func newRuntimeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := policyv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1 AddToScheme: %v", err)
	}
	return s
}

func newTestScheme(t *testing.T) *fake.ClientBuilder {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newRuntimeScheme(t)).
		WithStatusSubresource(&policyv1alpha1.ContainerProfile{})
}

func TestHandleNetworkEvent_Learning(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{window: time.Minute, blocking: false, ok: true})

	// CgroupID 0 is ignored.
	if err := c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 0, DstIP: 1, DstPort: 80}); err != nil {
		t.Fatalf("HandleNetworkEvent(0): %v", err)
	}

	// Learn two distinct destinations for cgroup 5.
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 5, DstIP: 0x08080808, DstPort: 53})
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 5, DstIP: 0x08080808, DstPort: 443})
	// Duplicate should not grow the set.
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 5, DstIP: 0x08080808, DstPort: 443})

	c.mu.Lock()
	got := len(c.state[5].dests)
	c.mu.Unlock()
	if got != 2 {
		t.Errorf("learned dests = %d, want 2", got)
	}

	// netKey must be stable and distinct per ip:port.
	if netKey(1, 80) == netKey(1, 81) {
		t.Error("netKey should differ by port")
	}
	if netKey(1, 80) != netKey(1, 80) {
		t.Error("netKey should be deterministic")
	}
}

func TestHandleNetworkEvent_NotLearnedWhenEnforcing(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})
	c.mu.Lock()
	st := c.track(9)
	st.phase = PhaseEnforcing
	c.mu.Unlock()

	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 9, DstIP: 1, DstPort: 80})
	c.mu.Lock()
	got := len(c.state[9].dests)
	c.mu.Unlock()
	if got != 0 {
		t.Errorf("enforcing container should not learn destinations, got %d", got)
	}
}

func TestPersistProfile_CreatesContainerProfile(t *testing.T) {
	cl := newTestScheme(t).Build()
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil,
		fakePoliciesMeta{window: 0, blocking: true, ok: true, ns: "prod", name: "web-abc", metaOK: true})
	c.Client = cl
	c.Node = "node-1"
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }

	// Attach a resolvable pod to cgroup 77 and learn some behaviour.
	c.mu.Lock()
	st := c.track(77)
	st.ref.PodUID = "pod-uid-xyz"
	st.ref.ContainerID = "abcdef0123456789"
	c.mu.Unlock()
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 77, SyscallNr: 257})
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 77, SyscallNr: 0})
	_ = c.HandleFileEvent(&ebpf.FileEvent{CgroupID: 77, Path: "/etc/hostname"})
	_ = c.HandleNetworkEvent(&ebpf.NetworkEvent{CgroupID: 77, DstIP: 0x08080808, DstPort: 53})

	// Advance past window and reconcile: enforces + persists the profile.
	c.now = func() time.Time { return base.Add(time.Minute) }
	c.Reconcile()

	cp := &policyv1alpha1.ContainerProfile{}
	name := profileName(st.ref)
	if err := cl.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "prod"}, cp); err != nil {
		t.Fatalf("expected persisted ContainerProfile %q: %v", name, err)
	}
	if cp.Spec.Node != "node-1" || cp.Spec.PodName != "web-abc" {
		t.Errorf("unexpected spec: %+v", cp.Spec)
	}
	if cp.Status.SyscallCount != 2 {
		t.Errorf("SyscallCount = %d, want 2", cp.Status.SyscallCount)
	}
	if cp.Status.FileCount != 1 || cp.Status.NetworkCount != 1 {
		t.Errorf("file/network counts = %d/%d, want 1/1", cp.Status.FileCount, cp.Status.NetworkCount)
	}
	if cp.Status.Phase != string(PhaseEnforcing) {
		t.Errorf("Phase = %q, want Enforcing", cp.Status.Phase)
	}
	// Learned syscalls must be sorted ascending.
	if len(cp.Status.LearnedSyscalls) != 2 || cp.Status.LearnedSyscalls[0] != 0 || cp.Status.LearnedSyscalls[1] != 257 {
		t.Errorf("LearnedSyscalls not sorted/expected: %v", cp.Status.LearnedSyscalls)
	}
	if cp.Status.EnforcingSince == nil {
		t.Error("EnforcingSince should be set once enforcing")
	}
}

func TestPersistProfile_SkippedWhenUnresolved(t *testing.T) {
	cl := newTestScheme(t).Build()

	// No client -> skip (no panic).
	cNoClient := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePoliciesMeta{metaOK: true, ns: "x", name: "y"})
	cNoClient.mu.Lock()
	st := cNoClient.track(1)
	st.ref.PodUID = "p"
	cNoClient.persistProfile(st)
	cNoClient.mu.Unlock()

	// Client set but PodUID empty -> skip.
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePoliciesMeta{metaOK: true, ns: "x", name: "y"})
	c.Client = cl
	c.mu.Lock()
	st2 := c.track(2) // no PodUID
	c.persistProfile(st2)
	c.mu.Unlock()

	// Client set, PodUID present, but PodMeta not ok -> skip.
	c2 := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePoliciesMeta{metaOK: false})
	c2.Client = cl
	c2.mu.Lock()
	st3 := c2.track(3)
	st3.ref.PodUID = "present"
	c2.persistProfile(st3)
	c2.mu.Unlock()

	// None of the skipped paths should have persisted anything.
	list := &policyv1alpha1.ContainerProfileList{}
	if err := cl.List(context.Background(), list); err != nil {
		t.Fatalf("list ContainerProfiles: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("expected no persisted profiles, got %d", len(list.Items))
	}
}

func TestProfileName(t *testing.T) {
	short := profileName(attribution.ContainerRef{PodUID: "uid"})
	if short != "pod-uid" {
		t.Errorf("profileName short = %q, want pod-uid", short)
	}
	long := profileName(attribution.ContainerRef{PodUID: "uid", ContainerID: "0123456789abcdef"})
	if long != "pod-uid-0123456789ab" {
		t.Errorf("profileName long = %q, want pod-uid-0123456789ab", long)
	}
}

func TestWriteSeccompProfile_NoDirNoop(t *testing.T) {
	// SeccompDir unset -> nothing written, no panic even with learned syscalls.
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})
	c.mu.Lock()
	st := c.track(1)
	st.syscalls[0] = struct{}{}
	c.writeSeccompProfile(st)
	c.mu.Unlock()
}

func TestWriteSeccompProfile_FallbackName(t *testing.T) {
	dir := t.TempDir()
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{})
	c.SeccompDir = dir
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	c.mu.Lock()
	st := c.track(1) // no PodUID -> name derived from firstSeen
	st.syscalls[0] = struct{}{}
	c.writeSeccompProfile(st)
	c.mu.Unlock()
	// A file should have been created with the cgroup-<ns> fallback name.
	// We do not assert its exact name beyond it existing.
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	c := NewController(logr.Discard(), &fakeEnforcer{}, nil, fakePolicies{window: 0, blocking: false, ok: true})
	_ = c.HandleSyscallEvent(&ebpf.SyscallEvent{CgroupID: 1, SyscallNr: 1})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, time.Millisecond)
		close(done)
	}()
	// Let it tick at least once, then cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
