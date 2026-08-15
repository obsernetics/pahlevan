package export

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

type captureSink struct {
	mu     sync.Mutex
	events []*Event
	reject bool
}

func (c *captureSink) Enqueue(e *Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reject {
		return false
	}
	c.events = append(c.events, e)
	return true
}

func (c *captureSink) all() []*Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Event, len(c.events))
	copy(out, c.events)
	return out
}

func newTestHandler(sink Enqueuer, opts HandlerOptions) *Handler {
	if opts.Now == nil {
		opts.Now = func() time.Time { return testNow }
	}
	return NewHandler(sink, opts)
}

func feedAll(t *testing.T, h *Handler) {
	t.Helper()
	if err := h.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 1, CgroupID: 100}); err != nil {
		t.Fatalf("syscall: %v", err)
	}
	if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/etc/passwd", Flags: DeniedFlag, CgroupID: 100}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := h.HandleNetworkEvent(&ebpf.NetworkEvent{DstIP: 0x08080808, DstPort: 53, CgroupID: 100}); err != nil {
		t.Fatalf("network: %v", err)
	}
	if err := h.HandleProcessEvent(&ebpf.ProcessEvent{Filename: "/bin/sh", Flags: DeniedFlag, CgroupID: 100}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if err := h.HandleCapabilityEvent(&ebpf.CapabilityEvent{Capability: 21, CgroupID: 100}); err != nil {
		t.Fatalf("capability: %v", err)
	}
}

func TestHandlerImplementsEBPFEventHandler(t *testing.T) {
	sink := &captureSink{}
	var h ebpf.EventHandler = newTestHandler(sink, HandlerOptions{})
	if err := h.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 39}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := sink.all()
	if len(got) != 1 || got[0].Syscall.Name != "getpid" {
		t.Fatalf("events = %+v", got)
	}
}

func TestHandlerPassesEverythingByDefault(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{})
	feedAll(t, h)

	got := sink.all()
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5", len(got))
	}
	seen := map[EventType]bool{}
	for _, e := range got {
		seen[e.Type] = true
		if !e.Timestamp.Time().Equal(testNow) {
			t.Errorf("timestamp = %v", e.Timestamp)
		}
	}
	for _, want := range AllEventTypes() {
		if !seen[want] {
			t.Errorf("missing %q events", want)
		}
	}
}

func TestHandlerTypeFilter(t *testing.T) {
	sink := &captureSink{}
	filter, err := NewFilter([]string{"file", "process"}, false)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	h := newTestHandler(sink, HandlerOptions{Filter: filter})
	feedAll(t, h)

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Type != EventTypeFile && e.Type != EventTypeProcess {
			t.Errorf("unexpected type %q", e.Type)
		}
	}
	if !h.Filter().AllowType(EventTypeFile) || h.Filter().AllowType(EventTypeNetwork) {
		t.Error("Filter() does not reflect the configured selection")
	}
}

func TestHandlerDenialsOnly(t *testing.T) {
	sink := &captureSink{}
	filter, err := NewFilter(nil, true)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	h := newTestHandler(sink, HandlerOptions{Filter: filter})
	feedAll(t, h)

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("got %d events, want the 2 denials: %+v", len(got), got)
	}
	for _, e := range got {
		if !e.Denied() {
			t.Errorf("event %q is not a denial", e.Type)
		}
	}
}

func TestHandlerAttribution(t *testing.T) {
	sink := &captureSink{}
	var calls int
	var mu sync.Mutex
	h := newTestHandler(sink, HandlerOptions{
		Attribution: func(id uint64) (KubernetesRef, bool) {
			mu.Lock()
			calls++
			mu.Unlock()
			if id != 100 {
				return KubernetesRef{}, false
			}
			return KubernetesRef{Namespace: "prod", Pod: "api-0", Container: "api", PodUID: "uid-1"}, true
		},
	})

	for i := 0; i < 3; i++ {
		if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/x", CgroupID: 100}); err != nil {
			t.Fatalf("handle: %v", err)
		}
	}
	if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/y", CgroupID: 200}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// A cgroup id of zero is never resolved.
	if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/z"}); err != nil {
		t.Fatalf("handle: %v", err)
	}

	got := sink.all()
	if len(got) != 5 {
		t.Fatalf("got %d events", len(got))
	}
	if got[0].Kubernetes == nil || got[0].Kubernetes.Pod != "api-0" {
		t.Fatalf("attribution missing: %+v", got[0].Kubernetes)
	}
	if got[3].Kubernetes != nil || got[4].Kubernetes != nil {
		t.Error("unresolvable cgroups must stay unattributed")
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Errorf("resolver called %d times, want 2 (results are memoised)", calls)
	}
}

func TestHandlerAttributionCacheIsBounded(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{
		AttributionCacheSize: 4,
		Attribution: func(id uint64) (KubernetesRef, bool) {
			return KubernetesRef{PodUID: "uid"}, true
		},
	})
	for i := uint64(1); i <= 50; i++ {
		if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/x", CgroupID: i}); err != nil {
			t.Fatalf("handle: %v", err)
		}
	}
	h.cacheMu.RLock()
	size := len(h.cache)
	h.cacheMu.RUnlock()
	if size > 4 {
		t.Errorf("cache grew to %d entries with a bound of 4", size)
	}
}

func TestHandlerAttributionCacheDisabled(t *testing.T) {
	sink := &captureSink{}
	var calls int
	h := newTestHandler(sink, HandlerOptions{
		AttributionCacheSize: -1,
		Attribution: func(id uint64) (KubernetesRef, bool) {
			calls++
			return KubernetesRef{PodUID: "uid"}, true
		},
	})
	for i := 0; i < 3; i++ {
		if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/x", CgroupID: 7}); err != nil {
			t.Fatalf("handle: %v", err)
		}
	}
	if calls != 3 {
		t.Errorf("resolver called %d times, want 3 with the cache disabled", calls)
	}
	if h.cache != nil {
		t.Error("cache should not be allocated")
	}
}

func TestHandlerIgnoresEmptyAttribution(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{
		Attribution: func(uint64) (KubernetesRef, bool) { return KubernetesRef{}, true },
	})
	if err := h.HandleFileEvent(&ebpf.FileEvent{Path: "/x", CgroupID: 5}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := sink.all()[0]; got.Kubernetes != nil {
		t.Errorf("an empty reference should not be attached: %+v", got.Kubernetes)
	}
}

func TestHandlerToleratesNilEventsAndSink(t *testing.T) {
	h := newTestHandler(nil, HandlerOptions{})
	if err := h.HandleSyscallEvent(nil); err != nil {
		t.Errorf("nil syscall: %v", err)
	}
	if err := h.HandleFileEvent(nil); err != nil {
		t.Errorf("nil file: %v", err)
	}
	if err := h.HandleNetworkEvent(nil); err != nil {
		t.Errorf("nil network: %v", err)
	}
	if err := h.HandleProcessEvent(nil); err != nil {
		t.Errorf("nil process: %v", err)
	}
	if err := h.HandleCapabilityEvent(nil); err != nil {
		t.Errorf("nil capability: %v", err)
	}
	// A nil sink must not panic either.
	if err := h.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 1}); err != nil {
		t.Errorf("nil sink: %v", err)
	}
}

func TestHandlerNeverFailsWhenTheSinkRejects(t *testing.T) {
	sink := &captureSink{reject: true}
	h := newTestHandler(sink, HandlerOptions{})
	feedAll(t, h)
	if len(sink.all()) != 0 {
		t.Error("rejected events must not be recorded")
	}
}

func TestHandlerConcurrent(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{
		Attribution: func(id uint64) (KubernetesRef, bool) {
			return KubernetesRef{PodUID: "uid"}, true
		},
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = h.HandleFileEvent(&ebpf.FileEvent{Path: "/x", CgroupID: uint64(worker*50 + j)})
			}
		}(i)
	}
	wg.Wait()
	if got := len(sink.all()); got != 400 {
		t.Fatalf("captured %d events, want 400", got)
	}
}

// The handler must name the destination on the way through, or the field exists
// and is always empty.
func TestHandlerNamesTheDestination(t *testing.T) {
	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{
		Destination: func(ip net.IP, port uint16) (string, string, string) {
			if ip.Equal(net.ParseIP("10.104.22.9")) && port == 5432 {
				return "prod/postgres", "service", "postgres"
			}
			return "external", "external", ""
		},
	})

	if err := h.HandleNetworkEvent(&ebpf.NetworkEvent{
		DstIP:   binary.LittleEndian.Uint32(net.ParseIP("10.104.22.9").To4()),
		DstPort: 5432, Protocol: 6, Family: 2, Comm: "api", CgroupID: 1,
	}); err != nil {
		t.Fatalf("HandleNetworkEvent: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	n := sink.events[0].Network
	if n == nil {
		t.Fatal("no network detail")
	}
	if n.DestinationName != "prod/postgres" {
		t.Errorf("DestinationName = %q, want prod/postgres", n.DestinationName)
	}
	if n.DestinationKind != "service" {
		t.Errorf("DestinationKind = %q, want service", n.DestinationKind)
	}
	if n.DestinationPortName != "postgres" {
		t.Errorf("DestinationPortName = %q, want postgres", n.DestinationPortName)
	}
}

// Without the hook the fields stay empty rather than being invented.
func TestHandlerWithoutADestinationHook(t *testing.T) {
	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{})
	if err := h.HandleNetworkEvent(&ebpf.NetworkEvent{
		DstIP:   binary.LittleEndian.Uint32(net.ParseIP("10.0.0.1").To4()),
		DstPort: 80, Protocol: 6, Family: 2, Comm: "api", CgroupID: 1,
	}); err != nil {
		t.Fatalf("HandleNetworkEvent: %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	if got := sink.events[0].Network.DestinationName; got != "" {
		t.Errorf("DestinationName = %q, want empty", got)
	}
}
