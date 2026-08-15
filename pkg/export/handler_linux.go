// The ebpf.EventHandler adapter. It converts raw data plane events into the
// exported envelope and offers them to a sink, so it is Linux only like
// pkg/ebpf itself.

package export

import (
	"net"
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// HandlerOptions configures the ebpf.EventHandler adapter.
type HandlerOptions struct {
	// Filter selects which events are exported.
	Filter Filter
	// Attribution, when set, fills in the Kubernetes block of each envelope.
	Attribution AttributionFunc
	// Destination, when set, names the far end of a network event. A denial
	// that says "10.104.22.9:5432" is one an operator has to go and look up;
	// one that says "prod/postgres" is one they can act on, and the two are
	// the difference between an alert investigated and an alert muted.
	Destination DestinationFunc
	// AttributionCacheSize bounds the memoisation of attribution lookups.
	// Zero uses DefaultAttributionCacheSize; a negative value disables the
	// cache.
	AttributionCacheSize int
	// Now overrides the wall clock, for tests.
	Now func() time.Time
}

// DefaultAttributionCacheSize bounds the cgroup id to pod cache in the adapter.
const DefaultAttributionCacheSize = 4096

// Handler converts raw eBPF events into envelopes and offers them to an
// Enqueuer. It implements ebpf.EventHandler, so it can be handed straight to
// (*ebpf.Manager).AddEventHandler. Every method is non-blocking and never
// returns an error: an export problem must not disturb the data plane.
type Handler struct {
	sink   Enqueuer
	filter Filter
	attrib AttributionFunc
	dest   DestinationFunc
	now    func() time.Time

	cacheMax int
	cacheMu  sync.RWMutex
	cache    map[uint64]*KubernetesRef
}

// compile time check that the adapter satisfies the eBPF sink interface.
var _ ebpf.EventHandler = (*Handler)(nil)

// NewHandler returns an adapter feeding sink. sink is usually a *Queue.
func NewHandler(sink Enqueuer, opts HandlerOptions) *Handler {
	RegisterMetrics()
	h := &Handler{
		sink:     sink,
		filter:   opts.Filter,
		attrib:   opts.Attribution,
		dest:     opts.Destination,
		now:      opts.Now,
		cacheMax: opts.AttributionCacheSize,
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.cacheMax == 0 {
		h.cacheMax = DefaultAttributionCacheSize
	}
	if h.cacheMax > 0 {
		h.cache = make(map[uint64]*KubernetesRef)
	}
	return h
}

// Filter returns the active filter.
func (h *Handler) Filter() Filter { return h.filter }

func (h *Handler) HandleSyscallEvent(event *ebpf.SyscallEvent) error {
	if event == nil || !h.filter.AllowType(EventTypeSyscall) {
		return nil
	}
	h.emit(FromSyscallEvent(event, h.now()))
	return nil
}

func (h *Handler) HandleFileEvent(event *ebpf.FileEvent) error {
	if event == nil || !h.filter.AllowType(EventTypeFile) {
		return nil
	}
	h.emit(FromFileEvent(event, h.now()))
	return nil
}

func (h *Handler) HandleNetworkEvent(event *ebpf.NetworkEvent) error {
	if event == nil || !h.filter.AllowType(EventTypeNetwork) {
		return nil
	}
	h.emit(FromNetworkEvent(event, h.now()))
	return nil
}

func (h *Handler) HandleProcessEvent(event *ebpf.ProcessEvent) error {
	if event == nil || !h.filter.AllowType(EventTypeProcess) {
		return nil
	}
	h.emit(FromProcessEvent(event, h.now()))
	return nil
}

func (h *Handler) HandleCapabilityEvent(event *ebpf.CapabilityEvent) error {
	if event == nil || !h.filter.AllowType(EventTypeCapability) {
		return nil
	}
	h.emit(FromCapabilityEvent(event, h.now()))
	return nil
}

func (h *Handler) emit(e *Event) {
	if e == nil || h.sink == nil {
		return
	}
	if !h.filter.Allow(e) {
		return
	}
	if ref := h.resolve(e.CgroupID); ref != nil {
		e.Kubernetes = ref
	}
	h.nameDestination(e)
	h.sink.Enqueue(e)
}

// nameDestination annotates a network event with what the cluster says its far
// end is.
//
// Deliberately not cached. The attribution cache above is keyed by cgroup id,
// of which a node has hundreds; destinations are keyed by address, of which a
// busy node sees thousands, and the lookup is already a single map read. A
// cache here would cost more memory than the map it is caching.
func (h *Handler) nameDestination(e *Event) {
	if h.dest == nil || e.Network == nil || e.Network.DestinationIP == "" {
		return
	}
	ip := net.ParseIP(e.Network.DestinationIP)
	if ip == nil {
		return
	}
	name, kind, portName := h.dest(ip, e.Network.DestinationPort)
	e.Network.DestinationName = name
	e.Network.DestinationKind = kind
	e.Network.DestinationPortName = portName
}

// resolve looks the cgroup id up through the attribution hook, memoising both
// hits and misses so a busy cgroup does not walk cgroupfs on every event.
func (h *Handler) resolve(cgroupID uint64) *KubernetesRef {
	if h.attrib == nil || cgroupID == 0 {
		return nil
	}
	if h.cache != nil {
		h.cacheMu.RLock()
		ref, ok := h.cache[cgroupID]
		h.cacheMu.RUnlock()
		if ok {
			return ref
		}
	}

	var resolved *KubernetesRef
	if ref, ok := h.attrib(cgroupID); ok && !ref.Empty() {
		copied := ref
		resolved = &copied
	}

	// Only a complete reference is memoised.
	//
	// This used to cache whatever came back, including nil. Events start
	// flowing the moment the programs attach, which is before the node's pod
	// cache has been populated, so the first lookup for a container routinely
	// failed or returned a bare pod UID. That answer was then cached for the
	// lifetime of the agent, and every later event for that container went out
	// with an empty namespace and pod - the denials an operator most needs to
	// attribute were exactly the ones that could not be.
	//
	// An unresolved cgroup now costs a resolver lookup per event until it
	// resolves, which is a map read under a read lock, and stops costing
	// anything the moment the pod cache catches up.
	if h.cache != nil && resolved.Complete() {
		h.cacheMu.Lock()
		if len(h.cache) >= h.cacheMax {
			// The cache is a bounded memo, not an LRU: dropping it wholesale
			// keeps the hot path free of bookkeeping.
			h.cache = make(map[uint64]*KubernetesRef, h.cacheMax)
		}
		h.cache[cgroupID] = resolved
		h.cacheMu.Unlock()
	}
	return resolved
}
