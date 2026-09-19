package dashboard

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// Default bounds for a Store.
//
// Every one of these exists because the alternative is a leak. A dashboard
// process lives for weeks while pods come and go, workloads are created and
// deleted, and a compromised container can exec a uniquely named binary on
// every request. An aggregate with no ceiling in any of those dimensions grows
// until the pod is OOM-killed, and the first person to notice is whoever was
// reading the denials at the time.
const (
	DefaultMaxWorkloads = 2048
	DefaultMaxDenials   = 64
	DefaultMaxProcesses = 256
)

// StoreOptions bounds a Store.
type StoreOptions struct {
	// MaxWorkloads is how many workloads are tracked before the least
	// recently seen is evicted. Zero uses DefaultMaxWorkloads.
	MaxWorkloads int
	// MaxDenials is how many recent denials are retained per workload. Zero
	// uses DefaultMaxDenials. This is a view of what is happening now, not an
	// audit log; the export sinks are the audit log.
	MaxDenials int
	// MaxProcesses is how many distinct nodes one workload's process tree may
	// hold. Zero uses DefaultMaxProcesses.
	MaxProcesses int
}

func (o StoreOptions) withDefaults() StoreOptions {
	if o.MaxWorkloads <= 0 {
		o.MaxWorkloads = DefaultMaxWorkloads
	}
	if o.MaxDenials <= 0 {
		o.MaxDenials = DefaultMaxDenials
	}
	if o.MaxProcesses <= 0 {
		o.MaxProcesses = DefaultMaxProcesses
	}
	return o
}

// WorkloadKey identifies the thing an operator actually reasons about.
//
// Keyed by the owning workload rather than by pod: a Deployment rolling out
// replaces every pod name, and a denial history that resets because the
// replica set changed is a history that is never there when it is needed.
type WorkloadKey struct {
	Namespace string
	Kind      string
	Name      string
}

func (k WorkloadKey) String() string { return k.Namespace + "/" + k.Kind + "/" + k.Name }

// Empty reports whether the key names nothing usable.
func (k WorkloadKey) Empty() bool { return k.Namespace == "" || k.Name == "" }

// KeyForEvent derives the workload an event belongs to.
//
// It returns false for an event whose pod could not be resolved. Such an event
// is dropped rather than filed under a placeholder, because everything in this
// package is gated on a per-namespace authorisation decision: an event with no
// namespace has no decision that can be made about it, and guessing one is how
// a viewer ends up shown a denial from a namespace they cannot read.
func KeyForEvent(e *export.Event) (WorkloadKey, bool) {
	k := e.Kubernetes
	if k == nil || k.Namespace == "" {
		return WorkloadKey{}, false
	}
	switch {
	case k.WorkloadKind != "" && k.WorkloadName != "":
		return WorkloadKey{Namespace: k.Namespace, Kind: k.WorkloadKind, Name: k.WorkloadName}, true
	case k.Pod != "":
		return WorkloadKey{Namespace: k.Namespace, Kind: "Pod", Name: k.Pod}, true
	default:
		return WorkloadKey{}, false
	}
}

// Counts is the per-signal event tally for one workload.
type Counts struct {
	Files        int `json:"files"`
	Network      int `json:"network"`
	Execs        int `json:"execs"`
	Capabilities int `json:"capabilities"`
	Syscalls     int `json:"syscalls"`
	Denials      int `json:"denials"`
	Total        int `json:"total"`
}

// Denial is one refused operation, with the reason spelled out.
//
// Reason is not decoration. A denial an operator cannot explain is a denial
// they roll back, and a rollback undoes the enforcement that was working. The
// field says which allow-set refused it, which is the difference between "this
// workload is being attacked" and "learning missed a path".
type Denial struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	Process   string    `json:"process"`
	PID       uint32    `json:"pid"`
	Ancestry  string    `json:"ancestry,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	Container string    `json:"container,omitempty"`
	Node      string    `json:"node,omitempty"`
}

// ProcessNode is one comm in a workload's process tree.
type ProcessNode struct {
	Comm     string         `json:"comm"`
	Count    int            `json:"count"`
	Denied   int            `json:"denied"`
	Children []*ProcessNode `json:"children,omitempty"`
}

// Activity is a workload's live aggregate, as a snapshot nothing else holds a
// reference into.
type Activity struct {
	Key       WorkloadKey    `json:"key"`
	Node      string         `json:"node,omitempty"`
	Image     string         `json:"image,omitempty"`
	Counts    Counts         `json:"counts"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	Denials   []Denial       `json:"denials,omitempty"`
	Processes []*ProcessNode `json:"processes,omitempty"`
	// ProcessesTruncated reports that the tree hit MaxProcesses and further
	// distinct commands were folded into their parent. A tree that silently
	// stopped growing would read as a workload that stopped spawning things.
	ProcessesTruncated bool `json:"processesTruncated,omitempty"`
}

// Store aggregates the live event stream per workload.
//
// It is optional: the dashboard renders everything the CRDs carry without one.
// What it adds is the part the CRDs cannot answer - the process tree behind a
// denial and the reason the kernel refused it, which is the difference between
// a number and something an operator can act on.
type Store struct {
	opts StoreOptions

	mu           sync.RWMutex
	workloads    map[string]*workloadState
	unattributed int
	evicted      int
}

type workloadState struct {
	key       WorkloadKey
	node      string
	image     string
	counts    Counts
	firstSeen time.Time
	lastSeen  time.Time

	// denials is a ring: the newest MaxDenials, oldest overwritten. A slice
	// that grew and was trimmed from the front would copy the whole backing
	// array on every denial, and denials arrive in bursts by definition.
	//
	// It grows to the ceiling rather than being allocated at it. A Denial is
	// not small, and a cluster of two thousand mostly quiet workloads would
	// otherwise pay tens of megabytes for rings that never hold anything.
	denials    []Denial
	denialNext int

	roots     map[string]*procState
	procCount int
	procFull  bool
}

type procState struct {
	comm     string
	count    int
	denied   int
	children map[string]*procState
}

// NewStore builds a Store.
func NewStore(opts StoreOptions) *Store {
	o := opts.withDefaults()
	return &Store{opts: o, workloads: make(map[string]*workloadState)}
}

// Name identifies the sink, satisfying export.Exporter.
func (s *Store) Name() string { return "dashboard" }

// Export folds a batch into the aggregate, satisfying export.Exporter so the
// store plugs into the same pipeline as the file and webhook sinks rather than
// tapping the event stream separately. One path means the dashboard and a SIEM
// see the same event with the same attribution.
func (s *Store) Export(_ context.Context, events []*export.Event) error {
	for _, e := range events {
		if e != nil {
			s.Add(e)
		}
	}
	return nil
}

// Close releases the store. It is idempotent and keeps no resources, but
// export.Exporter requires it.
func (s *Store) Close() error { return nil }

// Add folds one event into the aggregate.
func (s *Store) Add(e *export.Event) {
	key, ok := KeyForEvent(e)
	if !ok {
		s.mu.Lock()
		s.unattributed++
		s.mu.Unlock()
		return
	}
	when := e.Timestamp.Time()

	s.mu.Lock()
	defer s.mu.Unlock()

	w := s.workloads[key.String()]
	if w == nil {
		// lastSeen is set before the eviction pass, not after: a workload
		// inserted with a zero timestamp is by definition the least recently
		// seen, so the new arrival would evict itself and the store would
		// never grow past its ceiling minus one.
		w = &workloadState{
			key:       key,
			firstSeen: when,
			lastSeen:  when,
			roots:     make(map[string]*procState),
		}
		s.workloads[key.String()] = w
		s.evictOverflow()
	}
	if e.Kubernetes != nil {
		if e.Kubernetes.Node != "" {
			w.node = e.Kubernetes.Node
		}
		if e.Kubernetes.Image != "" {
			w.image = e.Kubernetes.Image
		}
	}
	if when.After(w.lastSeen) {
		w.lastSeen = when
	}
	if w.firstSeen.IsZero() || (!when.IsZero() && when.Before(w.firstSeen)) {
		w.firstSeen = when
	}

	w.counts.Total++
	switch e.Type {
	case export.EventTypeFile:
		w.counts.Files++
	case export.EventTypeNetwork:
		w.counts.Network++
	case export.EventTypeProcess:
		w.counts.Execs++
	case export.EventTypeCapability:
		w.counts.Capabilities++
	case export.EventTypeSyscall:
		w.counts.Syscalls++
	}

	denied := e.Denied()
	if denied {
		w.counts.Denials++
		w.pushDenial(denialFor(e, when), s.opts.MaxDenials)
	}
	s.foldProcess(w, e, denied)
}

// pushDenial writes into the ring, growing it up to max the first time round.
func (w *workloadState) pushDenial(d Denial, max int) {
	if max <= 0 {
		return
	}
	if len(w.denials) < max {
		w.denials = append(w.denials, d)
		w.denialNext = len(w.denials) % max
		return
	}
	w.denials[w.denialNext] = d
	w.denialNext = (w.denialNext + 1) % max
}

// evictOverflow drops the least recently seen workload once the map is over
// its ceiling. Least recently seen rather than oldest: a workload that was
// created long ago and is still producing events is the one being watched,
// and a namespace churning through short-lived Jobs is exactly what would
// otherwise push it out.
func (s *Store) evictOverflow() {
	if len(s.workloads) <= s.opts.MaxWorkloads {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, w := range s.workloads {
		if oldestKey == "" || w.lastSeen.Before(oldest) {
			oldestKey, oldest = k, w.lastSeen
		}
	}
	if oldestKey != "" {
		delete(s.workloads, oldestKey)
		s.evicted++
	}
}

// foldProcess places the event's command in the workload's process tree.
//
// The chain comes from the exec event's ancestry when there is one, because
// that is the only source that says what spawned what. Falling back to the
// parent comm carried on every event keeps a workload that has not execed
// anything since the dashboard started from showing an empty tree, which reads
// as "nothing is running" rather than "nothing has execed".
func (s *Store) foldProcess(w *workloadState, e *export.Event, denied bool) {
	chain := processChain(e)
	if len(chain) == 0 {
		return
	}
	level := w.roots
	var node *procState
	for _, comm := range chain {
		next := level[comm]
		if next == nil {
			// At the ceiling the event is attributed to the deepest node that
			// already exists rather than dropped: the count still tells the
			// truth about how busy that branch is.
			if w.procCount >= s.opts.MaxProcesses {
				w.procFull = true
				break
			}
			next = &procState{comm: comm, children: map[string]*procState{}}
			level[comm] = next
			w.procCount++
		}
		node = next
		level = next.children
	}
	if node == nil {
		return
	}
	node.count++
	if denied {
		node.denied++
	}
}

// processChain renders an event's lineage oldest first.
func processChain(e *export.Event) []string {
	comm := e.Process.Comm
	if comm == "" {
		comm = "?"
	}
	if e.Exec != nil && len(e.Exec.Ancestry) > 0 {
		// Ancestry is nearest ancestor first; a tree wants the other order.
		chain := make([]string, 0, len(e.Exec.Ancestry)+1)
		for i := len(e.Exec.Ancestry) - 1; i >= 0; i-- {
			if name := e.Exec.Ancestry[i].Comm; name != "" {
				chain = append(chain, name)
			}
		}
		return append(chain, comm)
	}
	if e.Exec != nil && e.Exec.AncestryChain != "" {
		parts := strings.Split(e.Exec.AncestryChain, " -> ")
		chain := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				chain = append(chain, p)
			}
		}
		if len(chain) > 0 {
			return chain
		}
	}
	if e.Process.ParentComm != "" && e.Process.ParentComm != comm {
		return []string{e.Process.ParentComm, comm}
	}
	return []string{comm}
}

// denialFor turns a refused event into the record the view shows.
func denialFor(e *export.Event, when time.Time) Denial {
	d := Denial{
		Time:    when,
		Process: e.Process.Comm,
		PID:     e.Process.PID,
	}
	if e.Kubernetes != nil {
		d.Pod, d.Container, d.Node = e.Kubernetes.Pod, e.Kubernetes.Container, e.Kubernetes.Node
	}
	if e.Exec != nil {
		d.Ancestry = e.Exec.AncestryChain
	}
	d.Kind, d.Subject, d.Reason = denialSubjectAndReason(e)
	return d
}

// denialSubjectAndReason says what was refused and which allow-set refused it.
//
// Pahlevan denies by omission: the kernel refuses an operation because the key
// is not in the learned allow-set, never because a rule named it. Saying so is
// what points an operator at the fix - extend the profile, or investigate why
// the workload is doing something it has never done - instead of leaving them
// looking for a rule that does not exist.
func denialSubjectAndReason(e *export.Event) (kind, subject, reason string) {
	switch {
	case e.File != nil:
		access := e.File.SyscallName
		if access == "" {
			access = "open"
		}
		return "file", e.File.Path,
			"the path is not in this container's learned file allow-set for " + access
	case e.Network != nil:
		dest := e.Network.Address()
		if e.Network.DestinationName != "" {
			dest = e.Network.DestinationName + " (" + dest + ")"
		}
		return "network", dest,
			"the destination is not in this container's learned egress allow-set"
	case e.Exec != nil:
		if e.Exec.Breakout {
			return "exec", e.Exec.Binary,
				"the exec ran with a working directory outside its own mount namespace, which is the container-breakout signature"
		}
		return "exec", e.Exec.Binary,
			"the binary is not in this container's learned executable allow-set"
	case e.Capability != nil:
		return "capability", e.Capability.Name,
			"the capability is not in this container's learned capability set"
	case e.Syscall != nil:
		return "syscall", e.Syscall.Name,
			"the syscall is not in this container's learned syscall allow-set"
	default:
		return string(e.Type), "", "the operation is not in this container's learned allow-set"
	}
}

// Stats reports what the store is holding, for the overview and for an
// operator wondering whether the aggregate is complete.
type Stats struct {
	Workloads    int `json:"workloads"`
	Unattributed int `json:"unattributed"`
	Evicted      int `json:"evicted"`
}

// Stats returns the store's own counters.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Workloads: len(s.workloads), Unattributed: s.unattributed, Evicted: s.evicted}
}

// Activity returns a snapshot for one workload.
func (s *Store) Activity(key WorkloadKey) (Activity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w := s.workloads[key.String()]
	if w == nil {
		return Activity{}, false
	}
	return w.snapshot(), true
}

// Namespaces returns every namespace the store has events for, sorted. The
// caller still has to authorise each one; this only says which questions are
// worth asking.
func (s *Store) Namespaces() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, w := range s.workloads {
		seen[w.key.Namespace] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// Snapshot returns every workload's aggregate, sorted by key. Namespace
// filtering is the caller's job, because only the caller knows what the viewer
// is allowed to see.
func (s *Store) Snapshot() []Activity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Activity, 0, len(s.workloads))
	for _, w := range s.workloads {
		out = append(out, w.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// snapshot deep-copies the state. Handing out the live structures would let a
// handler read a tree while the event pipeline is rewriting it, and the race
// would show up as a corrupted diagram long before anyone suspected the store.
func (w *workloadState) snapshot() Activity {
	a := Activity{
		Key:                w.key,
		Node:               w.node,
		Image:              w.image,
		Counts:             w.counts,
		FirstSeen:          w.firstSeen,
		LastSeen:           w.lastSeen,
		ProcessesTruncated: w.procFull,
	}
	if n := len(w.denials); n > 0 {
		a.Denials = make([]Denial, 0, n)
		// Newest first: the ring's write cursor is one past the newest entry,
		// and an operator reading a denial list reads the top of it.
		for i := 0; i < n; i++ {
			a.Denials = append(a.Denials, w.denials[(w.denialNext-1-i+n*2)%n])
		}
	}
	a.Processes = copyProcesses(w.roots)
	return a
}

func copyProcesses(level map[string]*procState) []*ProcessNode {
	if len(level) == 0 {
		return nil
	}
	out := make([]*ProcessNode, 0, len(level))
	for _, p := range level {
		out = append(out, &ProcessNode{
			Comm:     p.comm,
			Count:    p.count,
			Denied:   p.denied,
			Children: copyProcesses(p.children),
		})
	}
	// Busiest first, then by name, so the diagram is stable across reloads.
	// A tree that reshuffles on every refresh cannot be read.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Comm < out[j].Comm
	})
	return out
}
