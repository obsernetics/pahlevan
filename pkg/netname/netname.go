// Package netname answers the question an event about an address outside the
// cluster cannot: what is 203.0.113.7?
//
// internal/netmap already names everything the cluster knows about. It builds a
// map from Services, pods and nodes, so "connect to 10.104.22.9:5432" is
// reported as "prod/postgres" without anybody asking DNS anything. What it
// cannot do is name the far end of a connection that left the cluster, and
// those are the connections that matter in an exfiltration: the map returns
// "external" and the operator is handed a bare address at the exact moment they
// are trying to understand an incident.
//
// This package fills that gap under four rules, in order of how much trouble
// breaking them causes.
//
// 1. The event path is never blocked on a lookup. Naming is best effort and
// asynchronous. An event is emitted with whatever is known right now, and a
// lookup, if one happens at all, enriches the next event about that address.
// An exporter that stalls on a resolver during an incident is strictly worse
// than one that prints an address, because the events it is failing to ship are
// the incident.
//
// 2. Everything is bounded. Destinations are attacker controlled, so cache keys
// and in-flight lookups are attacker controlled, and both are capped. See
// cache.go for why the cap exists.
//
// 3. Passive naming is preferred over active lookup. A reverse DNS query on an
// attacker's address tells the attacker their address was noticed, arrives at a
// nameserver they may well control, and usually returns nothing useful anyway
// because PTR records for the sort of host used in an exfiltration are absent
// or deliberately misleading. So the order is: names the workload itself was
// given (Observe), then what the address range says on its own (Classify),
// and only then - if an operator has explicitly turned it on - a reverse
// lookup.
//
// 4. Naming is presentation only. Nothing here is consulted by an enforcement
// decision, and nothing here can change one. A name is what an operator reads;
// the kernel has already allowed or denied the connection by the time any of
// this runs.
package netname

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Defaults. Every one of these is a bound on something an attacker can drive.
const (
	// DefaultCacheSize caps the live generation of the name cache. Two
	// generations are resident, so the real ceiling is twice this. A few
	// thousand distinct external destinations is far more than a healthy node
	// sees, and well under what a scan would produce.
	DefaultCacheSize = 2048
	// DefaultMaxInFlight caps concurrent reverse lookups. Four is enough to
	// keep a handful of legitimate destinations named without letting a burst
	// of denials to distinct addresses become a burst of outbound DNS traffic
	// of its own.
	DefaultMaxInFlight = 4
	// DefaultLookupTimeout bounds one reverse lookup. Nothing waits on it, so
	// this only decides how long a worker slot stays occupied.
	DefaultLookupTimeout = 2 * time.Second
	// DefaultTTL is how long a learned name is trusted. Addresses get reused,
	// and a name that outlives its lease is a wrong name, which is worse than
	// no name.
	DefaultTTL = 30 * time.Minute
	// DefaultNegativeTTL is how long a failed lookup is remembered. Shorter
	// than DefaultTTL so a nameserver blip does not leave a destination
	// permanently unnamed, long enough that a PTR-less address is not re-asked
	// once per packet.
	DefaultNegativeTTL = 5 * time.Minute
	// maxHostLen is the longest DNS name, per RFC1035.
	maxHostLen = 253
)

// Source records where a name came from, so an operator reading an event can
// weigh it. A name the workload's own resolver returned is evidence; a name a
// PTR record volunteered is the far end's opinion of itself.
type Source string

const (
	// SourceNone is no name.
	SourceNone Source = ""
	// SourceRange is the address range itself, with no lookup of any kind.
	SourceRange Source = "range"
	// SourceObserved is a DNS answer the workload actually received.
	SourceObserved Source = "observed"
	// SourceReverse is an active PTR lookup, which only happens when an
	// operator has opted in.
	SourceReverse Source = "reverse"
)

// Result is what is known about a destination right now.
type Result struct {
	// Name is the best available name, or "" when nothing is known. An empty
	// name is a valid answer and the honest one: the caller keeps reporting the
	// address rather than inventing a label for it.
	Name   string
	Class  Class
	Source Source
}

// Resolver is the subset of *net.Resolver this package uses. It is an interface
// so tests can supply a resolver that sleeps forever and assert that nothing
// waits on it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Options configures a Namer. The zero value is usable and does no lookups.
type Options struct {
	// ReverseDNS enables active PTR lookups. Off by default, and deliberately
	// so: see rule 3 in the package comment. An operator who wants names for
	// public addresses on a network where that is safe can turn it on; nobody
	// gets it by accident.
	ReverseDNS bool
	// Resolver performs those lookups. Defaults to net.DefaultResolver when
	// ReverseDNS is on.
	Resolver Resolver
	// ClusterCIDRs are the pod and Service ranges. An address inside one that
	// the cluster map did not know is a pod the informers have not caught up
	// with, not an exfiltration destination, and saying so avoids the false
	// alert that reading it as external would produce.
	ClusterCIDRs []netip.Prefix
	// CacheSize caps the live cache generation. Zero uses DefaultCacheSize.
	CacheSize int
	// MaxInFlight caps concurrent reverse lookups. Zero uses
	// DefaultMaxInFlight.
	MaxInFlight int
	// LookupTimeout bounds one reverse lookup. Zero uses
	// DefaultLookupTimeout.
	LookupTimeout time.Duration
	// TTL is how long a learned name is trusted. Zero uses DefaultTTL.
	TTL time.Duration
	// NegativeTTL is how long a failed lookup is remembered. Zero uses
	// DefaultNegativeTTL.
	NegativeTTL time.Duration
	// Now overrides the wall clock, for tests.
	Now func() time.Time
}

// Namer names destinations the cluster map could not.
//
// It is safe for concurrent use and every exported method returns without
// waiting on anything external.
type Namer struct {
	cache *cache
	now   func() time.Time

	clusterCIDRs []netip.Prefix

	reverse     bool
	resolver    Resolver
	timeout     time.Duration
	ttl         time.Duration
	negativeTTL time.Duration

	// inflight is both the deduplicator and the concurrency bound. One map
	// serves as both because they are the same question - is there already a
	// lookup running for this address, and are there already too many - and one
	// lock answering both keeps the scheduling decision atomic.
	mu          sync.Mutex
	inflight    map[netip.Addr]struct{}
	maxInFlight int

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// New returns a Namer. With the zero Options it classifies address ranges and
// serves observed names, and never sends a packet.
func New(opts Options) *Namer {
	n := &Namer{
		now:          opts.Now,
		clusterCIDRs: opts.ClusterCIDRs,
		reverse:      opts.ReverseDNS,
		resolver:     opts.Resolver,
		timeout:      opts.LookupTimeout,
		ttl:          opts.TTL,
		negativeTTL:  opts.NegativeTTL,
		maxInFlight:  opts.MaxInFlight,
		inflight:     map[netip.Addr]struct{}{},
	}
	if n.now == nil {
		n.now = time.Now
	}
	size := opts.CacheSize
	if size <= 0 {
		size = DefaultCacheSize
	}
	n.cache = newCache(size)
	if n.maxInFlight <= 0 {
		n.maxInFlight = DefaultMaxInFlight
	}
	if n.timeout <= 0 {
		n.timeout = DefaultLookupTimeout
	}
	if n.ttl <= 0 {
		n.ttl = DefaultTTL
	}
	if n.negativeTTL <= 0 {
		n.negativeTTL = DefaultNegativeTTL
	}
	if n.reverse && n.resolver == nil {
		n.resolver = net.DefaultResolver
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return n
}

// Name returns the best available name for a destination, or "" when nothing is
// known. Its signature matches export.ExternalNameFunc so that a Namer can be
// handed straight to the export pipeline.
//
// It never blocks. If the address is unknown and reverse lookups are enabled,
// one may be scheduled in the background and will be available to a later
// event; this call still returns immediately.
func (n *Namer) Name(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	return n.Lookup(addr).Name
}

// Lookup is Name with the classification and provenance attached, for callers
// that want more than the string.
func (n *Namer) Lookup(addr netip.Addr) Result {
	if !addr.IsValid() {
		return Result{}
	}
	a := addr.Unmap()
	class := n.classify(a)

	// A name that was actually observed beats a range label: "private-network"
	// is true of 10.2.0.7 but "grafana.internal" is what the operator is
	// looking for.
	e, cached := n.cache.get(a, n.now())
	if cached && e.name != "" {
		return Result{Name: e.name, Class: class, Source: e.source}
	}

	if label := class.Label(); label != "" {
		return Result{Name: label, Class: class, Source: SourceRange}
	}

	// Only a globally routable address is worth a reverse lookup, and only if
	// nothing has been tried for it yet - a cached failure means the answer is
	// already known to be nothing.
	if class == ClassPublic && !cached {
		n.schedule(a)
	}
	return Result{Class: class}
}

// Observe records a DNS answer the workload itself received, which is the
// passive path: the resolution already happened, this only remembers it, so it
// costs no query and tells the far end nothing.
//
// ttl is the record's TTL; zero or anything longer than the configured maximum
// is clamped, because a hostile answer carrying a ten year TTL must not be able
// to pin a name in the cache.
func (n *Namer) Observe(host string, addrs []netip.Addr, ttl time.Duration) {
	name := sanitizeHost(host)
	if name == "" || len(addrs) == 0 {
		return
	}
	if ttl <= 0 || ttl > n.ttl {
		ttl = n.ttl
	}
	exp := n.now().Add(ttl)
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		n.cache.put(a.Unmap(), entry{name: name, source: SourceObserved, expires: exp})
	}
}

// Len reports how many addresses are currently remembered, for the bound test
// and for a debug command answering "why is this destination still unnamed".
func (n *Namer) Len() int { return n.cache.len() }

// Close cancels any in-flight lookups and waits for their goroutines. It is
// safe to call more than once and safe to call on a Namer that never did a
// lookup.
func (n *Namer) Close() {
	n.cancel()
	n.wg.Wait()
}

// classify applies the cluster CIDRs on top of the pure range classification.
// An address inside the cluster's own ranges is reported as such rather than as
// the RFC1918 space it is usually carved out of, since "cluster-network" is the
// more specific and more useful reading.
func (n *Namer) classify(a netip.Addr) Class {
	class := Classify(a)
	switch class {
	case ClassPrivate, ClassPublic, ClassCGNAT:
		for _, p := range n.clusterCIDRs {
			if p.Contains(a) {
				return ClassCluster
			}
		}
	}
	return class
}

// schedule starts a background reverse lookup if one is warranted and there is
// room for it. It never waits: when the in-flight budget is spent the lookup is
// simply not done, because the event has already gone out with the address and
// a name that arrives late is worth less than a reader that never stalls.
func (n *Namer) schedule(a netip.Addr) {
	if !n.reverse || n.resolver == nil {
		return
	}
	n.mu.Lock()
	if _, dup := n.inflight[a]; dup || len(n.inflight) >= n.maxInFlight {
		n.mu.Unlock()
		return
	}
	select {
	case <-n.ctx.Done():
		n.mu.Unlock()
		return
	default:
	}
	n.inflight[a] = struct{}{}
	n.mu.Unlock()

	n.wg.Add(1)
	go n.resolve(a)
}

func (n *Namer) resolve(a netip.Addr) {
	defer n.wg.Done()
	defer func() {
		n.mu.Lock()
		delete(n.inflight, a)
		n.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(n.ctx, n.timeout)
	defer cancel()
	names, err := n.resolver.LookupAddr(ctx, a.String())

	e := entry{source: SourceReverse, expires: n.now().Add(n.negativeTTL)}
	if err == nil {
		for _, candidate := range names {
			if h := sanitizeHost(candidate); h != "" {
				e.name = h
				e.expires = n.now().Add(n.ttl)
				break
			}
		}
	}
	// The failure is cached too. Without that, an address with no PTR record
	// would be re-queried for the lifetime of the connection.
	n.cache.put(a, e)
}

// sanitizeHost normalises a hostname and rejects anything that should not end
// up in an operator's log line.
//
// This is not cosmetic. A PTR record or a DNS answer is text the far end
// chooses, and it lands in JSON events, webhook payloads and a terminal. A name
// carrying a newline can forge a second log line, and one carrying terminal
// escapes can rewrite what the operator sees, so anything outside the printable
// ASCII a hostname is allowed to contain is dropped along with the name.
func sanitizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > maxHostLen {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_':
		default:
			return ""
		}
	}
	return strings.ToLower(h)
}
