// Package clusterdata reads Pahlevan's custom resources out of a cluster and
// flattens them into plain structs a terminal can render.
//
// It exists so that the console never touches a *v1beta1 object directly. A
// console that ranges over CRD types ends up dereferencing
// `status.learningStatus.progress` in a view function, and a policy that has
// only just been created - which has no status at all - then panics the whole
// UI on the frame that renders it. Everything optional is resolved here, once,
// where it can be tested.
//
// The package is strictly read-only: it lists, and that is all. A console is an
// inspection tool, and an operator scrolling through policies must not be one
// keystroke away from changing one, so no write verb is reachable from here at
// all. There is no Update, Patch, Create, Delete or SubResource call in this
// package, and a test asserts that stays true.
//
// It deliberately has no dependency on pkg/tui: the console owns its own
// display types, and a thin adapter converts these. That keeps the Kubernetes
// reading testable without a terminal and keeps the terminal testable without a
// cluster.
package clusterdata

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

const (
	// DefaultListLimit caps how many objects one view will read.
	//
	// An unbounded List against a cluster running Pahlevan on every node
	// returns one ContainerProfile per container, which is tens of thousands of
	// objects on a large cluster. Three concrete problems, in the order they
	// bite: the API server serves the whole set in one response and the console
	// holds all of it in memory while the operator looks at the twenty rows
	// that fit on screen; the round trip takes long enough that a keypress
	// which switches views appears to hang; and each profile carries its
	// learned file and syscall lists, so the bytes are not proportional to the
	// row count but to the behavioral history of the entire cluster. A terminal
	// cannot show more than a screenful anyway, so reading more than this is
	// spending an operator's latency on data nothing will draw.
	//
	// The limit is sent to the API server as a page size and re-applied to the
	// returned items, because a client that trusts the server to honor a limit
	// it may ignore is a client with no limit at all.
	DefaultListLimit = 500

	// DefaultTTL is how long a listed view stays usable without re-reading.
	//
	// The console re-asks for data on every view switch and every redraw, so
	// without a cache each press of a navigation key becomes an API server
	// round trip: the UI stutters, and a room full of operators with a console
	// open turns into a steady list load on the apiserver. Two seconds is
	// chosen because it is below the threshold at which a human reading a
	// screen notices staleness, and above the interval at which impatient
	// keypresses arrive. It is deliberately short: this data changes as the
	// agents report, and a console that shows a minute-old denial count while
	// an incident is unfolding is worse than one that is briefly slow.
	DefaultTTL = 2 * time.Second

	// maxFieldItems caps the per-object string and port lists.
	//
	// An attack surface for a build container can list thousands of writable
	// paths. Rendering that into one cell wedges a terminal, and the operator
	// only ever reads the first handful, so the slice is truncated and the true
	// size reported alongside it - a truncated list that does not say it was
	// truncated is how an operator concludes a workload writes to 100 paths
	// when it writes to 9000.
	maxFieldItems = 100

	// unknown is what a missing string renders as. An empty cell in a terminal
	// is indistinguishable from a rendering bug; this is not.
	unknown = "unknown"
)

// Policy is one PahlevanPolicy as a console row: is this policy learning or
// enforcing, over what, how far along, and is it blocking anything.
type Policy struct {
	Namespace string
	Name      string

	// Phase is status.phase, or "unknown" for a policy the controller has not
	// reconciled yet. A freshly applied policy legitimately has no status.
	Phase string

	// Enforcement is the effective mode, not the raw field: a Blocking policy
	// with alertOnly set does not block, and showing "Blocking" for it would
	// tell an operator their workload is protected when it is not.
	Enforcement string

	// Selector is spec.selector rendered the way a human writes it, e.g.
	// `app=web,tier in (front,edge)`. "<all pods>" for an empty selector,
	// which is a real and load-bearing configuration rather than a blank.
	Selector string

	// LearningProgress is 0-100. HasLearningProgress is false when the policy
	// reports no progress at all, which is not the same as reporting zero:
	// "not started" and "0% of the way through" look identical otherwise.
	LearningProgress    int
	HasLearningProgress bool

	// SamplesCollected is how much evidence the baseline rests on.
	SamplesCollected int64

	// ContainersEnforcing of ContainersTotal are under enforcement. The pair
	// answers "is this policy actually applied to anything", which a phase of
	// Enforcing on its own does not.
	ContainersEnforcing int
	ContainersTotal     int

	// Denials is everything the data plane has blocked under this policy.
	Denials int64

	// Declarations is how many operations spec.learningConfig.expectedBehavior
	// asserts the workload performs. It belongs next to the learned counts
	// because it changes how a baseline should be read: a policy with
	// declarations is permitting behavior nothing was ever observed doing, and
	// an operator auditing an allow-set has to know that before they read it
	// as evidence.
	Declarations int

	Created time.Time
	Age     time.Duration
}

// Profile is one ContainerProfile as a console row: what was learned for one
// container, and how much that baseline can be trusted.
type Profile struct {
	Namespace string
	Name      string

	// Pod, Container and Node locate the profile. Container is the short
	// runtime ID, because a ContainerProfile records the container it was
	// learned from by ID and cgroup - it carries no container *name* - and
	// inventing one from the object name would be a guess presented as a fact.
	Pod       string
	Container string
	Node      string

	// Phase is Learning or Enforcing, or "unknown" before the agent has
	// reported.
	Phase string

	// Counts of what was learned, per signal.
	Files        int
	Network      int
	Syscalls     int
	Capabilities int

	// Declared is how many entries are permitted because the policy declared
	// them rather than because this container was observed doing them. Kept
	// separate from the learned counts for the reason the CRD keeps them
	// separate: an assertion is not evidence, and an operator auditing a
	// profile has to see which is which.
	Declared int

	// Rollbacks and Denials are the evidence against this baseline: a rollback
	// is the cluster having already decided the baseline was wrong, and a
	// denial under enforcement is a behavior learning missed.
	Rollbacks int
	Denials   int

	// Confidence is 0-1, derived here rather than read from the CRD, which
	// carries no such field. See profileConfidence for the derivation; it is
	// reported next to the counts and rollbacks it is computed from so the
	// number is never the only thing an operator has to go on.
	Confidence float64

	Created time.Time
	Age     time.Duration
}

// AttackSurface is one AttackSurface report as a console row: how exposed this
// workload is, and by what.
type AttackSurface struct {
	Namespace string
	Name      string

	// Workload is the analyzed workload as `Kind/name`, falling back to the
	// policy it was computed for.
	Workload string

	// RiskScore is 0-100. HasRiskScore is false when the analyzer has not
	// scored this surface yet, which must not render as a reassuring zero.
	RiskScore    int
	HasRiskScore bool

	// The *Total fields are the true sizes; the slices are capped at
	// maxFieldItems. Total greater than len means the console is showing a
	// prefix and should say so.
	ExposedPorts      []int32
	ExposedPortTotal  int
	WritablePaths     []string
	WritablePathTotal int
	Capabilities      []string
	CapabilityTotal   int

	// LastAnalysis is when the surface was last computed. A surface that has
	// not been analyzed recently is stale advice; HasLastAnalysis is false when
	// it has never been analyzed at all.
	LastAnalysis    time.Time
	HasLastAnalysis bool

	Created time.Time
	Age     time.Duration
}

// View names the three things this package reads. It exists so truncation can
// be reported without three near-identical accessors.
type View string

const (
	ViewPolicies       View = "policies"
	ViewProfiles       View = "profiles"
	ViewAttackSurfaces View = "attacksurfaces"
)

// entry is one cached view.
//
// Each view carries its own mutex rather than sharing one on the Reader, so a
// slow profile list does not block the policy view the operator just switched
// to. Holding the lock across the refresh also makes concurrent callers
// single-flight for free: the second caller waits and then finds the cache
// fresh, instead of issuing a duplicate List.
type entry[T any] struct {
	mu        sync.Mutex
	data      []T
	fetchedAt time.Time
	valid     bool
	truncated bool
}

// Reader lists Pahlevan resources for display. The zero value is not usable;
// construct one with New.
type Reader struct {
	c     client.Client
	ttl   time.Duration
	limit int
	now   func() time.Time

	policies entry[Policy]
	profiles entry[Profile]
	surfaces entry[AttackSurface]
}

// Option configures a Reader.
type Option func(*Reader)

// WithTTL overrides how long a listed view stays usable. A zero or negative
// TTL disables caching, which is what a one-shot command wants; a long-lived
// console should not use it.
func WithTTL(ttl time.Duration) Option {
	return func(r *Reader) { r.ttl = ttl }
}

// WithListLimit overrides the per-view object cap. Values below 1 are ignored,
// because a limit of zero means "unbounded" to the API server and that is the
// one thing this package is here to prevent.
func WithListLimit(limit int) Option {
	return func(r *Reader) {
		if limit > 0 {
			r.limit = limit
		}
	}
}

// WithClock replaces the clock used for ages and cache expiry, so tests can
// step over a TTL without sleeping.
func WithClock(now func() time.Time) Option {
	return func(r *Reader) {
		if now != nil {
			r.now = now
		}
	}
}

// New builds a Reader over an existing controller-runtime client.
//
// It returns an error rather than accepting nil, because a nil client here
// means the CLI never managed to load a kubeconfig, and the console needs to
// say that in a sentence an operator can act on instead of panicking on the
// first list.
func New(c client.Client, opts ...Option) (*Reader, error) {
	if c == nil {
		return nil, &Error{Reason: ReasonNoClient}
	}
	r := &Reader{
		c:     c,
		ttl:   DefaultTTL,
		limit: DefaultListLimit,
		now:   time.Now,
	}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// NewScheme returns a scheme with the Pahlevan v1beta1 types registered.
//
// Offered because a client built without them fails every list in this package
// with a scheme error that reads nothing like a cluster problem, and the fix
// belongs next to the code that needs it.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := policyv1beta1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("registering Pahlevan v1beta1 types: %w", err)
	}
	return s, nil
}

// Limit reports the per-view object cap in force.
func (r *Reader) Limit() int { return r.limit }

// TTL reports the cache lifetime in force.
func (r *Reader) TTL() time.Duration { return r.ttl }

// Truncated reports whether the last successful read of a view hit the limit,
// so the console can tell the operator they are looking at a prefix. A view
// that has never been read successfully reports false.
func (r *Reader) Truncated(v View) bool {
	switch v {
	case ViewPolicies:
		return r.policies.readTruncated()
	case ViewProfiles:
		return r.profiles.readTruncated()
	case ViewAttackSurfaces:
		return r.surfaces.readTruncated()
	default:
		return false
	}
}

func (e *entry[T]) readTruncated() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.valid && e.truncated
}

// Invalidate drops every cached view, so the next call re-reads. It is what a
// manual refresh key should call.
func (r *Reader) Invalidate() {
	r.policies.invalidate()
	r.profiles.invalidate()
	r.surfaces.invalidate()
}

func (e *entry[T]) invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.valid = false
}

// Policies lists PahlevanPolicies, newest cache first.
//
// On a refresh failure it returns the last good data together with a non-nil
// error: a transient API blip must not blank a screen an operator is reading
// mid-incident. Callers should render what they get and show the error beside
// it rather than instead of it.
func (r *Reader) Policies(ctx context.Context) ([]Policy, error) {
	return read(ctx, r, &r.policies, r.listPolicies)
}

// Profiles lists ContainerProfiles. Stale-on-error, as Policies.
func (r *Reader) Profiles(ctx context.Context) ([]Profile, error) {
	return read(ctx, r, &r.profiles, r.listProfiles)
}

// AttackSurfaces lists AttackSurface reports. Stale-on-error, as Policies.
func (r *Reader) AttackSurfaces(ctx context.Context) ([]AttackSurface, error) {
	return read(ctx, r, &r.surfaces, r.listSurfaces)
}

// read is the cache, the cancellation check and the stale-on-error rule, in one
// place so all three views cannot drift apart.
func read[T any](ctx context.Context, r *Reader, e *entry[T], load func(context.Context) ([]T, bool, error)) ([]T, error) {
	if r == nil || r.c == nil {
		return nil, &Error{Reason: ReasonNoClient}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.valid && r.ttl > 0 && r.now().Sub(e.fetchedAt) < r.ttl {
		return slices.Clone(e.data), nil
	}

	// Checked before the call rather than left to the client: a canceled
	// context must return immediately, and a fake or cached client is free to
	// ignore ctx entirely and hand back data the caller no longer wants.
	if err := ctx.Err(); err != nil {
		return slices.Clone(e.data), classify(err, "")
	}

	data, truncated, err := load(ctx)
	if err != nil {
		// Last good data, plus the error. The caller decides how loudly to say
		// "this is from N seconds ago".
		return slices.Clone(e.data), err
	}

	e.data = data
	e.fetchedAt = r.now()
	e.valid = true
	e.truncated = truncated
	return slices.Clone(e.data), nil
}

// listOpts is the single place a List is bounded.
func (r *Reader) listOpts() []client.ListOption {
	return []client.ListOption{client.Limit(int64(r.limit))}
}

// cap trims items to the limit and reports whether it had to.
func capItems[T any](items []T, limit int) ([]T, bool) {
	if limit > 0 && len(items) > limit {
		return items[:limit], true
	}
	return items, false
}

func (r *Reader) listPolicies(ctx context.Context) ([]Policy, bool, error) {
	var list policyv1beta1.PahlevanPolicyList
	if err := r.c.List(ctx, &list, r.listOpts()...); err != nil {
		return nil, false, classify(err, "pahlevanpolicies")
	}
	items, truncated := capItems(list.Items, r.limit)
	now := r.now()
	out := make([]Policy, 0, len(items))
	for i := range items {
		out = append(out, policyRow(&items[i], now))
	}
	sortRows(out, func(p Policy) (string, string) { return p.Namespace, p.Name })
	return out, truncated, nil
}

func (r *Reader) listProfiles(ctx context.Context) ([]Profile, bool, error) {
	var list policyv1beta1.ContainerProfileList
	if err := r.c.List(ctx, &list, r.listOpts()...); err != nil {
		return nil, false, classify(err, "containerprofiles")
	}
	items, truncated := capItems(list.Items, r.limit)
	now := r.now()
	out := make([]Profile, 0, len(items))
	for i := range items {
		out = append(out, profileRow(&items[i], now))
	}
	sortRows(out, func(p Profile) (string, string) { return p.Namespace, p.Name })
	return out, truncated, nil
}

func (r *Reader) listSurfaces(ctx context.Context) ([]AttackSurface, bool, error) {
	var list policyv1beta1.AttackSurfaceList
	if err := r.c.List(ctx, &list, r.listOpts()...); err != nil {
		return nil, false, classify(err, "attacksurfaces")
	}
	items, truncated := capItems(list.Items, r.limit)
	now := r.now()
	out := make([]AttackSurface, 0, len(items))
	for i := range items {
		out = append(out, surfaceRow(&items[i], now))
	}
	sortRows(out, func(a AttackSurface) (string, string) { return a.Namespace, a.Name })
	return out, truncated, nil
}

// sortRows orders rows by namespace then name.
//
// The API server's list order is not guaranteed stable, and a table whose rows
// reshuffle under the cursor every two seconds is one an operator cannot read a
// value off of. Sorting here means the console never has to.
func sortRows[T any](rows []T, key func(T) (string, string)) {
	sort.SliceStable(rows, func(i, j int) bool {
		ai, bi := key(rows[i])
		aj, bj := key(rows[j])
		if ai != aj {
			return ai < aj
		}
		return bi < bj
	})
}

func policyRow(p *policyv1beta1.PahlevanPolicy, now time.Time) Policy {
	row := Policy{
		Namespace:    p.Namespace,
		Name:         p.Name,
		Phase:        orUnknown(string(p.Status.Phase)),
		Enforcement:  enforcementLabel(p.Spec.EnforcementConfig),
		Selector:     FormatSelector(p.Spec.Selector),
		Declarations: declarationCount(p.Spec.LearningConfig.ExpectedBehavior),
		Created:      p.CreationTimestamp.Time,
		Age:          age(p.CreationTimestamp, now),
	}

	// Every one of these is a pointer on the CRD, and a policy that has just
	// been applied has all of them nil. That is the normal state of a new
	// policy, not an error, and it must render as a row rather than a panic.
	if ls := p.Status.LearningStatus; ls != nil {
		row.SamplesCollected = ls.SamplesCollected
		if ls.Progress != nil {
			row.LearningProgress = clampPercent(int(*ls.Progress))
			row.HasLearningProgress = true
		}
	}
	if es := p.Status.EnforcementStatus; es != nil {
		row.ContainersEnforcing = int(es.EnforcingContainers)
		row.ContainersTotal = int(es.TotalContainers)
		row.Denials = denialTotal(es)
	}
	return row
}

// denialTotal prefers the reported total but never reports less than the
// breakdown adds up to: an operator seeing "0 denials" next to a non-zero
// blocked-file count would reasonably conclude the console is broken, and one
// of the two numbers is written by an older agent than the other.
// declarationCount counts what a policy asserts rather than what was learned.
// The whole block is optional and usually absent, so it is a pointer and a nil
// one is the normal case, not a missing value.
func declarationCount(e *policyv1beta1.ExpectedBehavior) int {
	if e == nil {
		return 0
	}
	return len(e.Files) + len(e.NetworkDestinations) + len(e.Executables) + len(e.Capabilities)
}

func denialTotal(es *policyv1beta1.EnforcementStatus) int64 {
	sum := es.BlockedNetworkConnections + es.BlockedFileAccess + es.BlockedExecs + es.BlockedCapabilities
	if es.BlockedTotal > sum {
		return es.BlockedTotal
	}
	return sum
}

func profileRow(p *policyv1beta1.ContainerProfile, now time.Time) Profile {
	s := &p.Status
	row := Profile{
		Namespace:    p.Namespace,
		Name:         p.Name,
		Pod:          orUnknown(p.Spec.PodName),
		Container:    shortContainerID(p.Spec.ContainerID),
		Node:         orUnknown(p.Spec.Node),
		Phase:        orUnknown(string(s.Phase)),
		Files:        countOf(s.FileCount, len(s.LearnedFiles)),
		Network:      countOf(s.NetworkCount, len(s.LearnedNetworkDestinations)),
		Syscalls:     countOf(s.SyscallCount, len(s.LearnedSyscalls)),
		Capabilities: len(s.LearnedCapabilities),
		Declared: len(s.DeclaredFiles) + len(s.DeclaredNetworkDestinations) +
			len(s.DeclaredExecutables) + len(s.DeclaredCapabilities),
		Rollbacks: int(s.RollbackCount),
		Denials:   int(s.DenialCount),
		Created:   p.CreationTimestamp.Time,
		Age:       age(p.CreationTimestamp, now),
	}
	row.Confidence = profileConfidence(row)
	return row
}

// countOf reconciles the agent's count field with the length of the list it
// summarizes. They disagree when the agent trimmed the list to keep the object
// under the API server's size limit, and in that case the count is the true
// number - so the larger of the two is the one that is not an undercount.
func countOf(reported int32, listed int) int {
	if int(reported) > listed {
		return int(reported)
	}
	return listed
}

// profileConfidence scores how much weight to put on a learned baseline.
//
// The CRD carries no confidence field, so this is derived rather than read, and
// the derivation is kept deliberately blunt and explainable - an operator has
// to be able to say why a number moved:
//
//   - A profile with no learned signal at all has no baseline to be confident
//     in, whatever phase it claims: 0.
//   - Learning starts at 0.5. It is provisional by definition; the window has
//     not closed.
//   - Enforcing starts at 0.9. The baseline survived a transition, which is
//     real evidence, but never 1.0: learning only ever sees a window, so a
//     once-a-week operation may still be missing from it.
//   - Each rollback costs 0.2. A rollback is the cluster having already
//     concluded this baseline was breaking the workload.
//   - Any denial under enforcement costs 0.1, once. It means the container did
//     something learning did not see, which is the definition of an incomplete
//     baseline - but the count is noisy (one retry loop is thousands), so it
//     is a flag, not a multiplier.
//
// The result is clamped to [0,1] and rounded to two decimals so a table column
// does not jitter in its fifth digit between refreshes.
func profileConfidence(p Profile) float64 {
	if p.Files+p.Network+p.Syscalls+p.Capabilities == 0 {
		return 0
	}
	var c float64
	switch p.Phase {
	case string(policyv1beta1.ProfilePhaseEnforcing):
		c = 0.9
	case string(policyv1beta1.ProfilePhaseLearning):
		c = 0.5
	default:
		// An unreported phase is not evidence of anything.
		return 0
	}
	c -= 0.2 * float64(p.Rollbacks)
	if p.Denials > 0 {
		c -= 0.1
	}
	// Only a floor is needed: the score starts at its maximum and every term
	// below subtracts, so it can never exceed the starting value.
	if c < 0 {
		c = 0
	}
	return float64(int(c*100+0.5)) / 100
}

func surfaceRow(a *policyv1beta1.AttackSurface, now time.Time) AttackSurface {
	s := &a.Status
	ports, portTotal := capField(s.ExposedPorts)
	paths, pathTotal := capField(s.WritableFiles)
	caps, capTotal := capField(s.Capabilities)

	row := AttackSurface{
		Namespace:         a.Namespace,
		Name:              a.Name,
		Workload:          workloadLabel(a.Spec.Workload, a.Spec.PolicyRef),
		ExposedPorts:      ports,
		ExposedPortTotal:  portTotal,
		WritablePaths:     paths,
		WritablePathTotal: pathTotal,
		Capabilities:      caps,
		CapabilityTotal:   capTotal,
		Created:           a.CreationTimestamp.Time,
		Age:               age(a.CreationTimestamp, now),
	}
	if s.RiskScore != nil {
		row.RiskScore = clampPercent(int(*s.RiskScore))
		row.HasRiskScore = true
	}
	if s.LastAnalysis != nil {
		row.LastAnalysis = s.LastAnalysis.Time
		row.HasLastAnalysis = true
	}
	return row
}

// capField trims a per-object list and reports its true length. The returned
// slice is a copy: handing out a sub-slice of the listed object would let a
// caller's append write into memory the cache still holds.
func capField[T any](in []T) ([]T, int) {
	total := len(in)
	if total == 0 {
		return nil, 0
	}
	n := total
	if n > maxFieldItems {
		n = maxFieldItems
	}
	return slices.Clone(in[:n]), total
}

// workloadLabel names the analyzed workload, falling back to the policy the
// surface was computed for. Never empty: a surface row with a blank subject
// cannot be acted on.
func workloadLabel(w *policyv1beta1.WorkloadReference, policyRef string) string {
	if w != nil {
		switch {
		case w.Kind != "" && w.Name != "":
			return w.Kind + "/" + w.Name
		case w.Name != "":
			return w.Name
		}
	}
	if policyRef != "" {
		return "policy/" + policyRef
	}
	return unknown
}

// enforcementLabel is the effective mode.
//
// alertOnly downgrades Blocking to monitoring in the data plane, so printing
// the raw mode would tell an operator a workload is protected while nothing is
// being blocked. An unset mode is reported as such rather than guessed at.
func enforcementLabel(c policyv1beta1.EnforcementConfig) string {
	mode := string(c.Mode)
	if mode == "" {
		mode = unknown
	}
	if c.AlertOnly {
		return mode + " (alert only)"
	}
	// An explicit blockUnknown=false is the documented way to downgrade a
	// Blocking policy, and it is invisible in the mode field.
	if c.Mode == policyv1beta1.EnforcementModeBlocking && c.BlockUnknown != nil && !*c.BlockUnknown {
		return mode + " (unknown allowed)"
	}
	return mode
}

// shortContainerID trims a runtime ID to something that fits a column while
// still being greppable against `crictl ps`. The scheme prefix is dropped
// because `containerd://` is the same on every row and buys nothing.
func shortContainerID(id string) string {
	if id == "" {
		return unknown
	}
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

func orUnknown(s string) string {
	if s == "" {
		return unknown
	}
	return s
}

// clampPercent keeps a percentage in range. The CRD bounds these fields, but
// an object written before the bounds existed is still in etcd, and a progress
// bar drawn from 413% overruns its row.
func clampPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// age is never negative: a node with a skewed clock can stamp a creation time
// in the future, and "-3m" in an Age column reads as a bug in the console
// rather than a bug on the node.
func age(ts metav1.Time, now time.Time) time.Duration {
	if ts.IsZero() {
		return 0
	}
	d := now.Sub(ts.Time)
	if d < 0 {
		return 0
	}
	return d
}
