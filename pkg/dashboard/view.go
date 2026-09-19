package dashboard

import (
	"sort"
	"strconv"
	"strings"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// PhaseCounts is how many things are in each phase of the lifecycle. The four
// buckets are the whole story an overview has to tell: what has not started,
// what is watching, what is enforcing, and what went wrong.
type PhaseCounts struct {
	Initializing int `json:"initializing"`
	Learning     int `json:"learning"`
	Enforcing    int `json:"enforcing"`
	Failed       int `json:"failed"`
	Total        int `json:"total"`
}

// DenialTotals is the per-signal denial breakdown.
//
// Split rather than summed because "twelve denials" and "twelve denied egress
// attempts" are very different findings, and an operator triaging the second
// one starts somewhere completely different.
type DenialTotals struct {
	Files        int64 `json:"files"`
	Network      int64 `json:"network"`
	Execs        int64 `json:"execs"`
	Capabilities int64 `json:"capabilities"`
	Total        int64 `json:"total"`
}

func (d *DenialTotals) add(other DenialTotals) {
	d.Files += other.Files
	d.Network += other.Network
	d.Execs += other.Execs
	d.Capabilities += other.Capabilities
	d.Total += other.Total
}

// NamespaceSummary is one row of the overview.
type NamespaceSummary struct {
	Namespace  string       `json:"namespace"`
	Policies   int          `json:"policies"`
	Workloads  int          `json:"workloads"`
	Containers PhaseCounts  `json:"containers"`
	Denials    DenialTotals `json:"denials"`
	Rollbacks  int          `json:"rollbacks"`
	MaxRisk    int          `json:"maxRisk"`
}

// Overview is the cluster-wide answer to "what is Pahlevan doing", restricted
// to what the viewer's own RBAC allows. A namespace the viewer cannot list is
// absent from every field here, counts included: leaking "there are 40 denials
// somewhere you cannot see" is still leaking.
type Overview struct {
	Namespaces []NamespaceSummary `json:"namespaces"`
	Policies   PhaseCounts        `json:"policies"`
	Containers PhaseCounts        `json:"containers"`
	Denials    DenialTotals       `json:"denials"`
	Workloads  int                `json:"workloads"`
	Live       *Stats             `json:"live,omitempty"`
	Generated  time.Time          `json:"generated"`
}

// Surface is the behaviour a workload was observed to need, which is exactly
// what the kernel allows once it is enforcing.
type Surface struct {
	Files        []string `json:"files,omitempty"`
	Network      []string `json:"network,omitempty"`
	Syscalls     []string `json:"syscalls,omitempty"`
	Executables  []string `json:"executables,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`

	FileCount       int `json:"fileCount"`
	NetworkCount    int `json:"networkCount"`
	SyscallCount    int `json:"syscallCount"`
	ExecutableCount int `json:"executableCount"`
	CapabilityCount int `json:"capabilityCount"`

	// Truncated reports that a list was cut to SurfaceSampleLimit. A page
	// showing 200 of 4000 paths without saying so is a page that reads as a
	// complete profile.
	Truncated bool `json:"truncated,omitempty"`
}

// SurfaceSampleLimit bounds each learned list in a response. A container that
// opened forty thousand paths during learning would otherwise produce a JSON
// document no browser can render and no reader can use.
const SurfaceSampleLimit = 250

// FlowStage is one step of the learning-to-enforcement flow.
type FlowStage struct {
	Name   string     `json:"name"`
	State  string     `json:"state"`
	Detail string     `json:"detail,omitempty"`
	At     *time.Time `json:"at,omitempty"`
}

// Flow stage states.
const (
	StateDone    = "done"
	StateActive  = "active"
	StatePending = "pending"
	StateFailed  = "failed"
)

// WorkloadSummary is one workload as the list view shows it.
type WorkloadSummary struct {
	Namespace  string       `json:"namespace"`
	Kind       string       `json:"kind"`
	Name       string       `json:"name"`
	Policy     string       `json:"policy,omitempty"`
	Phase      string       `json:"phase"`
	Node       string       `json:"node,omitempty"`
	Containers PhaseCounts  `json:"containers"`
	Surface    Surface      `json:"surface"`
	Denials    DenialTotals `json:"denials"`
	Rollbacks  int          `json:"rollbacks"`
	Risk       int          `json:"risk"`
	LastUpdate *time.Time   `json:"lastUpdate,omitempty"`
	// Live is absent when no event store is wired, which is a different
	// statement from "no events seen": the page says which one it is rather
	// than drawing zeroes that look like a quiet workload.
	Live *Counts `json:"live,omitempty"`
}

// ContainerView is one learned container under a workload.
type ContainerView struct {
	Name           string       `json:"name"`
	Pod            string       `json:"pod,omitempty"`
	Node           string       `json:"node,omitempty"`
	Phase          string       `json:"phase"`
	FirstSeen      *time.Time   `json:"firstSeen,omitempty"`
	EnforcingSince *time.Time   `json:"enforcingSince,omitempty"`
	Attempts       int          `json:"attempts"`
	Rollbacks      int          `json:"rollbacks"`
	RollbackReason string       `json:"rollbackReason,omitempty"`
	Denials        DenialTotals `json:"denials"`
	Seccomp        *SeccompView `json:"seccomp,omitempty"`
}

// SeccompView is the generated profile, reported so the reduction it achieves
// is visible without going to look on the node.
type SeccompView struct {
	LocalhostProfile string `json:"localhostProfile,omitempty"`
	Node             string `json:"node,omitempty"`
	Allowed          int    `json:"allowed"`
	Total            int    `json:"total"`
	SkippedUnknown   int    `json:"skippedUnknown,omitempty"`
}

// AttackSurfaceView is the computed exposure report for a workload.
type AttackSurfaceView struct {
	Risk            int        `json:"risk"`
	ExposedSyscalls []string   `json:"exposedSyscalls,omitempty"`
	ExposedPorts    []int32    `json:"exposedPorts,omitempty"`
	WritableFiles   []string   `json:"writableFiles,omitempty"`
	Capabilities    []string   `json:"capabilities,omitempty"`
	LastAnalysis    *time.Time `json:"lastAnalysis,omitempty"`
}

// WorkloadDetail is everything the per-workload view draws.
type WorkloadDetail struct {
	WorkloadSummary
	Flow           []FlowStage        `json:"flow"`
	ContainerViews []ContainerView    `json:"containerViews,omitempty"`
	AttackSurface  *AttackSurfaceView `json:"attackSurface,omitempty"`
	Denied         []Denial           `json:"denied,omitempty"`
	Processes      []*ProcessNode     `json:"processes,omitempty"`
	// ProcessesTruncated mirrors Activity.ProcessesTruncated.
	ProcessesTruncated bool `json:"processesTruncated,omitempty"`
}

// workloadOf names the workload a profile belongs to. A profile whose owning
// workload could not be resolved is filed under its pod, because a pod name is
// still something an operator can look up, and dropping the profile would hide
// a container that is actually being enforced.
func workloadOf(p *policyv1alpha1.ContainerProfile) WorkloadKey {
	ns := p.Spec.Namespace
	if ns == "" {
		ns = p.Namespace
	}
	if w := p.Spec.Workload; w != nil && w.Kind != "" && w.Name != "" {
		if w.Namespace != "" {
			ns = w.Namespace
		}
		return WorkloadKey{Namespace: ns, Kind: w.Kind, Name: w.Name}
	}
	if p.Spec.PodName != "" {
		return WorkloadKey{Namespace: ns, Kind: "Pod", Name: p.Spec.PodName}
	}
	return WorkloadKey{Namespace: ns, Kind: "ContainerProfile", Name: p.Name}
}

// phaseOf normalises a profile phase. The agent writes "Learning" or
// "Enforcing"; an empty phase is a profile the agent has created but not yet
// reported on, and calling that "Learning" would overstate what is happening.
func phaseOf(phase string) string {
	if phase == "" {
		return "Unknown"
	}
	return phase
}

func (c *PhaseCounts) addPhase(phase string) {
	c.Total++
	switch strings.ToLower(phase) {
	case "learning":
		c.Learning++
	case "enforcing":
		c.Enforcing++
	case "failed", "rollingback":
		c.Failed++
	default:
		c.Initializing++
	}
}

func denialsOfProfile(st *policyv1alpha1.ContainerProfileStatus) DenialTotals {
	return DenialTotals{
		Files:        int64(st.DeniedFiles),
		Network:      int64(st.DeniedNetwork),
		Execs:        int64(st.DeniedExecs),
		Capabilities: int64(st.DeniedCapabilities),
		Total:        int64(st.DenialCount),
	}
}

// surfaceOf renders one container profile's learned baseline.
func surfaceOf(st *policyv1alpha1.ContainerProfileStatus) Surface {
	s := Surface{
		Files:           limitStrings(st.LearnedFiles),
		Network:         limitStrings(st.LearnedNetworkDestinations),
		Executables:     limitStrings(st.LearnedExecutables),
		Capabilities:    limitStrings(st.LearnedCapabilities),
		FileCount:       len(st.LearnedFiles),
		NetworkCount:    len(st.LearnedNetworkDestinations),
		ExecutableCount: len(st.LearnedExecutables),
		CapabilityCount: len(st.LearnedCapabilities),
		SyscallCount:    len(st.LearnedSyscalls),
	}
	// The profile stores syscall numbers because that is what the kernel
	// enforces on. A number is not something an operator can judge, so it is
	// rendered through the same table the rest of the tool uses.
	names := make([]string, 0, len(st.LearnedSyscalls))
	for _, nr := range st.LearnedSyscalls {
		if nr < 0 {
			continue
		}
		names = append(names, export.SyscallName(uint64(nr)))
	}
	sort.Strings(names)
	s.Syscalls = limitStrings(names)
	// The counts on the status are what the agent reported; the lists are what
	// it materialised. Where they disagree the status wins, because a status
	// written before the list was trimmed is the more complete number.
	if int(st.FileCount) > s.FileCount {
		s.FileCount = int(st.FileCount)
	}
	if int(st.NetworkCount) > s.NetworkCount {
		s.NetworkCount = int(st.NetworkCount)
	}
	if int(st.SyscallCount) > s.SyscallCount {
		s.SyscallCount = int(st.SyscallCount)
	}
	s.Truncated = s.FileCount > len(s.Files) || s.NetworkCount > len(s.Network) ||
		s.SyscallCount > len(s.Syscalls) || s.ExecutableCount > len(s.Executables) ||
		s.CapabilityCount > len(s.Capabilities)
	return s
}

func limitStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	n := len(in)
	if n > SurfaceSampleLimit {
		n = SurfaceSampleLimit
	}
	out := make([]string, n)
	copy(out, in[:n])
	return out
}

// mergeSurface unions two containers' baselines into the workload's. A
// Deployment's replicas learn separately, and showing only one replica's
// profile as "the workload's surface" would hide whatever the others needed.
func mergeSurface(dst *Surface, src Surface) {
	dst.Files = mergeSample(dst.Files, src.Files)
	dst.Network = mergeSample(dst.Network, src.Network)
	dst.Syscalls = mergeSample(dst.Syscalls, src.Syscalls)
	dst.Executables = mergeSample(dst.Executables, src.Executables)
	dst.Capabilities = mergeSample(dst.Capabilities, src.Capabilities)
	if src.FileCount > dst.FileCount {
		dst.FileCount = src.FileCount
	}
	if src.NetworkCount > dst.NetworkCount {
		dst.NetworkCount = src.NetworkCount
	}
	if src.SyscallCount > dst.SyscallCount {
		dst.SyscallCount = src.SyscallCount
	}
	if src.ExecutableCount > dst.ExecutableCount {
		dst.ExecutableCount = src.ExecutableCount
	}
	if src.CapabilityCount > dst.CapabilityCount {
		dst.CapabilityCount = src.CapabilityCount
	}
	dst.Truncated = dst.Truncated || src.Truncated ||
		len(dst.Files) < dst.FileCount || len(dst.Network) < dst.NetworkCount
}

// mergeSample unions two sorted-by-nothing samples, deduplicating and keeping
// the result bounded and ordered so two page loads agree.
func mergeSample(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > SurfaceSampleLimit {
		out = out[:SurfaceSampleLimit]
	}
	return out
}

// flowFor renders the learning-to-enforcement path for one workload.
//
// It is a flow rather than a phase string because the phase alone answers the
// wrong question. "Learning" does not say whether anything has been learned
// yet, and "Enforcing" does not say that it got there on the third attempt
// after two rollbacks - which is the single most useful thing to know about a
// profile that is about to be trusted.
func flowFor(summary WorkloadSummary, containers []ContainerView) []FlowStage {
	stages := make([]FlowStage, 0, 4)

	selected := FlowStage{Name: "Selected", State: StateDone,
		Detail: pluralise(summary.Containers.Total, "container", "containers") + " matched by the policy selector"}
	if summary.Containers.Total == 0 {
		selected.State = StatePending
		selected.Detail = "no container has reported a profile yet"
	}
	stages = append(stages, selected)

	learning := FlowStage{Name: "Learning", State: StatePending,
		Detail: "waiting for the agent to observe this workload"}
	if summary.Surface.SyscallCount+summary.Surface.FileCount+summary.Surface.NetworkCount > 0 {
		learning.Detail = describeSurface(summary.Surface)
		if summary.Containers.Learning > 0 {
			learning.State = StateActive
		} else {
			learning.State = StateDone
		}
	} else if summary.Containers.Learning > 0 {
		learning.State = StateActive
		learning.Detail = "observing; nothing has been added to the baseline yet"
	}
	if first := earliestFirstSeen(containers); first != nil {
		learning.At = first
	}
	stages = append(stages, learning)

	transition := FlowStage{Name: "Transition", State: StatePending,
		Detail: "the baseline has not been promoted to the kernel yet"}
	attempts := totalAttempts(containers)
	rollbacks := summary.Rollbacks
	switch {
	case rollbacks > 0:
		transition.State = StateFailed
		transition.Detail = pluralise(rollbacks, "rollback", "rollbacks") + " out of " +
			pluralise(attempts, "attempt", "attempts") + ": " + lastRollbackReason(containers)
	case attempts > 0:
		transition.State = StateDone
		transition.Detail = pluralise(attempts, "attempt", "attempts") + ", no rollback"
	}
	stages = append(stages, transition)

	enforcing := FlowStage{Name: "Enforcing", State: StatePending,
		Detail: "the kernel is not refusing anything for this workload yet"}
	if summary.Containers.Enforcing > 0 {
		enforcing.State = StateActive
		enforcing.Detail = pluralise(summary.Containers.Enforcing, "container", "containers") +
			" enforcing, " + pluralise(int(summary.Denials.Total), "denial", "denials") + " since"
		if since := earliestEnforcingSince(containers); since != nil {
			enforcing.At = since
		}
	}
	stages = append(stages, enforcing)
	return stages
}

func describeSurface(s Surface) string {
	return pluralise(s.SyscallCount, "syscall", "syscalls") + ", " +
		pluralise(s.FileCount, "path", "paths") + ", " +
		pluralise(s.NetworkCount, "destination", "destinations") + " learned"
}

func pluralise(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return strconv.Itoa(n) + " " + word
}

func earliestFirstSeen(cs []ContainerView) *time.Time {
	var out *time.Time
	for i := range cs {
		if t := cs[i].FirstSeen; t != nil && (out == nil || t.Before(*out)) {
			out = t
		}
	}
	return out
}

func earliestEnforcingSince(cs []ContainerView) *time.Time {
	var out *time.Time
	for i := range cs {
		if t := cs[i].EnforcingSince; t != nil && (out == nil || t.Before(*out)) {
			out = t
		}
	}
	return out
}

func totalAttempts(cs []ContainerView) int {
	total := 0
	for i := range cs {
		total += cs[i].Attempts
	}
	return total
}

func lastRollbackReason(cs []ContainerView) string {
	for i := range cs {
		if cs[i].RollbackReason != "" {
			return cs[i].RollbackReason
		}
	}
	return "the agent did not record a reason"
}
