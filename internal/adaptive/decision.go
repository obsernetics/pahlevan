package adaptive

import (
	"net"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// Mode is how a policy governs a container, mirroring
// PahlevanPolicySpec.EnforcementConfig.Mode.
type Mode string

const (
	// ModeOff means the container is not governed at all: no learning, no
	// profile, no enforcement. Distinct from Monitoring, which still learns.
	ModeOff Mode = "Off"
	// ModeMonitoring learns and reports but never flips the kernel to
	// enforcing. This is the safe default for a new workload.
	ModeMonitoring Mode = "Monitoring"
	// ModeBlocking learns and then denies anything outside the baseline
	// in-kernel.
	ModeBlocking Mode = "Blocking"
)

// Destination is a concrete egress endpoint that can be seeded into the kernel
// allow-set. Only exact addresses are representable: the allow-set is a hash
// map, so a CIDR wider than a single host cannot be enumerated into it.
type Destination struct {
	IP   net.IP
	Port uint16
}

// Overrides are the operator-authored additions and subtractions applied to a
// learned baseline. Allowed entries are written into the kernel allow-sets
// before the container flips to enforcing, so behavior that never occurred
// during the learning window is still permitted. Denied entries are removed
// from the allow-set, so they are refused even if they were learned.
//
// This is what keeps "no rules to write" from meaning "no say in the outcome":
// the baseline is learned, and the operator corrects it at the edges.
type Overrides struct {
	// AllowedFiles and DeniedFiles govern reads. Writes are separate entries in
	// the kernel allow-set, so permitting a read does not permit a write.
	AllowedFiles []string
	DeniedFiles  []string

	// AllowedWriteFiles and DeniedWriteFiles govern writes to a path.
	AllowedWriteFiles []string
	DeniedWriteFiles  []string

	AllowedExecs []string
	DeniedExecs  []string

	AllowedCapabilities []uint32
	DeniedCapabilities  []uint32

	AllowedDestinations []Destination
	DeniedDestinations  []Destination

	// AllowedSyscalls and DeniedSyscalls adjust the generated seccomp profile
	// rather than a BPF map: syscalls are enforced by seccomp, while the BPF
	// syscall program is observation-only.
	AllowedSyscalls []string
	DeniedSyscalls  []string

	// ProcFilter constrains who may exec, as opposed to what may be exec'd.
	// It is not an allow-set correction like the fields above: the allow-set
	// answers "has this container run this binary", and the filter answers
	// "is this process allowed to run it". Both are enforced in
	// bprm_check_security. A nil filter means no constraint.
	ProcFilter *ebpf.ProcFilter
}

// Empty reports whether there is nothing to apply.
func (o Overrides) Empty() bool {
	return len(o.AllowedFiles) == 0 && len(o.DeniedFiles) == 0 &&
		len(o.AllowedWriteFiles) == 0 && len(o.DeniedWriteFiles) == 0 &&
		len(o.AllowedExecs) == 0 && len(o.DeniedExecs) == 0 &&
		len(o.AllowedCapabilities) == 0 && len(o.DeniedCapabilities) == 0 &&
		len(o.AllowedDestinations) == 0 && len(o.DeniedDestinations) == 0 &&
		len(o.AllowedSyscalls) == 0 && len(o.DeniedSyscalls) == 0 &&
		o.ProcFilter.Empty()
}

// Decision is how one PahlevanPolicy governs one container. It replaces the
// earlier (window, blocking, ok) triple, which could express only a fraction of
// what the CRD already accepted: grace periods, the Off/Monitoring distinction,
// and every exception and allow/deny list were parsed into the API type and
// then silently dropped.
type Decision struct {
	// PolicyName is the governing PahlevanPolicy, for events and metrics.
	PolicyName string

	// Mode is the enforcement mode after AlertOnly and BlockUnknown are folded
	// in, so the controller never has to re-derive it.
	Mode Mode

	// Window is the learning duration.
	Window time.Duration

	// GracePeriod is held after the learning window closes before enforcement
	// begins. It exists so a workload whose startup differs from its steady
	// state gets observed in both before anything is denied.
	GracePeriod time.Duration

	// Overrides are the operator's corrections to the learned baseline.
	Overrides Overrides

	// SelfHealing is the policy's rollback configuration. The agent used to
	// apply compiled-in defaults and ignore spec.selfHealing entirely, so a
	// policy that switched self-healing off still had its containers
	// un-enforced by denial noise.
	SelfHealing SelfHealingDecision
}

// SelfHealingDecision is how a policy configures rollback out of enforcement.
type SelfHealingDecision struct {
	// Enabled reflects spec.selfHealing.enabled. When false the container stays
	// enforcing whatever happens, which is what an operator who turned it off
	// asked for.
	Enabled bool

	// Threshold is the denial count that triggers a rollback, from
	// spec.selfHealing.rollbackThreshold. Zero means use the controller default.
	Threshold int

	// Window is how long after the enforce transition denials are attributable
	// to it, from spec.selfHealing.rollbackWindow. Zero means use the default.
	Window time.Duration
}

// EnforceAfter is the total time from the start of learning to the enforce
// transition.
func (d Decision) EnforceAfter() time.Duration { return d.Window + d.GracePeriod }

// Blocking reports whether this decision ever reaches in-kernel enforcement.
func (d Decision) Blocking() bool { return d.Mode == ModeBlocking }

// Tracked reports whether the container should be observed at all. An Off
// policy is the operator saying "ignore this workload", which must not cost a
// profile, a learned set, or a CR.
func (d Decision) Tracked() bool { return d.Mode != ModeOff }
