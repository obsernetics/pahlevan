package ebpf

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// Action is what the kernel does with an operation outside the learned set.
//
// For a long time there were two answers: refuse with EPERM, or - for exec
// only - refuse and kill. Two is not enough for the range of situations an
// operator is actually in.
//
// Somebody rolling enforcement out to a workload they do not fully understand
// needs to know what *would* be denied before anything is. Learning mode is a
// poor substitute, because it widens the allow-set as it goes: the very thing
// that would have been denied is added to the set instead of being reported.
// Somebody responding to an incident often wants the process frozen rather
// than destroyed, because SIGKILL takes the process memory with it and that
// memory is the evidence. And a workload that copes with ENOENT but treats
// EPERM as fatal is better served by the errno it can handle.
//
// The kernel half is bpf/enforce.h and the two must move together.
type Action uint8

const (
	// ActionLearn observes and widens the allow-set. Denies nothing.
	ActionLearn Action = 0
	// ActionDeny refuses with the configured errno, EPERM by default.
	ActionDeny Action = 1
	// ActionKill refuses and sends SIGKILL to the task that tried.
	ActionKill Action = 2
	// ActionAudit reports what would have been refused, and allows it.
	//
	// The only action that reports a violation and lets it through, which is
	// what makes it useful for a rollout and worth keeping distinct from the
	// others. It deliberately does not learn: an audit pass that quietly added
	// everything it reported would report each violation once and never again,
	// which is the opposite of what somebody enabling it wants.
	ActionAudit Action = 3
	// ActionSignal refuses and sends a configured signal.
	//
	// SIGSTOP is the reason this exists: freezing a process leaves its memory,
	// its open descriptors and its thread state intact for somebody to look at,
	// where SIGKILL destroys exactly the evidence an incident responder needs.
	ActionSignal Action = 4
)

// String renders an action for logs and status.
func (a Action) String() string {
	switch a {
	case ActionLearn:
		return "Learn"
	case ActionDeny:
		return "Deny"
	case ActionKill:
		return "Kill"
	case ActionAudit:
		return "Audit"
	case ActionSignal:
		return "Signal"
	}
	return "Action(" + strconv.Itoa(int(a)) + ")"
}

// Valid reports whether an action is one the kernel programs implement.
//
// An unknown action must not be written to the map. The kernel treats anything
// that is not ACT_LEARN as denying, so a typo'd action number would silently
// enforce rather than silently do nothing - the wrong direction to fail in for
// a value that arrives from a CRD.
func (a Action) Valid() bool { return a <= ActionSignal }

// Denies reports whether an action refuses the operation.
func (a Action) Denies() bool {
	return a == ActionDeny || a == ActionKill || a == ActionSignal
}

// ParseAction reads an action name, case-insensitively.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "learn", "":
		return ActionLearn, nil
	case "deny":
		return ActionDeny, nil
	case "kill":
		return ActionKill, nil
	case "audit":
		return ActionAudit, nil
	case "signal":
		return ActionSignal, nil
	}
	return 0, fmt.Errorf("unknown enforcement action %q: want one of Learn, Deny, Kill, Audit, Signal", s)
}

// EnforcementSpec is one cgroup's complete enforcement configuration.
//
// It packs into the single __u32 the kernel reads from the per-cgroup mode
// map, so the hot path costs one lookup and no second map.
type EnforcementSpec struct {
	Action Action
	// Signal is sent when Action is ActionSignal. Ignored otherwise.
	Signal syscall.Signal
	// Errno is returned to the caller instead of EPERM. Zero means EPERM.
	//
	// Only the value matters, not the sign: 1 is EPERM, 2 is ENOENT, 13 is
	// EACCES. The kernel program negates it.
	Errno uint16
}

// Validate rejects a spec the kernel would misinterpret.
func (s EnforcementSpec) Validate() error {
	if !s.Action.Valid() {
		return fmt.Errorf("enforcement action %d is not implemented", s.Action)
	}
	if s.Action == ActionSignal {
		if s.Signal <= 0 || s.Signal > 64 {
			return fmt.Errorf(
				"enforcement action Signal needs a signal between 1 and 64, got %d", s.Signal)
		}
	}
	// An errno above 4095 is not an errno. Returning one from an LSM hook
	// produces a value the kernel reads as a valid pointer rather than as an
	// error, which turns a denial into undefined behaviour.
	if s.Errno > 4095 {
		return fmt.Errorf("errno %d is out of range; the kernel reserves values above 4095", s.Errno)
	}
	if s.Errno != 0 && !s.Action.Denies() {
		return fmt.Errorf(
			"errno %d is set on action %s, which does not deny anything", s.Errno, s.Action)
	}
	if s.Signal != 0 && s.Action != ActionSignal {
		return fmt.Errorf(
			"signal %d is set on action %s, which does not signal", s.Signal, s.Action)
	}
	return nil
}

// Pack renders the spec as the __u32 the kernel map holds:
//
//	bits  0-7   action
//	bits  8-15  signal number
//	bits 16-31  errno, 0 meaning EPERM
func (s EnforcementSpec) Pack() uint32 {
	return uint32(s.Action) | uint32(uint8(s.Signal))<<8 | uint32(s.Errno)<<16
}

// UnpackEnforcementSpec is Pack's inverse, for reading back what is installed.
func UnpackEnforcementSpec(v uint32) EnforcementSpec {
	return EnforcementSpec{
		Action: Action(v & 0xff),
		Signal: syscall.Signal((v >> 8) & 0xff),
		Errno:  uint16((v >> 16) & 0xffff),
	}
}

// String renders the spec the way an operator reads it in a log line.
func (s EnforcementSpec) String() string {
	switch s.Action {
	case ActionSignal:
		return fmt.Sprintf("Signal(%s) with %s", signalName(s.Signal), s.errnoName())
	case ActionKill:
		return "Kill with " + s.errnoName()
	case ActionDeny:
		return "Deny with " + s.errnoName()
	default:
		return s.Action.String()
	}
}

func (s EnforcementSpec) errnoName() string {
	if s.Errno == 0 {
		return "EPERM"
	}
	if e := syscall.Errno(s.Errno); e.Error() != "" {
		return strings.ToUpper(errnoConst(e))
	}
	return "errno " + strconv.Itoa(int(s.Errno))
}

// errnoConst names the handful of errnos it makes sense to return from a denied
// operation. Anything else is rendered numerically rather than guessed at.
func errnoConst(e syscall.Errno) string {
	switch e {
	case syscall.EPERM:
		return "EPERM"
	case syscall.ENOENT:
		return "ENOENT"
	case syscall.EACCES:
		return "EACCES"
	case syscall.EIO:
		return "EIO"
	case syscall.ENOSYS:
		return "ENOSYS"
	case syscall.ECONNREFUSED:
		return "ECONNREFUSED"
	case syscall.ENETUNREACH:
		return "ENETUNREACH"
	case syscall.EHOSTUNREACH:
		return "EHOSTUNREACH"
	}
	return "errno " + strconv.Itoa(int(e))
}

func signalName(s syscall.Signal) string {
	if n := s.String(); n != "" && !strings.HasPrefix(n, "signal ") {
		return n
	}
	return "signal " + strconv.Itoa(int(s))
}

// setActionOn writes a spec into one of the per-cgroup mode maps.
//
// ActionLearn deletes the entry rather than writing a zero. The two are
// equivalent to the kernel, and deleting keeps the map's occupancy proportional
// to the number of cgroups actually being enforced rather than to every cgroup
// that has ever been reconciled.
func setActionOn(mp bpfMap, name string, cgroupID uint64, spec EnforcementSpec) error {
	if mp == nil {
		return fmt.Errorf("the %s map is absent from the loaded object", name)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.Action == ActionLearn {
		_ = mp.Delete(&cgroupID)
		return nil
	}
	v := spec.Pack()
	return mp.Put(&cgroupID, &v)
}

// bpfMap is the slice of *ebpf.Map the setters use, so they can be tested
// without a kernel.
type bpfMap interface {
	Put(key, value any) error
	Delete(key any) error
}

// SetFileAction sets what happens when a governed cgroup opens a path outside
// its learned set.
func (m *Manager) SetFileAction(cgroupID uint64, spec EnforcementSpec) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.fileCollection == nil {
		return fmt.Errorf("the file monitor is not loaded (bpf LSM unavailable?)")
	}
	return setActionOn(m.fileCollection.Maps["file_mode"], "file_mode", cgroupID, spec)
}

// SetNetworkAction sets what happens when a governed cgroup connects to a
// destination outside its learned set.
func (m *Manager) SetNetworkAction(cgroupID uint64, spec EnforcementSpec) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.networkCollection == nil {
		return fmt.Errorf("the network monitor is not loaded (bpf LSM unavailable?)")
	}
	return setActionOn(m.networkCollection.Maps["network_mode"], "network_mode", cgroupID, spec)
}

// SetExecAction sets what happens when a governed cgroup executes a binary
// outside its learned set, or one its process filter rejects.
func (m *Manager) SetExecAction(cgroupID uint64, spec EnforcementSpec) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.execCollection == nil {
		return fmt.Errorf("the exec monitor is not loaded (bpf LSM unavailable?)")
	}
	return setActionOn(m.execCollection.Maps["exec_mode"], "exec_mode", cgroupID, spec)
}

// SetCapabilityAction sets what happens when a governed cgroup exercises a
// capability outside its learned set.
func (m *Manager) SetCapabilityAction(cgroupID uint64, spec EnforcementSpec) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.capCollection == nil {
		return fmt.Errorf("the capability monitor is not loaded (bpf LSM unavailable?)")
	}
	return setActionOn(m.capCollection.Maps["cap_mode"], "cap_mode", cgroupID, spec)
}

// SetAction applies one spec to every hook at once, which is what a policy
// transition wants.
//
// Every hook that is loaded is set; a hook that is not loaded is skipped rather
// than failing the call, because the agent runs in a degraded mode on kernels
// without the BPF LSM and a policy transition there should configure what it
// can. The returned error names every hook that failed, so a partial
// application is visible rather than silent.
func (m *Manager) SetAction(cgroupID uint64, spec EnforcementSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	var failed []string
	for _, h := range []struct {
		name string
		set  func(uint64, EnforcementSpec) error
		on   bool
	}{
		{"file", m.SetFileAction, m.fileCollection != nil},
		{"network", m.SetNetworkAction, m.networkCollection != nil},
		{"exec", m.SetExecAction, m.execCollection != nil},
		{"capability", m.SetCapabilityAction, m.capCollection != nil},
	} {
		if !h.on {
			continue
		}
		if err := h.set(cgroupID, spec); err != nil {
			failed = append(failed, h.name+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("applying %s to cgroup %d: %s", spec, cgroupID, strings.Join(failed, "; "))
	}
	return nil
}
