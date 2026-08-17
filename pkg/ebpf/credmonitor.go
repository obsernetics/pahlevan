package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// Flags on a CredEvent, mirroring bpf/cred_monitor.c. The two halves must move
// together.
const (
	// CredGainedRoot means the effective uid became 0 and was not 0 before.
	CredGainedRoot uint32 = 0x01
	// CredGainedCaps means the effective capability set grew.
	CredGainedCaps uint32 = 0x02
	// CredInExecve means an execve was underway, so a setuid binary explains
	// the change. Its absence on an escalation is the interesting case.
	CredInExecve uint32 = 0x04
	// CredKilled means the task was sent SIGKILL by the kernel program.
	CredKilled uint32 = 0x08
	// CredLostRoot means the effective uid stopped being 0 - a daemon
	// dropping privilege, reported only when something was also gained.
	CredLostRoot uint32 = 0x10
)

// CredEvent is a credential change observed by the kprobe on commit_creds.
//
// Every other event in Pahlevan describes a request the kernel was asked to
// satisfy. This one describes a result: the moment a task's privileges
// actually changed, whatever route it took. A kernel exploit that overwrites a
// cred struct and calls commit_creds directly produces one of these and no
// syscall event at all.
type CredEvent struct {
	CgroupID    uint64
	Timestamp   uint64
	OldCaps     uint64
	NewCaps     uint64
	PID         uint32
	TID         uint32
	OldUID      uint32
	NewUID      uint32
	OldEUID     uint32
	NewEUID     uint32
	Flags       uint32
	Comm        string
	ContainerID string
}

// Denied reports whether the kernel acted on this event. Named to match the
// other event types, where the same question is asked of a Flags field.
func (e *CredEvent) Denied() bool { return e.Flags&CredKilled != 0 }

// Unexplained reports whether privilege was gained with no execve underway.
//
// This is the discriminator the whole monitor exists for. A setuid binary
// gains privilege inside execve, and sudo, ping and passwd all do it dozens of
// times a day in an ordinary container. A task whose credentials change with
// no execve in progress either called a setuid syscall - which the syscall
// monitor reports, with its arguments - or did something the kernel has no
// other name for.
func (e *CredEvent) Unexplained() bool {
	return e.Flags&(CredGainedRoot|CredGainedCaps) != 0 && e.Flags&CredInExecve == 0
}

// GainedCapabilities lists the capabilities added by this change, by name.
func (e *CredEvent) GainedCapabilities() []string {
	return CapabilityNames(e.NewCaps &^ e.OldCaps)
}

// Summary renders the event the way an operator reads it.
func (e *CredEvent) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s[%d] uid %d->%d euid %d->%d", e.Comm, e.PID, e.OldUID, e.NewUID, e.OldEUID, e.NewEUID)
	if caps := e.GainedCapabilities(); len(caps) > 0 {
		fmt.Fprintf(&b, " gained %s", strings.Join(caps, ","))
	}
	if e.Flags&CredInExecve != 0 {
		b.WriteString(" (during execve)")
	} else {
		b.WriteString(" (no execve underway)")
	}
	if e.Flags&CredKilled != 0 {
		b.WriteString(" KILLED")
	}
	return b.String()
}

// CredEventHandler receives credential-change events.
//
// Separate from EventHandler and satisfied by type assertion, so a handler
// that has no interest in credential changes is not made to stub a method for
// them. Every registered handler is offered the event; those that do not
// implement this are skipped.
type CredEventHandler interface {
	HandleCredEvent(event *CredEvent) error
}

// parseCredEvent decodes `struct cred_event` from bpf/cred_monitor.c:
//
//	__u64 cgroup_id; __u64 timestamp_ns; __u64 old_caps; __u64 new_caps;
//	__u32 pid; __u32 tid; __u32 old_uid; __u32 new_uid;
//	__u32 old_euid; __u32 new_euid; __u32 flags; __u8 comm[16];  // 60 -> 64
func parseCredEvent(data []byte) *CredEvent {
	const commOff = 8 + 8 + 8 + 8 + 4*7 // 60
	const size = commOff + 16           // 76
	if len(data) < size {
		return nil
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(data[off : off+4]) }

	e := &CredEvent{
		CgroupID:  binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		OldCaps:   binary.LittleEndian.Uint64(data[16:24]),
		NewCaps:   binary.LittleEndian.Uint64(data[24:32]),
		PID:       u32(32),
		TID:       u32(36),
		OldUID:    u32(40),
		NewUID:    u32(44),
		OldEUID:   u32(48),
		NewEUID:   u32(52),
		Flags:     u32(56),
	}
	comm := data[commOff : commOff+16]
	if i := indexZero(comm); i >= 0 {
		comm = comm[:i]
	}
	e.Comm = string(comm)
	e.ContainerID = fmt.Sprintf("cgroup:%d", e.CgroupID)
	return e
}

// setCredEnabled turns the kprobe's body on or off without detaching it.
//
// Detaching and reattaching a kprobe is not free and briefly leaves a window
// with no coverage; a config flag the program reads first costs one array
// lookup and has no window.
func (m *Manager) setCredEnabled(on bool) error {
	if m.credCollection == nil {
		return fmt.Errorf("the credential monitor is not loaded")
	}
	mp := m.credCollection.Maps["cred_config"]
	if mp == nil {
		return fmt.Errorf("the cred_config map is absent from the loaded object")
	}
	var key uint32
	var val uint32
	if on {
		val = 1
	}
	return mp.Put(&key, &val)
}

// CredMode is what the kernel does when a governed cgroup gains privilege.
type CredMode uint32

const (
	// CredObserve reports the change and lets it stand.
	CredObserve CredMode = 0
	// CredKill sends SIGKILL to the task before the new credentials are used
	// for anything.
	//
	// This is the only enforcement available at this site: commit_creds
	// returns void and is called past the point of no return, so the change
	// itself cannot be refused. There is no LSM hook here to refuse it at
	// either, which is precisely why the kprobe is worth having.
	CredKill CredMode = 1
)

// GovernCredentials sets what happens when a cgroup's tasks gain privilege.
//
// Ungoverned cgroups are observed and never killed, which is the right default
// for a control whose only response is a signal: a false positive here kills a
// process rather than denying one operation. A cgroup is governed only once an
// operator has decided that this workload never legitimately escalates.
func (m *Manager) GovernCredentials(cgroupID uint64, mode CredMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credCollection == nil {
		return fmt.Errorf("the credential monitor is not loaded")
	}
	mp := m.credCollection.Maps["cred_governed"]
	if mp == nil {
		return fmt.Errorf("the cred_governed map is absent from the loaded object")
	}
	key := cgroupID
	val := uint32(mode)
	return mp.Put(&key, &val)
}

// UngovernCredentials returns a cgroup to observation only.
func (m *Manager) UngovernCredentials(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credCollection == nil {
		return fmt.Errorf("the credential monitor is not loaded")
	}
	mp := m.credCollection.Maps["cred_governed"]
	if mp == nil {
		return fmt.Errorf("the cred_governed map is absent from the loaded object")
	}
	key := cgroupID
	// A cgroup that was never governed is already ungoverned; that is the
	// requested state, not a failure.
	if err := mp.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// SetCredKillDuringExecve controls whether a governed cgroup's setuid binaries
// are killed too.
//
// Off by default and it should stay off almost everywhere: killing every
// setuid binary in a container breaks sudo, ping and passwd, which is not a
// security posture anybody asked for. It is worth having for a container that
// is known to contain no legitimate setuid binary at all, where any execve
// that gains privilege is by definition unexpected.
func (m *Manager) SetCredKillDuringExecve(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credCollection == nil {
		return fmt.Errorf("the credential monitor is not loaded")
	}
	mp := m.credCollection.Maps["cred_config"]
	if mp == nil {
		return fmt.Errorf("the cred_config map is absent from the loaded object")
	}
	key := uint32(2)
	var val uint32
	if on {
		val = 1
	}
	return mp.Put(&key, &val)
}
