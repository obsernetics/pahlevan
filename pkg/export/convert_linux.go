// Conversion of the raw pkg/ebpf events into the exported envelope. The eBPF
// data plane is Linux only, so this file is too; the envelope itself and the
// sinks stay portable for the CLI.

package export

import (
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// FromSyscallEvent converts a raw syscall event into the envelope. now supplies
// the wall clock timestamp because the kernel stamp is monotonic since boot.
func FromSyscallEvent(e *ebpf.SyscallEvent, now time.Time) *Event {
	if e == nil {
		return nil
	}
	action := ActionObserve
	// The syscall probes do not deny today; a non-zero action is reserved for
	// the enforcement path and is reported as a denial when it appears.
	if e.Action != 0 {
		action = ActionDeny
	}
	return &Event{
		Version:      SchemaVersion,
		Timestamp:    Timestamp(now),
		Type:         EventTypeSyscall,
		Action:       action,
		CgroupID:     e.CgroupID,
		KernelTimeNs: e.Timestamp,
		Process: ProcessInfo{
			PID:  e.PID,
			TGID: e.TGID,
			UID:  e.UID,
			GID:  e.GID,
			Comm: e.Comm,
		},
		Syscall: &SyscallInfo{
			Number: e.SyscallNr,
			Name:   SyscallName(e.SyscallNr),
		},
	}
}

// FromFileEvent converts a raw file event into the envelope.
func FromFileEvent(e *ebpf.FileEvent, now time.Time) *Event {
	if e == nil {
		return nil
	}
	action := ActionObserve
	if e.Flags&DeniedFlag != 0 {
		action = ActionDeny
	}
	file := &FileInfo{
		Path:      e.Path,
		Flags:     e.Flags &^ DeniedFlag,
		Mode:      e.Mode,
		SyscallNr: e.SyscallNr,
	}
	if e.SyscallNr != 0 {
		file.SyscallName = SyscallName(uint64(e.SyscallNr))
	}
	return &Event{
		Version:      SchemaVersion,
		Timestamp:    Timestamp(now),
		Type:         EventTypeFile,
		Action:       action,
		CgroupID:     e.CgroupID,
		KernelTimeNs: e.Timestamp,
		Process: ProcessInfo{
			PID:  e.PID,
			TGID: e.TGID,
			UID:  e.UID,
			GID:  e.GID,
			Comm: e.Comm,
		},
		File: file,
	}
}

// FromNetworkEvent converts a raw network event into the envelope.
func FromNetworkEvent(e *ebpf.NetworkEvent, now time.Time) *Event {
	if e == nil {
		return nil
	}
	action := ActionObserve
	if e.Direction&DeniedDirection != 0 {
		action = ActionDeny
	}
	direction := "egress"
	if e.Direction&^DeniedDirection == 1 {
		direction = "ingress"
	}
	src := ""
	if e.SrcIP != 0 {
		src = ipv4String(e.SrcIP)
	}
	return &Event{
		Version:      SchemaVersion,
		Timestamp:    Timestamp(now),
		Type:         EventTypeNetwork,
		Action:       action,
		CgroupID:     e.CgroupID,
		KernelTimeNs: e.Timestamp,
		Process: ProcessInfo{
			PID:  e.PID,
			TGID: e.TGID,
		},
		Network: &NetworkInfo{
			SourceIP:        src,
			SourcePort:      e.SrcPort,
			DestinationIP:   ipv4String(e.DstIP),
			DestinationPort: e.DstPort,
			Protocol:        protocolName(e.Protocol),
			ProtocolNumber:  e.Protocol,
			Direction:       direction,
		},
	}
}

// FromProcessEvent converts a raw execve event into the envelope.
func FromProcessEvent(e *ebpf.ProcessEvent, now time.Time) *Event {
	if e == nil {
		return nil
	}
	action := ActionObserve
	if e.Flags&DeniedFlag != 0 {
		action = ActionDeny
	}
	return &Event{
		Version:      SchemaVersion,
		Timestamp:    Timestamp(now),
		Type:         EventTypeProcess,
		Action:       action,
		CgroupID:     e.CgroupID,
		KernelTimeNs: e.Timestamp,
		Process: ProcessInfo{
			PID:  e.PID,
			UID:  e.UID,
			Comm: e.Comm,
		},
		Exec: &ExecInfo{Binary: e.Filename},
	}
}

// FromCapabilityEvent converts a raw capability check into the envelope.
func FromCapabilityEvent(e *ebpf.CapabilityEvent, now time.Time) *Event {
	if e == nil {
		return nil
	}
	action := ActionObserve
	if e.Flags&DeniedFlag != 0 {
		action = ActionDeny
	}
	return &Event{
		Version:      SchemaVersion,
		Timestamp:    Timestamp(now),
		Type:         EventTypeCapability,
		Action:       action,
		CgroupID:     e.CgroupID,
		KernelTimeNs: e.Timestamp,
		Process: ProcessInfo{
			PID:  e.PID,
			Comm: e.Comm,
		},
		Capability: &CapabilityInfo{
			Number: e.Capability,
			Name:   ebpf.CapabilityName(e.Capability),
		},
	}
}
