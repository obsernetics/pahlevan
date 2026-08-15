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
		Exec: execInfo(e),
	}
}

// execInfo carries the binary and the lineage that led to it.
func execInfo(e *ebpf.ProcessEvent) *ExecInfo {
	info := &ExecInfo{Binary: e.Filename}
	if len(e.Args) > 0 {
		info.Args = append([]string(nil), e.Args...)
		info.CommandLine = e.CommandLine()
		info.ArgsTruncated = e.ArgsTruncated
	}
	if len(e.Ancestry) == 0 {
		return info
	}
	info.Ancestry = make([]AncestorInfo, 0, len(e.Ancestry))
	for _, a := range e.Ancestry {
		info.Ancestry = append(info.Ancestry, AncestorInfo{PID: a.PID, Comm: a.Comm})
	}
	info.AncestryChain = e.AncestryChain()
	return info
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
			// Rendered as names rather than bitmasks: a consumer should not
			// have to know the capability numbering to read the event.
			Effective:   ebpf.CapabilityNames(e.CapEffective),
			Permitted:   ebpf.CapabilityNames(e.CapPermitted),
			Inheritable: ebpf.CapabilityNames(e.CapInheritable),
		},
	}
}

// ipv4String renders a NetworkEvent address field as a dotted quad.
//
// It defers to pkg/ebpf, the one owner of this conversion. The local version
// shifted the uint32 as if it held a host-order number, but the field holds
// sin_addr.s_addr decoded little-endian, which is already in network byte
// order. Every exported destination came out backwards: 127.0.0.1 as
// 1.0.0.127.
func ipv4String(addr uint32) string {
	return ebpf.IPv4String(addr)
}
