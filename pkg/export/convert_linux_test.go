package export

import (
	"strings"
	"testing"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func TestFromSyscallEvent(t *testing.T) {
	ev := FromSyscallEvent(&ebpf.SyscallEvent{
		PID:       42,
		TGID:      41,
		UID:       1000,
		GID:       1001,
		SyscallNr: 59,
		Timestamp: 12345,
		Comm:      "sh",
		CgroupID:  777,
	}, testNow)

	if ev.Type != EventTypeSyscall {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Action != ActionObserve || ev.Denied() {
		t.Fatalf("action = %q, denied = %v", ev.Action, ev.Denied())
	}
	if ev.Version != SchemaVersion {
		t.Errorf("version = %q", ev.Version)
	}
	if ev.Syscall == nil || ev.Syscall.Name != "execve" || ev.Syscall.Number != 59 {
		t.Fatalf("syscall = %+v", ev.Syscall)
	}
	if ev.Process.PID != 42 || ev.Process.TGID != 41 || ev.Process.UID != 1000 ||
		ev.Process.GID != 1001 || ev.Process.Comm != "sh" {
		t.Errorf("process = %+v", ev.Process)
	}
	if ev.CgroupID != 777 || ev.KernelTimeNs != 12345 {
		t.Errorf("cgroup = %d kernel ts = %d", ev.CgroupID, ev.KernelTimeNs)
	}
	if got := ev.Timestamp.Time(); !got.Equal(testNow) {
		t.Errorf("timestamp = %v", got)
	}
}

func TestFromSyscallEventDenied(t *testing.T) {
	ev := FromSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 0, Action: 2}, testNow)
	if !ev.Denied() {
		t.Fatalf("expected a denial, got %q", ev.Action)
	}
	if ev.Syscall.Name != "read" {
		t.Errorf("syscall name = %q", ev.Syscall.Name)
	}
}

func TestFromSyscallEventUnknownNumber(t *testing.T) {
	ev := FromSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 999999}, testNow)
	if ev.Syscall.Name != "syscall_999999" {
		t.Errorf("syscall name = %q", ev.Syscall.Name)
	}
}

func TestFromFileEvent(t *testing.T) {
	ev := FromFileEvent(&ebpf.FileEvent{
		PID:       7,
		UID:       0,
		Flags:     DeniedFlag | 0x2,
		Mode:      0o644,
		SyscallNr: 257,
		Comm:      "curl",
		CgroupID:  9,
		Path:      "/etc/shadow",
	}, testNow)

	if ev.Type != EventTypeFile || !ev.Denied() {
		t.Fatalf("type = %q action = %q", ev.Type, ev.Action)
	}
	if ev.File.Path != "/etc/shadow" {
		t.Errorf("path = %q", ev.File.Path)
	}
	if ev.File.Flags != 0x2 {
		t.Errorf("denial bit should be stripped from flags, got %#x", ev.File.Flags)
	}
	if ev.File.SyscallName != "openat" {
		t.Errorf("syscall name = %q", ev.File.SyscallName)
	}
	if ev.File.Mode != 0o644 {
		t.Errorf("mode = %o", ev.File.Mode)
	}
}

func TestFromFileEventObserve(t *testing.T) {
	ev := FromFileEvent(&ebpf.FileEvent{Path: "/tmp/x", Flags: 1}, testNow)
	if ev.Action != ActionObserve {
		t.Fatalf("action = %q", ev.Action)
	}
	if ev.File.SyscallName != "" {
		t.Errorf("syscall name should be empty when the number is 0, got %q", ev.File.SyscallName)
	}
}

func TestFromNetworkEvent(t *testing.T) {
	ev := FromNetworkEvent(&ebpf.NetworkEvent{
		PID:       11,
		// Network byte order, as the kernel writes sin_addr.s_addr and the
		// decoder reads it: 192.168.1.1 and 8.8.8.8.
		SrcIP:     0x0101a8c0,
		DstIP:     0x08080808,
		SrcPort:   34567,
		DstPort:   53,
		Protocol:  17,
		Direction: DeniedDirection,
		CgroupID:  3,
	}, testNow)

	if ev.Type != EventTypeNetwork || !ev.Denied() {
		t.Fatalf("type = %q action = %q", ev.Type, ev.Action)
	}
	if ev.Network.DestinationIP != "8.8.8.8" || ev.Network.DestinationPort != 53 {
		t.Errorf("destination = %s", ev.Network.Address())
	}
	if ev.Network.SourceIP != "192.168.1.1" || ev.Network.SourcePort != 34567 {
		t.Errorf("source = %s:%d", ev.Network.SourceIP, ev.Network.SourcePort)
	}
	if ev.Network.DestinationIP != "8.8.8.8" {
		t.Errorf("destination = %q", ev.Network.DestinationIP)
	}
	if ev.Network.Protocol != "udp" || ev.Network.ProtocolNumber != 17 {
		t.Errorf("protocol = %s/%d", ev.Network.Protocol, ev.Network.ProtocolNumber)
	}
	if ev.Network.Direction != "egress" {
		t.Errorf("direction = %q", ev.Network.Direction)
	}
	if got := ev.Network.Address(); got != "8.8.8.8:53" {
		t.Errorf("address = %q", got)
	}
}

func TestFromNetworkEventIngressObserve(t *testing.T) {
	ev := FromNetworkEvent(&ebpf.NetworkEvent{DstIP: 0x0a000001, DstPort: 80, Protocol: 6, Direction: 1}, testNow)
	if ev.Denied() {
		t.Fatalf("action = %q", ev.Action)
	}
	if ev.Network.Direction != "ingress" {
		t.Errorf("direction = %q", ev.Network.Direction)
	}
	if ev.Network.SourceIP != "" {
		t.Errorf("source ip should stay empty when unset, got %q", ev.Network.SourceIP)
	}
	if ev.Network.Protocol != "tcp" {
		t.Errorf("protocol = %q", ev.Network.Protocol)
	}
}

func TestFromProcessEvent(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		PID:      3,
		UID:      0,
		Flags:    DeniedFlag,
		Comm:     "bash",
		Filename: "/usr/bin/nc",
		CgroupID: 5,
	}, testNow)

	if ev.Type != EventTypeProcess || !ev.Denied() {
		t.Fatalf("type = %q action = %q", ev.Type, ev.Action)
	}
	if ev.Exec == nil || ev.Exec.Binary != "/usr/bin/nc" {
		t.Fatalf("exec = %+v", ev.Exec)
	}
	if ev.Process.Comm != "bash" {
		t.Errorf("comm = %q", ev.Process.Comm)
	}
}

func TestFromCapabilityEvent(t *testing.T) {
	ev := FromCapabilityEvent(&ebpf.CapabilityEvent{
		PID:        4,
		Capability: 21,
		Comm:       "mount",
		CgroupID:   6,
	}, testNow)

	if ev.Type != EventTypeCapability || ev.Denied() {
		t.Fatalf("type = %q action = %q", ev.Type, ev.Action)
	}
	if ev.Capability == nil || ev.Capability.Number != 21 {
		t.Fatalf("capability = %+v", ev.Capability)
	}
	if !strings.Contains(strings.ToUpper(ev.Capability.Name), "SYS_ADMIN") {
		t.Errorf("capability name = %q", ev.Capability.Name)
	}

	denied := FromCapabilityEvent(&ebpf.CapabilityEvent{Capability: 21, Flags: DeniedFlag}, testNow)
	if !denied.Denied() {
		t.Errorf("expected a denial, got %q", denied.Action)
	}
}

func TestFromNilEvents(t *testing.T) {
	if FromSyscallEvent(nil, testNow) != nil ||
		FromFileEvent(nil, testNow) != nil ||
		FromNetworkEvent(nil, testNow) != nil ||
		FromProcessEvent(nil, testNow) != nil ||
		FromCapabilityEvent(nil, testNow) != nil {
		t.Fatal("nil input must convert to a nil envelope")
	}
}

func TestSyscallNameUsesTheGeneratedTable(t *testing.T) {
	if got := SyscallName(1); got != "write" {
		t.Errorf("SyscallName(1) = %q", got)
	}
	if got := SyscallName(60); got != "exit" && got != "syscall_60" {
		t.Errorf("SyscallName(60) = %q", got)
	}
}
