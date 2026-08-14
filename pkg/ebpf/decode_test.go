package ebpf

import (
	"encoding/binary"
	"testing"
)

// helpers to build the exact wire layouts the eBPF programs emit.
func buildSyscallRec(cgroup, ts, nr uint64, pid, uid, gid uint32, comm string) []byte {
	b := make([]byte, 56)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint64(b[16:], nr)
	binary.LittleEndian.PutUint32(b[24:], pid)
	binary.LittleEndian.PutUint32(b[32:], uid)
	binary.LittleEndian.PutUint32(b[36:], gid)
	copy(b[40:56], comm)
	return b
}

func buildFileRec(cgroup, ts uint64, pid, uid, gid, flags uint32, comm, path string) []byte {
	b := make([]byte, 176)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], uid)
	binary.LittleEndian.PutUint32(b[24:], gid)
	binary.LittleEndian.PutUint32(b[28:], flags)
	copy(b[32:48], comm)
	copy(b[48:176], path)
	return b
}

func buildNetRec(cgroup, ts uint64, pid, saddr, daddr uint32, sport, dport uint16, proto, dir uint8, comm string) []byte {
	b := make([]byte, 56)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], saddr)
	binary.LittleEndian.PutUint32(b[24:], daddr)
	binary.LittleEndian.PutUint16(b[28:], sport)
	binary.LittleEndian.PutUint16(b[30:], dport)
	b[32] = proto
	b[33] = dir
	copy(b[34:50], comm)
	return b
}

func TestParseSyscallEventDecode(t *testing.T) {
	ev := parseSyscallEvent(buildSyscallRec(7004, 123, 257, 42, 1000, 1001, "nginx"))
	if ev == nil {
		t.Fatal("nil event")
	}
	if ev.CgroupID != 7004 || ev.SyscallNr != 257 || ev.PID != 42 || ev.UID != 1000 || ev.GID != 1001 || ev.Comm != "nginx" {
		t.Errorf("bad decode: %+v", ev)
	}
	if parseSyscallEvent([]byte{1, 2, 3}) != nil {
		t.Error("short buffer should decode nil")
	}
}

func TestParseFileEventDecode(t *testing.T) {
	ev := parseFileEvent(buildFileRec(7004, 9, 42, 0, 0, 0x80000000, "cat", "/etc/shadow"))
	if ev == nil {
		t.Fatal("nil")
	}
	if ev.Path != "/etc/shadow" || ev.CgroupID != 7004 || ev.Comm != "cat" {
		t.Errorf("bad decode: %+v", ev)
	}
	if ev.Flags&0x80000000 == 0 {
		t.Error("expected denied flag preserved")
	}
}

func TestParseNetworkEventDecode(t *testing.T) {
	ev := parseNetworkEvent(buildNetRec(7004, 9, 42, 0x0100007f, 0x0a00000a, 12345, 443, 6, 0x80, "curl"))
	if ev == nil {
		t.Fatal("nil")
	}
	if ev.DstPort != 443 || ev.CgroupID != 7004 || ev.Protocol != 6 || ev.Direction != 0x80 {
		t.Errorf("bad decode: %+v", ev)
	}
}

func TestFnvPathHashStable(t *testing.T) {
	a := FnvPathHash("/etc/passwd")
	if a != FnvPathHash("/etc/passwd") {
		t.Error("hash not deterministic")
	}
	if a == FnvPathHash("/etc/shadow") {
		t.Error("distinct paths collided")
	}
}

func BenchmarkParseSyscallEvent(b *testing.B) {
	rec := buildSyscallRec(7004, 123, 257, 42, 1000, 1001, "nginx")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseSyscallEvent(rec)
	}
}

func BenchmarkParseFileEvent(b *testing.B) {
	rec := buildFileRec(7004, 9, 42, 0, 0, 0, "cat", "/usr/lib/x86_64-linux-gnu/libc.so.6")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseFileEvent(rec)
	}
}

func BenchmarkFnvPathHash(b *testing.B) {
	p := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FnvPathHash(p)
	}
}

func buildCapRec(cgroup, ts uint64, pid, cap, flags uint32, comm string) []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], cap)
	binary.LittleEndian.PutUint32(b[24:], flags)
	copy(b[28:44], comm)
	return b
}

func buildExecRec(cgroup, ts uint64, pid, ppid, uid, flags uint32, comm, pcomm, filename string) []byte {
	b := make([]byte, 192)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], ppid)
	binary.LittleEndian.PutUint32(b[24:], uid)
	binary.LittleEndian.PutUint32(b[28:], flags)
	copy(b[32:48], comm)
	copy(b[48:64], pcomm)
	copy(b[64:192], filename)
	return b
}

func TestParseCapabilityEventDecode(t *testing.T) {
	ev := parseCapabilityEvent(buildCapRec(7004, 99, 42, 21, 0x80000000, "nginx"))
	if ev == nil {
		t.Fatal("nil event")
	}
	if ev.CgroupID != 7004 || ev.PID != 42 || ev.Capability != 21 || ev.Comm != "nginx" {
		t.Errorf("bad decode: %+v", ev)
	}
	if ev.Flags&0x80000000 == 0 {
		t.Error("expected denied flag preserved")
	}
	if parseCapabilityEvent([]byte{1, 2, 3}) != nil {
		t.Error("short buffer must decode to nil")
	}
}

func TestParseProcessEventAncestry(t *testing.T) {
	ev := parseProcessEvent(buildExecRec(7004, 9, 4242, 1234, 0, 0xC0000000, "true", "bash", "/tmp/xmrig"))
	if ev == nil {
		t.Fatal("nil event")
	}
	if ev.PID != 4242 || ev.PPID != 1234 {
		t.Errorf("ancestry wrong: pid=%d ppid=%d", ev.PID, ev.PPID)
	}
	if ev.Comm != "true" || ev.ParentComm != "bash" {
		t.Errorf("comm/pcomm wrong: %q / %q", ev.Comm, ev.ParentComm)
	}
	if ev.Filename != "/tmp/xmrig" {
		t.Errorf("filename = %q", ev.Filename)
	}
	if ev.Flags&0x80000000 == 0 {
		t.Error("expected denied flag")
	}
	if ev.Flags&0x40000000 == 0 {
		t.Error("expected killed flag")
	}
	if parseProcessEvent(make([]byte, 10)) != nil {
		t.Error("short buffer must decode to nil")
	}
}

func TestCapabilityName(t *testing.T) {
	cases := map[uint32]string{
		0: "CAP_CHOWN", 21: "CAP_SYS_ADMIN", 39: "CAP_BPF", 12: "CAP_NET_ADMIN",
	}
	for n, want := range cases {
		if got := CapabilityName(n); got != want {
			t.Errorf("CapabilityName(%d) = %q, want %q", n, got, want)
		}
	}
	// Out-of-range must not panic and must stay informative.
	if got := CapabilityName(9999); got != "CAP_9999" {
		t.Errorf("out-of-range name = %q", got)
	}
}

func TestApplyMapSizing(t *testing.T) {
	spec, err := LoadFileMonitor()
	if err != nil {
		t.Skipf("bindings unavailable: %v", err)
	}
	orig := spec.Maps["file_allowed"].MaxEntries
	applyMapSizing(spec, map[string]uint32{"file_allowed": 4096, "nonexistent": 10})
	if spec.Maps["file_allowed"].MaxEntries != 4096 {
		t.Errorf("override not applied: %d", spec.Maps["file_allowed"].MaxEntries)
	}
	// Zero means "keep the compiled default".
	applyMapSizing(spec, map[string]uint32{"file_allowed": 0})
	if spec.Maps["file_allowed"].MaxEntries != 4096 {
		t.Error("zero override must not change the value")
	}
	applyMapSizing(nil, map[string]uint32{"x": 1}) // must not panic
	_ = orig
}

func BenchmarkParseCapabilityEvent(b *testing.B) {
	rec := buildCapRec(7004, 99, 42, 21, 0, "nginx")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseCapabilityEvent(rec)
	}
}

func BenchmarkParseProcessEvent(b *testing.B) {
	rec := buildExecRec(7004, 9, 4242, 1234, 0, 0, "true", "bash", "/usr/bin/true")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseProcessEvent(rec)
	}
}

func BenchmarkCapabilityName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CapabilityName(uint32(i % 41))
	}
}
