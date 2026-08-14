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
