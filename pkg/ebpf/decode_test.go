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
	return buildFileRecParent(cgroup, ts, pid, uid, gid, flags, comm, path, 0, "")
}

// buildFileRecParent encodes the whole struct file_event, parent included. The
// layout is spelled out independently of the constants in manager.go, so a
// change to one side fails the test rather than both moving together.
func buildFileRecParent(cgroup, ts uint64, pid, uid, gid, flags uint32, comm, path string,
	ppid uint32, pcomm string,
) []byte {
	const (
		offComm  = 32
		offPPID  = 48
		offPComm = 56
		offPath  = 72
		total    = offPath + 128 // 200
	)
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], uid)
	binary.LittleEndian.PutUint32(b[24:], gid)
	binary.LittleEndian.PutUint32(b[28:], flags)
	copy(b[offComm:offComm+16], comm)
	binary.LittleEndian.PutUint32(b[offPPID:], ppid)
	copy(b[offPComm:offPComm+16], pcomm)
	copy(b[offPath:total], path)
	return b
}

func buildNetRec(cgroup, ts uint64, pid, saddr, daddr uint32, sport, dport uint16, proto, dir uint8, comm string) []byte {
	return buildNetRecFamily(cgroup, ts, pid, saddr, daddr, sport, dport, proto, dir, 2, nil, comm)
}

// buildNetRecFamily builds the 72-byte dual-stack network_event wire record.
func buildNetRecFamily(cgroup, ts uint64, pid, saddr, daddr uint32, sport, dport uint16, proto, dir, family uint8, daddr6 []byte, comm string) []byte {
	return buildNetRecParent(cgroup, ts, pid, saddr, daddr, sport, dport, proto, dir, family, daddr6, comm, 0, "")
}

// buildNetRecParent encodes the whole struct network_event, parent included.
func buildNetRecParent(cgroup, ts uint64, pid, saddr, daddr uint32, sport, dport uint16,
	proto, dir, family uint8, daddr6 []byte, comm string, ppid uint32, pcomm string,
) []byte {
	const (
		offDstIP6 = 36
		offPPID   = 52
		offPComm  = 60
		offComm   = 76
		total     = offComm + 16 // 96
	)
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	binary.LittleEndian.PutUint32(b[20:], saddr)
	binary.LittleEndian.PutUint32(b[24:], daddr)
	binary.LittleEndian.PutUint16(b[28:], sport)
	binary.LittleEndian.PutUint16(b[30:], dport)
	b[32] = proto
	b[33] = dir
	b[34] = family
	copy(b[offDstIP6:offDstIP6+16], daddr6)
	binary.LittleEndian.PutUint32(b[offPPID:], ppid)
	copy(b[offPComm:offPComm+16], pcomm)
	copy(b[offComm:total], comm)
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

func buildCapRec(cgroup, ts uint64, pid, capability, flags uint32, comm string) []byte {
	return buildCapRecSets(cgroup, ts, pid, capability, flags, comm, 0, 0, 0)
}

// buildCapRecSets encodes the whole struct cap_event, capability sets included.
// The layout is spelled out independently of the constants in manager.go, so a
// change to one side fails the test rather than both moving together.
func buildCapRecSets(cgroup, ts uint64, pid, capability, flags uint32, comm string,
	effective, permitted, inheritable uint64,
) []byte {
	const (
		offEffective   = 16
		offPermitted   = 24
		offInheritable = 32
		offPID         = 40
		offComm        = 56
		offPPID        = 72
		offPComm       = 80
		total          = offPComm + 16 // 96
	)
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint64(b[offEffective:], effective)
	binary.LittleEndian.PutUint64(b[offPermitted:], permitted)
	binary.LittleEndian.PutUint64(b[offInheritable:], inheritable)
	binary.LittleEndian.PutUint32(b[offPID:], pid)
	binary.LittleEndian.PutUint32(b[offPID+4:], capability)
	binary.LittleEndian.PutUint32(b[offPID+8:], flags)
	copy(b[offComm:offComm+16], comm)
	return b
}

func buildExecRec(cgroup, ts uint64, pid, ppid, uid, flags uint32, comm, pcomm, filename string) []byte {
	var chain []Ancestor
	if ppid != 0 {
		chain = []Ancestor{{PID: ppid, Comm: pcomm}}
	}
	return buildExecRecAncestry(cgroup, ts, pid, uid, flags, comm, filename, chain)
}

// buildExecRecAncestry encodes the full `struct exec_event`, ancestry included.
// It mirrors the C layout independently of the constants in manager.go, so a
// change to one side fails the test instead of both moving together silently.
func buildExecRecAncestry(cgroup, ts uint64, pid, uid, flags uint32, comm, filename string, chain []Ancestor) []byte {
	return buildExecRecFull(cgroup, ts, pid, uid, flags, comm, filename, chain, nil, false)
}

// buildExecRecFull encodes the whole struct exec_event, argv included. The
// layout is spelled out here independently of the constants in manager.go, so
// a change to one side fails the test rather than both moving together.
func buildExecRecFull(cgroup, ts uint64, pid, uid, flags uint32, comm, filename string,
	chain []Ancestor, args []string, truncated bool,
) []byte {
	const (
		offComm      = 32
		offParent    = 48
		offAncestry  = 64
		ancSize      = 20
		offFilename  = offAncestry + 4*ancSize // 144
		offArgsCount = offFilename + 128       // 272
		offArgsLen   = offArgsCount + 4        // 276
		offArgsTrunc = offArgsLen + 4          // 280
		offArgs      = offArgsTrunc + 1        // 281
		total        = offArgs + 256           // 544
	)
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint32(b[16:], pid)
	if len(chain) > 0 {
		binary.LittleEndian.PutUint32(b[20:], chain[0].PID) // ppid
		copy(b[offParent:offParent+16], chain[0].Comm)
	}
	binary.LittleEndian.PutUint32(b[24:], uid)
	binary.LittleEndian.PutUint32(b[28:], flags)
	copy(b[offComm:offComm+16], comm)
	for i, a := range chain {
		if i >= 4 {
			break
		}
		off := offAncestry + i*ancSize
		binary.LittleEndian.PutUint32(b[off:], a.PID)
		copy(b[off+4:off+20], a.Comm)
	}
	copy(b[offFilename:offFilename+128], filename)

	// argv is NUL separated, exactly as /proc/<pid>/cmdline presents it.
	if len(args) > 0 {
		var blob []byte
		for _, a := range args {
			blob = append(blob, []byte(a)...)
			blob = append(blob, 0)
		}
		if len(blob) > 256 {
			blob = blob[:256]
		}
		binary.LittleEndian.PutUint32(b[offArgsCount:], uint32(len(args)))
		binary.LittleEndian.PutUint32(b[offArgsLen:], uint32(len(blob)))
		copy(b[offArgs:offArgs+256], blob)
	}
	if truncated {
		b[offArgsTrunc] = 1
	}
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
	if len(ev.Ancestry) != 1 || ev.Ancestry[0].PID != 1234 || ev.Ancestry[0].Comm != "bash" {
		t.Errorf("ancestry = %+v", ev.Ancestry)
	}
}

// The lineage is what makes a denial actionable, so decoding it correctly at
// every depth matters more than the single-parent case it replaces.
func TestParseProcessEventFullAncestry(t *testing.T) {
	chain := []Ancestor{
		{PID: 300, Comm: "sh"},
		{PID: 200, Comm: "nginx"},
		{PID: 1, Comm: "init"},
	}
	rec := buildExecRecAncestry(7004, 9, 400, 0, 0, "curl", "/usr/bin/curl", chain)
	ev := parseProcessEvent(rec)
	if ev == nil {
		t.Fatal("nil event")
	}
	if len(ev.Ancestry) != 3 {
		t.Fatalf("expected 3 ancestors, got %d: %+v", len(ev.Ancestry), ev.Ancestry)
	}
	for i, want := range chain {
		if ev.Ancestry[i] != want {
			t.Errorf("ancestry[%d] = %+v, want %+v", i, ev.Ancestry[i], want)
		}
	}
	// PPID stays consistent with the nearest ancestor for existing consumers.
	if ev.PPID != 300 || ev.ParentComm != "sh" {
		t.Errorf("ppid/pcomm = %d/%q, want 300/sh", ev.PPID, ev.ParentComm)
	}
	if got, want := ev.AncestryChain(), "init -> nginx -> sh -> curl"; got != want {
		t.Errorf("chain = %q, want %q", got, want)
	}
}

// A zero pid terminates the chain, so a shallow lineage must not report
// phantom ancestors from the zeroed tail of the array.
func TestParseProcessEventShallowAncestry(t *testing.T) {
	rec := buildExecRecAncestry(1, 1, 400, 0, 0, "curl", "/usr/bin/curl",
		[]Ancestor{{PID: 300, Comm: "sh"}})
	ev := parseProcessEvent(rec)
	if ev == nil {
		t.Fatal("nil event")
	}
	if len(ev.Ancestry) != 1 {
		t.Fatalf("expected exactly 1 ancestor, got %d: %+v", len(ev.Ancestry), ev.Ancestry)
	}
	if got, want := ev.AncestryChain(), "sh -> curl"; got != want {
		t.Errorf("chain = %q, want %q", got, want)
	}
}

func TestParseProcessEventNoAncestry(t *testing.T) {
	rec := buildExecRecAncestry(1, 1, 400, 0, 0, "init", "/sbin/init", nil)
	ev := parseProcessEvent(rec)
	if ev == nil {
		t.Fatal("nil event")
	}
	if len(ev.Ancestry) != 0 {
		t.Errorf("expected no ancestors, got %+v", ev.Ancestry)
	}
	if ev.PPID != 0 {
		t.Errorf("ppid = %d, want 0", ev.PPID)
	}
	if got := ev.AncestryChain(); got != "init" {
		t.Errorf("chain = %q, want %q", got, "init")
	}
}

// The array holds four entries; a deeper chain is truncated, not overrun.
func TestParseProcessEventAncestryIsBounded(t *testing.T) {
	chain := []Ancestor{
		{PID: 5, Comm: "a"}, {PID: 4, Comm: "b"}, {PID: 3, Comm: "c"}, {PID: 2, Comm: "d"},
	}
	ev := parseProcessEvent(buildExecRecAncestry(1, 1, 6, 0, 0, "e", "/e", chain))
	if ev == nil {
		t.Fatal("nil event")
	}
	if len(ev.Ancestry) != AncestryDepth {
		t.Fatalf("expected %d ancestors, got %d", AncestryDepth, len(ev.Ancestry))
	}
	if got, want := ev.AncestryChain(), "d -> c -> b -> a -> e"; got != want {
		t.Errorf("chain = %q, want %q", got, want)
	}
}

func BenchmarkParseProcessEventFullAncestry(b *testing.B) {
	rec := buildExecRecAncestry(1, 1, 6, 0, 0, "curl", "/usr/bin/curl", []Ancestor{
		{PID: 5, Comm: "sh"}, {PID: 4, Comm: "entrypoint"},
		{PID: 3, Comm: "nginx"}, {PID: 1, Comm: "init"},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseProcessEvent(rec)
	}
}

func BenchmarkAncestryChain(b *testing.B) {
	ev := &ProcessEvent{Comm: "curl", Ancestry: []Ancestor{
		{PID: 5, Comm: "sh"}, {PID: 4, Comm: "entrypoint"},
		{PID: 3, Comm: "nginx"}, {PID: 1, Comm: "init"},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ev.AncestryChain()
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

func TestParseNetworkEventIPv6(t *testing.T) {
	// 2001:db8::1
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ev := parseNetworkEvent(buildNetRecFamily(7004, 9, 42, 0, 0, 0, 443, 6, 0x80, 10, v6, "curl"))
	if ev == nil {
		t.Fatal("nil event")
	}
	if ev.Family != 10 {
		t.Errorf("family = %d, want 10 (AF_INET6)", ev.Family)
	}
	if ev.DstPort != 443 {
		t.Errorf("dport = %d", ev.DstPort)
	}
	if ev.Comm != "curl" {
		t.Errorf("comm = %q, want curl", ev.Comm)
	}
	if got := ev.DestinationString(); got != "[2001:db8::1]:443" {
		t.Errorf("DestinationString() = %q, want [2001:db8::1]:443", got)
	}
	if ev.Direction&0x80 == 0 {
		t.Error("expected denied marker preserved for IPv6 denials")
	}
}

func TestNetworkDestinationStringIPv4(t *testing.T) {
	// 127.0.0.1 in little-endian host order as the kernel reports it.
	ev := parseNetworkEvent(buildNetRecFamily(1, 1, 1, 0, 0x0100007f, 0, 8080, 6, 0, 2, nil, "app"))
	if ev == nil {
		t.Fatal("nil")
	}
	if got := ev.DestinationString(); got != "127.0.0.1:8080" {
		t.Errorf("DestinationString() = %q, want 127.0.0.1:8080", got)
	}
}

func BenchmarkDestinationStringIPv6(b *testing.B) {
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ev := parseNetworkEvent(buildNetRecFamily(1, 1, 1, 0, 0, 0, 443, 6, 0, 10, v6, "curl"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ev.DestinationString()
	}
}
