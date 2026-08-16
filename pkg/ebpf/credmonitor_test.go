package ebpf

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildCredRec assembles the wire format of `struct cred_event` exactly as
// bpf/cred_monitor.c emits it. If the two ever disagree these tests are the
// only thing between a skew and events that decode into nonsense.
func buildCredRec(cgroup, ts, oldCaps, newCaps uint64, pid, tid, oldUID, newUID, oldEUID, newEUID, flags uint32, comm string) []byte {
	b := make([]byte, 80)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint64(b[16:], oldCaps)
	binary.LittleEndian.PutUint64(b[24:], newCaps)
	for i, v := range []uint32{pid, tid, oldUID, newUID, oldEUID, newEUID, flags} {
		binary.LittleEndian.PutUint32(b[32+i*4:], v)
	}
	copy(b[60:76], comm)
	return b
}

func TestParseCredEvent(t *testing.T) {
	rec := buildCredRec(99, 12345, 0x1, 0x1|0x200000, 4242, 4243, 1000, 1000, 1000, 0, CredGainedRoot|CredGainedCaps, "python3")
	e := parseCredEvent(rec)
	if e == nil {
		t.Fatal("a well-formed record failed to decode")
	}
	if e.CgroupID != 99 || e.Timestamp != 12345 {
		t.Errorf("header decoded wrong: cgroup=%d ts=%d", e.CgroupID, e.Timestamp)
	}
	if e.PID != 4242 || e.TID != 4243 {
		t.Errorf("pid/tid decoded wrong: %d/%d", e.PID, e.TID)
	}
	if e.OldEUID != 1000 || e.NewEUID != 0 {
		t.Errorf("euid transition decoded wrong: %d->%d", e.OldEUID, e.NewEUID)
	}
	if e.Comm != "python3" {
		t.Errorf("comm decoded as %q", e.Comm)
	}
	if e.ContainerID != "cgroup:99" {
		t.Errorf("container id is %q", e.ContainerID)
	}
}

func TestParseCredEventRejectsShortRecords(t *testing.T) {
	// A short record must decode to nil rather than to a plausible-looking
	// event: the caller counts a nil as a decode error, and a decode error is
	// alerted on. Reading past the end and reporting garbage would be silent.
	full := buildCredRec(1, 2, 0, 0, 3, 4, 5, 6, 7, 8, 0, "sh")
	for n := 0; n < 76; n++ {
		if e := parseCredEvent(full[:n]); e != nil {
			t.Fatalf("a %d-byte record decoded to an event", n)
		}
	}
	if e := parseCredEvent(full[:76]); e == nil {
		t.Fatal("the exact minimum length failed to decode")
	}
}

func TestCredEventUnexplainedIsTheDiscriminator(t *testing.T) {
	cases := []struct {
		name  string
		flags uint32
		want  bool
	}{
		// A setuid binary: sudo, ping, passwd. Happens constantly and is not
		// news. If this ever returns true the monitor is unusable.
		{"root gained during execve", CredGainedRoot | CredInExecve, false},
		{"caps gained during execve", CredGainedCaps | CredInExecve, false},
		// The case the whole monitor exists for.
		{"root gained with no execve", CredGainedRoot, true},
		{"caps gained with no execve", CredGainedCaps, true},
		// Dropping privilege is the hardening pattern every daemon follows.
		{"privilege only dropped", CredLostRoot, false},
		{"nothing at all", 0, false},
	}
	for _, tc := range cases {
		e := &CredEvent{Flags: tc.flags}
		if got := e.Unexplained(); got != tc.want {
			t.Errorf("%s: Unexplained() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCredEventGainedCapabilities(t *testing.T) {
	// CAP_SYS_ADMIN is 21, CAP_NET_RAW is 13.
	e := &CredEvent{OldCaps: 1 << 13, NewCaps: 1<<13 | 1<<21}
	got := e.GainedCapabilities()
	if len(got) != 1 || got[0] != "CAP_SYS_ADMIN" {
		t.Errorf("gained capabilities = %v, want [CAP_SYS_ADMIN]", got)
	}

	// A task that drops capabilities has gained nothing, and reporting the
	// drop as a gain would bury the one case that matters.
	dropped := &CredEvent{OldCaps: 1<<13 | 1<<21, NewCaps: 1 << 13}
	if got := dropped.GainedCapabilities(); len(got) != 0 {
		t.Errorf("a capability drop reported gains: %v", got)
	}
}

func TestCredEventSummary(t *testing.T) {
	e := &CredEvent{
		Comm: "python3", PID: 4242,
		OldUID: 1000, NewUID: 0, OldEUID: 1000, NewEUID: 0,
		OldCaps: 0, NewCaps: 1 << 21,
		Flags: CredGainedRoot | CredGainedCaps | CredKilled,
	}
	s := e.Summary()
	for _, want := range []string{"python3", "4242", "1000->0", "CAP_SYS_ADMIN", "no execve underway", "KILLED"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q does not mention %q", s, want)
		}
	}

	inExecve := &CredEvent{Comm: "sudo", Flags: CredGainedRoot | CredInExecve}
	if !strings.Contains(inExecve.Summary(), "during execve") {
		t.Errorf("an execve-explained change does not say so: %q", inExecve.Summary())
	}
}

func TestCredEventDenied(t *testing.T) {
	if (&CredEvent{Flags: CredGainedRoot}).Denied() {
		t.Error("an observed escalation reports as denied")
	}
	if !(&CredEvent{Flags: CredGainedRoot | CredKilled}).Denied() {
		t.Error("a killed escalation does not report as denied")
	}
}

// The flag values are a contract with bpf/cred_monitor.c. A silent renumbering
// on either side turns every event into a misclassification, and nothing else
// would catch it.
func TestCredFlagValuesMatchTheKernelContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"CredGainedRoot", CredGainedRoot, 0x01},
		{"CredGainedCaps", CredGainedCaps, 0x02},
		{"CredInExecve", CredInExecve, 0x04},
		{"CredKilled", CredKilled, 0x08},
		{"CredLostRoot", CredLostRoot, 0x10},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, but bpf/cred_monitor.c defines %#x", tc.name, tc.got, tc.want)
		}
	}
}

func BenchmarkParseCredEvent(b *testing.B) {
	rec := buildCredRec(99, 12345, 0x1, 0x1|0x200000, 4242, 4243, 1000, 1000, 1000, 0, CredGainedRoot, "python3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if parseCredEvent(rec) == nil {
			b.Fatal("decode failed")
		}
	}
}

func BenchmarkCredEventSummary(b *testing.B) {
	e := &CredEvent{
		Comm: "python3", PID: 4242, OldEUID: 1000, NewEUID: 0,
		NewCaps: 1 << 21, Flags: CredGainedRoot | CredGainedCaps,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Summary()
	}
}

func BenchmarkCredEventUnexplained(b *testing.B) {
	e := &CredEvent{Flags: CredGainedRoot}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Unexplained()
	}
}
