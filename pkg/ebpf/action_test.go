package ebpf

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// The packing is a wire format shared with bpf/enforce.h. A change on either
// side that this does not catch turns a Deny into a Kill, or an errno into a
// signal number, with nothing else to notice.
func TestEnforcementSpecRoundTrip(t *testing.T) {
	cases := []EnforcementSpec{
		{Action: ActionLearn},
		{Action: ActionDeny},
		{Action: ActionDeny, Errno: uint16(syscall.ENOENT)},
		{Action: ActionKill},
		{Action: ActionKill, Errno: uint16(syscall.EACCES)},
		{Action: ActionAudit},
		{Action: ActionSignal, Signal: syscall.SIGSTOP},
		{Action: ActionSignal, Signal: syscall.SIGTERM, Errno: uint16(syscall.EIO)},
		// The widest legal values in every field at once.
		{Action: ActionSignal, Signal: 64, Errno: 4095},
	}
	for _, want := range cases {
		got := UnpackEnforcementSpec(want.Pack())
		if got != want {
			t.Errorf("round trip lost information: %+v packed to %#x and unpacked to %+v",
				want, want.Pack(), got)
		}
	}
}

// The three fields must occupy the bit ranges bpf/enforce.h reads. Asserting
// the layout rather than only the round trip is what catches a change that is
// self-consistent in Go and wrong against the kernel.
func TestEnforcementSpecBitLayout(t *testing.T) {
	s := EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP, Errno: uint16(syscall.ENOENT)}
	v := s.Pack()
	if got := v & 0xff; got != uint32(ActionSignal) {
		t.Errorf("action is in bits 0-7 as %d, want %d", got, ActionSignal)
	}
	if got := (v >> 8) & 0xff; got != uint32(syscall.SIGSTOP) {
		t.Errorf("signal is in bits 8-15 as %d, want %d", got, syscall.SIGSTOP)
	}
	if got := (v >> 16) & 0xffff; got != uint32(syscall.ENOENT) {
		t.Errorf("errno is in bits 16-31 as %d, want %d", got, syscall.ENOENT)
	}

	// ActionLearn with nothing set must pack to zero, because an absent map
	// entry is zero and the kernel must read the two identically.
	if v := (EnforcementSpec{}).Pack(); v != 0 {
		t.Errorf("the default spec packs to %#x, but an absent map entry reads as 0", v)
	}
}

func TestEnforcementSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		spec    EnforcementSpec
		wantErr string
	}{
		{"learn", EnforcementSpec{Action: ActionLearn}, ""},
		{"deny", EnforcementSpec{Action: ActionDeny}, ""},
		{"deny with errno", EnforcementSpec{Action: ActionDeny, Errno: 2}, ""},
		{"audit", EnforcementSpec{Action: ActionAudit}, ""},
		{"signal with a signal", EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP}, ""},

		// Signal without a signal number would deny and send nothing, which
		// looks like a plain Deny and is a configuration the operator did not
		// mean to write.
		{"signal with none", EnforcementSpec{Action: ActionSignal}, "between 1 and 64"},
		{"signal out of range", EnforcementSpec{Action: ActionSignal, Signal: 200}, "between 1 and 64"},

		// An errno above 4095 is read by the kernel as a pointer, not an error.
		{"errno too large", EnforcementSpec{Action: ActionDeny, Errno: 5000}, "out of range"},

		// Set on an action that cannot use it: silently ignoring these is how
		// an operator ends up believing a control is in place.
		{"errno on audit", EnforcementSpec{Action: ActionAudit, Errno: 2}, "does not deny"},
		{"errno on learn", EnforcementSpec{Action: ActionLearn, Errno: 2}, "does not deny"},
		{"signal on deny", EnforcementSpec{Action: ActionDeny, Signal: syscall.SIGSTOP}, "does not signal"},

		{"unknown action", EnforcementSpec{Action: Action(9)}, "not implemented"},
	}
	for _, tc := range cases {
		err := tc.spec.Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want an error mentioning %q", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.wantErr)
		}
	}
}

// An unknown action must never reach the map. The kernel treats anything that
// is not ACT_LEARN as denying, so a typo'd number would silently enforce rather
// than silently do nothing - the wrong direction to fail in for a value that
// arrives from a CRD.
func TestUnknownActionIsNotWritten(t *testing.T) {
	mp := &fakeMap{}
	err := setActionOn(mp, "file_mode", 42, EnforcementSpec{Action: Action(200)})
	if err == nil {
		t.Fatal("an unimplemented action was accepted")
	}
	if len(mp.puts) != 0 {
		t.Errorf("the map was written with %v despite the error", mp.puts)
	}
}

// ActionLearn deletes rather than writing a zero. Both read the same to the
// kernel, and deleting keeps the map's occupancy proportional to the cgroups
// actually being enforced rather than to every one ever reconciled.
func TestLearnDeletesTheEntry(t *testing.T) {
	mp := &fakeMap{}
	if err := setActionOn(mp, "file_mode", 42, EnforcementSpec{Action: ActionLearn}); err != nil {
		t.Fatalf("setting Learn: %v", err)
	}
	if len(mp.puts) != 0 {
		t.Errorf("Learn wrote %v to the map", mp.puts)
	}
	if len(mp.deletes) != 1 || mp.deletes[0] != 42 {
		t.Errorf("Learn did not delete the entry: %v", mp.deletes)
	}
}

// A cgroup that was never enforced is already learning; deleting a key that is
// not there is the requested state, not a failure.
func TestLearnIgnoresAMissingEntry(t *testing.T) {
	mp := &fakeMap{deleteErr: errors.New("key does not exist")}
	if err := setActionOn(mp, "file_mode", 42, EnforcementSpec{Action: ActionLearn}); err != nil {
		t.Errorf("deleting an absent key returned %v, want nil", err)
	}
}

func TestSetActionWritesThePackedValue(t *testing.T) {
	mp := &fakeMap{}
	spec := EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP, Errno: uint16(syscall.EACCES)}
	if err := setActionOn(mp, "exec_mode", 7, spec); err != nil {
		t.Fatalf("setting the action: %v", err)
	}
	if len(mp.puts) != 1 {
		t.Fatalf("the map was written %d times, want 1", len(mp.puts))
	}
	if mp.puts[0].key != 7 {
		t.Errorf("written under key %d, want 7", mp.puts[0].key)
	}
	if mp.puts[0].value != spec.Pack() {
		t.Errorf("wrote %#x, want %#x", mp.puts[0].value, spec.Pack())
	}
}

func TestSetActionOnAMissingMap(t *testing.T) {
	if err := setActionOn(nil, "file_mode", 1, EnforcementSpec{Action: ActionDeny}); err == nil {
		t.Error("writing to an absent map succeeded")
	}
}

func TestActionParsing(t *testing.T) {
	for in, want := range map[string]Action{
		"Learn": ActionLearn, "learn": ActionLearn, "": ActionLearn,
		"Deny": ActionDeny, "DENY": ActionDeny,
		"Kill": ActionKill, "Audit": ActionAudit, " signal ": ActionSignal,
	} {
		got, err := ParseAction(in)
		if err != nil {
			t.Errorf("ParseAction(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAction(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseAction("block"); err == nil {
		t.Error("an unknown action name was accepted")
	} else if !strings.Contains(err.Error(), "Learn, Deny, Kill, Audit, Signal") {
		t.Errorf("the error does not list the valid actions: %v", err)
	}
}

func TestActionDenies(t *testing.T) {
	// Audit is the one that reports and allows. Getting this wrong in either
	// direction is the difference between a dry run and an outage.
	if ActionAudit.Denies() {
		t.Error("Audit reports as denying, which would make a dry run an outage")
	}
	if ActionLearn.Denies() {
		t.Error("Learn reports as denying")
	}
	for _, a := range []Action{ActionDeny, ActionKill, ActionSignal} {
		if !a.Denies() {
			t.Errorf("%s does not report as denying", a)
		}
	}
}

func TestEnforcementSpecString(t *testing.T) {
	for _, tc := range []struct {
		spec EnforcementSpec
		want []string
	}{
		{EnforcementSpec{Action: ActionDeny}, []string{"Deny", "EPERM"}},
		{EnforcementSpec{Action: ActionDeny, Errno: uint16(syscall.ENOENT)}, []string{"Deny", "ENOENT"}},
		{EnforcementSpec{Action: ActionKill}, []string{"Kill", "EPERM"}},
		{EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP}, []string{"Signal", "stopped"}},
		{EnforcementSpec{Action: ActionAudit}, []string{"Audit"}},
		{EnforcementSpec{Action: ActionLearn}, []string{"Learn"}},
	} {
		got := tc.spec.String()
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%+v renders as %q, which does not mention %q", tc.spec, got, want)
			}
		}
	}
}

// The audit flag is a contract with bpf/enforce.h, and it must not collide with
// any other flag on any event type. A collision would make a would-be denial
// read as a breakout, or a write, depending on which event it landed on.
func TestFlagBitsDoNotCollide(t *testing.T) {
	// Flags that can appear together on one ProcessEvent.
	process := []struct {
		name string
		bit  uint32
	}{
		{"DeniedFlag", DeniedFlag},
		{"KilledFlag", KilledFlag},
		{"ExitedFlag", ExitedFlag},
		{"BreakoutFlag", BreakoutFlag},
		{"FilterDeniedFlag", FilterDeniedFlag},
		{"WouldDenyFlag", WouldDenyFlag},
	}
	assertDistinct(t, "process", process)

	file := []struct {
		name string
		bit  uint32
	}{
		{"DeniedFlag", DeniedFlag},
		{"WriteFlag", WriteFlag},
		{"WouldDenyFlag", WouldDenyFlag},
		{"FileKilledFlag", FileKilledFlag},
	}
	assertDistinct(t, "file", file)

	if WouldDenyFlag != 0x04000000 {
		t.Errorf("WouldDenyFlag is %#x, but bpf/enforce.h defines EV_WOULD_DENY as 0x04000000", WouldDenyFlag)
	}
}

func assertDistinct(t *testing.T, kind string, flags []struct {
	name string
	bit  uint32
}) {
	t.Helper()
	for i := range flags {
		for j := i + 1; j < len(flags); j++ {
			if flags[i].bit&flags[j].bit != 0 {
				t.Errorf("%s: %s (%#x) and %s (%#x) share a bit",
					kind, flags[i].name, flags[i].bit, flags[j].name, flags[j].bit)
			}
		}
	}
}

func TestNetworkDirectionBitsDoNotCollide(t *testing.T) {
	bits := map[string]uint8{
		"DeniedDirection":    DeniedDirection,
		"WouldDenyDirection": WouldDenyDirection,
		"KilledDirection":    KilledDirection,
	}
	seen := map[uint8]string{}
	for name, bit := range bits {
		if other, dup := seen[bit]; dup {
			t.Errorf("%s and %s share the bit %#x", name, other, bit)
		}
		seen[bit] = name
	}
}

// fakeMap records what a setter would have written, so the map-writing logic is
// testable without a kernel.
type fakeMap struct {
	puts      []struct{ key, value uint32 }
	deletes   []uint64
	putErr    error
	deleteErr error
}

func (f *fakeMap) Put(key, value any) error {
	if f.putErr != nil {
		return f.putErr
	}
	k, _ := key.(*uint64)
	v, _ := value.(*uint32)
	if k == nil || v == nil {
		return errors.New("unexpected key or value type")
	}
	f.puts = append(f.puts, struct{ key, value uint32 }{uint32(*k), *v})
	return nil
}

func (f *fakeMap) Delete(key any) error {
	k, _ := key.(*uint64)
	if k != nil {
		f.deletes = append(f.deletes, *k)
	}
	return f.deleteErr
}

func BenchmarkEnforcementSpecPack(b *testing.B) {
	s := EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP, Errno: 13}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pack()
	}
}

func BenchmarkEnforcementSpecValidate(b *testing.B) {
	s := EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP, Errno: 13}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Validate()
	}
}

func BenchmarkSetActionOn(b *testing.B) {
	mp := &fakeMap{}
	s := EnforcementSpec{Action: ActionDeny}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mp.puts = mp.puts[:0]
		_ = setActionOn(mp, "file_mode", 1, s)
	}
}
