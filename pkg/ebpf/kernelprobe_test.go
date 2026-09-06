package ebpf

import (
	"encoding/binary"
	"strings"
	"syscall"
	"testing"
)

// The wire format is shared with bpf/generic_kprobe.c. A change on either side
// that this does not catch turns a selector into a different selector, or an
// argument index into an operator, with nothing else to notice.
func TestProbeConfigMarshalLayout(t *testing.T) {
	p := KernelProbe{
		Symbol: "commit_creds",
		Action: EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP},
		Scoped: true,
		Selectors: []ProbeSelector{
			{Source: SourceArg, Arg: 2, Op: OpMaskSet, Value: 0x10000000},
			{Source: SourceUID, Op: OpEqual, Value: 0},
		},
	}
	b := p.marshal()
	if len(b) != kprobeConfigSize {
		t.Fatalf("config is %d bytes, the kernel struct is %d", len(b), kprobeConfigSize)
	}
	if got := binary.LittleEndian.Uint32(b[0:]); got != p.Action.Pack() {
		t.Errorf("action packed as %#x, want %#x", got, p.Action.Pack())
	}
	if b[4] != 2 {
		t.Errorf("selector count is %d, want 2", b[4])
	}
	if b[5] != 1 {
		t.Errorf("scoped flag is %d, want 1", b[5])
	}
	// First selector at offset 8, second 16 bytes later.
	if b[8] != uint8(SourceArg) || b[9] != 2 || b[10] != uint8(OpMaskSet) {
		t.Errorf("selector 0 header is %v, want src=arg arg=2 op=maskset", b[8:11])
	}
	if got := binary.LittleEndian.Uint64(b[16:]); got != 0x10000000 {
		t.Errorf("selector 0 value is %#x, want 0x10000000", got)
	}
	if b[24] != uint8(SourceUID) || b[26] != uint8(OpEqual) {
		t.Errorf("selector 1 header is %v, want src=uid op=equal", b[24:27])
	}
}

// A kprobe fires alongside the function, not in place of it. A policy that says
// Deny and quietly observes instead is worse than one that refuses to load,
// because the operator believes a control is in place that is not.
func TestAKernelProbeCannotDeny(t *testing.T) {
	p := KernelProbe{
		Symbol: "security_file_open",
		Action: EnforcementSpec{Action: ActionDeny},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("a probe with Deny was accepted; it can only report, audit, kill or signal")
	}
	if !strings.Contains(err.Error(), "cannot deny") {
		t.Errorf("the error does not explain why: %v", err)
	}
	if !strings.Contains(err.Error(), "LSM hook") {
		t.Errorf("the error does not say what would work instead: %v", err)
	}
}

// A probe on a kernel function fires for the whole node, the kubelet and the
// container runtime included. Signalling every caller with no condition
// attached is how one policy takes a cluster down.
func TestAnUnconditionalNodeWideSignalIsRefused(t *testing.T) {
	for _, act := range []Action{ActionKill, ActionSignal} {
		spec := EnforcementSpec{Action: act}
		if act == ActionSignal {
			spec.Signal = syscall.SIGSTOP
		}
		p := KernelProbe{Name: "everything", Symbol: "vfs_write", Action: spec}
		err := p.Validate()
		if err == nil {
			t.Fatalf("%s on every call to vfs_write, node-wide, was accepted", act)
		}
		if !strings.Contains(err.Error(), "add a selector") {
			t.Errorf("the error does not say how to fix it: %v", err)
		}

		// A selector makes it a policy rather than a blunt instrument.
		p.Selectors = []ProbeSelector{{Source: SourceUID, Op: OpEqual, Value: 0}}
		if err := p.Validate(); err != nil {
			t.Errorf("a selected probe was refused: %v", err)
		}

		// So does scoping it to governed workloads.
		p.Selectors = nil
		p.Scoped = true
		if err := p.Validate(); err != nil {
			t.Errorf("a scoped probe was refused: %v", err)
		}
	}
}

// Observing and auditing are safe without a selector: they change nothing.
func TestAnUnconditionalReportingProbeIsFine(t *testing.T) {
	for _, act := range []Action{ActionLearn, ActionAudit} {
		p := KernelProbe{Name: "watch", Symbol: "vfs_write", Action: EnforcementSpec{Action: act}}
		if err := p.Validate(); err != nil {
			t.Errorf("%s on every call was refused, but it does nothing: %v", act, err)
		}
	}
}

func TestProbeValidationRejectsMalformedSelectors(t *testing.T) {
	base := func(sels ...ProbeSelector) KernelProbe {
		return KernelProbe{Symbol: "vfs_write", Action: EnforcementSpec{Action: ActionAudit}, Selectors: sels}
	}
	cases := []struct {
		name  string
		probe KernelProbe
		want  string
	}{
		{"no symbol", KernelProbe{Action: EnforcementSpec{Action: ActionAudit}}, "needs a symbol"},
		{"argument out of range",
			base(ProbeSelector{Source: SourceArg, Arg: KernelProbeArgs, Op: OpEqual}), "out of range"},
		{"unknown operator",
			base(ProbeSelector{Source: SourceArg, Op: ProbeOp(99)}), "not implemented"},
		{"unknown source",
			base(ProbeSelector{Source: ProbeSource(9), Op: OpEqual}), "not implemented"},
		{"too many selectors", base(
			ProbeSelector{Source: SourceUID, Op: OpEqual}, ProbeSelector{Source: SourceUID, Op: OpEqual},
			ProbeSelector{Source: SourceUID, Op: OpEqual}, ProbeSelector{Source: SourceUID, Op: OpEqual},
			ProbeSelector{Source: SourceUID, Op: OpEqual}), "at most 4 selectors"},
	}
	for _, tc := range cases {
		err := tc.probe.Validate()
		if err == nil {
			t.Errorf("%s: accepted, want an error mentioning %q", tc.name, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

// The highest legal argument index must be accepted; an off-by-one in the bound
// silently makes the last argument unusable.
func TestTheLastArgumentIndexIsUsable(t *testing.T) {
	p := KernelProbe{
		Symbol:    "vfs_write",
		Action:    EnforcementSpec{Action: ActionAudit},
		Selectors: []ProbeSelector{{Source: SourceArg, Arg: KernelProbeArgs - 1, Op: OpEqual, Value: 1}},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("argument %d was refused: %v", KernelProbeArgs-1, err)
	}
}

func TestOperatorAndSourceParsing(t *testing.T) {
	for in, want := range map[string]ProbeOp{
		"Equal": OpEqual, "eq": OpEqual, "": OpEqual,
		"NotEqual": OpNotEqual, "ne": OpNotEqual,
		"Less": OpLess, "Greater": OpGreater,
		"MaskSet": OpMaskSet, "mask": OpMaskSet,
		"MaskClear": OpMaskClear, " nmask ": OpMaskClear,
	} {
		got, err := ParseProbeOp(in)
		if err != nil {
			t.Errorf("ParseProbeOp(%q): %v", in, err)
		} else if got != want {
			t.Errorf("ParseProbeOp(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseProbeOp("contains"); err == nil {
		t.Error("an unknown operator was accepted")
	} else if !strings.Contains(err.Error(), "MaskSet") {
		t.Errorf("the error does not list the valid operators: %v", err)
	}

	for in, want := range map[string]ProbeSource{
		"Arg": SourceArg, "": SourceArg, "UID": SourceUID, "gid": SourceGID, "pid": SourcePID,
	} {
		got, err := ParseProbeSource(in)
		if err != nil {
			t.Errorf("ParseProbeSource(%q): %v", in, err)
		} else if got != want {
			t.Errorf("ParseProbeSource(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseProbeSource("comm"); err == nil {
		t.Error("an unknown source was accepted")
	}
}

func TestProbeOpString(t *testing.T) {
	for op, want := range map[ProbeOp]string{
		OpEqual: "Equal", OpNotEqual: "NotEqual", OpLess: "Less",
		OpGreater: "Greater", OpMaskSet: "MaskSet", OpMaskClear: "MaskClear",
	} {
		if got := op.String(); got != want {
			t.Errorf("%d renders as %q, want %q", op, got, want)
		}
	}
	if got := ProbeOp(42).String(); !strings.Contains(got, "42") {
		t.Errorf("an unknown operator renders as %q, which hides which one it was", got)
	}
}

// An unreadable or absent kallsyms must not be read as "the symbol is missing":
// refusing a probe that would have worked is worse than attempting one that
// fails with a clear ENOENT.
func TestUnknownSymbolIsNotTreatedAsAbsent(t *testing.T) {
	// A symbol that certainly exists on any Linux kernel with kallsyms
	// readable; on a machine where it is not readable this returns true too,
	// which is the property under test.
	ok, err := KernelSymbolExists("vfs_read")
	if err != nil {
		t.Fatalf("KernelSymbolExists: %v", err)
	}
	if !ok {
		t.Error("vfs_read was reported absent; either kallsyms parsing is wrong or " +
			"an unreadable kallsyms is being read as absence")
	}
}

func TestParseKernelProbeEvent(t *testing.T) {
	rec := buildKprobeRec(99, 12345, 7, [KernelProbeArgs]uint64{1, 2, 3, 4, 5},
		4242, 4243, 1000, 1001, ProbeMatched|ProbeSignalled, "python3")
	e := parseKernelProbeEvent(rec)
	if e == nil {
		t.Fatal("a well-formed record failed to decode")
	}
	if e.CgroupID != 99 || e.ProbeID != 7 || e.Timestamp != 12345 {
		t.Errorf("header decoded wrong: %+v", e)
	}
	if e.Args != [KernelProbeArgs]uint64{1, 2, 3, 4, 5} {
		t.Errorf("arguments decoded as %v", e.Args)
	}
	if e.PID != 4242 || e.TID != 4243 || e.UID != 1000 || e.GID != 1001 {
		t.Errorf("identity decoded wrong: %+v", e)
	}
	if e.Comm != "python3" {
		t.Errorf("comm decoded as %q", e.Comm)
	}
	if !e.Signalled() {
		t.Error("the signalled flag was lost")
	}
	if e.WouldAct() {
		t.Error("a signalled event reports as audit-only")
	}
	if e.ContainerID != "cgroup:99" {
		t.Errorf("container id is %q", e.ContainerID)
	}
}

func TestParseKernelProbeEventRejectsShortRecords(t *testing.T) {
	full := buildKprobeRec(1, 2, 3, [KernelProbeArgs]uint64{}, 4, 5, 6, 7, 0, "sh")
	for _, n := range []int{0, 24, 63, len(full) - 1} {
		if parseKernelProbeEvent(full[:n]) != nil {
			t.Fatalf("a %d-byte record decoded to an event", n)
		}
	}
	if parseKernelProbeEvent(full) == nil {
		t.Fatal("a full-length record failed to decode")
	}
}

func TestProbeFlagValuesMatchTheKernelContract(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want uint32
	}{
		{"ProbeMatched", ProbeMatched, 0x01},
		{"ProbeSignalled", ProbeSignalled, 0x02},
		{"ProbeWouldAct", ProbeWouldAct, 0x04},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, but bpf/generic_kprobe.c defines %#x", tc.name, tc.got, tc.want)
		}
	}
	if KernelProbeArgs != 5 || KernelProbeSelectors != 4 {
		t.Errorf("limits are %d args / %d selectors, but the C defines 5 / 4",
			KernelProbeArgs, KernelProbeSelectors)
	}
}

func TestAttachWithoutTheProgramLoaded(t *testing.T) {
	m := &Manager{}
	_, err := m.AttachKernelProbe(KernelProbe{
		Symbol: "vfs_read", Action: EnforcementSpec{Action: ActionAudit}})
	if err == nil {
		t.Error("attaching succeeded with no program loaded")
	}
	if err := m.DetachKernelProbe(1); err != nil {
		t.Errorf("detaching something never attached returned %v, want nil", err)
	}
	if got := m.AttachedKernelProbes(); len(got) != 0 {
		t.Errorf("probes are listed as attached: %v", got)
	}
	// A malformed probe must be refused before the loaded check, so the
	// operator gets the real problem rather than "not loaded".
	_, err = m.AttachKernelProbe(KernelProbe{Symbol: ""})
	if err == nil || !strings.Contains(err.Error(), "needs a symbol") {
		t.Errorf("a probe with no symbol reported %v, want the symbol error", err)
	}
}

// buildKprobeRec assembles the wire format of `struct kp_event` exactly as
// bpf/generic_kprobe.c emits it.
func buildKprobeRec(cgroup, ts, probeID uint64, args [KernelProbeArgs]uint64,
	pid, tid, uid, gid, flags uint32, comm string) []byte {
	const argsOff = 24
	const u32Off = argsOff + KernelProbeArgs*8
	const commOff = u32Off + 6*4
	b := make([]byte, commOff+16)
	binary.LittleEndian.PutUint64(b[0:], cgroup)
	binary.LittleEndian.PutUint64(b[8:], ts)
	binary.LittleEndian.PutUint64(b[16:], probeID)
	for i, a := range args {
		binary.LittleEndian.PutUint64(b[argsOff+i*8:], a)
	}
	for i, v := range []uint32{pid, tid, uid, gid, flags} {
		binary.LittleEndian.PutUint32(b[u32Off+i*4:], v)
	}
	copy(b[commOff:], comm)
	return b
}

func BenchmarkProbeMarshal(b *testing.B) {
	p := KernelProbe{
		Symbol: "commit_creds",
		Action: EnforcementSpec{Action: ActionSignal, Signal: syscall.SIGSTOP},
		Selectors: []ProbeSelector{
			{Source: SourceArg, Arg: 2, Op: OpMaskSet, Value: 0x10000000},
			{Source: SourceUID, Op: OpEqual, Value: 0},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.marshal()
	}
}

func BenchmarkProbeValidate(b *testing.B) {
	p := KernelProbe{
		Symbol:    "commit_creds",
		Action:    EnforcementSpec{Action: ActionAudit},
		Selectors: []ProbeSelector{{Source: SourceUID, Op: OpEqual, Value: 0}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Validate()
	}
}

func BenchmarkParseKernelProbeEvent(b *testing.B) {
	rec := buildKprobeRec(99, 12345, 7, [KernelProbeArgs]uint64{1, 2, 3, 4, 5},
		4242, 4243, 1000, 1001, ProbeMatched, "python3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if parseKernelProbeEvent(rec) == nil {
			b.Fatal("decode failed")
		}
	}
}
