package ebpf

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"syscall"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/cilium/ebpf/link"
)

// Kernel probes an operator points at any function, without rebuilding.
//
// The other six programs each watch one thing, chosen because they answer the
// questions a learned baseline needs. That covers the model well and covers
// everything else not at all: a kernel function outside the set - a filesystem
// hook, a module load path, whatever tomorrow's advisory names - was
// unreachable without writing C and shipping a new agent.
//
// One pre-compiled program serves every probe. Userspace attaches it to each
// named symbol with an attach cookie carrying the probe id, and the program
// reads that cookie to find its configuration, so forty probes are forty links
// over one program rather than forty copies of it.

// KernelProbe argument and selector limits, mirroring bpf/generic_kprobe.c.
const (
	// KernelProbeArgs is how many function arguments are captured. Five is
	// what PT_REGS_PARM exposes portably on both architectures.
	KernelProbeArgs = 5
	// KernelProbeSelectors is how many conditions one probe may carry. They
	// are evaluated in an unrolled loop, and the verifier's instruction
	// budget is not free.
	KernelProbeSelectors = 4
)

// ProbeSource is what a selector compares against.
type ProbeSource uint8

const (
	// SourceArg compares a function argument.
	SourceArg ProbeSource = 0
	// SourceUID compares the calling task's effective uid. A probe that can
	// only see arguments cannot say "when root does it", which is most of
	// what makes a probe interesting.
	SourceUID ProbeSource = 1
	// SourceGID compares the effective gid.
	SourceGID ProbeSource = 2
	// SourcePID compares the thread-group id.
	SourcePID ProbeSource = 3
)

// ProbeOp is a selector's comparison.
type ProbeOp uint8

const (
	// OpEqual matches when the value is exactly equal.
	OpEqual ProbeOp = 1
	// OpNotEqual matches when it differs.
	OpNotEqual ProbeOp = 2
	// OpLess matches when the value is below.
	OpLess ProbeOp = 3
	// OpGreater matches when the value is above.
	OpGreater ProbeOp = 4
	// OpMaskSet matches when any of the value's bits are set, which is how a
	// flags argument is usefully matched.
	OpMaskSet ProbeOp = 5
	// OpMaskClear matches when none of them are.
	OpMaskClear ProbeOp = 6
)

// String renders an operator for policy translation and diagnostics.
func (o ProbeOp) String() string {
	switch o {
	case OpEqual:
		return "Equal"
	case OpNotEqual:
		return "NotEqual"
	case OpLess:
		return "Less"
	case OpGreater:
		return "Greater"
	case OpMaskSet:
		return "MaskSet"
	case OpMaskClear:
		return "MaskClear"
	}
	return fmt.Sprintf("ProbeOp(%d)", uint8(o))
}

// ParseProbeOp reads an operator name, case-insensitively.
func ParseProbeOp(s string) (ProbeOp, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "equal", "eq", "":
		return OpEqual, nil
	case "notequal", "ne":
		return OpNotEqual, nil
	case "less", "lt":
		return OpLess, nil
	case "greater", "gt":
		return OpGreater, nil
	case "maskset", "mask":
		return OpMaskSet, nil
	case "maskclear", "nmask":
		return OpMaskClear, nil
	}
	return 0, fmt.Errorf(
		"unknown selector operator %q: want Equal, NotEqual, Less, Greater, MaskSet or MaskClear", s)
}

// ParseProbeSource reads a selector source, case-insensitively.
func ParseProbeSource(s string) (ProbeSource, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "arg", "argument", "":
		return SourceArg, nil
	case "uid":
		return SourceUID, nil
	case "gid":
		return SourceGID, nil
	case "pid":
		return SourcePID, nil
	}
	return 0, fmt.Errorf("unknown selector source %q: want Arg, UID, GID or PID", s)
}

// ProbeSelector is one condition on a probe. Selectors are ANDed.
type ProbeSelector struct {
	Source ProbeSource
	// Arg is the argument index, 0 to KernelProbeArgs-1, when Source is
	// SourceArg. Ignored otherwise.
	Arg uint8
	Op  ProbeOp
	// Value is what the source is compared against. For a pointer argument
	// this is the pointer, not what it points at: the program does not
	// dereference, because a bad address in a probe on a hot kernel path is
	// not a mistake worth risking.
	Value uint64
}

// Validate rejects a selector the kernel would evaluate as never matching.
func (s ProbeSelector) Validate() error {
	if s.Source == SourceArg && s.Arg >= KernelProbeArgs {
		return fmt.Errorf(
			"selector argument index %d is out of range; only %d arguments are captured",
			s.Arg, KernelProbeArgs)
	}
	if s.Op < OpEqual || s.Op > OpMaskClear {
		return fmt.Errorf("selector operator %d is not implemented", s.Op)
	}
	if s.Source > SourcePID {
		return fmt.Errorf("selector source %d is not implemented", s.Source)
	}
	return nil
}

// KernelProbe is one function to watch and what to do when it matches.
type KernelProbe struct {
	// Name identifies the probe to an operator. Not used by the kernel.
	Name string
	// Symbol is the kernel function to attach to, as it appears in
	// /proc/kallsyms.
	Symbol string
	// Selectors are ANDed. None means every call matches, which is what
	// "watch this function" means - and why an unselected probe should not
	// carry a signalling action.
	Selectors []ProbeSelector
	// Action is what a match does.
	//
	// A kprobe fires alongside the function, not in place of it, so it cannot
	// refuse the call: denying needs bpf_override_return, which requires
	// CONFIG_BPF_KPROBE_OVERRIDE and a target the kernel marks error
	// injectable. ActionDeny is therefore rejected rather than silently
	// downgraded, because a policy that says Deny and quietly observes is
	// worse than one that fails to load.
	Action EnforcementSpec
	// Scoped restricts the probe to cgroups passed to GovernKernelProbes.
	//
	// A probe on a kernel function fires for the whole node, the kubelet and
	// the container runtime included. Anything that signals must be able to
	// say "only these workloads", or the first over-broad policy takes the
	// node down.
	Scoped bool
}

// Validate checks a probe before it reaches the kernel.
func (p KernelProbe) Validate() error {
	if strings.TrimSpace(p.Symbol) == "" {
		return fmt.Errorf("a kernel probe needs a symbol to attach to")
	}
	if len(p.Selectors) > KernelProbeSelectors {
		return fmt.Errorf(
			"a kernel probe may carry at most %d selectors, got %d",
			KernelProbeSelectors, len(p.Selectors))
	}
	for i, s := range p.Selectors {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("selector %d: %w", i, err)
		}
	}
	if p.Action.Action == ActionDeny {
		return fmt.Errorf(
			"a kernel probe cannot deny: a kprobe runs alongside the function rather than "+
				"in place of it, so %q can report, audit, kill or signal, but refusing the "+
				"call needs an LSM hook", p.Symbol)
	}
	if err := p.Action.Validate(); err != nil {
		return err
	}
	// Signalling every caller of a kernel function, node-wide, with no
	// condition attached is not a policy anybody means to write.
	if len(p.Selectors) == 0 && !p.Scoped &&
		(p.Action.Action == ActionKill || p.Action.Action == ActionSignal) {
		return fmt.Errorf(
			"probe %q signals on every call to %s across the whole node: add a selector "+
				"or set Scoped so it applies only to governed workloads",
			p.Name, p.Symbol)
	}
	return nil
}

// kprobeSelectorSize and kprobeConfigSize mirror the C structs in
// bpf/generic_kprobe.c. The two halves must move together.
const (
	kprobeSelectorSize = 16                                          // src,arg,op,pad + pad2 + value
	kprobeConfigSize   = 8 + KernelProbeSelectors*kprobeSelectorSize // action,n,scoped,pad
)

// marshal renders a probe's configuration in the layout the kernel map expects.
func (p KernelProbe) marshal() []byte {
	b := make([]byte, kprobeConfigSize)
	binary.LittleEndian.PutUint32(b[0:], p.Action.Pack())
	b[4] = uint8(len(p.Selectors))
	if p.Scoped {
		b[5] = 1
	}
	for i, s := range p.Selectors {
		off := 8 + i*kprobeSelectorSize
		b[off] = uint8(s.Source)
		b[off+1] = s.Arg
		b[off+2] = uint8(s.Op)
		binary.LittleEndian.PutUint64(b[off+8:], s.Value)
	}
	return b
}

// KernelSymbolExists reports whether a symbol is one the kernel can be probed
// at, by looking it up in /proc/kallsyms.
//
// Worth doing before the attach rather than after: attaching to a symbol that
// does not exist fails with ENOENT, which is indistinguishable from a dozen
// other causes, and a typo in a policy field deserves an error naming the typo.
// A kernel that hides kallsyms returns no error here - absence of evidence is
// not a reason to refuse a probe that might work.
func KernelSymbolExists(symbol string) (bool, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		// Unreadable: do not claim the symbol is missing.
		return true, nil //nolint:nilerr // deliberate: unknown is not absent
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		// "ffffffff81000000 T symbol_name [module]"
		line := sc.Text()
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		name := line[i+1:]
		if j := strings.IndexByte(name, '\t'); j >= 0 {
			name = name[:j]
		}
		if name == symbol {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return true, nil //nolint:nilerr // deliberate: a read error is not absence
	}
	return false, nil
}

// probeState is one attached probe.
type probeState struct {
	probe KernelProbe
	link  link.Link
	id    uint64
}

// AttachKernelProbe attaches the generic program to the probe's symbol.
//
// Each attachment carries an attach cookie set to a probe id, which is how the
// one program knows which configuration it is running under. The configuration
// is written before the link is created, so a probe can never fire against a
// map entry that does not exist yet.
func (m *Manager) AttachKernelProbe(p KernelProbe) (uint64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.kprobeCollection == nil {
		return 0, fmt.Errorf("the generic kprobe program is not loaded")
	}
	if ok, _ := KernelSymbolExists(p.Symbol); !ok {
		return 0, fmt.Errorf(
			"%q is not in /proc/kallsyms: check the spelling, and that the module "+
				"providing it is loaded", p.Symbol)
	}

	prog := m.kprobeCollection.Programs["generic_kprobe"]
	if prog == nil {
		return 0, fmt.Errorf("the generic_kprobe program is absent from the loaded object")
	}
	cfgMap := m.kprobeCollection.Maps["kp_config"]
	if cfgMap == nil {
		return 0, fmt.Errorf("the kp_config map is absent from the loaded object")
	}

	if m.kprobes == nil {
		m.kprobes = make(map[uint64]*probeState, 8)
	}
	m.nextProbeID++
	id := m.nextProbeID

	cfg := p.marshal()
	if err := cfgMap.Put(&id, cfg); err != nil {
		return 0, fmt.Errorf("writing the configuration for probe %q: %w", p.Name, err)
	}

	l, err := link.Kprobe(p.Symbol, prog, &link.KprobeOptions{Cookie: id})
	if err != nil {
		// Roll the configuration back rather than leaving an entry for a probe
		// that is not attached: the next attach would reuse neither the id nor
		// the entry, and the map would fill with orphans.
		_ = cfgMap.Delete(&id)
		return 0, fmt.Errorf("attaching a kprobe to %q: %w", p.Symbol, err)
	}

	m.kprobes[id] = &probeState{probe: p, link: l, id: id}
	if err := m.setKernelProbesEnabledLocked(true); err != nil {
		log.Log.V(0).Info("kernel probe attached but could not be enabled", "error", err.Error())
	}
	return id, nil
}

// DetachKernelProbe removes one probe and its configuration.
func (m *Manager) DetachKernelProbe(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.kprobes[id]
	if !ok {
		return nil
	}
	err := st.link.Close()
	delete(m.kprobes, id)

	if m.kprobeCollection != nil {
		if cfgMap := m.kprobeCollection.Maps["kp_config"]; cfgMap != nil {
			k := id
			_ = cfgMap.Delete(&k)
		}
	}
	// The last one out turns the program off, so a stray event cannot arrive
	// from a probe nobody remembers attaching.
	if len(m.kprobes) == 0 {
		_ = m.setKernelProbesEnabledLocked(false)
	}
	return err
}

// AttachedKernelProbes lists what is attached, by id.
func (m *Manager) AttachedKernelProbes() map[uint64]KernelProbe {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[uint64]KernelProbe, len(m.kprobes))
	for id, st := range m.kprobes {
		out[id] = st.probe
	}
	return out
}

// GovernKernelProbes adds a cgroup to the set that scoped probes apply to.
func (m *Manager) GovernKernelProbes(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kprobeCollection == nil {
		return fmt.Errorf("the generic kprobe program is not loaded")
	}
	mp := m.kprobeCollection.Maps["kp_governed"]
	if mp == nil {
		return fmt.Errorf("the kp_governed map is absent from the loaded object")
	}
	var one uint8 = 1
	return mp.Put(&cgroupID, &one)
}

// UngovernKernelProbes removes a cgroup from that set.
func (m *Manager) UngovernKernelProbes(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kprobeCollection == nil {
		return fmt.Errorf("the generic kprobe program is not loaded")
	}
	mp := m.kprobeCollection.Maps["kp_governed"]
	if mp == nil {
		return fmt.Errorf("the kp_governed map is absent from the loaded object")
	}
	k := cgroupID
	if err := mp.Delete(&k); err != nil && !isMissingKey(err) {
		return err
	}
	return nil
}

func (m *Manager) setKernelProbesEnabledLocked(on bool) error {
	if m.kprobeCollection == nil {
		return fmt.Errorf("the generic kprobe program is not loaded")
	}
	mp := m.kprobeCollection.Maps["kp_runtime"]
	if mp == nil {
		return fmt.Errorf("the kp_runtime map is absent from the loaded object")
	}
	var key, val uint32
	if on {
		val = 1
	}
	return mp.Put(&key, &val)
}

// Flags on a KernelProbeEvent, mirroring bpf/generic_kprobe.c.
const (
	// ProbeMatched is set on every emitted event; the kernel only emits on a
	// match.
	ProbeMatched uint32 = 0x01
	// ProbeSignalled means the task was sent a signal.
	ProbeSignalled uint32 = 0x02
	// ProbeWouldAct is the Audit action's marker: reported, nothing done.
	ProbeWouldAct uint32 = 0x04
)

// KernelProbeEvent is one match on a user-defined probe.
type KernelProbeEvent struct {
	CgroupID    uint64
	Timestamp   uint64
	ProbeID     uint64
	Args        [KernelProbeArgs]uint64
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	Flags       uint32
	Comm        string
	ContainerID string
}

// Signalled reports whether the task was signalled.
func (e *KernelProbeEvent) Signalled() bool { return e.Flags&ProbeSignalled != 0 }

// WouldAct reports whether the probe's action was withheld because it is in
// Audit.
func (e *KernelProbeEvent) WouldAct() bool { return e.Flags&ProbeWouldAct != 0 }

// KernelProbeEventHandler receives kernel-probe matches. Satisfied by type
// assertion, like the credential and shell handlers, so a consumer with no
// interest in probes is not made to stub a method.
type KernelProbeEventHandler interface {
	HandleKernelProbeEvent(event *KernelProbeEvent) error
}

// parseKernelProbeEvent decodes `struct kp_event` from bpf/generic_kprobe.c:
//
//	__u64 cgroup_id, timestamp_ns, probe_id; __u64 args[5];
//	__u32 pid, tid, uid, gid, flags, pad; __u8 comm[16];
func parseKernelProbeEvent(data []byte) *KernelProbeEvent {
	const argsOff = 24
	const u32Off = argsOff + KernelProbeArgs*8 // 64
	const commOff = u32Off + 6*4               // 88
	const size = commOff + 16                  // 104
	if len(data) < size {
		return nil
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(data[off : off+4]) }

	e := &KernelProbeEvent{
		CgroupID:  binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		ProbeID:   binary.LittleEndian.Uint64(data[16:24]),
		PID:       u32(u32Off),
		TID:       u32(u32Off + 4),
		UID:       u32(u32Off + 8),
		GID:       u32(u32Off + 12),
		Flags:     u32(u32Off + 16),
	}
	for i := 0; i < KernelProbeArgs; i++ {
		e.Args[i] = binary.LittleEndian.Uint64(data[argsOff+i*8 : argsOff+(i+1)*8])
	}
	e.Comm = internComm(data[commOff : commOff+16])
	e.ContainerID = containerIDFor(e.CgroupID)
	return e
}

// isMissingKey reports whether an error is the map's "no such key".
func isMissingKey(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "key does not exist") ||
		strings.Contains(err.Error(), syscall.ENOENT.Error()))
}
