package ebpf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

// Escalation primitives: the syscalls whose *arguments* decide whether an
// event is routine or an attack.
//
// These bypass the in-kernel deduplication that keeps the syscall monitor
// cheap. For a learned baseline, deduplication loses nothing - the question is
// which syscalls a workload uses, and the first occurrence answers it. For
// these it loses everything. The first ptrace a process makes is usually a
// debugger or a crash handler attaching to itself at startup; the interesting
// one is the fourteenth, an hour later, carrying PTRACE_ATTACH and somebody
// else's pid. Deduplicating that away deduplicates away the attack.
//
// The set is deliberately short. Every entry costs one hash lookup per
// syscall on the hottest path in the program, and every entry that fires
// routinely is noise that gets muted.
var escalationPrimitives = []string{
	// Reading or writing another process's memory: the mechanism behind
	// CVE-2025-4271 and every "attach to the process that has the token"
	// technique.
	"ptrace",
	"process_vm_readv",
	"process_vm_writev",

	// Namespace manipulation. unshare(CLONE_NEWUSER) is the front door to
	// unprivileged privilege escalation (CVE-2025-5103); setns is how a
	// process joins a namespace it was not started in, which is either a
	// container runtime doing its job or an escape in progress.
	"unshare",
	"setns",
	"pivot_root",
	"mount",
	"move_mount",
	"open_tree",
	"fsopen",

	// Loading code into the kernel.
	"bpf",
	"init_module",
	"finit_module",
	"kexec_load",
	"kexec_file_load",

	// open_by_handle_at is the shocker exploit: it resolves a file handle
	// without a path, so a container with CAP_DAC_READ_SEARCH can reach the
	// host filesystem without ever traversing a directory Pahlevan is
	// watching.
	"open_by_handle_at",
	"name_to_handle_at",

	// io_uring submits syscalls through a ring buffer rather than the syscall
	// entry path, which is exactly how it bypasses seccomp - and would bypass
	// this monitor too. Seeing the setup is the only chance to know it is
	// happening.
	"io_uring_setup",

	// userfaultfd lets userspace pause the kernel mid-fault, which is how
	// most heap-grooming exploits win their race.
	"userfaultfd",

	// perf_event_open has a long history of local root and is almost never
	// legitimate from inside a container.
	"perf_event_open",

	// Direct credential changes. Cheap to watch and unambiguous.
	"setuid",
	"setreuid",
	"setresuid",
}

// EscalationPrimitives returns the syscall numbers watched on this
// architecture, in ascending order.
//
// Names absent from the architecture's table are skipped rather than
// erroring: arm64 has no kexec_load and amd64 has no distinct entries some
// other architecture does, and a monitor that refuses to start because one
// name is missing is worse than one that watches the rest.
func EscalationPrimitives() []uint64 {
	byName := make(map[string]uint64, len(seccomp.SyscallName))
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}

	seen := make(map[uint64]struct{}, len(escalationPrimitives))
	out := make([]uint64, 0, len(escalationPrimitives))
	for _, name := range escalationPrimitives {
		nr, ok := byName[name]
		if !ok {
			continue
		}
		if _, dup := seen[nr]; dup {
			continue
		}
		seen[nr] = struct{}{}
		out = append(out, nr)
	}

	// Ascending, so the map is populated in a stable order and a test can
	// compare two runs.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// IsEscalationPrimitive reports whether a syscall number is watched.
func IsEscalationPrimitive(nr uint64) bool {
	name, ok := seccomp.SyscallName[nr]
	if !ok {
		return false
	}
	for _, p := range escalationPrimitives {
		if p == name {
			return true
		}
	}
	return false
}

// installSyscallWatch fills the kernel-side watch set.
//
// The numbers live here rather than in the eBPF program because they differ
// by architecture and the kernel side has no table to consult. Keeping them
// in Go is what lets bpf/syscall_monitor.c stay architecture-neutral.
func (m *Manager) installSyscallWatch() error {
	if m.syscallCollection == nil {
		return fmt.Errorf("syscall programs are not loaded")
	}
	mp := m.syscallCollection.Maps["syscall_watch"]
	if mp == nil {
		return fmt.Errorf("the syscall_watch map is absent from the loaded object")
	}

	var one uint8 = 1
	for _, nr := range EscalationPrimitives() {
		key := nr
		if err := mp.Put(&key, &one); err != nil {
			return fmt.Errorf("watching %s (%d): %w", SyscallNameOrNumber(nr), nr, err)
		}
	}
	return nil
}

// DescribeSyscallArgs renders a syscall's arguments the way a human reads
// them: the flags by name where Pahlevan knows the syscall, and the raw words
// where it does not.
//
// The distinction the whole feature exists for is here. "ptrace" and
// "ptrace(PTRACE_ATTACH, pid=1)" are the same event without arguments, and
// only one of them is worth waking somebody for.
func DescribeSyscallArgs(nr uint64, args [6]uint64) string {
	switch seccomp.SyscallName[nr] {
	case "ptrace":
		return fmt.Sprintf("request=%s pid=%d", ptraceRequest(args[0]), int64(args[1]))
	case "unshare":
		return "flags=" + cloneFlags(args[0])
	case "setns":
		return fmt.Sprintf("fd=%d nstype=%s", int64(args[0]), cloneFlags(args[1]))
	case "bpf":
		return fmt.Sprintf("cmd=%s", bpfCmd(args[0]))
	case "mount":
		return "flags=" + mountFlags(args[3])
	case "setuid":
		return fmt.Sprintf("uid=%d", uint32(args[0]))
	case "setreuid":
		return fmt.Sprintf("ruid=%d euid=%d", int32(args[0]), int32(args[1]))
	case "setresuid":
		return fmt.Sprintf("ruid=%d euid=%d suid=%d", int32(args[0]), int32(args[1]), int32(args[2]))
	case "process_vm_readv", "process_vm_writev":
		return fmt.Sprintf("pid=%d", int64(args[0]))
	case "perf_event_open":
		return fmt.Sprintf("pid=%d cpu=%d", int64(args[1]), int32(args[2]))
	case "socket":
		return fmt.Sprintf("family=%d type=%d protocol=%d", args[0], args[1], args[2])
	}

	// Unknown syscall, or one whose arguments Pahlevan does not interpret.
	// Printing the raw words is still more than the number alone conveys, and
	// trailing zeroes are dropped because six of them is noise.
	last := -1
	for i := 5; i >= 0; i-- {
		if args[i] != 0 {
			last = i
			break
		}
	}
	if last < 0 {
		return ""
	}
	parts := make([]string, 0, last+1)
	for i := 0; i <= last; i++ {
		parts = append(parts, "0x"+strconv.FormatUint(args[i], 16))
	}
	return strings.Join(parts, " ")
}

// ptraceRequest names the request numbers that matter. PTRACE_ATTACH and
// PTRACE_SEIZE are one process taking control of another; PTRACE_TRACEME is a
// process asking to be traced, which is what a debugger's child does and what
// an anti-debugging check does, and is not an escalation on its own.
func ptraceRequest(req uint64) string {
	switch req {
	case 0:
		return "PTRACE_TRACEME"
	case 1:
		return "PTRACE_PEEKTEXT"
	case 2:
		return "PTRACE_PEEKDATA"
	case 4:
		return "PTRACE_POKETEXT"
	case 5:
		return "PTRACE_POKEDATA"
	case 8:
		return "PTRACE_KILL"
	case 12:
		return "PTRACE_GETREGS"
	case 13:
		return "PTRACE_SETREGS"
	case 16:
		return "PTRACE_ATTACH"
	case 17:
		return "PTRACE_DETACH"
	case 0x4206:
		return "PTRACE_SETOPTIONS"
	case 0x4206 + 10:
		return "PTRACE_SEIZE"
	}
	return strconv.FormatUint(req, 10)
}

// cloneFlags names the namespace bits of clone(2)/unshare(2)/setns(2).
//
// Only the namespace flags: the rest of clone's flag space describes thread
// creation, which is not what these syscalls are watched for.
func cloneFlags(f uint64) string {
	named := []struct {
		bit  uint64
		name string
	}{
		{0x00020000, "CLONE_NEWNS"},
		{0x04000000, "CLONE_NEWUTS"},
		{0x08000000, "CLONE_NEWIPC"},
		{0x10000000, "CLONE_NEWUSER"},
		{0x20000000, "CLONE_NEWPID"},
		{0x40000000, "CLONE_NEWNET"},
		{0x02000000, "CLONE_NEWCGROUP"},
		{0x00000200, "CLONE_NEWTIME"},
	}
	return flagString(f, named)
}

// mountFlags names the mount(2) flags that change what a mount can be used
// for. MS_BIND and the propagation flags are how a container escape
// re-exposes the host filesystem.
func mountFlags(f uint64) string {
	named := []struct {
		bit  uint64
		name string
	}{
		{1, "MS_RDONLY"},
		{2, "MS_NOSUID"},
		{4, "MS_NODEV"},
		{8, "MS_NOEXEC"},
		{4096, "MS_BIND"},
		{8192, "MS_MOVE"},
		{16384, "MS_REC"},
		{1 << 18, "MS_SHARED"},
		{1 << 19, "MS_RELATIME"},
		{1 << 20, "MS_KERNMOUNT"},
		{1 << 17, "MS_UNBINDABLE"},
		{1 << 16, "MS_PRIVATE"},
		{1 << 8, "MS_SLAVE"},
		{1 << 5, "MS_REMOUNT"},
	}
	return flagString(f, named)
}

// bpfCmd names the bpf(2) commands that load or attach code. The rest are map
// operations, which any BPF-using process performs constantly.
func bpfCmd(c uint64) string {
	switch c {
	case 0:
		return "BPF_MAP_CREATE"
	case 5:
		return "BPF_PROG_LOAD"
	case 8:
		return "BPF_PROG_ATTACH"
	case 9:
		return "BPF_PROG_DETACH"
	case 10:
		return "BPF_PROG_TEST_RUN"
	case 18:
		return "BPF_BTF_LOAD"
	case 28:
		return "BPF_LINK_CREATE"
	}
	return strconv.FormatUint(c, 10)
}

func flagString(f uint64, named []struct {
	bit  uint64
	name string
}) string {
	if f == 0 {
		return "0"
	}
	var parts []string
	rest := f
	for _, n := range named {
		if f&n.bit != 0 {
			parts = append(parts, n.name)
			rest &^= n.bit
		}
	}
	if rest != 0 {
		parts = append(parts, "0x"+strconv.FormatUint(rest, 16))
	}
	return strings.Join(parts, "|")
}
