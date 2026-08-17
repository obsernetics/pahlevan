package ebpf

import (
	"strings"
	"testing"

	"github.com/obsernetics/pahlevan/pkg/seccomp"
)

// The watch set is the reason syscall arguments are worth capturing at all: a
// deduplicated ptrace is one event at process start, and the fourteenth one an
// hour later is the attack.
func TestEscalationPrimitivesResolveOnThisArchitecture(t *testing.T) {
	nrs := EscalationPrimitives()
	if len(nrs) == 0 {
		t.Fatal("no escalation primitive resolved to a syscall number; the name table is not being consulted")
	}

	// Every entry must be a real syscall on this architecture, and the ones
	// that carry the whole point of the feature must be present. If ptrace or
	// unshare ever fall out of the list the feature still compiles and quietly
	// stops watching the two syscalls it was built for.
	byNr := map[uint64]string{}
	for _, nr := range nrs {
		name, ok := seccomp.SyscallName[nr]
		if !ok {
			t.Errorf("watch set contains %d, which is not a syscall on this architecture", nr)
			continue
		}
		byNr[nr] = name
	}
	for _, required := range []string{"ptrace", "unshare", "setns", "bpf", "mount", "io_uring_setup"} {
		found := false
		for _, name := range byNr {
			if name == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is not watched, but it is one of the primitives the watch set exists for", required)
		}
	}
}

func TestEscalationPrimitivesAreSortedAndUnique(t *testing.T) {
	nrs := EscalationPrimitives()
	seen := map[uint64]bool{}
	for i, nr := range nrs {
		if seen[nr] {
			t.Errorf("%d appears twice; the map would be written twice for no reason", nr)
		}
		seen[nr] = true
		if i > 0 && nr < nrs[i-1] {
			t.Errorf("not ascending at index %d: %d after %d", i, nr, nrs[i-1])
		}
	}
}

func TestEscalationPrimitivesIsStableAcrossCalls(t *testing.T) {
	// Built from a map, which iterates in a random order. Without the sort at
	// the end this would pass most of the time and fail occasionally, which is
	// the worst possible failure mode for a test.
	first := EscalationPrimitives()
	for i := 0; i < 50; i++ {
		next := EscalationPrimitives()
		if len(next) != len(first) {
			t.Fatalf("length changed between calls: %d then %d", len(first), len(next))
		}
		for j := range first {
			if next[j] != first[j] {
				t.Fatalf("order changed between calls at index %d: %d then %d", j, first[j], next[j])
			}
		}
	}
}

func TestIsEscalationPrimitive(t *testing.T) {
	byName := map[string]uint64{}
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}

	if nr, ok := byName["ptrace"]; ok && !IsEscalationPrimitive(nr) {
		t.Error("ptrace is not recognised as an escalation primitive")
	}
	if nr, ok := byName["read"]; ok && IsEscalationPrimitive(nr) {
		t.Error("read is recognised as an escalation primitive; the watch set would fire on every event")
	}
	if IsEscalationPrimitive(1 << 20) {
		t.Error("an out-of-range syscall number is recognised as an escalation primitive")
	}
}

func TestDescribeSyscallArgsNamesTheFlags(t *testing.T) {
	byName := map[string]uint64{}
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}

	cases := []struct {
		syscall string
		args    [6]uint64
		want    []string
	}{
		// PTRACE_ATTACH against another process: the distinction the feature
		// exists to draw.
		{"ptrace", [6]uint64{16, 1234}, []string{"PTRACE_ATTACH", "pid=1234"}},
		// PTRACE_TRACEME is a process asking to be traced. Same syscall, not
		// an escalation.
		{"ptrace", [6]uint64{0, 0}, []string{"PTRACE_TRACEME"}},
		{"unshare", [6]uint64{0x10000000}, []string{"CLONE_NEWUSER"}},
		{"unshare", [6]uint64{0x10000000 | 0x00020000}, []string{"CLONE_NEWUSER", "CLONE_NEWNS"}},
		{"setns", [6]uint64{7, 0x40000000}, []string{"fd=7", "CLONE_NEWNET"}},
		{"bpf", [6]uint64{5}, []string{"BPF_PROG_LOAD"}},
		{"mount", [6]uint64{0, 0, 0, 4096 | 16384}, []string{"MS_BIND", "MS_REC"}},
		{"setresuid", [6]uint64{0, 0, 0}, []string{"ruid=0", "euid=0", "suid=0"}},
	}

	for _, tc := range cases {
		nr, ok := byName[tc.syscall]
		if !ok {
			t.Logf("skipping %s: not a syscall on this architecture", tc.syscall)
			continue
		}
		got := DescribeSyscallArgs(nr, tc.args)
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s(%v) rendered %q, which does not mention %q", tc.syscall, tc.args, got, want)
			}
		}
	}
}

func TestDescribeSyscallArgsFallsBackToRawWords(t *testing.T) {
	// An unknown syscall number: the raw words are still more than the number
	// alone, and trailing zeroes are noise.
	got := DescribeSyscallArgs(1<<20, [6]uint64{0xdead, 0xbeef, 0, 0, 0, 0})
	if !strings.Contains(got, "0xdead") || !strings.Contains(got, "0xbeef") {
		t.Errorf("raw arguments not rendered: %q", got)
	}
	if strings.Count(got, "0x0") > 0 {
		t.Errorf("trailing zero arguments were rendered: %q", got)
	}

	if got := DescribeSyscallArgs(1<<20, [6]uint64{}); got != "" {
		t.Errorf("an all-zero argument list rendered %q, want empty", got)
	}
}

func TestDescribeSyscallArgsKeepsUnnamedFlagBits(t *testing.T) {
	byName := map[string]uint64{}
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}
	nr, ok := byName["unshare"]
	if !ok {
		t.Skip("unshare is not a syscall on this architecture")
	}
	// A named bit plus one this table has never heard of. Dropping the unknown
	// bit would render two different calls identically, which is exactly the
	// blindness arguments were added to remove.
	got := DescribeSyscallArgs(nr, [6]uint64{0x10000000 | 0x800000})
	if !strings.Contains(got, "CLONE_NEWUSER") {
		t.Errorf("named bit lost: %q", got)
	}
	if !strings.Contains(got, "0x800000") {
		t.Errorf("unnamed bit lost: %q", got)
	}
}

func BenchmarkDescribeSyscallArgs(b *testing.B) {
	byName := map[string]uint64{}
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}
	nr := byName["ptrace"]
	args := [6]uint64{16, 1234}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DescribeSyscallArgs(nr, args)
	}
}

func BenchmarkDescribeSyscallArgsUnknown(b *testing.B) {
	args := [6]uint64{0xdead, 0xbeef, 0xcafe, 0, 0, 0}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DescribeSyscallArgs(1<<20, args)
	}
}

func BenchmarkEscalationPrimitives(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EscalationPrimitives()
	}
}

func BenchmarkIsEscalationPrimitive(b *testing.B) {
	byName := map[string]uint64{}
	for nr, name := range seccomp.SyscallName {
		byName[name] = nr
	}
	nr := byName["read"] // the miss path, which is the common one
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsEscalationPrimitive(nr)
	}
}
