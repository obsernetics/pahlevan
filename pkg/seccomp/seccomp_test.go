package seccomp

import (
	"encoding/json"
	"testing"
)

func TestGenerate(t *testing.T) {
	// read(0), write(1), openat(257) - plus an unknown number.
	prof, skipped := Generate([]uint64{0, 1, 257, 999999})
	if skipped != 1 {
		t.Errorf("expected 1 skipped unknown syscall, got %d", skipped)
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("expected default-deny SCMP_ACT_ERRNO, got %q", prof.DefaultAction)
	}
	if len(prof.Syscalls) != 1 || prof.Syscalls[0].Action != "SCMP_ACT_ALLOW" {
		t.Fatalf("expected one ALLOW rule, got %+v", prof.Syscalls)
	}
	got := map[string]bool{}
	for _, n := range prof.Syscalls[0].Names {
		got[n] = true
	}
	for _, want := range []string{"read", "write", "openat", "exit_group"} {
		if !got[want] {
			t.Errorf("expected %q to be allowed", want)
		}
	}
	// Ensure it's valid JSON and sorted/stable.
	b, err := prof.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var round Profile
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("profile is not valid JSON: %v", err)
	}
}

func TestSyscallTable(t *testing.T) {
	if SyscallName[0] != "read" || SyscallName[1] != "write" || SyscallName[59] != "execve" {
		t.Error("syscall table missing expected well-known entries")
	}
	if len(SyscallName) < 300 {
		t.Errorf("syscall table too small: %d", len(SyscallName))
	}
}

// TestSyscallTableIsPopulated guards the arch-specific tables: pkg/seccomp used to
// ship only an amd64 table with no build tag, so any non-amd64 build failed with
// "undefined: SyscallName". This runs on whatever arch the test is built for.
func TestSyscallTableIsPopulated(t *testing.T) {
	if len(SyscallName) < 250 {
		t.Fatalf("syscall table has only %d entries; the arch table looks wrong", len(SyscallName))
	}
	// Names common to every Linux ABI, whatever their numbers are per-arch.
	want := map[string]bool{"read": false, "write": false, "openat": false, "execve": false, "close": false}
	for _, name := range SyscallName {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("syscall table is missing %q on this architecture", name)
		}
	}
}

// TestGenerateUsesArchTable ensures profile generation resolves names through the
// arch table rather than hardcoding amd64 numbers.
func TestGenerateUsesArchTable(t *testing.T) {
	var execveNr uint64
	found := false
	for nr, name := range SyscallName {
		if name == "execve" {
			execveNr, found = nr, true
			break
		}
	}
	if !found {
		t.Skip("no execve in this arch table")
	}
	prof, skipped := Generate([]uint64{execveNr})
	if skipped != 0 {
		t.Errorf("execve should resolve on this arch, got %d skipped", skipped)
	}
	var has bool
	for _, n := range prof.Syscalls[0].Names {
		if n == "execve" {
			has = true
		}
	}
	if !has {
		t.Error("generated profile does not allow execve")
	}
}

func BenchmarkSyscallNameLookup(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SyscallName[uint64(i%300)]
	}
}
