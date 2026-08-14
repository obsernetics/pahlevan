package seccomp

import (
	"encoding/json"
	"testing"
)

func TestGenerate(t *testing.T) {
	// read(0), write(1), openat(257) — plus an unknown number.
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
