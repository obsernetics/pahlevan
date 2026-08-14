// Package seccomp turns a learned syscall set into a seccomp profile.
//
// The eBPF data plane can observe every syscall and block file/network access
// in-kernel, but it cannot retroactively seccomp-filter an already-running
// process (seccomp is installed at exec). So Pahlevan's syscall enforcement is
// delivered as a generated seccomp profile: from the syscalls a workload used
// during learning, we emit a profile that ALLOWs those (plus a minimal safety
// baseline) and returns EPERM for everything else. The operator writes the
// profile to the node and admission sets it as the pod's localhostProfile, so new
// pods of the workload start already confined.
package seccomp

import (
	"encoding/json"
	"sort"
)

// Profile is the seccomp profile format accepted by the kubelet / OCI runtimes
// (a subset of runtime-spec LinuxSeccomp).
type Profile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

// SyscallRule allows (or otherwise acts on) a set of syscalls by name.
type SyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// baseline syscalls are always allowed so an otherwise-confined process can start
// and exit cleanly (and receive signals) even if a few weren't seen during
// learning. Kept deliberately small and non-sensitive.
var baseline = []string{
	"exit", "exit_group", "rt_sigreturn", "restart_syscall",
	"brk", "mmap", "munmap", "mprotect", "futex",
	"nanosleep", "clock_nanosleep", "sched_yield",
}

// Generate builds a default-deny (SCMP_ACT_ERRNO) profile that allows the learned
// syscalls plus the safety baseline. Unknown syscall numbers are skipped (they
// cannot be named in a profile); callers can inspect the returned skipped count.
func Generate(allowed []uint64) (Profile, int) {
	names := map[string]struct{}{}
	for _, s := range baseline {
		names[s] = struct{}{}
	}
	skipped := 0
	for _, nr := range allowed {
		if name, ok := SyscallName[nr]; ok {
			names[name] = struct{}{}
		} else {
			skipped++
		}
	}
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	sort.Strings(list)

	return Profile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: seccompArchitectures,
		Syscalls: []SyscallRule{{
			Names:  list,
			Action: "SCMP_ACT_ALLOW",
		}},
	}, skipped
}

// KnownSyscallCount is the size of the syscall table for the build
// architecture. It is the denominator for "how much of the syscall surface did
// this workload actually need", which is the number that justifies enforcing.
func KnownSyscallCount() int { return len(SyscallName) }

// Architectures reports the seccomp architectures generated profiles declare.
func Architectures() []string {
	out := make([]string, len(seccompArchitectures))
	copy(out, seccompArchitectures)
	return out
}

// JSON renders the profile as the JSON a localhostProfile file must contain.
func (p Profile) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}
