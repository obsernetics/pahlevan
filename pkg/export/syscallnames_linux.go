//go:build linux && (amd64 || arm64)

package export

import "github.com/obsernetics/pahlevan/pkg/seccomp"

// lookupSyscallName resolves a syscall number through the generated table in
// pkg/seccomp, which exists for the architectures the data plane supports.
func lookupSyscallName(nr uint64) (string, bool) {
	name, ok := seccomp.SyscallName[nr]
	return name, ok
}
