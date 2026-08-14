//go:build !linux || (!amd64 && !arm64)

package export

// lookupSyscallName has no table on architectures without a generated syscall
// map (the CLI builds there; the data plane does not). Callers fall back to
// the numeric form.
func lookupSyscallName(uint64) (string, bool) { return "", false }
