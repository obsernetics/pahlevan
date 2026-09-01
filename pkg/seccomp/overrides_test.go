package seccomp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allowedNames(t *testing.T, p Profile) map[string]bool {
	t.Helper()
	require.Len(t, p.Syscalls, 1)
	out := make(map[string]bool, len(p.Syscalls[0].Names))
	for _, n := range p.Syscalls[0].Names {
		out[n] = true
	}
	return out
}

func TestGenerateWithOverridesAddsPolicyAllows(t *testing.T) {
	p, skipped := GenerateWithOverrides(nil, []string{"ptrace", "mount"}, nil)
	assert.Zero(t, skipped)
	names := allowedNames(t, p)
	assert.True(t, names["ptrace"], "a policy-allowed syscall must be in the profile")
	assert.True(t, names["mount"])
	// The safety baseline is still there.
	assert.True(t, names["exit_group"])
}

// A denial wins over everything, including the safety baseline. An operator who
// explicitly denies a syscall meant it, and quietly keeping it would make the
// generated profile misrepresent what the workload can call.
func TestGenerateWithOverridesDenialsBeatTheBaseline(t *testing.T) {
	p, _ := GenerateWithOverrides(nil, nil, []string{"futex", "brk"})
	names := allowedNames(t, p)
	assert.False(t, names["futex"], "a policy denial must remove a baseline syscall")
	assert.False(t, names["brk"])
	assert.True(t, names["exit_group"], "the rest of the baseline is untouched")
}

// A denial also beats a learned syscall and an explicit allow, since it is
// applied last.
func TestGenerateWithOverridesDenialsBeatLearnedAndAllowed(t *testing.T) {
	var openat uint64
	for nr, name := range SyscallName {
		if name == "openat" {
			openat = nr
		}
	}
	require.NotZero(t, openat, "the table should contain openat")

	p, _ := GenerateWithOverrides([]uint64{openat}, []string{"openat"}, []string{"openat"})
	assert.False(t, allowedNames(t, p)["openat"],
		"a denial applied last must win over both the learned set and an allow")
}

func TestGenerateWithOverridesCountsUnknownNumbers(t *testing.T) {
	_, skipped := GenerateWithOverrides([]uint64{1 << 40, 1 << 41}, nil, nil)
	assert.Equal(t, 2, skipped, "syscall numbers with no name cannot go in a profile")
}

func TestGenerateWithOverridesIgnoresBlankNames(t *testing.T) {
	p, _ := GenerateWithOverrides(nil, []string{""}, []string{""})
	assert.False(t, allowedNames(t, p)[""], "an empty name must never reach the profile")
	assert.True(t, allowedNames(t, p)["exit_group"])
}

// GenerateWithOverrides with no overrides must be deterministic: the same
// input always produces the same profile.
func TestGenerateWithOverridesIsDeterministic(t *testing.T) {
	a, skippedA := GenerateWithOverrides([]uint64{0, 1, 2}, nil, nil)
	b, skippedB := GenerateWithOverrides([]uint64{0, 1, 2}, nil, nil)
	assert.Equal(t, skippedA, skippedB)
	assert.Equal(t, a, b)
}

func TestKnownSyscallCount(t *testing.T) {
	assert.Equal(t, len(SyscallName), KnownSyscallCount())
	assert.Greater(t, KnownSyscallCount(), 300, "the table should be a real syscall table")
}

func TestKnownName(t *testing.T) {
	assert.True(t, KnownName("openat"))
	assert.True(t, KnownName("exit_group"))
	assert.False(t, KnownName("opennat"), "a typo must not be reported as known")
	assert.False(t, KnownName(""))
}

// The generated profile must name the architecture it was built for. It used to
// claim SCMP_ARCH_X86_64 unconditionally, which is wrong on arm64.
func TestArchitecturesMatchTheBuild(t *testing.T) {
	arches := Architectures()
	require.NotEmpty(t, arches)

	p, _ := GenerateWithOverrides(nil, nil, nil)
	assert.Equal(t, arches, p.Architectures, "the profile must declare the build's architectures")

	// The accessor returns a copy, so a caller cannot mutate the package state.
	arches[0] = "SCMP_ARCH_TAMPERED"
	assert.NotEqual(t, arches, Architectures())
}

func TestProfileJSONIsValidSeccomp(t *testing.T) {
	p, _ := GenerateWithOverrides(nil, []string{"ptrace"}, []string{"futex"})
	data, err := p.JSON()
	require.NoError(t, err)

	var decoded struct {
		DefaultAction string   `json:"defaultAction"`
		Architectures []string `json:"architectures"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "SCMP_ACT_ERRNO", decoded.DefaultAction, "the profile must be default-deny")
	assert.Equal(t, Architectures(), decoded.Architectures)
	require.Len(t, decoded.Syscalls, 1)
	assert.Equal(t, "SCMP_ACT_ALLOW", decoded.Syscalls[0].Action)
	assert.Contains(t, decoded.Syscalls[0].Names, "ptrace")
	assert.NotContains(t, decoded.Syscalls[0].Names, "futex")
}

func BenchmarkGenerateWithOverrides(b *testing.B) {
	learned := make([]uint64, 0, 60)
	for nr := range SyscallName {
		learned = append(learned, nr)
		if len(learned) == 60 {
			break
		}
	}
	allow := []string{"ptrace"}
	deny := []string{"futex"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateWithOverrides(learned, allow, deny)
	}
}

func BenchmarkKnownName(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = KnownName("openat")
	}
}
