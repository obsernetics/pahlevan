package seccomp

import "testing"

// largeSyscallSet returns every known syscall number plus a batch of unknown
// numbers, so GenerateWithOverrides exercises both the name-lookup and skip
// paths at scale.
func largeSyscallSet() []uint64 {
	set := make([]uint64, 0, len(SyscallName)+64)
	for nr := range SyscallName {
		set = append(set, nr)
	}
	// Append unknown numbers that will be skipped.
	for i := uint64(0); i < 64; i++ {
		set = append(set, 100000+i)
	}
	return set
}

func BenchmarkGenerateWithOverrides_LargeSet(b *testing.B) {
	allowed := largeSyscallSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateWithOverrides(allowed, nil, nil)
	}
}

func BenchmarkGenerateWithOverrides_SmallSet(b *testing.B) {
	// A typical learned workload: a few dozen common syscalls.
	allowed := []uint64{0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 21, 22, 41, 42, 44, 45, 59, 60, 61, 202, 257, 262, 288}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateWithOverrides(allowed, nil, nil)
	}
}

func BenchmarkGenerateAndJSON(b *testing.B) {
	allowed := largeSyscallSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prof, _ := GenerateWithOverrides(allowed, nil, nil)
		if _, err := prof.JSON(); err != nil {
			b.Fatal(err)
		}
	}
}
