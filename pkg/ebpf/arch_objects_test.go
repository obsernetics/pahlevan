package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The arm64 objects are shipped in the multi-arch image and have never been
// loaded by an arm64 kernel: the VM harness is amd64, so the only thing CI
// proves about them is that clang produced a file.
//
// That is weaker than it sounds. The arm64 build broke once already, when
// PT_REGS_PARM*_CORE_SYSCALL was used - it needs struct user_pt_regs, which an
// x86-derived vmlinux.h does not have - and nothing but a compile error caught
// it. A change that compiles on both but silently drops a program or renames a
// map on one would ship.
//
// These tests close most of that gap without a kernel. An ELF's CollectionSpec
// can be parsed on any architecture, so the programs, their types and attach
// points, and the maps with their key and value sizes can all be compared
// between the two builds. What this does NOT prove is that the arm64 verifier
// accepts them, which needs an arm64 kernel and is listed as an open gap in
// ROADMAP.md rather than papered over here.

// objects are the seven programs, by the base name bpf2go derives.
var archObjects = []string{
	"syscallmonitor",
	"networkmonitor",
	"filemonitor",
	"execmonitor",
	"capabilitymonitor",
	"credmonitor",
	"shellmonitor",
}

func loadArchSpec(t *testing.T, base, arch string) *ebpf.CollectionSpec {
	t.Helper()
	path := filepath.Join(".", base+"_"+arch+"_bpfel.o")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not present (run `make ebpf`): %v", path, err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	require.NoError(t, err, "%s must be a well-formed BPF ELF", path)
	return spec
}

// Both builds must expose exactly the same programs, with the same type and
// attach point. A program present on x86 and missing on arm64 is an agent that
// silently enforces less on arm64 nodes.
func TestArm64ObjectsHaveTheSamePrograms(t *testing.T) {
	for _, base := range archObjects {
		t.Run(base, func(t *testing.T) {
			x86 := loadArchSpec(t, base, "x86")
			arm := loadArchSpec(t, base, "arm64")

			require.Equal(t, len(x86.Programs), len(arm.Programs),
				"the two builds expose a different number of programs")

			for name, want := range x86.Programs {
				got, ok := arm.Programs[name]
				require.True(t, ok, "arm64 is missing program %q", name)
				assert.Equal(t, want.Type, got.Type, "program %q has a different type", name)
				assert.Equal(t, want.AttachType, got.AttachType,
					"program %q has a different attach type", name)
				assert.Equal(t, want.SectionName, got.SectionName,
					"program %q attaches to a different hook", name)
			}
		})
	}
}

// The maps are the contract between the kernel and userspace. A key or value
// size that differs by architecture means the Go side writes entries the kernel
// can never match - an allow-set that looks populated and denies everything.
func TestArm64ObjectsHaveTheSameMaps(t *testing.T) {
	for _, base := range archObjects {
		t.Run(base, func(t *testing.T) {
			x86 := loadArchSpec(t, base, "x86")
			arm := loadArchSpec(t, base, "arm64")

			require.Equal(t, len(x86.Maps), len(arm.Maps),
				"the two builds declare a different number of maps")

			for name, want := range x86.Maps {
				got, ok := arm.Maps[name]
				require.True(t, ok, "arm64 is missing map %q", name)
				assert.Equal(t, want.Type, got.Type, "map %q has a different type", name)
				assert.Equal(t, want.KeySize, got.KeySize, "map %q has a different key size", name)
				assert.Equal(t, want.ValueSize, got.ValueSize,
					"map %q has a different value size", name)
				assert.Equal(t, want.MaxEntries, got.MaxEntries,
					"map %q has a different capacity", name)
			}
		})
	}
}

// The maps userspace writes into by name must exist, on both builds. A rename
// in the C without a matching rename in allowset.go produces a runtime error on
// a path an operator only exercises when they add a policy exception.
func TestAllowSetMapsExistOnBothArches(t *testing.T) {
	want := map[string][]string{
		"filemonitor":       {"file_allowed", "file_mode"},
		"networkmonitor":    {"network_allowed", "network_mode"},
		"execmonitor":       {"exec_allowed", "exec_mode", "exec_filter_on", "exec_filter_allowed"},
		"capabilitymonitor": {"cap_allowed", "cap_mode"},
		"credmonitor":       {"cred_config", "cred_governed"},
		"shellmonitor":      {"shell_config"},
	}
	for _, arch := range []string{"x86", "arm64"} {
		for base, maps := range want {
			t.Run(arch+"/"+base, func(t *testing.T) {
				spec := loadArchSpec(t, base, arch)
				for _, m := range maps {
					assert.Contains(t, spec.Maps, m,
						"%s (%s) must declare map %q, which userspace writes by name", base, arch, m)
				}
			})
		}
	}
}

// The LSM programs are where enforcement happens. If one of them is compiled as
// something else on arm64, the agent attaches nothing and denies nothing while
// reporting itself healthy.
func TestEnforcementHooksAreLSMOnBothArches(t *testing.T) {
	want := map[string]string{
		"filemonitor":       "file_open",
		"networkmonitor":    "socket_connect",
		"execmonitor":       "bprm_check",
		"capabilitymonitor": "capable_check",
	}
	for _, arch := range []string{"x86", "arm64"} {
		for base, prog := range want {
			t.Run(arch+"/"+base, func(t *testing.T) {
				spec := loadArchSpec(t, base, arch)
				p, ok := spec.Programs[prog]
				require.True(t, ok, "%s (%s) must declare program %q", base, arch, prog)
				assert.Equal(t, ebpf.LSM, p.Type,
					"%s must be an LSM program or it enforces nothing", prog)
			})
		}
	}
}

func BenchmarkLoadArm64Spec(b *testing.B) {
	path := "execmonitor_arm64_bpfel.o"
	if _, err := os.Stat(path); err != nil {
		b.Skip("object not present")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ebpf.LoadCollectionSpec(path); err != nil {
			b.Fatal(err)
		}
	}
}

// The per-cgroup mode maps hold a packed enforcement action, not the bare mode
// byte they held before the action set existed. Userspace writes a uint32; a
// map still declared with a one-byte value would fail every write at runtime,
// on a path only exercised once a policy reaches enforcement.
func TestModeMapsHoldAPackedAction(t *testing.T) {
	modeMaps := map[string]string{
		"filemonitor":       "file_mode",
		"networkmonitor":    "network_mode",
		"execmonitor":       "exec_mode",
		"capabilitymonitor": "cap_mode",
	}
	for _, arch := range []string{"x86", "arm64"} {
		for base, name := range modeMaps {
			t.Run(arch+"/"+name, func(t *testing.T) {
				spec := loadArchSpec(t, base, arch)
				m, ok := spec.Maps[name]
				require.True(t, ok, "%s (%s) must declare %q", base, arch, name)
				assert.Equal(t, uint32(8), m.KeySize,
					"%s is keyed by cgroup id, which is 8 bytes", name)
				assert.Equal(t, uint32(4), m.ValueSize,
					"%s must hold the packed action from bpf/enforce.h, which is 4 bytes", name)
			})
		}
	}
}

// The credential monitor is a kprobe and the shell monitor a uretprobe, on
// purpose: neither needs the BPF LSM, so both work on kernels where the LSM
// hooks do not attach at all. Compiled as the wrong type on one architecture
// they would silently fail to attach there.
func TestProbeTypesOnBothArches(t *testing.T) {
	want := []struct {
		base, prog string
		typ        ebpf.ProgramType
	}{
		{"credmonitor", "handle_commit_creds", ebpf.Kprobe},
		{"shellmonitor", "handle_readline", ebpf.Kprobe}, // uprobes are kprobe-type programs
		{"syscallmonitor", "handle_sys_enter", ebpf.TracePoint},
	}
	for _, arch := range []string{"x86", "arm64"} {
		for _, w := range want {
			t.Run(arch+"/"+w.prog, func(t *testing.T) {
				spec := loadArchSpec(t, w.base, arch)
				p, ok := spec.Programs[w.prog]
				require.True(t, ok, "%s (%s) must declare program %q", w.base, arch, w.prog)
				assert.Equal(t, w.typ, p.Type,
					"%s must be a %s program or it attaches nowhere", w.prog, w.typ)
			})
		}
	}
}
