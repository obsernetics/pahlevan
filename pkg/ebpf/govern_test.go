package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The credential and kernel-probe governance writers follow the exact same
// shape as the allow-set writers in allowset.go (nil-collection guard, named-map
// guard, then a Put/Delete on a real map) but, unlike those, had no tests of
// their own: GovernCredentials, UngovernCredentials, SetCredKillDuringExecve,
// setCredEnabled, GovernKernelProbes, UngovernKernelProbes and
// setKernelProbesEnabledLocked all ran at 0% coverage. An operator governing a
// cgroup wrong - or an agent restart racing a governance write - would have
// surfaced first as a workload's privilege escalations going unnoticed rather
// than as a failing test.

func TestGovernCredentialsWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.GovernCredentials(1, CredKill)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential monitor is not loaded")
}

func TestGovernCredentialsMissingMap(t *testing.T) {
	m := &Manager{credCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.GovernCredentials(1, CredKill)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cred_governed map is absent")
}

func TestGovernCredentialsSetsMode(t *testing.T) {
	governed := newTestHashMap(t, 8, 4)
	m := &Manager{credCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"cred_governed": governed},
	}}

	require.NoError(t, m.GovernCredentials(42, CredKill))
	var mode uint32
	require.NoError(t, governed.Lookup(uint64(42), &mode))
	assert.Equal(t, uint32(CredKill), mode)

	// Re-governing with a different mode overwrites rather than erroring.
	require.NoError(t, m.GovernCredentials(42, CredObserve))
	require.NoError(t, governed.Lookup(uint64(42), &mode))
	assert.Equal(t, uint32(CredObserve), mode)
}

func TestUngovernCredentialsWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.UngovernCredentials(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential monitor is not loaded")
}

func TestUngovernCredentialsMissingMap(t *testing.T) {
	m := &Manager{credCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.UngovernCredentials(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cred_governed map is absent")
}

func TestUngovernCredentialsRemovesEntry(t *testing.T) {
	governed := newTestHashMap(t, 8, 4)
	m := &Manager{credCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"cred_governed": governed},
	}}

	require.NoError(t, m.GovernCredentials(7, CredKill))
	require.NoError(t, m.UngovernCredentials(7))

	var mode uint32
	require.Error(t, governed.Lookup(uint64(7), &mode), "an ungoverned cgroup must leave no entry behind")
}

// A cgroup that was never governed is already in the requested state, not a
// failure: a caller un-governing on cleanup should not have to special-case
// "never governed in the first place".
func TestUngovernCredentialsOfUngovernedCgroupIsNotAnError(t *testing.T) {
	governed := newTestHashMap(t, 8, 4)
	m := &Manager{credCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"cred_governed": governed},
	}}
	require.NoError(t, m.UngovernCredentials(999))
}

func TestSetCredKillDuringExecveWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.SetCredKillDuringExecve(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential monitor is not loaded")
}

func TestSetCredKillDuringExecveMissingMap(t *testing.T) {
	m := &Manager{credCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.SetCredKillDuringExecve(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cred_config map is absent")
}

func TestSetCredKillDuringExecveTogglesConfig(t *testing.T) {
	cfg := newTestHashMap(t, 4, 4)
	m := &Manager{credCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"cred_config": cfg},
	}}
	const key = uint32(2)

	require.NoError(t, m.SetCredKillDuringExecve(true))
	var v uint32
	require.NoError(t, cfg.Lookup(key, &v))
	assert.Equal(t, uint32(1), v)

	require.NoError(t, m.SetCredKillDuringExecve(false))
	require.NoError(t, cfg.Lookup(key, &v))
	assert.Equal(t, uint32(0), v)
}

func TestSetCredEnabledWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.setCredEnabled(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential monitor is not loaded")
}

func TestSetCredEnabledMissingMap(t *testing.T) {
	m := &Manager{credCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.setCredEnabled(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cred_config map is absent")
}

func TestSetCredEnabledTogglesKey0(t *testing.T) {
	cfg := newTestHashMap(t, 4, 4)
	m := &Manager{credCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"cred_config": cfg},
	}}
	const key = uint32(0)

	require.NoError(t, m.setCredEnabled(true))
	var v uint32
	require.NoError(t, cfg.Lookup(key, &v))
	assert.Equal(t, uint32(1), v)

	// setCredEnabled and SetCredKillDuringExecve share the map but address
	// different keys (0 vs 2), so toggling one must never touch the other.
	require.NoError(t, m.SetCredKillDuringExecve(true))
	require.NoError(t, m.setCredEnabled(false))
	require.NoError(t, cfg.Lookup(key, &v))
	assert.Equal(t, uint32(0), v, "setCredEnabled must not be aliased by the kill-during-execve key")
	require.NoError(t, cfg.Lookup(uint32(2), &v))
	assert.Equal(t, uint32(1), v, "SetCredKillDuringExecve must survive setCredEnabled toggling key 0")
}

func TestGovernKernelProbesWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.GovernKernelProbes(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generic kprobe program is not loaded")
}

func TestGovernKernelProbesMissingMap(t *testing.T) {
	m := &Manager{kprobeCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.GovernKernelProbes(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kp_governed map is absent")
}

func TestGovernKernelProbesSetsEntry(t *testing.T) {
	governed := newTestHashMap(t, 8, 1)
	m := &Manager{kprobeCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"kp_governed": governed},
	}}

	require.NoError(t, m.GovernKernelProbes(55))
	var v uint8
	require.NoError(t, governed.Lookup(uint64(55), &v))
	assert.Equal(t, uint8(1), v)
}

func TestUngovernKernelProbesWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.UngovernKernelProbes(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generic kprobe program is not loaded")
}

func TestUngovernKernelProbesMissingMap(t *testing.T) {
	m := &Manager{kprobeCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.UngovernKernelProbes(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kp_governed map is absent")
}

func TestUngovernKernelProbesRemovesEntry(t *testing.T) {
	governed := newTestHashMap(t, 8, 1)
	m := &Manager{kprobeCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"kp_governed": governed},
	}}

	require.NoError(t, m.GovernKernelProbes(9))
	require.NoError(t, m.UngovernKernelProbes(9))

	var v uint8
	require.Error(t, governed.Lookup(uint64(9), &v), "an ungoverned cgroup must leave no entry behind")
}

func TestUngovernKernelProbesOfUngovernedCgroupIsNotAnError(t *testing.T) {
	governed := newTestHashMap(t, 8, 1)
	m := &Manager{kprobeCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"kp_governed": governed},
	}}
	require.NoError(t, m.UngovernKernelProbes(404))
}

func TestSetKernelProbesEnabledLockedWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.setKernelProbesEnabledLocked(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generic kprobe program is not loaded")
}

func TestSetKernelProbesEnabledLockedMissingMap(t *testing.T) {
	m := &Manager{kprobeCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.setKernelProbesEnabledLocked(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kp_runtime map is absent")
}

func TestSetKernelProbesEnabledLockedTogglesKey0(t *testing.T) {
	runtime := newTestHashMap(t, 4, 4)
	m := &Manager{kprobeCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"kp_runtime": runtime},
	}}
	const key = uint32(0)

	require.NoError(t, m.setKernelProbesEnabledLocked(true))
	var v uint32
	require.NoError(t, runtime.Lookup(key, &v))
	assert.Equal(t, uint32(1), v)

	require.NoError(t, m.setKernelProbesEnabledLocked(false))
	require.NoError(t, runtime.Lookup(key, &v))
	assert.Equal(t, uint32(0), v)
}

// checkMapCompatible guards against adopting a pinned map whose shape no
// longer matches this binary's spec - the one case the pin digest cannot catch
// on its own, since MapSizing is a runtime setting rather than part of the
// compiled programs. It had no tests of its own: a regression here would
// surface in production as an agent silently running with a smaller map than
// its own configuration asks for, rather than as a failing test.
func TestCheckMapCompatibleMatchingSpec(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8}
	require.NoError(t, checkMapCompatible("file_allowed", mp, spec))
}

func TestCheckMapCompatibleTypeMismatch(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	spec := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 8, ValueSize: 1, MaxEntries: 8}
	err := checkMapCompatible("file_allowed", mp, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a Hash")
	assert.Contains(t, err.Error(), "spec says Array")
}

func TestCheckMapCompatibleKeySizeMismatch(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 8}
	err := checkMapCompatible("file_allowed", mp, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "8-byte key")
	assert.Contains(t, err.Error(), "spec says 4")
}

func TestCheckMapCompatibleValueSizeMismatch(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 8}
	err := checkMapCompatible("file_allowed", mp, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-byte value")
	assert.Contains(t, err.Error(), "spec says 4")
}

// This is the mismatch checkMapCompatible exists to catch: MapSizing lets an
// operator resize an allow-set between restarts, and the pinned map must not
// be silently adopted at its old, smaller capacity.
func TestCheckMapCompatibleMaxEntriesMismatch(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 4096}
	err := checkMapCompatible("file_allowed", mp, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holds 8 entries")
	assert.Contains(t, err.Error(), "spec says 4096")
}

func BenchmarkGovernCredentials(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Skipf("cannot remove memlock rlimit: %v", err)
	}
	governed, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 1024})
	if err != nil {
		b.Skipf("system doesn't support eBPF maps: %v", err)
	}
	defer governed.Close()
	m := &Manager{credCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"cred_governed": governed}}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GovernCredentials(uint64(i%1024), CredKill)
	}
}

func BenchmarkCheckMapCompatible(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Skipf("cannot remove memlock rlimit: %v", err)
	}
	mp, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8})
	if err != nil {
		b.Skipf("system doesn't support eBPF maps: %v", err)
	}
	defer mp.Close()
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkMapCompatible("file_allowed", mp, spec)
	}
}
