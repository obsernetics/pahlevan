package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestHashMap creates a real kernel BPF_MAP_TYPE_HASH map. Creating a bare
// map needs no BPF LSM and no loaded program, so this runs on any host with
// working bpf() syscalls - unlike the VM-gated tests in vmload_test.go, which
// load and attach real programs.
func newTestHashMap(t *testing.T, keySize, valueSize uint32) *ebpf.Map {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("Skipping test - cannot remove memlock rlimit: %v", err)
	}
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("Skipping test - system doesn't support eBPF maps: %v", err)
	}
	t.Cleanup(func() { _ = mp.Close() })
	return mp
}

func TestAllowMapNilCollection(t *testing.T) {
	m := &Manager{}
	mp, err := m.allowMap(nil, "file", "file_allowed")
	require.Error(t, err)
	assert.Nil(t, mp)
	assert.Contains(t, err.Error(), "file monitor not loaded")
}

func TestAllowMapMissingNamedMap(t *testing.T) {
	m := &Manager{}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
	mp, err := m.allowMap(coll, "network", "network_allowed")
	require.Error(t, err)
	assert.Nil(t, mp)
	assert.Contains(t, err.Error(), "network_allowed map not found")
}

func TestAllowMapFound(t *testing.T) {
	real := newTestHashMap(t, 8, 1)
	m := &Manager{}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{"file_allowed": real}}
	mp, err := m.allowMap(coll, "file", "file_allowed")
	require.NoError(t, err)
	assert.Same(t, real, mp)
}

func TestSetAllowEntryInsertsAndLooksUp(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)

	require.NoError(t, setAllowEntry(mp, 42, true))

	var v uint8
	require.NoError(t, mp.Lookup(uint64(42), &v))
	assert.Equal(t, uint8(1), v)
}

func TestSetAllowEntryRevokesLearnedEntry(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)

	require.NoError(t, setAllowEntry(mp, 7, true))
	require.NoError(t, setAllowEntry(mp, 7, false))

	var v uint8
	err := mp.Lookup(uint64(7), &v)
	require.Error(t, err, "a revoked entry must no longer be present")
}

// Revoking a key that was never learned is not an error: ENOENT is the
// expected outcome for anything the workload never did, and callers should
// not have to special-case it.
func TestSetAllowEntryRevokeOfAbsentKeyIsNotAnError(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)
	require.NoError(t, setAllowEntry(mp, 999, false))
}

func TestSetAllowEntryOverwritesExisting(t *testing.T) {
	mp := newTestHashMap(t, 8, 1)

	require.NoError(t, setAllowEntry(mp, 1, true))
	require.NoError(t, setAllowEntry(mp, 1, true))

	var v uint8
	require.NoError(t, mp.Lookup(uint64(1), &v))
	assert.Equal(t, uint8(1), v)
}

func TestSetNetworkRelaxWithoutLoadedProgram(t *testing.T) {
	m := &Manager{}
	err := m.SetNetworkRelax(1, RelaxLoopback)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network monitor not loaded")
}

func TestSetNetworkRelaxMissingMap(t *testing.T) {
	m := &Manager{networkCollection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	err := m.SetNetworkRelax(1, RelaxLoopback)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network_relax map not found")
}

func TestSetNetworkRelaxSetsAndClearsMask(t *testing.T) {
	relax := newTestHashMap(t, 8, 1)
	m := &Manager{networkCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"network_relax": relax},
	}}

	require.NoError(t, m.SetNetworkRelax(5, RelaxLoopback|RelaxDNS))
	var v uint8
	require.NoError(t, relax.Lookup(uint64(5), &v))
	assert.Equal(t, RelaxLoopback|RelaxDNS, v)

	// A mask of zero clears the entry rather than storing a zero value, so a
	// cgroup with no blanket permissions costs no map entry at all.
	require.NoError(t, m.SetNetworkRelax(5, 0))
	err := relax.Lookup(uint64(5), &v)
	require.Error(t, err, "a cleared mask must leave no entry behind")
}

func TestSetNetworkRelaxClearingAnUnsetCgroupIsNotAnError(t *testing.T) {
	relax := newTestHashMap(t, 8, 1)
	m := &Manager{networkCollection: &ebpf.Collection{
		Maps: map[string]*ebpf.Map{"network_relax": relax},
	}}
	require.NoError(t, m.SetNetworkRelax(123, 0))
}

func TestNetworkRelaxString(t *testing.T) {
	cases := []struct {
		name string
		mask uint8
		want string
	}{
		{"none", 0, "none"},
		{"loopback only", RelaxLoopback, "loopback"},
		{"dns only", RelaxDNS, "dns"},
		{"both", RelaxLoopback | RelaxDNS, "loopback,dns"},
		{"unknown bit only", 0x80, ""},
		{"known plus unknown bit", RelaxDNS | 0x80, "dns"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NetworkRelaxString(tc.mask))
		})
	}
}

// BenchmarkSetAllowEntry covers the write side of the allow-set: every
// PahlevanPolicy exception seeded before a cgroup starts enforcing goes
// through this call.
func BenchmarkSetAllowEntry(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Skipf("cannot remove memlock rlimit: %v", err)
	}
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 1024,
	})
	if err != nil {
		b.Skipf("system doesn't support eBPF maps: %v", err)
	}
	defer mp.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = setAllowEntry(mp, uint64(i%1024), true)
	}
}

func BenchmarkNetworkRelaxString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NetworkRelaxString(RelaxLoopback | RelaxDNS)
	}
}
