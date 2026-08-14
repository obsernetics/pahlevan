package ebpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mixProto reproduces the kernel's protocol term with explicit wraparound,
// matching C's modular arithmetic on __u64.
func mixProto(p uint8) uint64 {
	var acc uint64
	for i := uint8(0); i < p; i++ {
		acc += 0x9E3779B97F4A7C15
	}
	return acc
}

// fnv is an independent reimplementation of FNV-1a, so these tests fail if
// FnvPathHash is changed rather than agreeing with it by construction.
func fnv(b []byte) uint64 {
	var h uint64 = 1469598103934665603
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func TestFileAllowKeyMatchesKernelDerivation(t *testing.T) {
	// Kernel: __u64 key = cgroup_id ^ hash_path(e->path, sizeof(e->path));
	const cgroup = uint64(0xdeadbeef)
	assert.Equal(t, cgroup^fnv([]byte("/etc/passwd")), FileAllowKey(cgroup, "/etc/passwd"))
	// The kernel stops at the first NUL, so trailing buffer bytes never
	// contribute; a Go string hashed to its length is the same value.
	assert.Equal(t, FnvPathHash("/etc/passwd"), fnv([]byte("/etc/passwd")))
}

func TestExecAllowKeyMatchesKernelDerivation(t *testing.T) {
	const cgroup = uint64(7)
	assert.Equal(t, cgroup^fnv([]byte("/bin/sh")), ExecAllowKey(cgroup, "/bin/sh"))
}

func TestCapabilityAllowKeyMatchesKernelDerivation(t *testing.T) {
	// Kernel: __u64 key = (cgroup_id << 8) | ((__u64)cap & 0xff);
	assert.Equal(t, uint64(21), CapabilityAllowKey(0, 21))
	assert.Equal(t, uint64(1<<8|21), CapabilityAllowKey(1, 21))
	// Only the low 8 bits of the capability participate.
	assert.Equal(t, CapabilityAllowKey(1, 21), CapabilityAllowKey(1, 21+256))
}

func TestNetworkAllowKeyIPv4(t *testing.T) {
	// Kernel folds sin_addr.s_addr, which is the address in network byte order
	// reinterpreted as a host u32 - little-endian on the supported targets.
	const cgroup = uint64(0x1234)
	key, err := NetworkAllowKey(cgroup, net.ParseIP("1.2.3.4"), 443)
	require.NoError(t, err)

	addrHash := uint64(0x04030201) // bytes 1,2,3,4 read little-endian
	want := cgroup ^ (addrHash << 16) ^ 443 ^ 2 ^ mixProto(ProtocolTCP)
	assert.Equal(t, want, key)
}

func TestNetworkAllowKeyIPv6(t *testing.T) {
	const cgroup = uint64(0x1234)
	ip := net.ParseIP("2001:db8::1")
	key, err := NetworkAllowKey(cgroup, ip, 443)
	require.NoError(t, err)

	want := cgroup ^ (fnv(ip.To16()) << 16) ^ 443 ^ 10 ^ mixProto(ProtocolTCP)
	assert.Equal(t, want, key)
}

// The v4/v6 split is a security property, not a detail: before the family was
// folded in, a v6 destination could be smuggled past a v4 allow entry.
func TestNetworkAllowKeySeparatesFamilies(t *testing.T) {
	v4, err := NetworkAllowKey(1, net.ParseIP("127.0.0.1"), 80)
	require.NoError(t, err)
	v6, err := NetworkAllowKey(1, net.ParseIP("::1"), 80)
	require.NoError(t, err)
	assert.NotEqual(t, v4, v6)

	// An IPv4-mapped IPv6 address is the same destination as its v4 form, and
	// To4() folds it there, so the keys agree.
	mapped, err := NetworkAllowKey(1, net.ParseIP("::ffff:127.0.0.1"), 80)
	require.NoError(t, err)
	assert.Equal(t, v4, mapped)
}

func TestNetworkAllowKeyDistinctPortsAndCgroups(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	a, err := NetworkAllowKey(1, ip, 80)
	require.NoError(t, err)
	b, err := NetworkAllowKey(1, ip, 443)
	require.NoError(t, err)
	c, err := NetworkAllowKey(2, ip, 80)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "ports must not collide")
	assert.NotEqual(t, a, c, "cgroups must not collide")
}

// A destination learned over TCP must not be permitted over UDP on the same
// port. The protocol was absent from the key entirely, and the event reported a
// hardcoded IPPROTO_TCP regardless of the real socket.
func TestNetworkAllowKeySeparatesProtocols(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	tcp, err := NetworkAllowKeyProto(1, ip, 53, ProtocolTCP)
	require.NoError(t, err)
	udp, err := NetworkAllowKeyProto(1, ip, 53, ProtocolUDP)
	require.NoError(t, err)
	assert.NotEqual(t, tcp, udp)

	// The convenience wrapper is the TCP case.
	viaWrapper, err := NetworkAllowKey(1, ip, 53)
	require.NoError(t, err)
	assert.Equal(t, tcp, viaWrapper)
}

// Distinct (port, protocol) pairs must not collide. The port list deliberately
// includes 1536 (6<<8) and 4352 (17<<8), which are exactly the values that
// would alias with TCP and UDP if the protocol were shifted into the port's
// bits instead of mixed.
func TestNetworkAllowKeyPortProtocolDoNotAlias(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	seen := map[uint64]string{}
	for _, proto := range []uint8{0, ProtocolTCP, ProtocolUDP, 1, 132} {
		for _, port := range []uint16{0, 53, 80, 443, 1536, 4352, 65535} {
			k, err := NetworkAllowKeyProto(1, ip, port, proto)
			require.NoError(t, err)
			label := fmt.Sprintf("port=%d proto=%d", port, proto)
			if prev, dup := seen[k]; dup {
				t.Fatalf("key collision between %s and %s", prev, label)
			}
			seen[k] = label
		}
	}
}

func TestNetworkAllowKeyRejectsBadAddress(t *testing.T) {
	_, err := NetworkAllowKey(1, nil, 80)
	require.Error(t, err)

	_, err = NetworkAllowKey(1, net.IP{1, 2, 3}, 80)
	require.Error(t, err, "a 3-byte address is neither v4 nor v6")
}

// Distinct paths must not collide within a cgroup, and the same path must not
// collide across cgroups.
func TestAllowKeysDoNotCollide(t *testing.T) {
	seen := map[uint64]string{}
	paths := []string{"/etc/passwd", "/etc/shadow", "/", "/a", "/b", "/etc/passwd/"}
	for _, cg := range []uint64{1, 2, 1 << 40} {
		for _, p := range paths {
			k := FileAllowKey(cg, p)
			label := p + "@" + string(rune('0'+cg%10))
			if prev, dup := seen[k]; dup {
				t.Fatalf("key collision between %s and %s", prev, label)
			}
			seen[k] = label
		}
	}
}

// Without a loaded collection the writers must report why rather than panic on
// the nil map: a kernel without the BPF LSM runs the agent in degraded mode.
func TestAllowWritersWithoutLoadedPrograms(t *testing.T) {
	m := &Manager{}

	err := m.AllowFilePath(1, "/etc/passwd", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file monitor not loaded")

	err = m.AllowExecPath(1, "/bin/sh", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec monitor not loaded")

	err = m.AllowCapability(1, 21, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capability monitor not loaded")

	err = m.AllowNetworkDestination(1, net.ParseIP("1.2.3.4"), 80, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network monitor not loaded")

	err = m.AllowNetworkDestinationProto(1, net.ParseIP("1.2.3.4"), 53, ProtocolUDP, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network monitor not loaded")
}

func TestAllowWritersRejectInvalidInput(t *testing.T) {
	m := &Manager{}
	require.Error(t, m.AllowFilePath(1, "", true), "empty path")
	require.Error(t, m.AllowExecPath(1, "", true), "empty path")

	err := m.AllowCapability(1, 300, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range",
		"a capability above 255 would silently alias onto another one")

	// A bad address must fail before the map lookup, so the error names the
	// address rather than the missing collection.
	err = m.AllowNetworkDestination(1, nil, 80, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil destination address")
}

func BenchmarkFileAllowKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FileAllowKey(42, "/usr/share/zoneinfo/Etc/UTC")
	}
}

func BenchmarkNetworkAllowKeyIPv4(b *testing.B) {
	ip := net.ParseIP("10.0.0.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NetworkAllowKey(42, ip, 443)
	}
}

func BenchmarkNetworkAllowKeyIPv6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NetworkAllowKey(42, ip, 443)
	}
}
