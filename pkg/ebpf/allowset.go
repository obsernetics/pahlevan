package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Allow-set seeding.
//
// The BPF programs populate their own allow-sets while a cgroup is learning:
// the first time a path is opened, a destination dialed, a binary executed or a
// capability used, the hook records it and lets it through. Enforcement then
// denies anything absent from that set.
//
// That is the whole adaptive model, but it means the set can only ever contain
// what actually happened during the window. An operator who knows a path will
// be needed on a code path that did not run - a failure handler, a rarely-hit
// admin endpoint, a config reload - has no way to say so, and finds out when
// the workload breaks in production.
//
// These writers close that gap: a PahlevanPolicy exception is inserted straight
// into the kernel allow-set before the cgroup flips to enforcing, using the same
// key derivation the BPF side computes. The two halves must agree exactly, so
// every derivation below is paired with the C line it mirrors and covered by a
// VM test that asserts the kernel honours a userspace-written entry.

const (
	// afInet and afInet6 are the address-family values the kernel folds into the
	// network allow-set key. They are the Linux AF_* constants, hardcoded rather
	// than taken from syscall so the value cannot drift by GOOS.
	afInet  = 2
	afInet6 = 10
)

// FileAllowKey derives the file allow-set key for a (cgroup, path) pair.
// Mirrors: __u64 key = cgroup_id ^ hash_path(e->path, sizeof(e->path));
func FileAllowKey(cgroupID uint64, path string) uint64 {
	return cgroupID ^ FnvPathHash(path)
}

// ExecAllowKey derives the exec allow-set key for a (cgroup, binary) pair.
// Mirrors: __u64 key = cgroup_id ^ hash_name(e->filename, sizeof(e->filename));
func ExecAllowKey(cgroupID uint64, path string) uint64 {
	return cgroupID ^ FnvPathHash(path)
}

// CapabilityAllowKey derives the capability allow-set key.
// Mirrors: __u64 key = (cgroup_id << 8) | ((__u64)cap & 0xff);
func CapabilityAllowKey(cgroupID uint64, capability uint32) uint64 {
	return (cgroupID << 8) | (uint64(capability) & 0xff)
}

// NetworkAllowKey derives the egress allow-set key for a destination.
// Mirrors: __u64 key = cgroup_id ^ (addr_hash << 16) ^ (__u64)dport ^ (__u64)family;
//
// For IPv4 the kernel folds in sin_addr.s_addr verbatim, which is the address in
// network byte order reinterpreted as a host __u32. Reading the four bytes
// little-endian reproduces that on the little-endian targets the BPF objects are
// built for. For IPv6 it is an FNV-1a over the 16 address bytes in order.
func NetworkAllowKey(cgroupID uint64, ip net.IP, port uint16) (uint64, error) {
	if ip == nil {
		return 0, fmt.Errorf("nil destination address")
	}
	var addrHash uint64
	var family uint64
	if v4 := ip.To4(); v4 != nil {
		addrHash = uint64(binary.LittleEndian.Uint32(v4))
		family = afInet
	} else {
		v6 := ip.To16()
		if v6 == nil {
			return 0, fmt.Errorf("address %q is neither IPv4 nor IPv6", ip)
		}
		addrHash = 1469598103934665603
		for i := 0; i < 16; i++ {
			addrHash ^= uint64(v6[i])
			addrHash *= 1099511628211
		}
		family = afInet6
	}
	return cgroupID ^ (addrHash << 16) ^ uint64(port) ^ family, nil
}

// allowMap looks up one of the allow-set maps, returning a descriptive error
// when the owning program is not loaded (a kernel without the BPF LSM runs the
// agent in degraded, observation-only mode rather than failing outright).
func (m *Manager) allowMap(coll *ebpf.Collection, program, name string) (*ebpf.Map, error) {
	if coll == nil {
		return nil, fmt.Errorf("%s monitor not loaded (bpf LSM unavailable?)", program)
	}
	mp := coll.Maps[name]
	if mp == nil {
		return nil, fmt.Errorf("%s map not found", name)
	}
	return mp, nil
}

// setAllowEntry inserts or removes a single allow-set entry.
func setAllowEntry(mp *ebpf.Map, key uint64, allowed bool) error {
	if allowed {
		return mp.Put(key, uint8(1))
	}
	// Absent means denied under enforcement, so revoking is a delete. ENOENT is
	// the expected outcome for anything never learned and is not an error.
	_ = mp.Delete(key)
	return nil
}

// AllowFilePath seeds the file allow-set so opens of path are permitted once the
// cgroup is enforcing. Pass allowed=false to revoke, which denies the path even
// if it was learned.
//
// The path must be the fully resolved one. The kernel hashes what bpf_d_path
// returns, which follows symlinks to the real dentry, so seeding
// "/etc/os-release" grants nothing on a distro where it links to
// /usr/lib/os-release - the entry is written and simply never matches.
// TestVMSeededSymlinkPathDoesNotMatch pins both halves of that behaviour.
func (m *Manager) AllowFilePath(cgroupID uint64, path string, allowed bool) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	mp, err := m.allowMap(m.fileCollection, "file", "file_allowed")
	if err != nil {
		return err
	}
	return setAllowEntry(mp, FileAllowKey(cgroupID, path), allowed)
}

// AllowExecPath seeds the exec allow-set for a binary path.
func (m *Manager) AllowExecPath(cgroupID uint64, path string, allowed bool) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	mp, err := m.allowMap(m.execCollection, "exec", "exec_allowed")
	if err != nil {
		return err
	}
	return setAllowEntry(mp, ExecAllowKey(cgroupID, path), allowed)
}

// AllowCapability seeds the capability allow-set. Capability numbers above 255
// cannot be represented in the kernel key and are rejected rather than silently
// aliased onto another capability.
func (m *Manager) AllowCapability(cgroupID uint64, capability uint32, allowed bool) error {
	if capability > 0xff {
		return fmt.Errorf("capability %d out of range (kernel key holds 8 bits)", capability)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	mp, err := m.allowMap(m.capCollection, "capability", "cap_allowed")
	if err != nil {
		return err
	}
	return setAllowEntry(mp, CapabilityAllowKey(cgroupID, capability), allowed)
}

// AllowNetworkDestination seeds the egress allow-set for one ip:port.
func (m *Manager) AllowNetworkDestination(cgroupID uint64, ip net.IP, port uint16, allowed bool) error {
	key, err := NetworkAllowKey(cgroupID, ip, port)
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	mp, err := m.allowMap(m.networkCollection, "network", "network_allowed")
	if err != nil {
		return err
	}
	return setAllowEntry(mp, key, allowed)
}
