package ebpf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// VM tests for selector-derived egress entries.
//
// A namespaceSelector or podSelector peer names a set of workloads, and that
// set moves: pods are rescheduled onto new addresses, relabelled out of the
// selector, or deleted. The agent expands the selector into addresses, writes
// them into the egress allow-set, re-expands it on every reconcile and
// withdraws the entries for pods that no longer match
// (adaptive.Controller.refreshSelectorPeers).
//
// The userspace half of that is unit tested. These are the half that has to be
// true in the kernel, because a withdrawal the kernel does not honor means an
// address stays reachable long after the pod that justified it is gone - and
// the CNI has since given that address to something else.
//
// Both seed and withdraw exactly as Manager.AllowNetworkDestinationProto does,
// under the key the BPF side computes.

// govern puts the calling process's own cgroup under enforcement for the
// network hook, returning the cgroup id and a cleanup. The test dials from
// itself rather than from a child so the connect is unambiguously the one
// being governed.
func govern(t *testing.T, coll *ebpf.Collection) uint64 {
	t.Helper()
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("cannot read own cgroup: %v", err)
	}
	line := strings.TrimSpace(string(self))
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		t.Skipf("unexpected cgroup line %q", line)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(cgroupV2Root, line[idx+1:]), &st); err != nil {
		t.Skipf("cannot stat own cgroup: %v", err)
	}
	cgID := st.Ino
	t.Cleanup(func() { _ = coll.Maps["network_mode"].Delete(cgID) })
	return cgID
}

// loadNetworkLSM loads and attaches the network monitor, skipping unless the
// VM harness asked for it. eBPF programs are never loaded on the host.
func loadNetworkLSM(t *testing.T) *ebpf.Collection {
	t.Helper()
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadNetworkMonitor()
	if err != nil {
		t.Fatalf("LoadNetworkMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	t.Cleanup(coll.Close)
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["socket_connect"]})
	if err != nil {
		t.Fatalf("AttachLSM(socket_connect): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return coll
}

func denied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "operation not permitted")
}

// TestVMWithdrawingASelectorPeerDeniesIt is the kernel half of "a pod that
// stops matching the selector stops being allowed".
func TestVMWithdrawingASelectorPeerDeniesIt(t *testing.T) {
	coll := loadNetworkLSM(t)
	cgID := govern(t, coll)

	// A destination this process has never dialed, so nothing but the seeding
	// below can permit it. That is exactly what a selector peer is: an address
	// the workload was not observed using.
	const port = uint16(59321)
	peer := net.ParseIP("127.0.0.1")
	target := fmt.Sprintf("127.0.0.1:%d", port)

	key, err := NetworkAllowKeyProto(cgID, peer, port, ProtocolTCP)
	if err != nil {
		t.Fatalf("NetworkAllowKeyProto: %v", err)
	}

	// SEED, as a selector peer that matches a pod right now.
	if err := coll.Maps["network_allowed"].Put(key, uint8(1)); err != nil {
		t.Fatalf("seeding the selector peer: %v", err)
	}
	if err := coll.Maps["network_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	dial := func() error {
		c, err := net.DialTimeout("tcp4", target, 300*time.Millisecond)
		if c != nil {
			c.Close()
		}
		return err
	}

	if err := dial(); denied(err) {
		t.Fatalf("a seeded selector peer must be reachable under enforcement: %v", err)
	}
	t.Log("selector peer allowed under enforcement")

	// WITHDRAW, as the pod ceasing to match the selector.
	if err := coll.Maps["network_allowed"].Delete(key); err != nil {
		t.Fatalf("withdrawing the selector peer: %v", err)
	}

	if err := dial(); err == nil {
		t.Error("a withdrawn selector peer must be DENIED; the connect succeeded")
	} else if !denied(err) {
		t.Errorf("the connect failed for the wrong reason: %v", err)
	} else {
		t.Logf("DENIED in-kernel after withdrawal as expected: %v", err)
	}

	// And re-seeding brings it back, which is what lets a pod rejoining the
	// selector take effect without restarting anything.
	if err := coll.Maps["network_allowed"].Put(key, uint8(1)); err != nil {
		t.Fatalf("re-seeding: %v", err)
	}
	if err := dial(); denied(err) {
		t.Errorf("a re-seeded selector peer should be allowed again: %v", err)
	} else {
		t.Log("allowed again after re-seeding")
	}
}

// TestVMIPv6SelectorPeerIsGoverned pins the IPv6 half of the same claim.
//
// A selector matching a dual-stack pod expands to both of its addresses, and
// the v6 one has to reach the kernel under the key the BPF side computes from
// the sixteen address bytes. Anything in between that carried the address as a
// uint32 would seed the key for 0.0.0.0, the entry would never match, and the
// peer would be denied while the policy said it was allowed - which is the
// shape of a bug this repository has shipped once already, on the export path.
func TestVMIPv6SelectorPeerIsGoverned(t *testing.T) {
	coll := loadNetworkLSM(t)
	cgID := govern(t, coll)

	const port = uint16(59322)
	peer := net.ParseIP("::1")
	target := fmt.Sprintf("[::1]:%d", port)

	key, err := NetworkAllowKeyProto(cgID, peer, port, ProtocolTCP)
	if err != nil {
		t.Fatalf("NetworkAllowKeyProto: %v", err)
	}
	if err := coll.Maps["network_allowed"].Put(key, uint8(1)); err != nil {
		t.Fatalf("seeding the IPv6 selector peer: %v", err)
	}
	if err := coll.Maps["network_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	dial := func() error {
		c, err := net.DialTimeout("tcp6", target, 300*time.Millisecond)
		if c != nil {
			c.Close()
		}
		return err
	}
	if err := dial(); denied(err) {
		t.Fatalf("a seeded IPv6 selector peer must be reachable under enforcement: %v", err)
	}
	t.Log("IPv6 selector peer allowed under enforcement")

	if err := coll.Maps["network_allowed"].Delete(key); err != nil {
		t.Fatalf("withdrawing the IPv6 selector peer: %v", err)
	}
	if err := dial(); err == nil {
		t.Error("a withdrawn IPv6 selector peer must be DENIED; the connect succeeded")
	} else if !denied(err) {
		t.Errorf("the IPv6 connect failed for the wrong reason: %v", err)
	} else {
		t.Logf("IPv6 DENIED in-kernel after withdrawal as expected: %v", err)
	}
}

// TestVMSelectorPeerDoesNotGrantANeighbouringPort proves the withdrawal and
// the grant are both exact.
//
// A selector expands to (address, port) pairs, one allow-set entry each. If
// the key folded the port loosely, permitting one pod's service port would
// quietly permit every port on that address, and a selector peer would be a
// much larger grant than it reads as.
func TestVMSelectorPeerDoesNotGrantANeighbouringPort(t *testing.T) {
	coll := loadNetworkLSM(t)
	cgID := govern(t, coll)

	const granted = uint16(59323)
	const neighbour = uint16(59324)
	peer := net.ParseIP("127.0.0.1")

	key, err := NetworkAllowKeyProto(cgID, peer, granted, ProtocolTCP)
	if err != nil {
		t.Fatalf("NetworkAllowKeyProto: %v", err)
	}
	if err := coll.Maps["network_allowed"].Put(key, uint8(1)); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := coll.Maps["network_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	dial := func(port uint16) error {
		c, err := net.DialTimeout("tcp4",
			fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if c != nil {
			c.Close()
		}
		return err
	}
	if err := dial(granted); denied(err) {
		t.Fatalf("the seeded port must be reachable: %v", err)
	}
	if err := dial(neighbour); err == nil {
		t.Error("a neighbouring port must be DENIED; the connect succeeded")
	} else if !denied(err) {
		t.Errorf("the neighbouring connect failed for the wrong reason: %v", err)
	} else {
		t.Logf("neighbouring port denied as expected: %v", err)
	}
}
