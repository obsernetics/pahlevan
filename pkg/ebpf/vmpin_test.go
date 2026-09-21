package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// Proving that enforcement survives an agent restart.
//
// These tests exist because the property cannot be proved any other way. A test
// that asserts a pin file exists proves nothing at all: the question is whether
// the KERNEL is still refusing an unlearned open at the moment when no Pahlevan
// process is running, and whether the next process inherits the learned
// allow-set rather than an empty map. Both are kernel facts, so they are checked
// against a real kernel, in the VM, and never on the host.

// vmPinGate skips unless the VM harness is driving the test.
func vmPinGate(t *testing.T) {
	t.Helper()
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; never on the host)")
	}
}

// vmPinRoot gives each test its own installation directory, so one test's
// teardown cannot remove another's state and a failure leaves nothing behind.
func vmPinRoot(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(DefaultBPFFSRoot, pinNamespace, fmt.Sprintf("vmtest-%s-%d", name, os.Getpid()))
	t.Cleanup(func() {
		if err := PurgePinnedState(root); err != nil {
			t.Logf("cleanup: PurgePinnedState(%s): %v", root, err)
		}
	})
	return root
}

// vmTestCgroup makes a dedicated cgroup so enforcement touches only the helper
// processes this test starts, never the test binary or the VM.
func vmTestCgroup(t *testing.T, name string) (dir string, id uint64) {
	t.Helper()
	dir = fmt.Sprintf("%s/pahlevan-pin-%s-%d", cgroupV2Root, name, os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create test cgroup (need cgroup v2, root): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })

	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	return dir, st.Ino
}

// catIn runs `cat <path>` inside the dedicated cgroup and returns cat's error,
// which is non-nil exactly when the open was refused in-kernel. The error
// carries cat's own diagnostic, so a failure names the reason rather than an
// exit status.
func catIn(cgDir, path string) error {
	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec cat %s", cgDir, path)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// eventuallyAllowed waits for an open to start succeeding.
//
// Needed only after a teardown. Dropping the last reference to a BPF link does
// not detach the program inline: the kernel defers bpf_link_free to a workqueue,
// so the LSM hook can still refuse an open for a short while after the pin is
// gone and the descriptor is closed. Asserting immediately would make a correct
// teardown look like a teardown that did nothing.
func eventuallyAllowed(t *testing.T, cgDir, path string) error {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = catIn(cgDir, path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startPinnedManager builds a Manager the way cmd/pahlevan-agent does: point it
// at the pin root, load (adopting anything already pinned there), then Start,
// which is what attaches the hooks.
func startPinnedManager(t *testing.T, root string) (*Manager, context.CancelFunc) {
	t.Helper()
	m, err := NewManager()
	if err != nil {
		t.Skipf("NewManager (needs a privileged eBPF-capable kernel): %v", err)
	}
	m.SetPinRoot(root)
	if err := m.LoadPrograms(); err != nil {
		t.Fatalf("LoadPrograms: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	return m, cancel
}

func countAllowEntries(t *testing.T, mp *ebpf.Map) int {
	t.Helper()
	if mp == nil {
		return 0
	}
	var k uint64
	var v uint8
	n := 0
	it := mp.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterating allow-set: %v", err)
	}
	return n
}

// TestVMEnforcementSurvivesAgentRestart is the whole point of the pinning work.
//
// It learns a baseline, switches a cgroup to enforcing, closes the Manager
// EXACTLY the way the agent's deferred Close() does, and then - with no Pahlevan
// process alive at all - asserts that the kernel still denies an unlearned open
// and still allows a learned one. Then a second Manager adopts the pinned state
// and the same two assertions must hold, with the allow-set intact.
//
// Before this change, step 4 would have passed every open: the links were closed
// on shutdown and the node was completely unenforced until the replacement pod
// attached.
func TestVMEnforcementSurvivesAgentRestart(t *testing.T) {
	vmPinGate(t)

	root := vmPinRoot(t, "restart")
	cgDir, cgID := vmTestCgroup(t, "restart")

	// --- 1. First agent: load, attach, learn. ------------------------------
	m1, cancel1 := startPinnedManager(t, root)
	if m1.fileCollection == nil {
		cancel1()
		m1.Close()
		t.Skip("file monitor did not load; this kernel has no BPF LSM")
	}
	if m1.PinRoot() != root {
		t.Fatalf("pinning was disabled during startup: PinRoot = %q, want %q (reason: %s)",
			m1.PinRoot(), root, m1.pins.disabledReason)
	}
	if m1.AdoptedPinnedState() {
		t.Fatal("the first agent adopted state; the pin root should have been empty")
	}

	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("learning run failed: %v", err)
	}
	learned := countAllowEntries(t, m1.fileCollection.Maps["file_allowed"])
	if learned == 0 {
		cancel1()
		m1.Close()
		t.Fatal("nothing was learned; the rest of the test would prove nothing")
	}
	t.Logf("learned %d (cgroup,path) allow-set entries", learned)

	// --- 2. Enforce, and confirm enforcement works at all. ------------------
	if err := m1.fileCollection.Maps["file_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("set enforce mode: %v", err)
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("learned path denied under enforcement: %v", err)
	}
	if err := catIn(cgDir, "/etc/os-release"); err == nil {
		cancel1()
		m1.Close()
		t.Fatal("unlearned path was allowed under enforcement; enforcement is not working")
	}

	// --- 3. Restart: close the way cmd/pahlevan-agent's defer does. ---------
	cancel1()
	m1.Close()

	// --- 4. THE PROPERTY. No Pahlevan process is running. ------------------
	// The pinned links hold the LSM programs in the kernel, so the node is
	// still enforcing, and the pinned maps still hold the learned set.
	if err := catIn(cgDir, "/etc/os-release"); err == nil {
		t.Fatal("ENFORCEMENT GAP: an unlearned open succeeded while no agent was running")
	} else {
		t.Logf("still denied in-kernel with no agent running: %v", err)
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		t.Fatalf("ALLOW-SET LOST: a learned open was denied while no agent was running: %v", err)
	}

	// --- 5. Second agent adopts rather than rebuilding. --------------------
	m2, cancel2 := startPinnedManager(t, root)
	defer func() {
		cancel2()
		m2.Close()
	}()

	if !m2.AdoptedPinnedState() {
		t.Fatal("the second agent did not adopt the pinned state; it rebuilt, which is the gap this change removes")
	}
	t.Logf("adopted collections: %v; inherited hooks: %v", m2.adoptedCollections.names(), m2.adoptedLinkNames)

	inheritedFileHook := false
	for _, n := range m2.adoptedLinkNames {
		if n == linkFileOpen {
			inheritedFileHook = true
		}
	}
	if !inheritedFileHook {
		t.Errorf("lsm/file_open was re-attached rather than inherited; hooks = %v", m2.adoptedLinkNames)
	}

	// --- 6. The allow-set and the enforcement mode came across intact. -----
	after := countAllowEntries(t, m2.fileCollection.Maps["file_allowed"])
	if after < learned {
		t.Errorf("allow-set shrank across the restart: %d entries before, %d after", learned, after)
	}
	var mode uint32
	if err := m2.fileCollection.Maps["file_mode"].Lookup(cgID, &mode); err != nil {
		t.Fatalf("enforcement mode for the test cgroup was lost across the restart: %v", err)
	}
	if mode != uint32(ActionDeny) {
		t.Errorf("enforcement mode = %d after the restart, want %d", mode, ActionDeny)
	}

	// --- 7. And the new agent is really the one enforcing now. -------------
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		t.Errorf("learned path denied after adoption: %v", err)
	}
	if err := catIn(cgDir, "/etc/os-release"); err == nil {
		t.Error("unlearned path allowed after adoption")
	}

	// --- 8. Teardown is the ONLY thing that turns enforcement off. ---------
	if err := m2.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := eventuallyAllowed(t, cgDir, "/etc/os-release"); err != nil {
		t.Errorf("after an explicit teardown the programs are still attached and denying: %v", err)
	} else {
		t.Log("teardown detached the programs; the node is no longer enforcing")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("pin root still present after teardown: %v", err)
	}
}

// TestVMIncompatiblePinnedStateIsRejected covers the upgrade case: pinned state
// left by a DIFFERENT version of the programs must be refused and rebuilt, never
// adopted.
//
// Adopting it would leave the previous version's programs attached while the new
// agent read their maps and decoded their events with its own structs - a
// mismatch that produces wrong answers rather than errors, which is why the
// digest check refuses it outright.
func TestVMIncompatiblePinnedStateIsRejected(t *testing.T) {
	vmPinGate(t)

	root := vmPinRoot(t, "incompat")
	cgDir, cgID := vmTestCgroup(t, "incompat")

	m1, cancel1 := startPinnedManager(t, root)
	if m1.fileCollection == nil {
		cancel1()
		m1.Close()
		t.Skip("file monitor did not load; this kernel has no BPF LSM")
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("learning run failed: %v", err)
	}
	if err := m1.fileCollection.Maps["file_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("set enforce mode: %v", err)
	}
	cancel1()
	m1.Close()

	// Stand in for "the agent was upgraded and its BPF objects changed" by
	// rewriting the digest the tree is stamped with. Everything else about the
	// tree is genuine, which is exactly the situation that must be caught:
	// the map names match, the sizes match, and adopting anyway would be the
	// silent mismatch.
	meta, err := ebpf.LoadPinnedMap(filepath.Join(root, pinMetaName), &ebpf.LoadPinOptions{})
	if err != nil {
		t.Fatalf("loading the pinned stamp: %v", err)
	}
	var stamp pinMeta
	if err := meta.Lookup(uint32(0), &stamp); err != nil {
		meta.Close()
		t.Fatalf("reading the pinned stamp: %v", err)
	}
	original := stamp.Digest
	stamp.Digest ^= 0xFFFFFFFFFFFFFFFF
	if err := meta.Put(uint32(0), stamp); err != nil {
		meta.Close()
		t.Fatalf("rewriting the pinned stamp: %v", err)
	}
	meta.Close()
	t.Logf("stamped the tree with digest %#x instead of %#x", stamp.Digest, original)

	m2, cancel2 := startPinnedManager(t, root)
	defer func() {
		cancel2()
		m2.Close()
	}()

	if m2.AdoptedPinnedState() {
		t.Fatal("adopted state stamped by a different version of the programs")
	}
	// A rebuild means brand new maps, so the previous enforcement mode must be
	// gone. If it were still there, the old maps had been adopted after all.
	var mode uint32
	err = m2.fileCollection.Maps["file_mode"].Lookup(cgID, &mode)
	if err == nil {
		t.Fatalf("the rebuilt file_mode map still holds the old state (mode %d); this is adoption wearing a rebuild's name", mode)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("unexpected error reading the rebuilt map: %v", err)
	}

	// And the rebuild re-stamped the tree with THIS agent's digest, so the
	// next restart adopts normally rather than rebuilding forever.
	restamped, err := ebpf.LoadPinnedMap(filepath.Join(root, pinMetaName), &ebpf.LoadPinOptions{})
	if err != nil {
		t.Fatalf("the rebuild left no stamp; every future restart would rebuild: %v", err)
	}
	defer restamped.Close()
	var got pinMeta
	if err := restamped.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("reading the new stamp: %v", err)
	}
	if got.Digest != objectDigest() {
		t.Errorf("new stamp digest = %#x, want %#x", got.Digest, objectDigest())
	}
	if got.Magic != pinMagic || got.Schema != pinSchemaVersion {
		t.Errorf("new stamp = %+v, want magic %#x schema %d", got, pinMagic, pinSchemaVersion)
	}
}

// TestVMPinnedMapWithADifferentLayoutIsRefused is the silent-corruption case
// named in the design: a pinned map whose NAME matches but whose value layout
// does not.
//
// The stamp is left genuine here, so the digest check passes and the only thing
// standing between the agent and a map it would read wrongly is the per-map
// geometry comparison on the adopt path.
func TestVMPinnedMapWithADifferentLayoutIsRefused(t *testing.T) {
	vmPinGate(t)

	root := vmPinRoot(t, "layout")
	cgDir, cgID := vmTestCgroup(t, "layout")

	m1, cancel1 := startPinnedManager(t, root)
	if m1.fileCollection == nil {
		cancel1()
		m1.Close()
		t.Skip("file monitor did not load; this kernel has no BPF LSM")
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("learning run failed: %v", err)
	}
	if err := m1.fileCollection.Maps["file_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("set enforce mode: %v", err)
	}
	spec, err := m1.specFor(collFile)
	if err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("specFor(file): %v", err)
	}
	want := spec.Maps["file_allowed"]
	cancel1()
	m1.Close()

	// Replace the pinned allow-set with a map of the same name, the same type
	// and the same key, but a wider value - the shape a value-struct change
	// produces. Nothing in the tree's stamp records it.
	pinPath := filepath.Join(root, collectionDir[collFile], "maps", "file_allowed")
	if err := os.Remove(pinPath); err != nil {
		t.Fatalf("removing the genuine pin: %v", err)
	}
	impostor, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "file_allowed",
		Type:       want.Type,
		KeySize:    want.KeySize,
		ValueSize:  want.ValueSize + 7,
		MaxEntries: want.MaxEntries,
	})
	if err != nil {
		t.Fatalf("creating the impostor map: %v", err)
	}
	if err := impostor.Pin(pinPath); err != nil {
		impostor.Close()
		t.Fatalf("pinning the impostor map: %v", err)
	}
	impostor.Close()

	m2, cancel2 := startPinnedManager(t, root)
	defer func() {
		cancel2()
		m2.Close()
	}()

	if m2.AdoptedPinnedState() {
		t.Fatal("adopted a tree containing a map whose value layout does not match the spec")
	}
	if m2.fileCollection == nil {
		t.Fatal("the rebuild produced no file collection")
	}
	if got := m2.fileCollection.Maps["file_allowed"].ValueSize(); got != want.ValueSize {
		t.Errorf("rebuilt file_allowed has a %d-byte value, want %d", got, want.ValueSize)
	}
	var mode uint32
	if err := m2.fileCollection.Maps["file_mode"].Lookup(cgID, &mode); err == nil {
		t.Errorf("the rebuilt tree still carries the old enforcement mode (%d)", mode)
	}
}

// TestVMMissingLinkPinIsReattached covers the mixed case: the maps and programs
// are adoptable but one hook's link pin is gone.
//
// That hook must simply be attached again with the ADOPTED program, not cause a
// whole-tree rebuild - a kernel that never had one of these hooks is normal, and
// throwing away every other collection's state over it would turn a missing
// tracepoint into a cluster-wide enforcement gap.
func TestVMMissingLinkPinIsReattached(t *testing.T) {
	vmPinGate(t)

	root := vmPinRoot(t, "relink")
	cgDir, cgID := vmTestCgroup(t, "relink")

	m1, cancel1 := startPinnedManager(t, root)
	if m1.fileCollection == nil {
		cancel1()
		m1.Close()
		t.Skip("file monitor did not load; this kernel has no BPF LSM")
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("learning run failed: %v", err)
	}
	if err := m1.fileCollection.Maps["file_mode"].Put(cgID, uint32(ActionDeny)); err != nil {
		cancel1()
		m1.Close()
		t.Fatalf("set enforce mode: %v", err)
	}
	learned := countAllowEntries(t, m1.fileCollection.Maps["file_allowed"])
	cancel1()
	m1.Close()

	linkPath := filepath.Join(root, collectionDir[collFile], "links", linkFileOpen)
	if _, err := os.Stat(linkPath); err != nil {
		t.Skipf("lsm/file_open was never pinned on this kernel: %v", err)
	}
	// Removing the pin drops the last reference, so the hook detaches here.
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("removing the link pin: %v", err)
	}

	m2, cancel2 := startPinnedManager(t, root)
	defer func() {
		cancel2()
		m2.Close()
	}()

	if !m2.AdoptedPinnedState() {
		t.Fatal("a missing link pin caused a whole-tree rebuild; one absent hook must not cost every collection its state")
	}
	if got := countAllowEntries(t, m2.fileCollection.Maps["file_allowed"]); got < learned {
		t.Errorf("allow-set shrank: %d entries before, %d after", learned, got)
	}
	for _, n := range m2.adoptedLinkNames {
		if n == linkFileOpen {
			t.Error("claimed to inherit a hook whose pin had been removed")
		}
	}
	// Re-attached with the adopted program, so enforcement works again.
	if err := catIn(cgDir, "/etc/os-release"); err == nil {
		t.Error("unlearned path allowed after the hook was re-attached")
	}
	if err := catIn(cgDir, "/etc/hostname"); err != nil {
		t.Errorf("learned path denied after the hook was re-attached: %v", err)
	}
	// And the new link was pinned, so the NEXT restart is gapless again.
	if _, err := os.Stat(linkPath); err != nil {
		t.Errorf("the re-attached hook was not pinned; the next restart would have a gap: %v", err)
	}
}
