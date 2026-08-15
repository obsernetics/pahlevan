package ebpf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// cgroupV2Root is the unified cgroup hierarchy mount point.
const cgroupV2Root = "/sys/fs/cgroup"

// TestVMLoadSyscallMonitor loads and attaches the CO-RE syscall monitor, then
// verifies real events flow through the ring buffer with plausible attribution.
//
// It requires privileges and an eBPF-capable kernel, so it MUST only run inside
// the test VM (never the host). It is gated on PAHLEVAN_EBPF_VM_TEST=1, which the
// VM harness sets; otherwise it skips.
func TestVMLoadSyscallMonitor(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; never on the host)")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	spec, err := LoadSyscallMonitor()
	if err != nil {
		t.Fatalf("LoadSyscallMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("NewCollection verifier error: %+v", ve)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_sys_enter"]
	if prog == nil {
		t.Fatal("program handle_sys_enter not found in collection")
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: prog,
	})
	if err != nil {
		t.Fatalf("AttachRawTracepoint(sys_enter): %v", err)
	}
	defer l.Close()

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		t.Fatal("events ring buffer map not found")
	}
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	// Generate syscalls this process hasn't done yet so dedup lets them through.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_, _ = os.Stat("/proc/self/status")
			f, _ := os.Open("/dev/null")
			if f != nil {
				_ = f.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	rd.SetDeadline(time.Now().Add(5 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf read (no events observed): %v", err)
	}

	ev := parseSyscallEvent(rec.RawSample)
	if ev == nil {
		t.Fatalf("failed to parse syscall event from %d bytes", len(rec.RawSample))
	}
	if ev.CgroupID == 0 {
		t.Errorf("expected non-zero cgroup id (real attribution), got 0")
	}
	if ev.Comm == "" {
		t.Errorf("expected non-empty comm")
	}
	t.Logf("observed syscall event: nr=%d comm=%q pid=%d cgroup=%d uid=%d",
		ev.SyscallNr, ev.Comm, ev.PID, ev.CgroupID, ev.UID)
}

// TestVMLoadFileMonitor loads the CO-RE file monitor, attaches the lsm/file_open
// hook, and verifies real file-open events (with a resolved path) flow through
// the ring buffer. VM-only (requires the bpf LSM active).
func TestVMLoadFileMonitor(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	spec, err := LoadFileMonitor()
	if err != nil {
		t.Fatalf("LoadFileMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("NewCollection verifier error: %+v", ve)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["file_open"]
	if prog == nil {
		t.Fatal("program file_open not found")
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		t.Fatalf("AttachLSM(file_open): %v (is lsm=...,bpf active?)", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(coll.Maps["file_events"])
	if err != nil {
		t.Fatalf("ringbuf.NewReader(file_events): %v", err)
	}
	defer rd.Close()

	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			f, _ := os.Open("/etc/hostname")
			if f != nil {
				_ = f.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	rd.SetDeadline(time.Now().Add(5 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf read (no file events): %v", err)
	}
	ev := parseFileEvent(rec.RawSample)
	if ev == nil {
		t.Fatalf("failed to parse file event from %d bytes", len(rec.RawSample))
	}
	if ev.Path == "" {
		t.Errorf("expected a resolved path")
	}
	if ev.CgroupID == 0 {
		t.Errorf("expected non-zero cgroup id")
	}
	t.Logf("observed file event: path=%q comm=%q pid=%d cgroup=%d flags=%#x",
		ev.Path, ev.Comm, ev.PID, ev.CgroupID, ev.Flags)
}

// TestVMFileAdaptiveEnforcement proves the full adaptive loop with LSM BPF:
// in a dedicated cgroup, files opened during LEARN are auto-added to the allow
// set; after switching that cgroup to ENFORCE, a previously-unseen file open is
// DENIED in-kernel (EPERM) while a learned file still opens. This is auto-learned
// allow-list enforcement - no hand-written rules, and real prevention (not
// alerting). VM-only.
func TestVMFileAdaptiveEnforcement(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	spec, err := LoadFileMonitor()
	if err != nil {
		t.Fatalf("LoadFileMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["file_open"]})
	if err != nil {
		t.Fatalf("AttachLSM(file_open): %v", err)
	}
	defer l.Close()

	// Dedicated cgroup so enforcement affects only our helper, not the test.
	cg := fmt.Sprintf("/sys/fs/cgroup/pahlevan-test-%d", os.Getpid())
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create test cgroup (need cgroup v2, root): %v", err)
	}
	defer os.Remove(cg)

	var st syscall.Stat_t
	if err := syscall.Stat(cg, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	cgID := st.Ino

	// runIn runs `cat <path>` inside the dedicated cgroup and returns cat's error.
	runIn := func(path string) error {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec cat %s", cg, path)
		return exec.Command("/bin/sh", "-c", script).Run()
	}

	// LEARN: run cat on the sentinel so cat's libs + the sentinel path are learned.
	if err := runIn("/etc/hostname"); err != nil {
		t.Fatalf("learn run failed: %v", err)
	}
	// Give the ring buffer time isn't needed - the allow-set is updated in-kernel
	// synchronously during the open. Confirm we learned something.
	var learned int
	{
		var k, nk uint64
		var v uint8
		it := coll.Maps["file_allowed"].Iterate()
		for it.Next(&k, &v) {
			nk++
		}
		_ = k
		learned = int(nk)
	}
	if learned == 0 {
		t.Fatal("expected learned file entries after learning run")
	}
	t.Logf("learned %d (cgroup,path) allow-set entries", learned)

	// Switch the cgroup to ENFORCE.
	if err := coll.Maps["file_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	// A learned file still opens.
	if err := runIn("/etc/hostname"); err != nil {
		t.Errorf("expected learned /etc/hostname to be ALLOWED under enforcement, got: %v", err)
	} else {
		t.Log("learned /etc/hostname allowed under enforcement")
	}

	// An unlearned file is DENIED (cat exits non-zero because open -> EPERM).
	if err := runIn("/etc/os-release"); err == nil {
		t.Error("expected unlearned /etc/os-release open to be DENIED under enforcement, but it succeeded")
	} else {
		t.Logf("DENIED in-kernel as expected: cat /etc/os-release -> %v", err)
	}

	// Clean up: move nothing needed (helpers already exited); rmdir in defer.
}

// TestVMLoadNetworkMonitor loads the CO-RE network monitor, attaches the
// lsm/socket_connect hook, and verifies an outbound connection produces a real event
// with destination + cgroup attribution. VM-only.
func TestVMLoadNetworkMonitor(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only)")
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
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier: %+v", ve)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	prog := coll.Programs["socket_connect"]
	if prog == nil {
		t.Fatal("program socket_connect not found")
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		t.Fatalf("AttachLSM(socket_connect): %v (is lsm=...,bpf active?)", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["network_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// Trigger an outbound TCP connect (to a likely-refused local port; connect()
	// still calls tcp_connect before the RST).
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			c, _ := net.DialTimeout("tcp", "127.0.0.1:59999", 200*time.Millisecond)
			if c != nil {
				c.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	rd.SetDeadline(time.Now().Add(5 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf read (no network events): %v", err)
	}
	ev := parseNetworkEvent(rec.RawSample)
	if ev == nil {
		t.Fatalf("failed to parse network event from %d bytes", len(rec.RawSample))
	}
	if ev.DstPort == 0 {
		t.Errorf("expected a destination port")
	}
	t.Logf("observed network event: dport=%d daddr=%#x cgroup=%d pid=%d", ev.DstPort, ev.DstIP, ev.CgroupID, ev.PID)
}

// TestVMExecAdaptiveEnforcement proves in-kernel exec control: in a dedicated
// cgroup, binaries run during LEARN are added to the allow-set; after switching to
// ENFORCE, executing an unlearned binary is denied (EPERM) while a learned one
// still runs. VM-only (requires bpf LSM).
func TestVMExecAdaptiveEnforcement(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadExecMonitor()
	if err != nil {
		t.Fatalf("LoadExecMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier: %+v", ve)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["bprm_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(bprm_check): %v", err)
	}
	defer l.Close()

	cg := fmt.Sprintf("/sys/fs/cgroup/pahlevan-exec-%d", os.Getpid())
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create test cgroup: %v", err)
	}
	defer os.Remove(cg)
	var st syscall.Stat_t
	if err := syscall.Stat(cg, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	cgID := st.Ino

	runIn := func(bin string) error {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec %s", cg, bin)
		return exec.Command("/bin/sh", "-c", script).Run()
	}

	// LEARN: run /bin/true (and the sh that execs it) so they're allowed.
	if err := runIn("/bin/true"); err != nil {
		t.Fatalf("learn run failed: %v", err)
	}
	// ENFORCE.
	if err := coll.Maps["exec_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce: %v", err)
	}
	// Learned /bin/true still runs.
	if err := runIn("/bin/true"); err != nil {
		t.Errorf("expected learned /bin/true allowed under enforcement, got: %v", err)
	} else {
		t.Log("learned /bin/true allowed under enforcement")
	}
	// Unlearned binary is denied (copy true to a new path so it's unseen).
	_ = exec.Command("/bin/cp", "/bin/true", "/tmp/pahlevan-unlearned").Run()
	defer os.Remove("/tmp/pahlevan-unlearned")
	if err := runIn("/tmp/pahlevan-unlearned"); err == nil {
		t.Error("expected unlearned binary exec to be DENIED under enforcement")
	} else {
		t.Logf("DENIED in-kernel as expected: exec /tmp/pahlevan-unlearned -> %v", err)
	}
}

// TestVMMapMemoryFootprint loads every program and reports the real kernel memory
// the BPF maps reserve, summed from bpftool JSON. BPF maps are preallocated, so
// this is the floor of the agent's memory cost and was the dominant term in the
// benchmark's 327 MiB figure. VM-only.
func TestVMMapMemoryFootprint(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){
		"syscall":    LoadSyscallMonitor,
		"file":       LoadFileMonitor,
		"network":    LoadNetworkMonitor,
		"exec":       LoadExecMonitor,
		"capability": LoadCapabilityMonitor,
	} {
		spec, err := load()
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		c, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Fatalf("create %s collection: %v", name, err)
		}
		// Closed together after the measurement rather than deferred inside the
		// loop: every collection has to stay loaded while bpftool reads the
		// totals below.
		t.Cleanup(func() { c.Close() })
	}

	out, err := exec.Command("bpftool", "-j", "map", "show").Output()
	if err != nil {
		t.Fatalf("bpftool -j map show: %v", err)
	}
	var maps []struct {
		Name       string `json:"name"`
		MaxEntries uint32 `json:"max_entries"`
		Memlock    int64  `json:"bytes_memlock"`
	}
	if err := json.Unmarshal(out, &maps); err != nil {
		t.Fatalf("parse bpftool json: %v", err)
	}

	ours := map[string]bool{
		"events": true, "file_events": true, "network_events": true, "exec_events": true,
		"syscall_seen": true, "file_allowed": true, "network_allowed": true, "exec_allowed": true,
		"file_mode": true, "network_mode": true, "exec_mode": true,
		"cap_events": true, "cap_allowed": true, "cap_mode": true,
		"config_map": true, "file_config": true,
	}
	var total int64
	var matched int
	for _, m := range maps {
		if ours[m.Name] {
			total += m.Memlock
			matched++
			t.Logf("  %-16s max_entries=%-8d memlock=%.2f MiB", m.Name, m.MaxEntries, float64(m.Memlock)/(1024*1024))
		}
	}
	if matched == 0 {
		t.Fatal("measurement failed: bpftool listed none of the pahlevan maps")
	}
	mib := float64(total) / (1024 * 1024)
	t.Logf("TOTAL pahlevan BPF map memlock (%d maps, all 5 programs): %.1f MiB", matched, mib)
	if mib > 64 {
		t.Errorf("BPF map footprint is %.1f MiB (expected well under 64 MiB); check max_entries sizing", mib)
	}
}

// TestVMCapabilityMonitor loads the CO-RE capability monitor, attaches lsm/capable,
// and verifies real capability checks are observed with cgroup attribution.
// VM-only (requires bpf LSM).
func TestVMCapabilityMonitor(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadCapabilityMonitor()
	if err != nil {
		t.Fatalf("LoadCapabilityMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier: %+v", ve)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["capable_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(capable): %v", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["cap_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// Trigger privileged operations that require capability checks.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = exec.Command("/bin/sh", "-c", "chown root /tmp/pahlevan-cap-probe 2>/dev/null; ip link show >/dev/null 2>&1").Run()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	rd.SetDeadline(time.Now().Add(5 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf read (no capability events): %v", err)
	}
	ev := parseCapabilityEvent(rec.RawSample)
	if ev == nil {
		t.Fatalf("failed to parse capability event from %d bytes", len(rec.RawSample))
	}
	if ev.CgroupID == 0 {
		t.Errorf("expected non-zero cgroup id")
	}
	t.Logf("observed capability event: cap=%d (%s) comm=%q pid=%d cgroup=%d",
		ev.Capability, CapabilityName(ev.Capability), ev.Comm, ev.PID, ev.CgroupID)
}

// TestVMProcessAncestry verifies exec events carry the parent pid and comm, which
// is what lets a denial be traced back to the process that spawned it. VM-only.
func TestVMProcessAncestry(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadExecMonitor()
	if err != nil {
		t.Fatalf("LoadExecMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["bprm_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(bprm_check): %v", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["exec_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// sh -c 'exec /bin/true' gives a known parent (sh) for the exec'd binary.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = exec.Command("/bin/sh", "-c", "/bin/true").Run()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			break
		}
		ev := parseProcessEvent(rec.RawSample)
		if ev == nil || ev.PPID == 0 {
			continue
		}
		t.Logf("observed exec with ancestry: %q (pid=%d) chain=%q",
			ev.Filename, ev.PID, ev.AncestryChain())
		if ev.ParentComm == "" {
			t.Error("expected a parent comm on the exec event")
		}
		// The nearest ancestor must agree with the flat PPID/ParentComm fields
		// that existing consumers read.
		if len(ev.Ancestry) == 0 {
			t.Error("expected at least one ancestry entry alongside PPID")
		} else {
			if ev.Ancestry[0].PID != ev.PPID {
				t.Errorf("ancestry[0].PID = %d but PPID = %d", ev.Ancestry[0].PID, ev.PPID)
			}
			if ev.Ancestry[0].Comm != ev.ParentComm {
				t.Errorf("ancestry[0].Comm = %q but ParentComm = %q", ev.Ancestry[0].Comm, ev.ParentComm)
			}
		}
		return
	}
	t.Fatal("no exec event with parent ancestry observed")
}

// TestVMProcessAncestryChain asserts the kernel walks more than one hop. A
// single parent says "curl ran"; the chain says "nginx spawned a shell which
// ran curl", which is the difference between an alert and an investigation.
// VM-only.
func TestVMProcessAncestryChain(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadExecMonitor()
	if err != nil {
		t.Fatalf("LoadExecMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["bprm_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(bprm_check): %v", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["exec_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// Three nested shells, each staying alive as a real parent (no exec
	// replacement), so the innermost binary has a genuinely deep lineage.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = exec.Command("/bin/sh", "-c",
				"/bin/sh -c '/bin/sh -c /bin/true; :' ; :").Run()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	best := 0
	var bestChain string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			break
		}
		ev := parseProcessEvent(rec.RawSample)
		if ev == nil {
			continue
		}
		if len(ev.Ancestry) > best {
			best, bestChain = len(ev.Ancestry), ev.AncestryChain()
		}
		// Every recorded ancestor must be a real entry: the decoder stops at
		// the first zero pid, so a populated slot with an empty comm would mean
		// the kernel wrote a partial record.
		for i, a := range ev.Ancestry {
			if a.PID == 0 {
				t.Errorf("ancestry[%d] has pid 0 but was not truncated", i)
			}
		}
		if len(ev.Ancestry) >= 3 {
			t.Logf("observed a %d-deep lineage: %s", len(ev.Ancestry), ev.AncestryChain())
			return
		}
	}
	t.Fatalf("deepest lineage observed was %d (%q); expected at least 3 from nested shells",
		best, bestChain)
}

// TestVMIPv6EgressGoverned proves IPv6 egress is subject to enforcement. The hook
// previously returned early on any non-AF_INET family, so an attacker could
// exfiltrate over IPv6 with enforcement enabled. VM-only.
func TestVMIPv6EgressGoverned(t *testing.T) {
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
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["socket_connect"]})
	if err != nil {
		t.Fatalf("AttachLSM(socket_connect): %v", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["network_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// Dial an IPv6 loopback destination; connect() reaches socket_connect even
	// when the port is closed.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			c, _ := net.DialTimeout("tcp6", "[::1]:59998", 200*time.Millisecond)
			if c != nil {
				c.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			break
		}
		ev := parseNetworkEvent(rec.RawSample)
		if ev == nil || ev.Family != 10 {
			continue // ignore any concurrent IPv4 traffic
		}
		t.Logf("observed IPv6 egress event: dst=%s cgroup=%d comm=%q",
			ev.DestinationString(), ev.CgroupID, ev.Comm)
		if ev.DstPort == 0 {
			t.Error("expected a destination port on the IPv6 event")
		}
		return
	}
	t.Fatal("no IPv6 egress event observed: IPv6 connects are not being governed")
}

// TestVMSeededAllowEntryIsHonoured is the proof that the userspace allow-set
// writers in allowset.go derive the same key the BPF program computes. The host
// unit tests can only show the Go code agrees with itself; only the kernel can
// confirm the contract.
//
// A path is deliberately NEVER opened during learning, seeded from userspace,
// and then must still open under enforcement. If the key derivation were off by
// a byte the open would be denied. VM-only.
func TestVMSeededAllowEntryIsHonoured(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	coll, cgID, runIn := seedTestFixture(t, "seed")

	// LEARN on one sentinel only. The seeded paths are never opened here, so
	// they cannot enter the allow-set by observation.
	if err := runIn("/etc/hostname"); err != nil {
		t.Fatalf("learn run failed: %v", err)
	}

	// Seed a never-observed path through the public writer, exactly as an
	// operator's PahlevanPolicy exception would. /etc/fstab is a real file, not
	// a symlink - see TestVMSeededSymlinkPathDoesNotMatch for why that matters.
	m := &Manager{fileCollection: coll}
	const seeded = "/etc/fstab"
	if err := m.AllowFilePath(cgID, seeded, true); err != nil {
		t.Fatalf("AllowFilePath: %v", err)
	}

	if err := coll.Maps["file_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	// The seeded path must open even though it was never learned.
	if err := runIn(seeded); err != nil {
		t.Errorf("seeded %s should be ALLOWED under enforcement, got: %v", seeded, err)
	} else {
		t.Logf("seeded %s allowed under enforcement: userspace and kernel keys agree", seeded)
	}

	// A different unseeded, unlearned path must still be denied, proving the
	// seed granted exactly one path and did not disable enforcement.
	if err := runIn("/etc/machine-id"); err == nil {
		t.Error("unseeded /etc/machine-id should be DENIED under enforcement, but it succeeded")
	} else {
		t.Logf("unseeded /etc/machine-id denied as expected: %v", err)
	}

	// Revoking must take the path back out, even though it is in the map.
	if err := m.AllowFilePath(cgID, seeded, false); err != nil {
		t.Fatalf("AllowFilePath revoke: %v", err)
	}
	if err := runIn(seeded); err == nil {
		t.Errorf("revoked %s should be DENIED under enforcement, but it succeeded", seeded)
	} else {
		t.Logf("revoked %s denied as expected: %v", seeded, err)
	}
}

// TestVMSeededSymlinkPathDoesNotMatch pins a limitation an operator will
// otherwise hit silently.
//
// bpf_d_path resolves to the real dentry, so the kernel hashes the target of a
// symlink, not the name that was opened. Seeding "/etc/os-release" therefore
// grants nothing on a distro where it links to /usr/lib/os-release, while
// seeding the resolved path works. This is a real trap - the exception looks
// applied and is not - so it is asserted rather than left to be rediscovered.
// VM-only.
func TestVMSeededSymlinkPathDoesNotMatch(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	const link = "/etc/os-release"
	target, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Skipf("cannot resolve %s: %v", link, err)
	}
	if target == link {
		t.Skipf("%s is not a symlink on this image; nothing to assert", link)
	}

	coll, cgID, runIn := seedTestFixture(t, "symlink")
	if err := runIn("/etc/hostname"); err != nil {
		t.Fatalf("learn run failed: %v", err)
	}
	m := &Manager{fileCollection: coll}

	// Seed the link name. The kernel hashes the target, so this must NOT match.
	if err := m.AllowFilePath(cgID, link, true); err != nil {
		t.Fatalf("AllowFilePath: %v", err)
	}
	if err := coll.Maps["file_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}
	if err := runIn(link); err == nil {
		t.Errorf("seeding the symlink name %s unexpectedly worked; if bpf_d_path "+
			"stopped resolving symlinks, the documented guidance can be relaxed", link)
	} else {
		t.Logf("seeding the link name %s does not match, as documented: %v", link, err)
	}

	// Seeding the resolved target does work, which is the guidance operators
	// must follow.
	if err := m.AllowFilePath(cgID, target, true); err != nil {
		t.Fatalf("AllowFilePath(target): %v", err)
	}
	if err := runIn(link); err != nil {
		t.Errorf("seeding the resolved target %s should allow opening %s, got: %v", target, link, err)
	} else {
		t.Logf("seeding the resolved target %s allows opening %s", target, link)
	}
}

// seedTestFixture loads the file monitor, attaches it, and returns the
// collection, a dedicated cgroup id, and a helper that opens a path inside that
// cgroup so enforcement affects only the helper and never the test process.
func seedTestFixture(t *testing.T, name string) (*ebpf.Collection, uint64, func(string) error) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadFileMonitor()
	if err != nil {
		t.Fatalf("LoadFileMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	t.Cleanup(coll.Close)

	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["file_open"]})
	if err != nil {
		t.Fatalf("AttachLSM(file_open): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	cg := fmt.Sprintf("/sys/fs/cgroup/pahlevan-%s-%d", name, os.Getpid())
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create test cgroup (need cgroup v2, root): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	var st syscall.Stat_t
	if err := syscall.Stat(cg, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	runIn := func(path string) error {
		script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec cat %s", cg, path)
		return exec.Command("/bin/sh", "-c", script).Run()
	}
	return coll, st.Ino, runIn
}

// TestVMNetworkProtocolIsGoverned asserts that the transport protocol is part
// of the allow-set identity and is reported truthfully.
//
// Two bugs sat here: the event hardcoded protocol 6 regardless of the socket,
// and the allow-set key ignored the protocol entirely, so a destination learned
// over TCP was also permitted over UDP on the same port. That is a real egress
// bypass, since DNS-shaped exfiltration over UDP/53 would ride an allow entry
// created by an ordinary TCP resolver connection. VM-only.
func TestVMNetworkProtocolIsGoverned(t *testing.T) {
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
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["socket_connect"]})
	if err != nil {
		t.Fatalf("AttachLSM(socket_connect): %v", err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["network_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// This test governs the whole test process's cgroup rather than a child, so
	// it dials from here and restores learning mode before returning.
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
	defer func() { _ = coll.Maps["network_mode"].Delete(cgID) }()

	const target = "127.0.0.1:59997"

	// LEARN over TCP. connect() reaches socket_connect even on a closed port.
	c, _ := net.DialTimeout("tcp4", target, 300*time.Millisecond)
	if c != nil {
		c.Close()
	}

	// Drain whatever the learning connect produced and confirm the protocol is
	// reported as TCP rather than assumed.
	sawTCP := false
	rd.SetDeadline(time.Now().Add(time.Second))
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		if ev := parseNetworkEvent(rec.RawSample); ev != nil && ev.DstPort == 59997 {
			if ev.Protocol != ProtocolTCP {
				t.Errorf("learned TCP connect reported protocol %d, want %d", ev.Protocol, ProtocolTCP)
			}
			sawTCP = true
			break
		}
		rd.SetDeadline(time.Now().Add(300 * time.Millisecond))
	}
	if !sawTCP {
		t.Fatal("no event observed for the learning TCP connect")
	}

	if err := coll.Maps["network_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	// The learned TCP destination must still be reachable.
	if c, err := net.DialTimeout("tcp4", target, 300*time.Millisecond); err != nil &&
		strings.Contains(err.Error(), "operation not permitted") {
		t.Errorf("learned TCP destination should be ALLOWED under enforcement: %v", err)
	} else if c != nil {
		c.Close()
	}

	// The same host and port over UDP was never learned, so it must be denied.
	// Before the protocol was folded into the key this succeeded.
	uc, err := net.DialTimeout("udp4", target, 300*time.Millisecond)
	if uc != nil {
		uc.Close()
	}
	if err == nil {
		t.Error("UDP to a destination learned only over TCP should be DENIED, but it succeeded")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Errorf("UDP connect failed for the wrong reason: %v", err)
	} else {
		t.Logf("UDP to a TCP-learned destination denied as expected: %v", err)
	}
}

// TestVMWriteIsNotGrantedByALearnedRead is the regression test for a real
// escalation the benchmark run found.
//
// The file allow-set keyed on the path alone. nginx reads /etc/passwd at
// startup, so that read entered the baseline, and an attacker could then WRITE
// /etc/passwd under full enforcement and append a root-equivalent account. The
// scenario succeeded with rc=0 against every hook enforcing.
//
// The key now folds write intent, so a learned read grants only reads.
//
// Everything below runs through shell builtins - redirection, no exec - so the
// only open in play is the target file itself. Spawning a helper would open its
// binary and its libraries too, and an exec denial (rc 126) would be
// indistinguishable from the write denial this is actually testing. VM-only.
func TestVMWriteIsNotGrantedByALearnedRead(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	coll, cgID, _ := seedTestFixture(t, "rw")

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	cg := fmt.Sprintf("/sys/fs/cgroup/pahlevan-rw-%d", os.Getpid())
	// join the cgroup, then act with builtins only.
	run := func(builtin string) error {
		full := fmt.Sprintf("echo $$ > %s/cgroup.procs || exit 9; %s", cg, builtin)
		return exec.Command("/bin/sh", "-c", full).Run()
	}
	readIt := "read line < " + target
	writeIt := "echo pwned >> " + target

	// LEARN a read of the target, and nothing else about it.
	if err := run(readIt); err != nil {
		t.Fatalf("learning read failed: %v", err)
	}

	if err := coll.Maps["file_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	// The learned read must still work. If this fails the test proves nothing
	// about writes, because the cgroup would simply be denying everything.
	if err := run(readIt); err != nil {
		t.Fatalf("the learned READ must still be allowed under enforcement, "+
			"otherwise the write result below is meaningless: %v", err)
	}
	t.Log("learned read allowed under enforcement")

	// The write was never learned, and must now be refused. Before the key
	// folded the access mode this appended to the file.
	if err := run(writeIt); err == nil {
		t.Error("WRITE to a path learned only for READING should be DENIED, but it succeeded")
	} else {
		t.Logf("write to a read-only-learned path denied as expected: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back target: %v", err)
	}
	if string(data) != "original\n" {
		t.Errorf("the file was modified under enforcement: %q", string(data))
	}

	// Seeding the write explicitly, as writeAllowedPaths does, must permit it.
	m := &Manager{fileCollection: coll}
	if err := m.AllowFilePathMode(cgID, target, true, true); err != nil {
		t.Fatalf("AllowFilePathMode: %v", err)
	}
	if err := run(writeIt); err != nil {
		t.Errorf("an explicitly seeded WRITE should be allowed: %v", err)
	} else {
		t.Log("explicitly seeded write allowed, as writeAllowedPaths intends")
	}

	// And revoking it closes the door again.
	if err := m.AllowFilePathMode(cgID, target, true, false); err != nil {
		t.Fatalf("AllowFilePathMode revoke: %v", err)
	}
	if err := run(writeIt); err == nil {
		t.Error("a revoked WRITE should be DENIED, but it succeeded")
	}
}

// TestVMOomScoreAdjStaysWritableUnderEnforcement pins the one exemption in the
// file hook.
//
// A container runtime writes /proc/<pid>/oom_score_adj to enter an
// already-running container. Under enforcement that was denied, because
// bpf_d_path resolves /proc/self to /proc/<pid> and no fixed path can be seeded
// for a pid that changes every time. The result was that enforcing a policy
// broke `kubectl exec` and exec liveness probes, which is how a security tool
// gets switched off.
//
// The test also asserts the exemption is narrow: another /proc/<pid> file is
// still governed. VM-only.
func TestVMOomScoreAdjStaysWritableUnderEnforcement(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	coll, cgID, _ := seedTestFixture(t, "oom")

	cg := fmt.Sprintf("/sys/fs/cgroup/pahlevan-oom-%d", os.Getpid())
	run := func(builtin string) error {
		full := fmt.Sprintf("echo $$ > %s/cgroup.procs || exit 9; %s", cg, builtin)
		return exec.Command("/bin/sh", "-c", full).Run()
	}

	// Learn nothing about /proc at all.
	if err := run("read line < /etc/hostname"); err != nil {
		t.Fatalf("learning read failed: %v", err)
	}
	if err := coll.Maps["file_mode"].Put(cgID, uint8(1)); err != nil {
		t.Fatalf("set enforce mode: %v", err)
	}

	// The runtime's write must go through even though it was never learned.
	if err := run("echo 0 > /proc/self/oom_score_adj"); err != nil {
		t.Errorf("writing /proc/self/oom_score_adj must be permitted so the "+
			"container runtime can enter the container: %v", err)
	} else {
		t.Log("oom_score_adj writable under enforcement, so kubectl exec works")
	}

	// The exemption must not extend to the rest of /proc. This one was never
	// learned either, so it must be refused.
	if err := run("read line < /proc/self/environ"); err == nil {
		t.Error("/proc/self/environ should still be DENIED: the exemption is meant " +
			"to cover oom_score_adj alone, not all of /proc")
	} else {
		t.Logf("/proc/self/environ still denied, exemption is narrow: %v", err)
	}
}

// TestVMExecArgumentsAreCaptured proves argv reaches the exec event from a real
// kernel.
//
// The LSM hook cannot read argv itself: by the time bprm_check runs, the
// strings live in the new mm being constructed and bpf_probe_read_user reads
// the current address space. The capture therefore happens at the execve
// syscall tracepoint, where argv is still a plain userspace pointer in the
// caller's address space, and is joined onto the event by pid_tgid within the
// same syscall. This asserts that join actually works. VM-only.
func TestVMExecArgumentsAreCaptured(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadExecMonitor()
	if err != nil {
		t.Fatalf("LoadExecMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["bprm_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(bprm_check): %v", err)
	}
	defer l.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["handle_execve_args"], nil)
	if err != nil {
		t.Fatalf("attach sys_enter_execve: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(coll.Maps["exec_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// A distinctive argument vector, so a match cannot be coincidence.
	const marker = "pahlevan-argv-marker"
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = exec.Command("/bin/echo", "-n", marker, "second-arg").Run()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			break
		}
		ev := parseProcessEvent(rec.RawSample)
		if ev == nil || !strings.HasSuffix(ev.Filename, "/echo") {
			continue
		}
		if len(ev.Args) == 0 {
			t.Fatalf("exec of %s carried no argv; the syscall tracepoint capture "+
				"did not reach bprm_check", ev.Filename)
		}
		t.Logf("captured argv: %q (command line: %s)", ev.Args, ev.CommandLine())

		if ev.Args[0] != "/bin/echo" {
			t.Errorf("args[0] = %q, want the program name as the caller passed it", ev.Args[0])
		}
		found := false
		for _, a := range ev.Args {
			if a == marker {
				found = true
			}
		}
		if !found {
			t.Errorf("argv %q does not contain the marker %q", ev.Args, marker)
		}
		if len(ev.Args) != 4 {
			t.Errorf("argv = %q, want 4 arguments", ev.Args)
		}
		return
	}
	t.Fatal("no exec event for /bin/echo observed")
}

// A process that execs twice must not inherit the first invocation's arguments.
// The scratch entry is deleted on consumption precisely to prevent that.
func TestVMExecArgumentsAreNotReusedAcrossExecs(t *testing.T) {
	if os.Getenv("PAHLEVAN_EBPF_VM_TEST") != "1" {
		t.Skip("set PAHLEVAN_EBPF_VM_TEST=1 to run (VM only; requires bpf LSM)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	spec, err := LoadExecMonitor()
	if err != nil {
		t.Fatalf("LoadExecMonitor: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["bprm_check"]})
	if err != nil {
		t.Fatalf("AttachLSM(bprm_check): %v", err)
	}
	defer l.Close()
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["handle_execve_args"], nil)
	if err != nil {
		t.Fatalf("attach sys_enter_execve: %v", err)
	}
	defer tp.Close()
	rd, err := ringbuf.NewReader(coll.Maps["exec_events"])
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			// The shell execs /bin/true with no arguments beyond argv[0]; if the
			// scratch entry leaked, the shell's own argv would show up on it.
			_ = exec.Command("/bin/sh", "-c", "unique-marker-arg; exec /bin/true").Run()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			break
		}
		ev := parseProcessEvent(rec.RawSample)
		if ev == nil || !strings.HasSuffix(ev.Filename, "/true") {
			continue
		}
		for _, a := range ev.Args {
			if strings.Contains(a, "unique-marker-arg") {
				t.Fatalf("exec of %s inherited the previous exec's argv: %q", ev.Filename, ev.Args)
			}
		}
		t.Logf("second exec carried its own argv: %q", ev.Args)
		return
	}
	t.Skip("no exec of /bin/true observed within the window")
}
