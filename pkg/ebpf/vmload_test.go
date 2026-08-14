package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

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
// allow-list enforcement — no hand-written rules, and real prevention (not
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
	// Give the ring buffer time isn't needed — the allow-set is updated in-kernel
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
