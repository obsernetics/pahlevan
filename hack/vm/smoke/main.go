// smoke - loads and attaches the CO-RE eBPF smoke test inside the VM.
//
// It proves the VM can do what the host must never do:
//   * load a compiled CO-RE object,
//   * attach an ordinary tracepoint,
//   * attach a BPF-LSM program (only possible when the bpf LSM is active),
//   * observe both programs actually running.
//
// Exit code 0 only if BOTH the tracepoint and the LSM hook loaded, attached,
// and fired. Any failure prints the error and exits non-zero.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const objPath = "smoke.bpf.o"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "SMOKE TEST FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SMOKE TEST PASSED")
}

func run() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec %q: %w", objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("new collection (verifier):\n%+v", ve)
		}
		return fmt.Errorf("new collection: %w", err)
	}
	defer coll.Close()

	tpProg := coll.Programs["handle_execve"]
	lsmProg := coll.Programs["lsm_file_open"]
	if tpProg == nil || lsmProg == nil {
		return fmt.Errorf("expected programs not found in object (got %v)", programNames(coll))
	}

	// 1. Attach the ordinary tracepoint.
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", tpProg, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()
	fmt.Println("[ok] tracepoint sys_enter_execve attached")

	// 2. Attach the BPF-LSM program. This is the decisive step: it only works
	//    when the running kernel has the bpf LSM enabled (lsm=...,bpf).
	lsm, err := link.AttachLSM(link.LSMOptions{Program: lsmProg})
	if err != nil {
		return fmt.Errorf("attach LSM program (is the bpf LSM enabled? check /sys/kernel/security/lsm): %w", err)
	}
	defer lsm.Close()
	fmt.Println("[ok] LSM hook lsm/file_open attached")

	// 3. Generate activity: an execve (fires the tracepoint) which also opens
	//    files (fires the LSM hook).
	for i := 0; i < 3; i++ {
		_ = exec.Command("/bin/true").Run()
	}
	time.Sleep(200 * time.Millisecond)

	// 4. Read the counters back.
	counters := coll.Maps["counters"]
	if counters == nil {
		return errors.New("counters map not found")
	}
	var execveCount, lsmCount uint64
	if err := counters.Lookup(uint32(0), &execveCount); err != nil {
		return fmt.Errorf("read execve counter: %w", err)
	}
	if err := counters.Lookup(uint32(1), &lsmCount); err != nil {
		return fmt.Errorf("read lsm counter: %w", err)
	}

	fmt.Printf("[ok] tracepoint fired %d time(s)\n", execveCount)
	fmt.Printf("[ok] LSM file_open hook fired %d time(s)\n", lsmCount)

	if execveCount == 0 {
		return errors.New("tracepoint never fired")
	}
	if lsmCount == 0 {
		return errors.New("LSM hook never fired (BPF-LSM not effective)")
	}
	return nil
}

func programNames(coll *ebpf.Collection) []string {
	var names []string
	for n := range coll.Programs {
		names = append(names, n)
	}
	return names
}
