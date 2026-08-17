package ebpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/link"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Flags on a ShellEvent, mirroring bpf/shell_monitor.c.
const (
	// ShellTruncated means the command was longer than the capture buffer and
	// only its beginning is present.
	ShellTruncated uint32 = 0x01
	// ShellEmpty means the user pressed return at an empty prompt.
	ShellEmpty uint32 = 0x02
)

// shellLineLen must equal LINE_LEN in bpf/shell_monitor.c.
const shellLineLen = 232

// ShellEvent is one command typed at an interactive shell prompt, captured by
// a uretprobe on readline before the shell parsed it.
//
// This is the one thing kernel instrumentation alone cannot see. `cd /root`,
// `export KUBECONFIG=...`, `history -c` and every other shell builtin change
// what a session is doing and produce no exec, no open and no connect. An
// exec-based monitor watches an attacker work through them and reports
// nothing but the shell's own process.
type ShellEvent struct {
	CgroupID    uint64
	Timestamp   uint64
	PID         uint32
	TID         uint32
	UID         uint32
	Flags       uint32
	Comm        string
	Line        string
	ContainerID string
}

// Truncated reports whether the command was longer than the capture buffer.
func (e *ShellEvent) Truncated() bool { return e.Flags&ShellTruncated != 0 }

// Summary renders the event the way an operator reads it.
func (e *ShellEvent) Summary() string {
	line := e.Line
	if e.Flags&ShellEmpty != 0 {
		line = "(empty prompt)"
	}
	if e.Truncated() {
		line += " …"
	}
	return fmt.Sprintf("%s[%d] uid=%d $ %s", e.Comm, e.PID, e.UID, line)
}

// ShellEventHandler receives interactive shell commands. Satisfied by type
// assertion; see CredEventHandler for why these are separate from
// EventHandler.
type ShellEventHandler interface {
	HandleShellEvent(event *ShellEvent) error
}

// parseShellEvent decodes `struct shell_event` from bpf/shell_monitor.c:
//
//	__u64 cgroup_id; __u64 timestamp_ns;
//	__u32 pid; __u32 tid; __u32 uid; __u32 flags;
//	__u8 comm[16]; __u8 line[232];
func parseShellEvent(data []byte) *ShellEvent {
	const commOff = 8 + 8 + 4*4 // 32
	const lineOff = commOff + 16
	const size = lineOff + shellLineLen
	if len(data) < size {
		return nil
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(data[off : off+4]) }

	e := &ShellEvent{
		CgroupID:  binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		PID:       u32(16),
		TID:       u32(20),
		UID:       u32(24),
		Flags:     u32(28),
	}
	comm := data[commOff:lineOff]
	if i := indexZero(comm); i >= 0 {
		comm = comm[:i]
	}
	e.Comm = string(comm)

	line := data[lineOff : lineOff+shellLineLen]
	if i := indexZero(line); i >= 0 {
		line = line[:i]
	}
	e.Line = strings.TrimRight(string(line), "\r\n")
	e.ContainerID = fmt.Sprintf("cgroup:%d", e.CgroupID)
	return e
}

// TraceShell attaches the readline uretprobe to a shell binary.
//
// The path is an executable on this host's filesystem. For a shell inside a
// container that means the path as seen through /proc/<pid>/root, which
// TraceShellForPID resolves; a uprobe is attached to an inode, so probing the
// container's own bash binary covers every process that execs it and nothing
// outside the container image.
//
// Attaching twice to the same path is a no-op rather than an error: several
// containers commonly share one image, and every process running that image's
// bash is already covered by the first probe.
//
// The symbol is readline, which bash exports because Debian and most other
// distributions build it against a statically linked readline. A shell built
// without readline - dash, busybox sh, or a bash configured for the minimal
// build - has no such symbol and returns an error naming it. That is a real
// limit and worth reporting rather than hiding: those shells have no line
// editor to hook, and their commands are only visible through the exec and
// syscall monitors.
func (m *Manager) TraceShell(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.traceShellLocked(path)
}

func (m *Manager) traceShellLocked(path string) error {
	if m.shellCollection == nil {
		return fmt.Errorf("the shell monitor is not loaded")
	}
	if _, done := m.shellLinks[path]; done {
		return nil
	}
	prog := m.shellCollection.Programs["handle_readline"]
	if prog == nil {
		return fmt.Errorf("the handle_readline program is absent from the loaded object")
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	l, err := ex.Uretprobe("readline", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching uretprobe on readline in %s: %w", path, err)
	}

	if m.shellLinks == nil {
		m.shellLinks = make(map[string]link.Link, 4)
	}
	m.shellLinks[path] = l

	// Enable only once something is attached. Until then the program cannot
	// run, and leaving the flag off means a half-configured monitor reports
	// nothing rather than reporting from an unexpected binary.
	if err := m.setShellEnabledLocked(true); err != nil {
		log.Log.V(0).Info("shell uprobe attached but could not be enabled", "error", err.Error())
	}
	return nil
}

// TraceShellForPID attaches to the shell a process is running, reached through
// that process's mount namespace.
//
// /proc/<pid>/exe resolves to the executable inside the container's own
// filesystem, so this works for a shell that does not exist on the host at all
// - which is the normal case, since the container image supplies it.
func (m *Manager) TraceShellForPID(pid uint32) error {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	// Resolve first, so the map key is the real binary and two processes
	// running the same shell are recognised as one attach.
	resolved, err := os.Readlink(exe)
	if err != nil {
		return fmt.Errorf("reading /proc/%d/exe: %w", pid, err)
	}
	// The link target is a path in the container's namespace, which this
	// process cannot open directly. /proc/<pid>/root is the way in - except
	// when the target was deleted, where the link carries a " (deleted)"
	// suffix and there is nothing left to probe.
	if strings.HasSuffix(resolved, " (deleted)") {
		return fmt.Errorf("the executable of pid %d has been deleted", pid)
	}
	path := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), resolved)

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.traceShellLocked(path)
}

// UntraceShell detaches the uretprobe from one binary. Detaching the last one
// disables the program, so a stray event cannot arrive from a probe nobody
// remembers attaching.
func (m *Manager) UntraceShell(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.shellLinks[path]
	if !ok {
		return nil
	}
	err := l.Close()
	delete(m.shellLinks, path)
	if len(m.shellLinks) == 0 {
		_ = m.setShellEnabledLocked(false)
	}
	return err
}

// TracedShells lists the binaries currently probed.
func (m *Manager) TracedShells() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.shellLinks))
	for p := range m.shellLinks {
		out = append(out, p)
	}
	return out
}

func (m *Manager) setShellEnabledLocked(on bool) error {
	if m.shellCollection == nil {
		return fmt.Errorf("the shell monitor is not loaded")
	}
	mp := m.shellCollection.Maps["shell_config"]
	if mp == nil {
		return fmt.Errorf("the shell_config map is absent from the loaded object")
	}
	var key uint32
	var val uint32
	if on {
		val = 1
	}
	return mp.Put(&key, &val)
}

// InteractiveShells are the process names worth probing when one is seen
// execing.
//
// Only shells that link readline are listed. dash and busybox have no line
// editor and no symbol to attach to, so listing them would produce an attach
// error for every container that starts one - noise describing a limitation
// that cannot be fixed by trying harder.
var InteractiveShells = map[string]bool{
	"bash": true,
	"zsh":  true,
	"ksh":  true,
	"fish": false, // fish has its own reader, not readline
}

// IsInteractiveShell reports whether a process name is a shell whose prompt
// can be probed.
func IsInteractiveShell(comm string) bool {
	return InteractiveShells[comm]
}
