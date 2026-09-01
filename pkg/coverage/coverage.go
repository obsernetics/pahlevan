// Package coverage maps Pahlevan's seven eBPF programs to the MITRE ATT&CK
// techniques their observations can help an analyst confirm or rule out.
//
// Nothing else in the codebase answers "what does this cover" short of
// reading bpf/*.c one file at a time. This is Pahlevan's own reading of what
// each program's data is useful for, not an official MITRE mapping and not a
// claim that a listed technique is blocked: a detector marked against a
// technique means its allow-set decisions and event fields give an analyst
// evidence for that technique, nothing stronger. See https://attack.mitre.org
// for the authoritative technique definitions, and ROADMAP.md for the gap
// this package exists to close.
package coverage

import "sort"

// Detector names one of Pahlevan's seven eBPF programs, matching the names
// used in bpf/*.c and pkg/ebpf.
type Detector string

const (
	DetectorFile       Detector = "file"
	DetectorNetwork    Detector = "network"
	DetectorExec       Detector = "exec"
	DetectorCapability Detector = "capability"
	DetectorSyscall    Detector = "syscall"
	DetectorCred       Detector = "cred"
	DetectorShell      Detector = "shell"
)

// Technique is one MITRE ATT&CK technique or sub-technique.
type Technique struct {
	// ID is the ATT&CK identifier, e.g. "T1059.004".
	ID string
	// Name is the technique's ATT&CK name, e.g.
	// "Command and Scripting Interpreter: Unix Shell".
	Name string
}

// Entry describes one detector: the kernel hook it attaches to, whether that
// hook requires the BPF LSM (lsm=bpf on the kernel command line), what it
// observes, and the ATT&CK techniques that observation is useful evidence
// for.
type Entry struct {
	Detector   Detector
	Hook       string
	NeedsLSM   bool
	Observes   string
	Techniques []Technique
}

// Table is the full detector-to-technique mapping, one entry per eBPF
// program. Order matches bpf/*.c's rough dependency order (file, network,
// exec, capability, syscall, cred, shell).
var Table = []Entry{
	{
		Detector: DetectorFile,
		Hook:     "lsm/file_open",
		NeedsLSM: true,
		Observes: "Per-path file opens, split into read and write allow-set " +
			"entries so a learned read never grants a write.",
		Techniques: []Technique{
			{ID: "T1005", Name: "Data from Local System"},
			{ID: "T1565.001", Name: "Data Manipulation: Stored Data Manipulation"},
		},
	},
	{
		Detector: DetectorNetwork,
		Hook:     "lsm/socket_connect",
		NeedsLSM: true,
		Observes: "Per-destination egress connects (IPv4 and IPv6, protocol " +
			"mixed into the allow-set key), named against Services, pods and " +
			"nodes when the destination is in-cluster.",
		Techniques: []Technique{
			{ID: "T1071", Name: "Application Layer Protocol"},
			{ID: "T1041", Name: "Exfiltration Over C2 Channel"},
		},
	},
	{
		Detector: DetectorExec,
		Hook:     "lsm/bprm_check_security",
		NeedsLSM: true,
		Observes: "Every exec: binary, argv, working directory and four " +
			"levels of ancestry, plus container-breakout detection by " +
			"comparing the working directory's mount namespace with the " +
			"task's.",
		Techniques: []Technique{
			{ID: "T1059", Name: "Command and Scripting Interpreter"},
			{ID: "T1611", Name: "Escape to Host"},
		},
	},
	{
		Detector: DetectorCapability,
		Hook:     "lsm/capable",
		NeedsLSM: true,
		Observes: "Every capability check, plus the task's effective, " +
			"permitted and inheritable sets at the time of the check - what " +
			"the process could have done, not only what it asked to do.",
		Techniques: []Technique{
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism"},
		},
	},
	{
		Detector: DetectorSyscall,
		Hook:     "tracepoint/raw_syscalls/sys_enter",
		NeedsLSM: false,
		Observes: "Every syscall with a per-(cgroup,syscall) allow-set, " +
			"decoded arguments for the syscalls Pahlevan interprets, and a " +
			"watch set of escalation primitives reported on every " +
			"occurrence rather than deduplicated.",
		Techniques: []Technique{
			{ID: "T1106", Name: "Native API"},
		},
	},
	{
		Detector: DetectorCred,
		Hook:     "kprobe/commit_creds",
		NeedsLSM: false,
		Observes: "Every credential change, discriminated by whether an " +
			"execve was underway: a setuid binary explains a change inside " +
			"execve, so a change with none in progress is the interesting " +
			"case.",
		Techniques: []Technique{
			{ID: "T1068", Name: "Exploitation for Privilege Escalation"},
		},
	},
	{
		Detector: DetectorShell,
		Hook:     "uretprobe/readline",
		NeedsLSM: false,
		Observes: "One command per interactive shell prompt, captured before " +
			"the shell parses it - the builtins (cd, export, history -c) " +
			"that produce no exec, no open and no connect.",
		Techniques: []Technique{
			{ID: "T1059.004", Name: "Command and Scripting Interpreter: Unix Shell"},
		},
	},
}

// Techniques returns the deduplicated ATT&CK techniques covered across every
// detector in Table, sorted by ID.
func Techniques() []Technique {
	seen := make(map[string]Technique)
	for _, e := range Table {
		for _, t := range e.Techniques {
			seen[t.ID] = t
		}
	}
	out := make([]Technique, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ForTechnique returns the detectors whose Table entry lists the given
// ATT&CK technique ID, in Table order. An unknown ID returns an empty slice.
func ForTechnique(id string) []Detector {
	var out []Detector
	for _, e := range Table {
		for _, t := range e.Techniques {
			if t.ID == id {
				out = append(out, e.Detector)
				break
			}
		}
	}
	return out
}
