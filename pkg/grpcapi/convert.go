package grpcapi

import (
	"time"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// ToProto converts the exported JSON envelope into the wire message.
//
// The two representations are deliberately the same shape. A gRPC event and a
// JSON-lines event describing the same denial must agree in every field an
// operator might act on; two encodings that drift are worse than one, because
// a discrepancy is discovered during an incident.
func ToProto(e *export.Event) *apiv1alpha1.Event {
	if e == nil {
		return nil
	}
	out := &apiv1alpha1.Event{
		Version:      e.Version,
		Type:         eventTypeToProto(e.Type),
		Action:       actionToProto(e.Action),
		Timestamp:    e.Timestamp.Time().UTC().Format(time.RFC3339Nano),
		KernelTimeNs: e.KernelTimeNs,
		CgroupId:     e.CgroupID,
		Process: &apiv1alpha1.ProcessInfo{
			Pid:  e.Process.PID,
			Tgid: e.Process.TGID,
			Uid:  e.Process.UID,
			Gid:  e.Process.GID,
			Comm: e.Process.Comm,
		},
	}

	if k := e.Kubernetes; k != nil {
		out.Kubernetes = &apiv1alpha1.KubernetesRef{
			Namespace:    k.Namespace,
			Pod:          k.Pod,
			Container:    k.Container,
			PodUid:       k.PodUID,
			ContainerId:  k.ContainerID,
			Runtime:      k.Runtime,
			QosClass:     k.QoSClass,
			Node:         k.Node,
			WorkloadKind: k.WorkloadKind,
			WorkloadName: k.WorkloadName,
			Image:        k.Image,
		}
		if len(k.Labels) > 0 {
			// Copied: the caller's map belongs to the pod cache, which is
			// replaced wholesale on every refresh.
			out.Kubernetes.Labels = make(map[string]string, len(k.Labels))
			for key, v := range k.Labels {
				out.Kubernetes.Labels[key] = v
			}
		}
	}

	switch {
	case e.Syscall != nil:
		out.Detail = &apiv1alpha1.Event_Syscall{Syscall: &apiv1alpha1.SyscallInfo{
			Number: e.Syscall.Number,
			Name:   e.Syscall.Name,
		}}
	case e.File != nil:
		out.Detail = &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{
			Path:  e.File.Path,
			Flags: e.File.Flags,
			Mode:  uint32(e.File.Mode),
			// Write intent is part of the allow-set identity, so it is a
			// first-class field rather than something a client has to
			// rediscover by masking Flags.
			Write: e.File.Flags&writeFlag != 0,
		}}
	case e.Network != nil:
		out.Detail = &apiv1alpha1.Event_Network{Network: &apiv1alpha1.NetworkInfo{
			DestinationIp:   e.Network.DestinationIP,
			DestinationPort: uint32(e.Network.DestinationPort),
			Protocol:        e.Network.Protocol,
			ProtocolNumber:  uint32(e.Network.ProtocolNumber),
			Direction:       e.Network.Direction,
		}}
	case e.Exec != nil:
		exec := &apiv1alpha1.ExecInfo{
			Binary:        e.Exec.Binary,
			CommandLine:   e.Exec.CommandLine,
			ArgsTruncated: e.Exec.ArgsTruncated,
			AncestryChain: e.Exec.AncestryChain,
		}
		if len(e.Exec.Args) > 0 {
			exec.Args = append([]string(nil), e.Exec.Args...)
		}
		for _, a := range e.Exec.Ancestry {
			exec.Ancestry = append(exec.Ancestry, &apiv1alpha1.Ancestor{
				Pid: a.PID, Comm: a.Comm,
			})
		}
		out.Detail = &apiv1alpha1.Event_Exec{Exec: exec}
	case e.Capability != nil:
		out.Detail = &apiv1alpha1.Event_Capability{Capability: &apiv1alpha1.CapabilityInfo{
			Number: e.Capability.Number,
			Name:   e.Capability.Name,
		}}
	}

	return out
}

// writeFlag mirrors ebpf.WriteFlag. It is duplicated rather than imported so
// this package builds on every platform; the value is asserted against the
// source of truth in the tests.
const writeFlag uint32 = 0x40000000

func eventTypeToProto(t export.EventType) apiv1alpha1.EventType {
	switch t {
	case export.EventTypeSyscall:
		return apiv1alpha1.EventType_EVENT_TYPE_SYSCALL
	case export.EventTypeFile:
		return apiv1alpha1.EventType_EVENT_TYPE_FILE
	case export.EventTypeNetwork:
		return apiv1alpha1.EventType_EVENT_TYPE_NETWORK
	case export.EventTypeProcess:
		return apiv1alpha1.EventType_EVENT_TYPE_PROCESS
	case export.EventTypeCapability:
		return apiv1alpha1.EventType_EVENT_TYPE_CAPABILITY
	default:
		return apiv1alpha1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}

// EventTypeFromProto is the inverse, for turning a client's filter back into
// the names the rest of the codebase uses.
func EventTypeFromProto(t apiv1alpha1.EventType) (export.EventType, bool) {
	switch t {
	case apiv1alpha1.EventType_EVENT_TYPE_SYSCALL:
		return export.EventTypeSyscall, true
	case apiv1alpha1.EventType_EVENT_TYPE_FILE:
		return export.EventTypeFile, true
	case apiv1alpha1.EventType_EVENT_TYPE_NETWORK:
		return export.EventTypeNetwork, true
	case apiv1alpha1.EventType_EVENT_TYPE_PROCESS:
		return export.EventTypeProcess, true
	case apiv1alpha1.EventType_EVENT_TYPE_CAPABILITY:
		return export.EventTypeCapability, true
	default:
		return "", false
	}
}

// EventTypeToProto maps a name from the CLI or config onto the wire enum.
func EventTypeToProto(t export.EventType) apiv1alpha1.EventType { return eventTypeToProto(t) }

func actionToProto(a export.Action) apiv1alpha1.Action {
	switch a {
	case export.ActionDeny:
		return apiv1alpha1.Action_ACTION_DENY
	case export.ActionObserve:
		return apiv1alpha1.Action_ACTION_OBSERVE
	default:
		return apiv1alpha1.Action_ACTION_UNSPECIFIED
	}
}
