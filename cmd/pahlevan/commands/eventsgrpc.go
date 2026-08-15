package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// buildSubscribeRequest turns the command's flags into a server-side filter.
//
// Filtering server-side rather than locally is the point of doing this over
// gRPC: on a busy node the observation stream dwarfs the denials, and shipping
// all of it across the network to discard it at the client would waste exactly
// the resource the API exists to conserve.
func buildSubscribeRequest(opts *eventsOptions) (*apiv1alpha1.SubscribeRequest, error) {
	req := &apiv1alpha1.SubscribeRequest{
		DenialsOnly: opts.denialsOnly,
	}
	for _, name := range opts.types {
		t, err := export.ParseEventType(strings.TrimSpace(name))
		if err != nil {
			return nil, err
		}
		pt := eventTypeToProto(t)
		if pt == apiv1alpha1.EventType_EVENT_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("event type %q has no wire representation", name)
		}
		req.Types = append(req.Types, pt)
	}
	// --pod accepts "namespace/name" as well as a bare name, matching how the
	// file-backed path already reads it.
	if opts.pod != "" {
		if ns, name, ok := strings.Cut(opts.pod, "/"); ok {
			req.Namespace, req.Pod = ns, name
		} else {
			req.Pod = opts.pod
		}
	}
	return req, nil
}

// eventTypeToProto maps an export type name onto the wire enum. Kept here
// rather than imported from pkg/grpcapi so the CLI does not pull in the server.
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

// runEventsGRPC subscribes to an agent's event stream and prints what arrives.
func runEventsGRPC(ctx context.Context, opts *eventsOptions, out io.Writer) error {
	req, err := buildSubscribeRequest(opts)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(opts.grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to the agent at %s: %w", opts.grpcAddr, err)
	}
	defer func() { _ = conn.Close() }()

	client := apiv1alpha1.NewEventServiceClient(conn)

	// The stream context is the caller's: a subscription is meant to stay open
	// indefinitely, so it must not carry a dial deadline. A bad address surfaces
	// on the first Recv with the connection error attached.
	stream, err := client.Subscribe(ctx, req)
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", opts.grpcAddr, err)
	}

	enc := json.NewEncoder(out)
	seen := 0
	for {
		ev, err := stream.Recv()
		if err != nil {
			// A cancelled context is the user pressing Ctrl-C, not a failure.
			if ctx.Err() != nil {
				return nil
			}
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("receiving from %s after %d events: %w", opts.grpcAddr, seen, err)
		}
		if err := enc.Encode(protoEventToJSON(ev)); err != nil {
			return err
		}
		seen++
		if opts.tail > 0 && seen >= opts.tail {
			return nil
		}
	}
}

// protoEventToJSON renders a wire event in the same shape as the JSON-lines
// sink, so `--grpc` and `--file` print the same thing and a pipeline can move
// between them without rewriting its parsers.
func protoEventToJSON(ev *apiv1alpha1.Event) map[string]interface{} {
	if ev == nil {
		return nil
	}
	out := map[string]interface{}{
		"version":   ev.GetVersion(),
		"timestamp": ev.GetTimestamp(),
		"type":      protoTypeName(ev.GetType()),
		"action":    protoActionName(ev.GetAction()),
		"cgroupId":  ev.GetCgroupId(),
	}
	if p := ev.GetProcess(); p != nil {
		proc := map[string]interface{}{
			"pid": p.GetPid(), "tgid": p.GetTgid(),
			"uid": p.GetUid(), "gid": p.GetGid(), "comm": p.GetComm(),
		}
		if p.GetPpid() != 0 {
			proc["ppid"] = p.GetPpid()
			proc["parentComm"] = p.GetParentComm()
		}
		out["process"] = proc
	}
	if k := ev.GetKubernetes(); k != nil {
		kube := map[string]interface{}{}
		addIfSet(kube, "namespace", k.GetNamespace())
		addIfSet(kube, "pod", k.GetPod())
		addIfSet(kube, "container", k.GetContainer())
		addIfSet(kube, "node", k.GetNode())
		addIfSet(kube, "image", k.GetImage())
		addIfSet(kube, "workloadKind", k.GetWorkloadKind())
		addIfSet(kube, "workloadName", k.GetWorkloadName())
		if len(k.GetLabels()) > 0 {
			kube["labels"] = k.GetLabels()
		}
		if len(kube) > 0 {
			out["kubernetes"] = kube
		}
	}

	switch d := ev.GetDetail().(type) {
	case *apiv1alpha1.Event_Syscall:
		out["syscall"] = map[string]interface{}{
			"number": d.Syscall.GetNumber(), "name": d.Syscall.GetName(),
		}
	case *apiv1alpha1.Event_File:
		out["file"] = map[string]interface{}{
			"path": d.File.GetPath(), "flags": d.File.GetFlags(), "write": d.File.GetWrite(),
		}
	case *apiv1alpha1.Event_Network:
		out["network"] = map[string]interface{}{
			"destinationIp":   d.Network.GetDestinationIp(),
			"destinationPort": d.Network.GetDestinationPort(),
			"protocol":        d.Network.GetProtocol(),
		}
	case *apiv1alpha1.Event_Exec:
		exec := map[string]interface{}{"binary": d.Exec.GetBinary()}
		if cwd := d.Exec.GetCwd(); cwd != "" {
			exec["cwd"] = cwd
		}
		if d.Exec.GetExited() {
			exec["exited"] = true
		}
		if args := d.Exec.GetArgs(); len(args) > 0 {
			exec["args"] = args
			exec["commandLine"] = d.Exec.GetCommandLine()
		}
		if d.Exec.GetArgsTruncated() {
			exec["argsTruncated"] = true
		}
		if chain := d.Exec.GetAncestryChain(); chain != "" {
			exec["ancestryChain"] = chain
		}
		out["exec"] = exec
	case *apiv1alpha1.Event_Capability:
		out["capability"] = map[string]interface{}{
			"number": d.Capability.GetNumber(), "name": d.Capability.GetName(),
		}
	}
	return out
}

func addIfSet(m map[string]interface{}, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func protoTypeName(t apiv1alpha1.EventType) string {
	switch t {
	case apiv1alpha1.EventType_EVENT_TYPE_SYSCALL:
		return string(export.EventTypeSyscall)
	case apiv1alpha1.EventType_EVENT_TYPE_FILE:
		return string(export.EventTypeFile)
	case apiv1alpha1.EventType_EVENT_TYPE_NETWORK:
		return string(export.EventTypeNetwork)
	case apiv1alpha1.EventType_EVENT_TYPE_PROCESS:
		return string(export.EventTypeProcess)
	case apiv1alpha1.EventType_EVENT_TYPE_CAPABILITY:
		return string(export.EventTypeCapability)
	default:
		return "unknown"
	}
}

func protoActionName(a apiv1alpha1.Action) string {
	switch a {
	case apiv1alpha1.Action_ACTION_DENY:
		return string(export.ActionDeny)
	case apiv1alpha1.Action_ACTION_OBSERVE:
		return string(export.ActionObserve)
	default:
		return "unknown"
	}
}
