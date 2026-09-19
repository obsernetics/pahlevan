package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
	"github.com/obsernetics/pahlevan/pkg/tui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcSource subscribes to an agent's event stream and converts the wire
// events into the exported envelope the rest of the tool uses, so the view
// renders the same shape whether it came from a socket or a replay file.
type grpcSource struct{ addr string }

func (s *grpcSource) Describe() string { return s.addr }

func (s *grpcSource) Run(ctx context.Context, out chan<- export.Event) error {
	conn, err := grpc.NewClient(s.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to the agent at %s: %w", s.addr, err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := apiv1alpha1.NewEventServiceClient(conn).
		Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", s.addr, err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			// Cancellation and a clean close are how a session normally ends,
			// not failures to report.
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receiving from %s: %w", s.addr, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case out <- protoEventToExport(ev):
		}
	}
}

// protoEventToExport converts a wire event into the envelope. It mirrors
// protoEventToJSON, which produces the same fields as a map for the JSON
// printer; both exist because one feeds a renderer and the other a marshaller.
func protoEventToExport(ev *apiv1alpha1.Event) export.Event {
	if ev == nil {
		return export.Event{}
	}
	e := export.Event{
		Version:  ev.GetVersion(),
		Type:     export.EventType(strings.ToLower(protoTypeName(ev.GetType()))),
		Action:   export.Action(strings.ToLower(protoActionName(ev.GetAction()))),
		CgroupID: ev.GetCgroupId(),
	}
	// The wire carries an RFC3339 string. A stamp that will not parse is not
	// worth failing an event over - the rest of it is still true - so it falls
	// back to now and the line still renders in order.
	if t, err := time.Parse(time.RFC3339Nano, ev.GetTimestamp()); err == nil {
		e.Timestamp = export.Timestamp(t)
	} else {
		e.Timestamp = export.Timestamp(time.Now())
	}

	if p := ev.GetProcess(); p != nil {
		e.Process = export.ProcessInfo{
			PID: p.GetPid(), TGID: p.GetTgid(), UID: p.GetUid(), GID: p.GetGid(),
			Comm: p.GetComm(), PPID: p.GetPpid(), ParentComm: p.GetParentComm(),
		}
	}
	if k := ev.GetKubernetes(); k != nil {
		e.Kubernetes = &export.KubernetesRef{
			Namespace: k.GetNamespace(), Pod: k.GetPod(), Container: k.GetContainer(),
			Node: k.GetNode(), WorkloadKind: k.GetWorkloadKind(), WorkloadName: k.GetWorkloadName(),
		}
	}

	switch d := ev.GetDetail().(type) {
	case *apiv1alpha1.Event_Syscall:
		e.Syscall = &export.SyscallInfo{Number: d.Syscall.GetNumber(), Name: d.Syscall.GetName()}
	case *apiv1alpha1.Event_File:
		f := &export.FileInfo{Path: d.File.GetPath(), Flags: d.File.GetFlags()}
		// Read and write are separate allow-set entries in the kernel, so the
		// view says which one it was rather than calling everything "open".
		if d.File.GetWrite() {
			f.SyscallName = "write"
		} else {
			f.SyscallName = "read"
		}
		e.File = f
	case *apiv1alpha1.Event_Network:
		e.Network = &export.NetworkInfo{
			DestinationIP:   d.Network.GetDestinationIp(),
			DestinationPort: uint16(d.Network.GetDestinationPort()),
			Protocol:        d.Network.GetProtocol(),
			Direction:       d.Network.GetDirection(),
		}
		// A named destination is what an operator recognises; the address is
		// the fallback when nothing in the cluster claims it.
		if n := d.Network.GetDestinationName(); n != "" {
			e.Network.DestinationIP = n
		}
	case *apiv1alpha1.Event_Exec:
		e.Exec = &export.ExecInfo{
			Binary:        d.Exec.GetBinary(),
			AncestryChain: d.Exec.GetAncestryChain(),
		}
	case *apiv1alpha1.Event_Capability:
		e.Capability = &export.CapabilityInfo{
			Number: d.Capability.GetNumber(), Name: d.Capability.GetName(),
		}
	}
	return e
}

// runPlain is the non-terminal path: consume the stream and print a summary.
//
// It is not a degraded drawing of the UI, it is a different, useful thing. A
// pipeline wants a stable, greppable block; redrawing a screen into a file
// produces neither.
func runPlain(ctx context.Context, src tui.Source, out io.Writer) error {
	ch := make(chan export.Event, 256)
	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, ch); close(ch) }()

	type agg struct {
		files, network, execs, caps, syscalls, denials int
	}
	byWorkload := map[string]*agg{}
	var total, denied int

	for e := range ch {
		total++
		if e.Denied() {
			denied++
		}
		k := workloadKeyFor(e)
		a := byWorkload[k]
		if a == nil {
			a = &agg{}
			byWorkload[k] = a
		}
		switch e.Type {
		case export.EventTypeFile:
			a.files++
		case export.EventTypeNetwork:
			a.network++
		case export.EventTypeProcess:
			a.execs++
		case export.EventTypeCapability:
			a.caps++
		case export.EventTypeSyscall:
			a.syscalls++
		}
		if e.Denied() {
			a.denials++
		}
	}
	if err := <-errCh; err != nil {
		return err
	}

	// Malformed records have to reach the summary. A capture that decoded to
	// nothing prints "0 events", which reads exactly like a quiet node - the
	// wrong conclusion to hand somebody looking for an incident. Tolerating a
	// bad record is right; hiding that it happened is not.
	var malformed int
	if r, ok := src.(interface{ Malformed() int }); ok {
		malformed = r.Malformed()
	}
	if total == 0 && malformed > 0 {
		return fmt.Errorf("%s: no events decoded from %d malformed records; this is not a quiet node, it is an unreadable capture",
			src.Describe(), malformed)
	}

	keys := make([]string, 0, len(byWorkload))
	for k := range byWorkload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintf(out, "source\t%s\n", src.Describe())
	fmt.Fprintf(out, "events\t%d\ndenied\t%d\nworkloads\t%d\n", total, denied, len(keys))
	if malformed > 0 {
		fmt.Fprintf(out, "malformed\t%d\n", malformed)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%-44s %7s %7s %6s %6s %8s %8s\n",
		"WORKLOAD", "FILE", "NET", "EXEC", "CAP", "SYSCALL", "DENIED")
	for _, k := range keys {
		a := byWorkload[k]
		fmt.Fprintf(out, "%-44s %7d %7d %6d %6d %8d %8d\n",
			k, a.files, a.network, a.execs, a.caps, a.syscalls, a.denials)
	}
	return nil
}

// workloadKeyFor mirrors the model's grouping so the plain output and the
// interactive view name the same things the same way.
func workloadKeyFor(e export.Event) string {
	k := e.Kubernetes
	if k == nil {
		return fmt.Sprintf("cgroup:%d", e.CgroupID)
	}
	switch {
	case k.WorkloadKind != "" && k.WorkloadName != "":
		return k.Namespace + "/" + k.WorkloadKind + "/" + k.WorkloadName
	case k.Pod != "":
		return k.Namespace + "/Pod/" + k.Pod
	default:
		return fmt.Sprintf("cgroup:%d", e.CgroupID)
	}
}
