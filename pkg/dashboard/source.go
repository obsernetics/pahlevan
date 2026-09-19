package dashboard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// Where the live half of the dashboard comes from.
//
// The CRDs say what was learned and how many things were denied. They cannot
// say which process was denied, what it was trying to open, or what spawned
// it, because none of that is in a status block - it is in the event stream
// the agents already serve over gRPC. An AgentSource subscribes to that stream
// as any other client would and folds it into a Store.
//
// This is strictly optional. A dashboard with no sources renders every CRD
// view and says so where a live view would be, rather than drawing zeroes.

// reconnectBackoff bounds how fast a source retries.
//
// An agent pod restarting during a rollout should be picked up again in
// seconds, but a source pointed at an address that will never answer must not
// spin: a tight reconnect loop against a dead endpoint is a self-inflicted
// denial of service on the API of whatever does answer that address.
const (
	reconnectInitial = time.Second
	reconnectMax     = 30 * time.Second
)

// AgentSource subscribes to one agent's event stream.
type AgentSource struct {
	// Endpoint is host:port of the agent's gRPC listener.
	Endpoint string
	// Token is the bearer token the agent requires, if it was started with
	// one. It is refused without TLS, because a token on an unencrypted
	// connection is a token you have published.
	Token string
	// CAFile verifies the agent's certificate. Empty uses the system roots.
	CAFile string
	// ServerName overrides the name verified in the agent's certificate, for
	// the case where the dashboard dials a pod IP rather than a Service name.
	ServerName string
	// Insecure dials plaintext. As everywhere else in this project it has to
	// be set on purpose.
	Insecure bool

	Log logr.Logger
}

// Validate rejects a source that would not do what it appears to.
func (a *AgentSource) Validate() error {
	if strings.TrimSpace(a.Endpoint) == "" {
		return errors.New("an agent source needs an endpoint, for example pahlevan-agent.pahlevan-system:9090")
	}
	if a.Token != "" && a.Insecure {
		return fmt.Errorf(
			"the agent token for %s would be sent in cleartext on a plaintext connection, which "+
				"publishes it; configure --agent-ca and drop --agent-insecure", a.Endpoint)
	}
	return nil
}

// dialOptions renders the source's transport security.
func (a *AgentSource) dialOptions() ([]grpc.DialOption, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	var opts []grpc.DialOption
	if a.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: a.ServerName}
		if a.CAFile != "" {
			pem, err := os.ReadFile(a.CAFile) // #nosec G304 -- the operator named this file
			if err != nil {
				return nil, fmt.Errorf("reading the agent CA %q: %w", a.CAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("the agent CA %q contains no certificates", a.CAFile)
			}
			cfg.RootCAs = pool
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	}
	if a.Token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearerCredentials(a.Token)))
	}
	return opts, nil
}

// bearerCredentials sends the agent's token on every call.
type bearerCredentials string

func (b bearerCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}

// RequireTransportSecurity is true and not configurable: gRPC refusing to
// attach the token to a plaintext connection is the last line of defence
// behind Validate, for the case where a source is built in code rather than
// from flags.
func (b bearerCredentials) RequireTransportSecurity() bool { return true }

// Run subscribes until ctx is cancelled, reconnecting on failure.
//
// It returns nil on cancellation. A dashboard whose agent connection dropped
// is still a useful dashboard - every CRD view keeps working - so a broken
// stream is logged and retried rather than taking the process down.
func (a *AgentSource) Run(ctx context.Context, store *Store) error {
	opts, err := a.dialOptions()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(a.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("preparing a connection to the agent at %s: %w", a.Endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	client := apiv1alpha1.NewEventServiceClient(conn)
	backoff := reconnectInitial
	for {
		if err := a.stream(ctx, client, store); err != nil {
			a.Log.Error(err, "agent event stream ended", "endpoint", a.Endpoint)
		}
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

func (a *AgentSource) stream(ctx context.Context, client apiv1alpha1.EventServiceClient, store *Store) error {
	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("subscribing to the agent at %s: %w", a.Endpoint, err)
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			// Cancellation and a clean close are how a session normally ends,
			// not failures to report.
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receiving from the agent at %s: %w", a.Endpoint, err)
		}
		event := EventFromProto(msg)
		store.Add(&event)
	}
}

// EventFromProto converts a wire event into the exported envelope.
//
// The forward direction lives in pkg/grpcapi as ToProto; there is no shared
// inverse, so this is the second hand-written one in the tree after the CLI's.
// It carries the fields this dashboard actually renders - the denial verdict,
// the subject of the denial, and the ancestry behind it - rather than being a
// complete mirror, and the tests assert a round trip for exactly those.
func EventFromProto(ev *apiv1alpha1.Event) export.Event {
	if ev == nil {
		return export.Event{}
	}
	e := export.Event{
		Version:      ev.GetVersion(),
		Type:         eventTypeFromProto(ev.GetType()),
		Action:       actionFromProto(ev.GetAction()),
		CgroupID:     ev.GetCgroupId(),
		KernelTimeNs: ev.GetKernelTimeNs(),
	}
	// A stamp that will not parse is not worth discarding the event over - the
	// rest of it is still true - so it falls back to now and the denial still
	// appears in the list, in order.
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
			PodUID: k.GetPodUid(), ContainerID: k.GetContainerId(), Node: k.GetNode(),
			WorkloadKind: k.GetWorkloadKind(), WorkloadName: k.GetWorkloadName(),
			Image: k.GetImage(),
		}
	}

	switch d := ev.GetDetail().(type) {
	case *apiv1alpha1.Event_Syscall:
		e.Syscall = &export.SyscallInfo{Number: d.Syscall.GetNumber(), Name: d.Syscall.GetName()}
	case *apiv1alpha1.Event_File:
		f := &export.FileInfo{Path: d.File.GetPath(), Flags: d.File.GetFlags()}
		// Read and write are separate allow-set entries in the kernel, so the
		// denial reason says which one was refused rather than calling
		// everything "open".
		if d.File.GetWrite() {
			f.SyscallName = "write"
		} else {
			f.SyscallName = "read"
		}
		e.File = f
	case *apiv1alpha1.Event_Network:
		e.Network = &export.NetworkInfo{
			DestinationIP:       d.Network.GetDestinationIp(),
			DestinationPort:     uint16(d.Network.GetDestinationPort()),
			Protocol:            d.Network.GetProtocol(),
			Direction:           d.Network.GetDirection(),
			DestinationName:     d.Network.GetDestinationName(),
			DestinationKind:     d.Network.GetDestinationKind(),
			DestinationPortName: d.Network.GetDestinationPortName(),
		}
	case *apiv1alpha1.Event_Exec:
		exec := &export.ExecInfo{
			Binary:        d.Exec.GetBinary(),
			AncestryChain: d.Exec.GetAncestryChain(),
			CommandLine:   d.Exec.GetCommandLine(),
			Cwd:           d.Exec.GetCwd(),
			Exited:        d.Exec.GetExited(),
		}
		for _, a := range d.Exec.GetAncestry() {
			exec.Ancestry = append(exec.Ancestry, export.AncestorInfo{PID: a.GetPid(), Comm: a.GetComm()})
		}
		e.Exec = exec
	case *apiv1alpha1.Event_Capability:
		e.Capability = &export.CapabilityInfo{
			Number: d.Capability.GetNumber(), Name: d.Capability.GetName(),
		}
	}
	return e
}

func eventTypeFromProto(t apiv1alpha1.EventType) export.EventType {
	if known, ok := grpcEventType(t); ok {
		return known
	}
	return ""
}

// grpcEventType is split out so the mapping is one switch rather than two
// slightly different ones.
func grpcEventType(t apiv1alpha1.EventType) (export.EventType, bool) {
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

// actionFromProto decides whether an event is a denial.
//
// Anything that is not explicitly a deny is treated as an observation. An
// unrecognised action rendered as a denial would put an imaginary incident in
// front of an operator, which is the more expensive mistake.
func actionFromProto(a apiv1alpha1.Action) export.Action {
	if a == apiv1alpha1.Action_ACTION_DENY {
		return export.ActionDeny
	}
	return export.ActionObserve
}
