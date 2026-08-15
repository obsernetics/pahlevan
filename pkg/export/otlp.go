package export

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
)

// OTLP log export.
//
// The file and webhook sinks assume something downstream is watching: a log
// shipper tailing the JSON-lines file, or an endpoint someone wrote. That works
// and it is not how a cluster running the LGTM stack is put together. There,
// the collector is already there, everything speaks OTLP to it, and a signal
// that arrives any other way needs its own pipeline, its own parser and its own
// set of labels that will not match anybody else's.
//
// This sink emits each event as an OTLP log record, so security events land in
// Loki through the same collector as everything else, carrying the same
// resource attributes as the agent's metrics and traces. That shared resource
// is the whole point: it is what lets a Grafana panel move from a denial spike
// in Mimir, to the node's logs in Loki, to the trace of the reconcile that
// enforced the policy in Tempo, without anybody hand-writing a join.
//
// Attribute names follow OpenTelemetry semantic conventions where one exists
// (server.address, process.pid, k8s.pod.name) and are prefixed pahlevan.* where
// none does. Inventing a name for something the conventions already cover is
// how a dashboard ends up working for exactly one tool.

// OTLPOptions configures the OTLP log sink.
type OTLPOptions struct {
	// Endpoint is the collector's OTLP/gRPC address, e.g. "otel-collector:4317".
	// Empty uses the OTel default, which honors OTEL_EXPORTER_OTLP_ENDPOINT.
	Endpoint string
	// Insecure disables TLS. Usual for an in-cluster collector reached over the
	// pod network.
	Insecure bool
	// Headers are sent with every export, for collectors behind an auth proxy.
	Headers map[string]string
	// Resource identifies this agent. It should be the same resource the
	// metrics and traces carry, which is what makes the three correlate.
	Resource *resource.Resource
	// Timeout bounds one export. Zero uses the OTel default.
	Timeout time.Duration
	// DenialsOnly emits only in-kernel denials. Observations are high volume
	// and are usually better served by the metrics, so this defaults on at the
	// flag layer rather than here.
	DenialsOnly bool
}

// OTLPExporter ships events to an OpenTelemetry collector as log records.
type OTLPExporter struct {
	opts     OTLPOptions
	provider *log.LoggerProvider
	logger   otellog.Logger

	mu     sync.Mutex
	closed bool
}

// NewOTLPExporter builds the sink and dials lazily: the gRPC exporter does not
// connect on construction, so a collector that is not up yet delays events
// rather than failing agent startup. An agent that refuses to start because the
// observability stack is down is worse than one that starts without it.
func NewOTLPExporter(ctx context.Context, opts OTLPOptions) (*OTLPExporter, error) {
	grpcOpts := []otlploggrpc.Option{}
	if opts.Endpoint != "" {
		grpcOpts = append(grpcOpts, otlploggrpc.WithEndpoint(opts.Endpoint))
	}
	if opts.Insecure {
		grpcOpts = append(grpcOpts, otlploggrpc.WithInsecure())
	}
	if len(opts.Headers) > 0 {
		grpcOpts = append(grpcOpts, otlploggrpc.WithHeaders(opts.Headers))
	}
	if opts.Timeout > 0 {
		grpcOpts = append(grpcOpts, otlploggrpc.WithTimeout(opts.Timeout))
	}

	exp, err := otlploggrpc.New(ctx, grpcOpts...)
	if err != nil {
		return nil, fmt.Errorf("export: otlp log exporter: %w", err)
	}

	providerOpts := []log.LoggerProviderOption{
		log.WithProcessor(log.NewBatchProcessor(exp)),
	}
	if opts.Resource != nil {
		providerOpts = append(providerOpts, log.WithResource(opts.Resource))
	}
	provider := log.NewLoggerProvider(providerOpts...)

	return &OTLPExporter{
		opts:     opts,
		provider: provider,
		logger:   provider.Logger("pahlevan.io/security-events"),
	}, nil
}

// SetGlobalLoggerProvider publishes the sink's provider as the process-wide
// one, so any other component that emits OTel logs shares the same pipeline and
// resource rather than starting a second connection to the same collector.
func (e *OTLPExporter) SetGlobalLoggerProvider() {
	if e != nil && e.provider != nil {
		global.SetLoggerProvider(e.provider)
	}
}

func (e *OTLPExporter) Name() string { return "otlp" }

func (e *OTLPExporter) Export(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return ErrClosed
	}

	for _, ev := range events {
		if ev == nil {
			continue
		}
		if e.opts.DenialsOnly && !ev.Denied() {
			continue
		}
		e.logger.Emit(ctx, e.record(ev))
	}
	return nil
}

// Close flushes buffered records. The batch processor holds records in memory,
// so skipping the flush loses precisely the events an operator most wants after
// an agent restart: the last ones before it went down.
func (e *OTLPExporter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	// Bounded: a collector that has gone away must not hold up agent shutdown
	// past the kubelet's patience.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("export: otlp shutdown: %w", err)
	}
	return nil
}

// record turns one envelope into an OTLP log record.
func (e *OTLPExporter) record(ev *Event) otellog.Record {
	var r otellog.Record
	r.SetTimestamp(ev.Timestamp.Time())
	r.SetObservedTimestamp(time.Now())
	r.SetSeverity(severityOf(ev))
	r.SetSeverityText(strings.ToUpper(string(ev.Action)))
	r.SetBody(otellog.StringValue(SummaryLine(ev)))

	attrs := make([]otellog.KeyValue, 0, 20)
	add := func(k string, v otellog.Value) { attrs = append(attrs, otellog.KeyValue{Key: k, Value: v}) }
	addStr := func(k, v string) {
		if v != "" {
			add(k, otellog.StringValue(v))
		}
	}
	addInt := func(k string, v int64) {
		if v != 0 {
			add(k, otellog.Int64Value(v))
		}
	}

	addStr("pahlevan.schema", ev.Version)
	addStr("pahlevan.event.type", string(ev.Type))
	addStr("pahlevan.action", string(ev.Action))
	add("pahlevan.denied", otellog.BoolValue(ev.Denied()))
	addStr("pahlevan.cgroup.id", fmt.Sprint(ev.CgroupID))

	// Process, using the semantic-convention names so a Grafana panel written
	// against any OTel-instrumented workload lines up with these.
	addInt("process.pid", int64(ev.Process.PID))
	addStr("process.executable.name", ev.Process.Comm)
	addInt("process.parent_pid", int64(ev.Process.PPID))
	addStr("pahlevan.process.parent_comm", ev.Process.ParentComm)
	addInt("pahlevan.process.uid", int64(ev.Process.UID))
	addInt("pahlevan.process.gid", int64(ev.Process.GID))

	if k := ev.Kubernetes; k != nil {
		addStr("k8s.namespace.name", k.Namespace)
		addStr("k8s.pod.name", k.Pod)
		addStr("k8s.pod.uid", k.PodUID)
		addStr("k8s.container.name", k.Container)
		addStr("k8s.node.name", k.Node)
		addStr("container.id", k.ContainerID)
		addStr("container.image.name", k.Image)
		addStr("container.runtime", k.Runtime)
		addStr("k8s.workload.kind", k.WorkloadKind)
		addStr("k8s.workload.name", k.WorkloadName)
	}

	switch {
	case ev.Syscall != nil:
		addStr("pahlevan.syscall.name", ev.Syscall.Name)
		addInt("pahlevan.syscall.number", int64(ev.Syscall.Number))
	case ev.File != nil:
		// file.path is a semantic convention; the write bit is ours, and it is
		// the field an alert filters on - a denied read and a denied write to
		// the same path are very different findings.
		addStr("file.path", ev.File.Path)
		add("pahlevan.file.write", otellog.BoolValue(ev.File.Flags&writeFlagBit != 0))
		addStr("pahlevan.file.syscall", ev.File.SyscallName)
	case ev.Network != nil:
		addStr("server.address", ev.Network.DestinationIP)
		addInt("server.port", int64(ev.Network.DestinationPort))
		addStr("network.transport", strings.ToLower(ev.Network.Protocol))
		addStr("pahlevan.network.direction", ev.Network.Direction)
	case ev.Exec != nil:
		addStr("process.executable.path", ev.Exec.Binary)
		addStr("process.command_line", ev.Exec.CommandLine)
		addStr("process.working_directory", ev.Exec.Cwd)
		// The lineage is the field that turns "curl was denied" into "nginx ran
		// a shell that ran curl", which is the difference between an alert
		// somebody investigates and one they mute.
		addStr("pahlevan.process.ancestry", ev.Exec.AncestryChain)
		add("pahlevan.process.exited", otellog.BoolValue(ev.Exec.Exited))
	case ev.Capability != nil:
		addStr("pahlevan.capability.name", ev.Capability.Name)
		addInt("pahlevan.capability.number", int64(ev.Capability.Number))
	}

	r.AddAttributes(attrs...)
	return r
}

// writeFlagBit mirrors ebpf.WriteFlag. Duplicated rather than imported so this
// package builds on every platform; the value is asserted in the tests.
const writeFlagBit uint32 = 0x40000000

// severityOf maps an event onto an OTLP severity.
//
// A denial is a WARN rather than an ERROR: enforcement working as designed is
// not an error condition, and grading every denial as ERROR is how an alert
// channel becomes something people turn off. Observations are DEBUG, because at
// full volume they are a trace of normal behavior.
func severityOf(ev *Event) otellog.Severity {
	if ev.Denied() {
		return otellog.SeverityWarn
	}
	return otellog.SeverityDebug
}

// SummaryLine renders the one-line human description used as the log body.
//
// It is the same sentence the CLI prints, so an operator reading Loki and an
// operator reading `pahlevan events` see the same words for the same event.
func SummaryLine(ev *Event) string {
	if ev == nil {
		return ""
	}
	verb := "observed"
	if ev.Denied() {
		verb = "DENIED"
	}
	who := ev.Process.Comm
	if who == "" {
		who = fmt.Sprintf("pid %d", ev.Process.PID)
	}
	if ev.Process.ParentComm != "" {
		who = ev.Process.ParentComm + " -> " + who
	}
	where := ""
	if k := ev.Kubernetes; k != nil && k.Pod != "" {
		where = fmt.Sprintf(" in %s/%s", k.Namespace, k.Pod)
	}

	switch {
	case ev.File != nil:
		mode := "read"
		if ev.File.Flags&writeFlagBit != 0 {
			mode = "write"
		}
		return fmt.Sprintf("%s %s of %s by %s%s", verb, mode, ev.File.Path, who, where)
	case ev.Network != nil:
		return fmt.Sprintf("%s %s connect to %s:%d by %s%s", verb,
			strings.ToLower(ev.Network.Protocol), ev.Network.DestinationIP,
			ev.Network.DestinationPort, who, where)
	case ev.Exec != nil:
		if ev.Exec.Exited {
			return fmt.Sprintf("exit of %s%s", who, where)
		}
		return fmt.Sprintf("%s exec of %s by %s%s", verb, ev.Exec.Binary, who, where)
	case ev.Capability != nil:
		return fmt.Sprintf("%s use of %s by %s%s", verb, ev.Capability.Name, who, where)
	case ev.Syscall != nil:
		return fmt.Sprintf("%s syscall %s by %s%s", verb, ev.Syscall.Name, who, where)
	}
	return fmt.Sprintf("%s %s event by %s%s", verb, ev.Type, who, where)
}

// AgentResource builds the OTel resource every signal from this agent carries.
//
// The Kubernetes attributes are what make correlation work: Grafana joins Loki,
// Tempo and Mimir on shared labels, and if the agent's metrics say node=X while
// its logs say host=X the join silently produces nothing. They come from the
// downward API rather than being discovered, because a pod knows what it is and
// asking the API server for it is a request that can fail.
func AgentResource(serviceName, version, namespace, pod, node string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
	}
	if node != "" {
		attrs = append(attrs, semconv.K8SNodeName(node), semconv.HostName(node))
	}
	if namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceName(namespace))
	}
	if pod != "" {
		// service.instance.id must be unique per replica or Mimir collapses
		// every agent in the DaemonSet into one series.
		attrs = append(attrs, semconv.K8SPodName(pod), semconv.ServiceInstanceID(pod))
	}
	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}
