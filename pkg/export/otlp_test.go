package export

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// recordingProcessor captures what the sink emitted, so the assertions are
// about the record that would reach the collector rather than about the
// arguments the sink was called with.
type recordingProcessor struct{ records []sdklog.Record }

func (p *recordingProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.records = append(p.records, *r)
	return nil
}
func (p *recordingProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (p *recordingProcessor) Shutdown(context.Context) error                         { return nil }
func (p *recordingProcessor) ForceFlush(context.Context) error                       { return nil }

// newTestSink returns a sink writing into an in-memory processor. The real
// constructor dials a collector, which a unit test must not need.
func newTestSink(t *testing.T, denialsOnly bool) (*OTLPExporter, *recordingProcessor) {
	t.Helper()
	proc := &recordingProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &OTLPExporter{
		opts:     OTLPOptions{DenialsOnly: denialsOnly},
		provider: provider,
		logger:   provider.Logger("test"),
	}, proc
}

func attrsOf(t *testing.T, r sdklog.Record) map[string]string {
	t.Helper()
	out := map[string]string{}
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		out[kv.Key] = kv.Value.String()
		return true
	})
	return out
}

func deniedFileEvent() *Event {
	return &Event{
		Version:   SchemaVersion,
		Timestamp: Timestamp(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)),
		Type:      EventTypeFile,
		Action:    ActionDeny,
		CgroupID:  4242,
		Process: ProcessInfo{
			PID: 900, UID: 0, Comm: "cat", PPID: 800, ParentComm: "sh",
		},
		File: &FileInfo{Path: "/etc/shadow", Flags: 0, SyscallName: "openat"},
		Kubernetes: &KubernetesRef{
			Namespace: "prod", Pod: "api-7d9", Container: "api", Node: "node-3",
			ContainerID: "abc123", Image: "api:1.2", WorkloadKind: "Deployment", WorkloadName: "api",
		},
	}
}

func TestOTLPRecordCarriesTheSemanticConventionNames(t *testing.T) {
	sink, proc := newTestSink(t, false)
	require.NoError(t, sink.Export(context.Background(), []*Event{deniedFileEvent()}))
	require.Len(t, proc.records, 1)

	a := attrsOf(t, proc.records[0])
	// Convention names, not invented ones: a Grafana panel written against any
	// OTel-instrumented workload must line up with these.
	assert.Equal(t, "/etc/shadow", a["file.path"])
	assert.Equal(t, "900", a["process.pid"])
	assert.Equal(t, "cat", a["process.executable.name"])
	assert.Equal(t, "800", a["process.parent_pid"])
	assert.Equal(t, "prod", a["k8s.namespace.name"])
	assert.Equal(t, "api-7d9", a["k8s.pod.name"])
	assert.Equal(t, "node-3", a["k8s.node.name"])
	assert.Equal(t, "api", a["k8s.container.name"])
	// And the ones that are genuinely ours are namespaced.
	assert.Equal(t, "true", a["pahlevan.denied"])
	assert.Equal(t, "sh", a["pahlevan.process.parent_comm"])
	assert.Equal(t, "4242", a["pahlevan.cgroup.id"])
}

// A denied read and a denied write to the same path are very different
// findings, and the write bit is the field an alert filters on.
func TestOTLPRecordDistinguishesReadsFromWrites(t *testing.T) {
	sink, proc := newTestSink(t, false)
	read := deniedFileEvent()
	write := deniedFileEvent()
	write.File.Flags = writeFlagBit

	require.NoError(t, sink.Export(context.Background(), []*Event{read, write}))
	require.Len(t, proc.records, 2)
	assert.Equal(t, "false", attrsOf(t, proc.records[0])["pahlevan.file.write"])
	assert.Equal(t, "true", attrsOf(t, proc.records[1])["pahlevan.file.write"])
}

// writeFlagBit is duplicated from ebpf.WriteFlag so this package builds on
// every platform. If the two drift, every exported event reports the wrong
// access mode.
func TestWriteFlagBitMatchesTheKernelContract(t *testing.T) {
	assert.Equal(t, uint32(0x40000000), writeFlagBit)
}

// Enforcement working as designed is not an error condition. Grading every
// denial ERROR is how an alert channel becomes something people turn off.
func TestOTLPSeverity(t *testing.T) {
	sink, proc := newTestSink(t, false)
	observed := deniedFileEvent()
	observed.Action = ActionObserve

	require.NoError(t, sink.Export(context.Background(), []*Event{deniedFileEvent(), observed}))
	require.Len(t, proc.records, 2)
	assert.Equal(t, otellog.SeverityWarn, proc.records[0].Severity())
	assert.Equal(t, "DENY", proc.records[0].SeverityText())
	assert.Equal(t, otellog.SeverityDebug, proc.records[1].Severity())
}

// The kernel's timestamp is the one that matters. Using arrival time would
// reorder events under load, which is exactly when ordering matters.
func TestOTLPUsesTheEventTimestamp(t *testing.T) {
	sink, proc := newTestSink(t, false)
	ev := deniedFileEvent()
	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	require.Len(t, proc.records, 1)
	assert.Equal(t, ev.Timestamp.Time().UTC(), proc.records[0].Timestamp().UTC())
	assert.False(t, proc.records[0].ObservedTimestamp().IsZero(),
		"the arrival time is still recorded, just not as the event time")
}

func TestOTLPDenialsOnlyDropsObservations(t *testing.T) {
	sink, proc := newTestSink(t, true)
	observed := deniedFileEvent()
	observed.Action = ActionObserve

	require.NoError(t, sink.Export(context.Background(), []*Event{observed, deniedFileEvent()}))
	require.Len(t, proc.records, 1, "only the denial should be emitted")
	assert.Equal(t, "true", attrsOf(t, proc.records[0])["pahlevan.denied"])
}

// The lineage is what turns "curl was denied" into "nginx ran a shell that ran
// curl" - the difference between an alert somebody investigates and one they
// mute.
func TestOTLPExecRecordCarriesTheLineage(t *testing.T) {
	sink, proc := newTestSink(t, false)
	ev := &Event{
		Type: EventTypeProcess, Action: ActionDeny,
		Process: ProcessInfo{PID: 1, Comm: "curl", ParentComm: "sh"},
		Exec: &ExecInfo{
			Binary: "/usr/bin/curl", CommandLine: "curl http://x",
			AncestryChain: "nginx -> sh -> curl", Cwd: "/tmp",
		},
	}
	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	require.Len(t, proc.records, 1)

	a := attrsOf(t, proc.records[0])
	assert.Equal(t, "/usr/bin/curl", a["process.executable.path"])
	assert.Equal(t, "curl http://x", a["process.command_line"])
	assert.Equal(t, "nginx -> sh -> curl", a["pahlevan.process.ancestry"])
	assert.Equal(t, "/tmp", a["process.working_directory"])
}

func TestOTLPNetworkRecordUsesServerAddress(t *testing.T) {
	sink, proc := newTestSink(t, false)
	ev := &Event{
		Type: EventTypeNetwork, Action: ActionDeny,
		Process: ProcessInfo{PID: 1, Comm: "nc"},
		Network: &NetworkInfo{
			DestinationIP: "203.0.113.7", DestinationPort: 4444,
			Protocol: "TCP", Direction: "egress",
		},
	}
	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	a := attrsOf(t, proc.records[0])
	assert.Equal(t, "203.0.113.7", a["server.address"])
	assert.Equal(t, "4444", a["server.port"])
	assert.Equal(t, "tcp", a["network.transport"])
}

func TestOTLPCapabilityRecord(t *testing.T) {
	sink, proc := newTestSink(t, false)
	ev := &Event{
		Type: EventTypeCapability, Action: ActionDeny,
		Process:    ProcessInfo{PID: 1, Comm: "mount"},
		Capability: &CapabilityInfo{Number: 21, Name: "CAP_SYS_ADMIN"},
	}
	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	a := attrsOf(t, proc.records[0])
	assert.Equal(t, "CAP_SYS_ADMIN", a["pahlevan.capability.name"])
	assert.Equal(t, "21", a["pahlevan.capability.number"])
}

// A nil entry in a batch must be skipped, not dereferenced: the queue can hand
// one over when a converter declined an event.
func TestOTLPSkipsNilEvents(t *testing.T) {
	sink, proc := newTestSink(t, false)
	require.NoError(t, sink.Export(context.Background(), []*Event{nil, deniedFileEvent(), nil}))
	assert.Len(t, proc.records, 1)
}

func TestOTLPEmptyBatchIsANoOp(t *testing.T) {
	sink, proc := newTestSink(t, false)
	require.NoError(t, sink.Export(context.Background(), nil))
	require.NoError(t, sink.Export(context.Background(), []*Event{}))
	assert.Empty(t, proc.records)
}

// A sink used after Close must say so rather than silently accept events that
// will never be flushed.
func TestOTLPExportAfterCloseReportsClosed(t *testing.T) {
	sink, _ := newTestSink(t, false)
	require.NoError(t, sink.Close())
	assert.ErrorIs(t, sink.Export(context.Background(), []*Event{deniedFileEvent()}), ErrClosed)
	// Close is idempotent, as the interface requires.
	assert.NoError(t, sink.Close())
}

func TestOTLPName(t *testing.T) {
	sink, _ := newTestSink(t, false)
	assert.Equal(t, "otlp", sink.Name())
}

// The body is the sentence an operator reads in Loki. It must be the same one
// the CLI prints, or the two views of one event disagree in words.
func TestSummaryLine(t *testing.T) {
	for name, tc := range map[string]struct {
		ev   *Event
		want string
	}{
		"denied write": {
			ev: &Event{
				Action: ActionDeny, Process: ProcessInfo{Comm: "sh", ParentComm: "nginx"},
				File:       &FileInfo{Path: "/etc/passwd", Flags: writeFlagBit},
				Kubernetes: &KubernetesRef{Namespace: "prod", Pod: "api-1"},
			},
			want: "DENIED write of /etc/passwd by nginx -> sh in prod/api-1",
		},
		"observed read": {
			ev: &Event{
				Action: ActionObserve, Process: ProcessInfo{Comm: "api"},
				File: &FileInfo{Path: "/etc/hosts"},
			},
			want: "observed read of /etc/hosts by api",
		},
		"denied connect": {
			ev: &Event{
				Action: ActionDeny, Process: ProcessInfo{Comm: "nc"},
				Network: &NetworkInfo{DestinationIP: "1.2.3.4", DestinationPort: 4444, Protocol: "TCP"},
			},
			want: "DENIED tcp connect to 1.2.3.4:4444 by nc",
		},
		"denied exec": {
			ev: &Event{
				Action: ActionDeny, Process: ProcessInfo{Comm: "sh"},
				Exec: &ExecInfo{Binary: "/tmp/x"},
			},
			want: "DENIED exec of /tmp/x by sh",
		},
		"exit": {
			ev: &Event{
				Action: ActionObserve, Process: ProcessInfo{Comm: "api"},
				Exec: &ExecInfo{Exited: true},
			},
			want: "exit of api",
		},
		"capability": {
			ev: &Event{
				Action: ActionDeny, Process: ProcessInfo{Comm: "mount"},
				Capability: &CapabilityInfo{Name: "CAP_SYS_ADMIN"},
			},
			want: "DENIED use of CAP_SYS_ADMIN by mount",
		},
		"syscall": {
			ev: &Event{
				Action: ActionObserve, Process: ProcessInfo{Comm: "api"},
				Syscall: &SyscallInfo{Name: "openat"},
			},
			want: "observed syscall openat by api",
		},
		"no comm falls back to the pid": {
			ev:   &Event{Action: ActionObserve, Type: EventTypeSyscall, Process: ProcessInfo{PID: 77}},
			want: "observed syscall event by pid 77",
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, SummaryLine(tc.ev))
		})
	}
	assert.Equal(t, "", SummaryLine(nil))
}

// service.instance.id must be unique per replica or Mimir collapses every agent
// in the DaemonSet into one series.
func TestAgentResourceCarriesTheCorrelationAttributes(t *testing.T) {
	res := AgentResource("pahlevan-agent", "1.2.3", "pahlevan-system", "agent-abc", "node-7")
	got := map[string]string{}
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.AsString()
	}
	assert.Equal(t, "pahlevan-agent", got["service.name"])
	assert.Equal(t, "1.2.3", got["service.version"])
	assert.Equal(t, "agent-abc", got["service.instance.id"])
	assert.Equal(t, "node-7", got["k8s.node.name"])
	assert.Equal(t, "node-7", got["host.name"])
	assert.Equal(t, "pahlevan-system", got["k8s.namespace.name"])
	assert.Equal(t, "agent-abc", got["k8s.pod.name"])
}

// Outside a cluster the downward API values are empty. The resource must still
// be usable rather than carrying empty attributes that break a join.
func TestAgentResourceOmitsUnknownFields(t *testing.T) {
	res := AgentResource("pahlevan-agent", "dev", "", "", "")
	for _, kv := range res.Attributes() {
		assert.NotEmpty(t, kv.Value.AsString(), "attribute %s is present but empty", kv.Key)
		assert.NotContains(t, []string{"k8s.pod.name", "k8s.node.name", "service.instance.id"},
			string(kv.Key), "unknown fields must be omitted, not blank")
	}
}

// The pipeline must build the OTLP sink when an endpoint is configured, and the
// config must count as enabled on the strength of that alone.
func TestConfigEnabledByOTLPEndpointAlone(t *testing.T) {
	assert.False(t, Config{}.Enabled())
	assert.True(t, Config{OTLPEndpoint: "collector:4317"}.Enabled())
}

func BenchmarkOTLPRecord(b *testing.B) {
	proc := &recordingProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	sink := &OTLPExporter{provider: provider, logger: provider.Logger("bench")}
	ev := deniedFileEvent()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sink.record(ev)
	}
}

func BenchmarkSummaryLine(b *testing.B) {
	ev := deniedFileEvent()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SummaryLine(ev)
	}
}

func BenchmarkOTLPExportBatch(b *testing.B) {
	proc := &recordingProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	sink := &OTLPExporter{provider: provider, logger: provider.Logger("bench")}

	batch := make([]*Event, 256)
	for i := range batch {
		batch[i] = deniedFileEvent()
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proc.records = proc.records[:0]
		if err := sink.Export(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
	_ = strings.TrimSpace("")
}

// An address the operator has to go and look up is a line they will not act on
// at 3am. The name goes in the body, and the kind becomes the attribute an
// alert can filter on.
func TestSummaryLineNamesTheDestination(t *testing.T) {
	named := &Event{
		Action: ActionDeny, Process: ProcessInfo{Comm: "api"},
		Network: &NetworkInfo{
			DestinationIP: "10.104.22.9", DestinationPort: 5432, Protocol: "TCP",
			DestinationName: "prod/postgres", DestinationKind: "service",
		},
	}
	assert.Equal(t,
		"DENIED tcp connect to prod/postgres (10.104.22.9:5432) by api",
		SummaryLine(named))

	// The one that matters: an address the cluster does not know is the shape
	// exfiltration takes, and it must read differently from a Service denial.
	external := &Event{
		Action: ActionDeny, Process: ProcessInfo{Comm: "api"},
		Network: &NetworkInfo{
			DestinationIP: "203.0.113.7", DestinationPort: 4444, Protocol: "TCP",
			DestinationName: "external", DestinationKind: "external",
		},
	}
	assert.Equal(t,
		"DENIED tcp connect to 203.0.113.7:4444 [external] by api",
		SummaryLine(external))

	// Before the map is populated there is no name, and the line falls back to
	// the address rather than claiming anything.
	bare := &Event{
		Action: ActionDeny, Process: ProcessInfo{Comm: "api"},
		Network: &NetworkInfo{DestinationIP: "10.0.0.1", DestinationPort: 80, Protocol: "TCP"},
	}
	assert.Equal(t, "DENIED tcp connect to 10.0.0.1:80 by api", SummaryLine(bare))
}

func TestOTLPNetworkRecordCarriesTheDestination(t *testing.T) {
	sink, proc := newTestSink(t, false)
	ev := &Event{
		Type: EventTypeNetwork, Action: ActionDeny,
		Process: ProcessInfo{PID: 1, Comm: "api"},
		Network: &NetworkInfo{
			DestinationIP: "10.104.22.9", DestinationPort: 5432, Protocol: "TCP",
			DestinationName: "prod/postgres", DestinationKind: "service",
			DestinationPortName: "postgres",
		},
	}
	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	a := attrsOf(t, proc.records[0])
	assert.Equal(t, "prod/postgres", a["pahlevan.destination.name"])
	assert.Equal(t, "service", a["pahlevan.destination.kind"])
	assert.Equal(t, "postgres", a["pahlevan.destination.port_name"])
}
