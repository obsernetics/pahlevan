/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package observability

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ScopeName is the instrumentation scope every pahlevan span is recorded under.
// One scope for the whole agent, so a backend groups the operator's spans
// together rather than scattering them across a scope per package.
const ScopeName = "github.com/obsernetics/pahlevan"

// Span names.
//
// These are constants rather than string literals at the call sites because a
// trace is only queryable if the name is stable: a dashboard or a Tempo query
// that filters on name = "pahlevan.ebpf.program.attach" breaks silently the
// moment one call site spells it differently, and nothing in the build would
// catch that.
//
// Names are low-cardinality on purpose. Anything that varies per container,
// per policy or per program belongs in an attribute; a span name containing a
// container id turns every trace into its own operation and makes latency
// aggregation impossible.
const (
	// SpanPolicyReconcile covers one pass of the PahlevanPolicy reconciler. It
	// is the root of every policy trace and carries the phase transition as an
	// event, so "why did this policy move to enforcing" is answerable from the
	// trace alone.
	SpanPolicyReconcile = "pahlevan.policy.reconcile"
	// SpanPolicyPhase covers the handler for one lifecycle phase.
	SpanPolicyPhase = "pahlevan.policy.phase"
	// SpanWorkloadDiscovery covers the label-selector sweep that finds the
	// workloads a policy targets - the usual answer to "the policy matched
	// nothing".
	SpanWorkloadDiscovery = "pahlevan.policy.discover_workloads"
	// SpanProfileAggregate covers rolling ContainerProfile status up onto the
	// policy.
	SpanProfileAggregate = "pahlevan.policy.aggregate_profiles"

	// SpanLearningWindow covers one evaluation of a policy's learning window:
	// how far through it is, and whether this pass closed it.
	SpanLearningWindow = "pahlevan.learning.window"
	// SpanLearningStart covers opening the learning window for one container.
	SpanLearningStart = "pahlevan.learning.start"
	// SpanLearningStop covers closing it.
	SpanLearningStop = "pahlevan.learning.stop"

	// SpanProfileGenerate covers turning a learned profile into an enforceable
	// policy.
	SpanProfileGenerate = "pahlevan.profile.generate"
	// SpanPolicyApply covers pushing a generated policy into the BPF maps.
	SpanPolicyApply = "pahlevan.policy.apply"

	// SpanEBPFLoad covers the whole load of the data plane; one child per
	// program.
	SpanEBPFLoad = "pahlevan.ebpf.load"
	// SpanEBPFProgramLoad covers loading one program's collection, including
	// the map sizing applied to it.
	SpanEBPFProgramLoad = "pahlevan.ebpf.program.load"
	// SpanEBPFAttach covers the whole attach; one child per hook.
	SpanEBPFAttach = "pahlevan.ebpf.attach"
	// SpanEBPFProgramAttach covers attaching one program to one hook. A failed
	// attach is the single most common reason the agent runs degraded, and
	// this is the span that shows it.
	SpanEBPFProgramAttach = "pahlevan.ebpf.program.attach"
	// SpanEBPFReaders covers creating the ring buffer readers.
	SpanEBPFReaders = "pahlevan.ebpf.setup_readers"

	// SpanEnforcementMode covers flipping one cgroup between learning and
	// enforcing for one subsystem.
	SpanEnforcementMode = "pahlevan.enforcement.mode"
	// SpanLifecyclePhase covers a workload lifecycle phase change in the
	// enforcement engine.
	SpanLifecyclePhase = "pahlevan.enforcement.lifecycle"
)

// Span event names.
const (
	// EventPhaseTransition marks the point inside a reconcile where the policy
	// changed phase. It is an event rather than a span because the transition
	// is instantaneous - a zero-duration span would just be noise in a
	// waterfall.
	EventPhaseTransition = "policy.phase_transition"
	// EventLearningWindowClosed marks the pass that ended a learning window.
	EventLearningWindowClosed = "learning.window_closed"
	// EventMapSizing records the max_entries actually applied to a program's
	// maps. A node that OOMs on load, or an allow-set that silently evicts,
	// is explained by these numbers.
	EventMapSizing = "ebpf.map_sizing"
	// EventDegraded marks a best-effort component that could not be brought
	// up, leaving the agent running with less visibility than configured.
	EventDegraded = "ebpf.degraded"
)

// Attribute keys.
//
// Prefixed with pahlevan. so they never collide with the semantic conventions
// carried on the same spans by the Kubernetes and gRPC instrumentation.
const (
	AttrNamespace    = attribute.Key("pahlevan.namespace")
	AttrPolicy       = attribute.Key("pahlevan.policy")
	AttrPolicyCount  = attribute.Key("pahlevan.policies")
	AttrWorkload     = attribute.Key("pahlevan.workload")
	AttrWorkloadKind = attribute.Key("pahlevan.workload.kind")
	AttrPod          = attribute.Key("pahlevan.pod")
	AttrContainerID  = attribute.Key("pahlevan.container.id")
	AttrCgroupID     = attribute.Key("pahlevan.cgroup.id")
	AttrPhase        = attribute.Key("pahlevan.phase")
	AttrPhaseFrom    = attribute.Key("pahlevan.phase.from")
	AttrPhaseTo      = attribute.Key("pahlevan.phase.to")
	AttrReason       = attribute.Key("pahlevan.reason")

	// AttrProgram is the eBPF program (syscall_monitor, file_monitor, ...) and
	// AttrHook the kernel attach point (lsm/file_open, tracepoint/sys_enter).
	// Together they identify exactly which half of the data plane failed.
	AttrProgram  = attribute.Key("pahlevan.ebpf.program")
	AttrHook     = attribute.Key("pahlevan.ebpf.hook")
	AttrRequired = attribute.Key("pahlevan.ebpf.required")
	// AttrMap is a prefix: each resized map contributes
	// pahlevan.ebpf.map.<name> = max_entries.
	AttrMap = attribute.Key("pahlevan.ebpf.map")

	AttrSubsystem   = attribute.Key("pahlevan.enforcement.subsystem")
	AttrMode        = attribute.Key("pahlevan.enforcement.mode")
	AttrSyscalls    = attribute.Key("pahlevan.profile.syscalls")
	AttrFileRules   = attribute.Key("pahlevan.profile.file_rules")
	AttrNetRules    = attribute.Key("pahlevan.profile.network_rules")
	AttrConfidence  = attribute.Key("pahlevan.profile.confidence")
	AttrQuality     = attribute.Key("pahlevan.profile.quality")
	AttrWorkloads   = attribute.Key("pahlevan.workloads")
	AttrProgress    = attribute.Key("pahlevan.learning.progress")
	AttrElapsedSecs = attribute.Key("pahlevan.learning.elapsed_seconds")
	AttrWindowSecs  = attribute.Key("pahlevan.learning.window_seconds")
)

// disabledSpan is the span handed back when tracing is off. It is a package
// level value rather than a fresh noop.Span per call so the disabled path
// allocates nothing of its own.
var disabledSpan trace.Span = noop.Span{}

// activeTracer holds the tracer every pahlevan span is started on, or nil when
// tracing is off.
//
// An atomic pointer rather than a mutex because StartSpan is called from every
// reconcile worker and from the eBPF manager concurrently, and a shared
// RWMutex on a path that runs on every reconcile is a contention point for no
// benefit: the pointer is written once at startup and read forever after.
//
// Nil is a deliberate, checkable state and not merely "we forgot to set it".
// The previous pipeline built a TracerProvider unconditionally, so there was
// no way to distinguish tracing that was off from tracing that was on and
// broken; both produced no spans and both reported themselves as enabled.
var activeTracer atomic.Pointer[trace.Tracer]

// SetTracerProvider installs the provider that pahlevan spans are recorded on.
// Passing nil disables tracing.
func SetTracerProvider(tp trace.TracerProvider) {
	if tp == nil {
		DisableTracing()
		return
	}
	t := tp.Tracer(ScopeName)
	activeTracer.Store(&t)
}

// DisableTracing turns tracing off process-wide. After this every StartSpan
// returns the caller's own context and a span that records nothing.
func DisableTracing() {
	activeTracer.Store(nil)
}

// TracingActive reports whether spans started now will actually be recorded.
// Callers on expensive-but-not-hot paths can use it to skip building
// attributes they would otherwise throw away.
func TracingActive() bool {
	return activeTracer.Load() != nil
}

// StartSpan begins a span, or does nothing measurable if tracing is off.
//
// NEVER call this once per eBPF event. A span costs an allocation, a
// timestamp, a sampler decision and a slot in the batch processor's queue -
// each individually trivial, and all of them multiplied by the syscall rate of
// every container on the node. The event path handles hundreds of thousands of
// records a second; tracing it would make the monitoring cost more than the
// thing being monitored, and the resulting trace would be unreadable anyway.
// Per-event visibility is a counter's job, and pkg/ebpf already keeps those.
// Spans belong on control-plane operations that happen per reconcile, per
// container or per program.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tr := activeTracer.Load()
	if tr == nil {
		// Return the caller's context untouched: handing back a context
		// derived from a no-op span would make every downstream lookup walk an
		// extra level for nothing.
		return ctx, disabledSpan
	}
	if len(attrs) == 0 {
		return (*tr).Start(ctx, name)
	}
	return (*tr).Start(ctx, name, trace.WithAttributes(attrs...))
}

// RecordError marks a span as failed and returns the error unchanged, so it
// can wrap a return: `return observability.RecordError(span, err)`.
//
// Both halves matter. RecordError alone leaves the span's status Unset, which
// most backends render as success - a failed LSM attach would then be visible
// only as an exception event nobody filters on. The status is what makes the
// span red in a trace view and findable with status = error.
func RecordError(span trace.Span, err error) error {
	if err == nil || span == nil || !span.IsRecording() {
		return err
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}

// EndSpan ends a span, recording err first when there is one. Intended for
// `defer` where the error is captured by a named return.
func EndSpan(span trace.Span, err error) {
	if span == nil {
		return
	}
	RecordError(span, err)
	span.End()
}

// RecordPhaseTransition notes a lifecycle phase change on the surrounding
// span. Recorded as an event on the reconcile span so the transition is
// timestamped inside the reconcile that caused it, which is the question an
// operator actually asks: not "when did it become enforcing" but "which
// reconcile decided that, and what else did that reconcile do".
func RecordPhaseTransition(span trace.Span, from, to, reason string) {
	if span == nil || !span.IsRecording() {
		return
	}
	span.AddEvent(EventPhaseTransition, trace.WithAttributes(
		AttrPhaseFrom.String(from),
		AttrPhaseTo.String(to),
		AttrReason.String(reason),
	))
}

// RecordDegraded notes a best-effort component that could not be brought up.
// This is not an error on the span: the agent is designed to run without the
// BPF LSM, and marking the load span failed would make every ordinary kernel
// look broken. The event keeps the fact visible without crying wolf.
func RecordDegraded(span trace.Span, component, reason string) {
	if span == nil || !span.IsRecording() {
		return
	}
	span.AddEvent(EventDegraded, trace.WithAttributes(
		AttrProgram.String(component),
		AttrReason.String(reason),
	))
}

// RecordMapSizing notes the max_entries applied to one program's maps. Zero
// means the compiled default was kept and is skipped, so the event shows only
// what an operator actually overrode.
func RecordMapSizing(span trace.Span, sizes map[string]uint32) {
	if span == nil || !span.IsRecording() {
		return
	}
	// One attribute per map, keyed by the map's name. A pair of
	// (pahlevan.ebpf.map, pahlevan.ebpf.max_entries) attributes would be
	// deduplicated by key, so a program with four resized maps would report
	// only the last one.
	attrs := make([]attribute.KeyValue, 0, len(sizes))
	for name, n := range sizes {
		if n == 0 {
			continue
		}
		attrs = append(attrs, attribute.Int64(string(AttrMap)+"."+name, int64(n)))
	}
	if len(attrs) == 0 {
		return
	}
	span.AddEvent(EventMapSizing, trace.WithAttributes(attrs...))
}

// SpanFromContext returns the span currently in ctx, or a span that records
// nothing. It exists so instrumented packages need not import
// go.opentelemetry.io/otel/trace just to add an event to the span their caller
// already started.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent records a timestamped event on a span. A thin wrapper so callers
// need not import go.opentelemetry.io/otel/trace for trace.WithAttributes,
// and so the IsRecording guard is applied in one place rather than forgotten
// in most of them.
func AddEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	if span == nil || !span.IsRecording() {
		return
	}
	span.AddEvent(name, trace.WithAttributes(attrs...))
}
