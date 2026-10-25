package export

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// The adapter is where the signal is attached, and the order matters: the
// filter asks whether the event is signalled, so annotating after it would
// publish an envelope whose own filter decision was made without the field it
// depends on. With DenialsOnly set, an allowed web shell exec would be dropped
// and then annotated, which is to say dropped.
func TestHandlerAnnotatesBeforeTheFilterDecides(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{Filter: Filter{DenialsOnly: true}})

	// No DeniedFlag: this is a kernel without the BPF LSM, or an agent still
	// learning. The exec is allowed and the lineage is the only finding.
	require.NoError(t, h.HandleProcessEvent(&ebpf.ProcessEvent{
		PID: 4242, PPID: 4241, Comm: "sh", ParentComm: "php-fpm",
		Filename: "/bin/sh", CgroupID: 100,
	}))

	got := sink.all()
	require.Len(t, got, 1, "an allowed exec of sh under php-fpm must reach the sink even in denials-only mode")
	assert.Equal(t, ActionObserve, got[0].Action, "nothing was denied, and the envelope must not pretend otherwise")
	assert.True(t, got[0].HasSignal(SignalServerSpawnedShell))
}

// The same adapter, the same filter, an exec that is not the shape: it must
// still be dropped, or "denials only" has quietly become "everything".
func TestHandlerStillFiltersAnUnsignalledObservation(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{Filter: Filter{DenialsOnly: true}})

	require.NoError(t, h.HandleProcessEvent(&ebpf.ProcessEvent{
		PID: 4242, PPID: 4241, Comm: "nginx", ParentComm: "nginx",
		Filename: "/usr/sbin/nginx", CgroupID: 100,
	}))

	assert.Empty(t, sink.all())
}

// A web shell file drop through the file hook, with the same reasoning.
func TestHandlerAnnotatesAWebShellWrite(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(sink, HandlerOptions{Filter: Filter{DenialsOnly: true}})

	require.NoError(t, h.HandleFileEvent(&ebpf.FileEvent{
		Path: "/usr/share/nginx/html/.x.php", Flags: ebpf.WriteFlag,
		Comm: "php-fpm", CgroupID: 100,
	}))

	got := sink.all()
	require.Len(t, got, 1)
	assert.True(t, got[0].HasSignal(SignalWebShellWrite))
}

// writeFlagBit is a hand copy of ebpf.WriteFlag, kept so this package builds
// on every platform. The copy is what the detector reads, so a drift between
// the two would silently stop the web shell write from being recognised.
func TestWriteFlagBitMatchesTheKernelFlag(t *testing.T) {
	assert.Equal(t, ebpf.WriteFlag, writeFlagBit)
}

func BenchmarkHandlerAnnotatesExec(b *testing.B) {
	sink := &captureSink{}
	h := NewHandler(sink, HandlerOptions{Filter: Filter{DenialsOnly: true}})
	ev := &ebpf.ProcessEvent{
		PID: 4242, PPID: 4241, Comm: "sh", ParentComm: "php-fpm",
		Filename: "/bin/sh", CgroupID: 100,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.HandleProcessEvent(ev)
	}
}

// The converter for the exec event used to build ProcessInfo without PPID or
// ParentComm, alone among the four converters. Every signal here is keyed on
// the parent, so the field that was missing was the field that mattered: the
// exec hook's own four-level ancestry capture fills in often but not always,
// and nothing else on the exec path names the parent at all.
func TestProcessEventConversionKeepsTheParent(t *testing.T) {
	ev := FromProcessEvent(&ebpf.ProcessEvent{
		PID: 4242, PPID: 4241, Comm: "sh", ParentComm: "php-fpm",
		Filename: "/bin/sh", CgroupID: 100,
	}, testNow)

	require.NotNil(t, ev)
	assert.Equal(t, uint32(4241), ev.Process.PPID)
	assert.Equal(t, "php-fpm", ev.Process.ParentComm)
	assert.Contains(t, SummaryLine(ev), "php-fpm -> sh",
		"the one-line summary is what an operator reads first, and it renders the lineage")
}
