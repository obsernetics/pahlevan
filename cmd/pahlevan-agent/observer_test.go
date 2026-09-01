package main

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/obsernetics/pahlevan/internal/netmap"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func newTestObserver() *agentObserver {
	return &agentObserver{log: logr.Discard()}
}

func TestAgentObserver_HandleSyscallEvent(t *testing.T) {
	o := newTestObserver()

	require.NoError(t, o.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 1, Comm: "curl", CgroupID: 1, PID: 100}))

	syscalls, _, _, _, _, denials := o.Counts()
	assert.Equal(t, uint64(1), syscalls)
	assert.Equal(t, uint64(0), denials)
}

func TestAgentObserver_HandleSyscallEvent_SampledSummary(t *testing.T) {
	o := newTestObserver()
	for i := 0; i < 1000; i++ {
		require.NoError(t, o.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: uint64(i), Comm: "app"}))
	}

	syscalls, _, _, _, _, _ := o.Counts()
	assert.Equal(t, uint64(1000), syscalls)
}

func BenchmarkAgentObserver_HandleSyscallEvent(b *testing.B) {
	o := newTestObserver()
	e := &ebpf.SyscallEvent{SyscallNr: 1, Comm: "app", CgroupID: 1, PID: 100}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = o.HandleSyscallEvent(e)
	}
}

func TestAgentObserver_HandleNetworkEvent(t *testing.T) {
	t.Run("allowed connect", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleNetworkEvent(&ebpf.NetworkEvent{DstIP: 0x0100007f, DstPort: 443, Comm: "curl"}))

		_, networks, _, _, _, denials := o.Counts()
		assert.Equal(t, uint64(1), networks)
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("denied connect", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleNetworkEvent(&ebpf.NetworkEvent{
			DstIP: 0x0100007f, DstPort: 4444, Direction: ebpf.DeniedDirection, Comm: "nc",
		}))

		_, networks, _, _, _, denials := o.Counts()
		assert.Equal(t, uint64(1), networks)
		assert.Equal(t, uint64(1), denials)
	})
}

func TestAgentObserver_HandleFileEvent(t *testing.T) {
	t.Run("allowed read", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleFileEvent(&ebpf.FileEvent{Path: "/etc/passwd", Comm: "cat"}))

		_, _, files, _, _, denials := o.Counts()
		assert.Equal(t, uint64(1), files)
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("denied write", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleFileEvent(&ebpf.FileEvent{
			Path: "/etc/shadow", Comm: "vi", Flags: ebpf.WriteFlag | ebpf.DeniedFlag,
		}))

		_, _, files, _, _, denials := o.Counts()
		assert.Equal(t, uint64(1), files)
		assert.Equal(t, uint64(1), denials)
	})
}

func TestAgentObserver_HandleProcessEvent(t *testing.T) {
	t.Run("exit is not counted as an exec", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleProcessEvent(&ebpf.ProcessEvent{Comm: "sh", Flags: ebpf.ExitedFlag}))

		_, _, _, execs, _, denials := o.Counts()
		assert.Equal(t, uint64(0), execs)
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("plain exec", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleProcessEvent(&ebpf.ProcessEvent{Comm: "nginx", Filename: "/usr/sbin/nginx"}))

		_, _, _, execs, _, denials := o.Counts()
		assert.Equal(t, uint64(1), execs)
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("denied exec", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleProcessEvent(&ebpf.ProcessEvent{
			Comm: "curl", Filename: "/usr/bin/curl", Flags: ebpf.DeniedFlag,
		}))

		_, _, _, execs, _, denials := o.Counts()
		assert.Equal(t, uint64(1), execs)
		assert.Equal(t, uint64(1), denials)
	})

	t.Run("breakout is denied even without the denied flag", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleProcessEvent(&ebpf.ProcessEvent{
			Comm: "sh", Filename: "/bin/sh", Flags: ebpf.BreakoutFlag, Cwd: "/host",
		}))

		_, _, _, execs, _, denials := o.Counts()
		assert.Equal(t, uint64(1), execs)
		assert.Equal(t, uint64(1), denials)
	})

	t.Run("interactive shell traced when enabled with a manager", func(t *testing.T) {
		o := newTestObserver()
		o.traceShells = true
		o.mgr = &ebpf.Manager{}

		assert.NotPanics(t, func() {
			_ = o.HandleProcessEvent(&ebpf.ProcessEvent{Comm: "bash", Filename: "/bin/bash", PID: 42})
		})
	})

	t.Run("interactive shell tracing disabled by default", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleProcessEvent(&ebpf.ProcessEvent{Comm: "bash", Filename: "/bin/bash", PID: 42}))
	})
}

func TestAgentObserver_HandleCapabilityEvent(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleCapabilityEvent(&ebpf.CapabilityEvent{Capability: 21, Comm: "app"}))

		_, _, _, _, caps, denials := o.Counts()
		assert.Equal(t, uint64(1), caps)
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("denied", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleCapabilityEvent(&ebpf.CapabilityEvent{
			Capability: 21, Comm: "app", Flags: ebpf.DeniedFlag,
		}))

		_, _, _, _, caps, denials := o.Counts()
		assert.Equal(t, uint64(1), caps)
		assert.Equal(t, uint64(1), denials)
	})
}

func TestAgentObserver_HandleCredEvent(t *testing.T) {
	t.Run("explained by execve", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleCredEvent(&ebpf.CredEvent{
			Comm: "sudo", NewEUID: 0, Flags: ebpf.CredGainedRoot | ebpf.CredInExecve,
		}))

		creds, _ := o.EscalationCounts()
		assert.Equal(t, uint64(1), creds)
		_, _, _, _, _, denials := o.Counts()
		assert.Equal(t, uint64(0), denials)
	})

	t.Run("unexplained escalation is denied", func(t *testing.T) {
		o := newTestObserver()
		require.NoError(t, o.HandleCredEvent(&ebpf.CredEvent{
			Comm: "worker", NewEUID: 0, Flags: ebpf.CredGainedRoot,
		}))

		creds, _ := o.EscalationCounts()
		assert.Equal(t, uint64(1), creds)
		_, _, _, _, _, denials := o.Counts()
		assert.Equal(t, uint64(1), denials)
	})
}

func TestAgentObserver_HandleShellEvent(t *testing.T) {
	o := newTestObserver()
	require.NoError(t, o.HandleShellEvent(&ebpf.ShellEvent{Line: "cat /etc/passwd", UID: 0, Comm: "bash"}))

	_, shell := o.EscalationCounts()
	assert.Equal(t, uint64(1), shell)
}

func TestAgentObserver_CountsAndEscalationCountsStartAtZero(t *testing.T) {
	o := newTestObserver()

	syscalls, networks, files, execs, caps, denials := o.Counts()
	assert.Zero(t, syscalls)
	assert.Zero(t, networks)
	assert.Zero(t, files)
	assert.Zero(t, execs)
	assert.Zero(t, caps)
	assert.Zero(t, denials)

	creds, shell := o.EscalationCounts()
	assert.Zero(t, creds)
	assert.Zero(t, shell)
}

func newRefreshTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

func TestRefreshNetmap(t *testing.T) {
	t.Run("populates the resolver from cluster state", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.5"},
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"},
			Status:     corev1.PodStatus{PodIP: "10.0.0.6"},
		}
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		}
		fc := fake.NewClientBuilder().WithScheme(newRefreshTestScheme(t)).WithObjects(svc, pod, node).Build()
		r := netmap.New()

		err := refreshNetmap(context.Background(), fc, r)
		require.NoError(t, err)
	})

	t.Run("List errors are aggregated rather than returned on first failure", func(t *testing.T) {
		// A scheme with no registered types makes every List call fail, so this
		// exercises the error-collection path without needing three distinct
		// failure injections.
		fc := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
		r := netmap.New()

		err := refreshNetmap(context.Background(), fc, r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "services")
		assert.Contains(t, err.Error(), "pods")
		assert.Contains(t, err.Error(), "nodes")
	})
}
