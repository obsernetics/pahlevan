package grpcapi

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

var testNow = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func denialEvent(t export.EventType, ns, pod string) *export.Event {
	ev := &export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(testNow),
		Type:       t,
		Action:     export.ActionDeny,
		CgroupID:   42,
		Process:    export.ProcessInfo{PID: 400, Comm: "nc"},
		Kubernetes: &export.KubernetesRef{Namespace: ns, Pod: pod, Node: "node-1"},
	}
	switch t {
	case export.EventTypeFile:
		ev.File = &export.FileInfo{Path: "/etc/shadow"}
	case export.EventTypeProcess:
		ev.Exec = &export.ExecInfo{
			Binary: "/usr/bin/nc", Args: []string{"nc", "-e", "/bin/sh"},
			CommandLine: "nc -e /bin/sh",
		}
	case export.EventTypeNetwork:
		ev.Network = &export.NetworkInfo{DestinationIP: "10.0.0.1", DestinationPort: 4444}
	}
	return ev
}

// dialServer starts the service over an in-memory listener, which exercises the
// real gRPC stack without binding a port.
func dialServer(t *testing.T, s *Server) apiv1alpha1.EventServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.serveListener(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = lis.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return apiv1alpha1.NewEventServiceClient(conn)
}

// The point of the API: a client subscribes and receives events as they happen.
func TestSubscribeStreamsEvents(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
	require.NoError(t, err)

	// Wait for the server to register the subscriber before publishing.
	require.Eventually(t, func() bool { return s.Subscribers() == 1 },
		5*time.Second, 10*time.Millisecond)

	s.Enqueue(denialEvent(export.EventTypeProcess, "prod", "nginx-1"))

	got, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, apiv1alpha1.EventType_EVENT_TYPE_PROCESS, got.GetType())
	assert.Equal(t, apiv1alpha1.Action_ACTION_DENY, got.GetAction())
	assert.Equal(t, "prod", got.GetKubernetes().GetNamespace())
	assert.Equal(t, "node-1", got.GetKubernetes().GetNode())

	// The detail an analyst actually reads has to survive the wire.
	exec := got.GetExec()
	require.NotNil(t, exec)
	assert.Equal(t, []string{"nc", "-e", "/bin/sh"}, exec.GetArgs())
	assert.Equal(t, "nc -e /bin/sh", exec.GetCommandLine())
}

func TestSubscribeFiltersByType(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{
		Types: []apiv1alpha1.EventType{apiv1alpha1.EventType_EVENT_TYPE_FILE},
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Subscribers() == 1 }, 5*time.Second, 10*time.Millisecond)

	// The network event must be filtered out, so the file event that follows is
	// the first thing received.
	s.Enqueue(denialEvent(export.EventTypeNetwork, "prod", "nginx-1"))
	s.Enqueue(denialEvent(export.EventTypeFile, "prod", "nginx-1"))

	got, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, apiv1alpha1.EventType_EVENT_TYPE_FILE, got.GetType())
}

func TestSubscribeFiltersDenialsOnly(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{DenialsOnly: true})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Subscribers() == 1 }, 5*time.Second, 10*time.Millisecond)

	observed := denialEvent(export.EventTypeFile, "prod", "nginx-1")
	observed.Action = export.ActionObserve
	s.Enqueue(observed)
	s.Enqueue(denialEvent(export.EventTypeFile, "prod", "nginx-1"))

	got, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, apiv1alpha1.Action_ACTION_DENY, got.GetAction(),
		"an observed event must not reach a denials-only subscriber")
}

// An unattributed event is not evidence that it belongs to the namespace being
// asked for, so a namespace filter must exclude it.
func TestSubscribeNamespaceFilterExcludesUnattributed(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{Namespace: "prod"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Subscribers() == 1 }, 5*time.Second, 10*time.Millisecond)

	unattributed := denialEvent(export.EventTypeFile, "", "")
	unattributed.Kubernetes = nil
	s.Enqueue(unattributed)
	s.Enqueue(denialEvent(export.EventTypeFile, "dev", "other"))
	s.Enqueue(denialEvent(export.EventTypeFile, "prod", "nginx-1"))

	got, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "prod", got.GetKubernetes().GetNamespace())
}

// A subscriber that stops reading must lose events rather than stall the data
// plane. Blocking here would back-pressure into the ring-buffer reader and cost
// every other consumer too.
func TestSlowSubscriberDropsRatherThanBlocks(t *testing.T) {
	s := New(Options{QueueSize: 4})

	// Attach a subscriber directly: a real stream would drain, and the point is
	// what happens when nothing does.
	sub := &subscriber{ch: make(chan *apiv1alpha1.Event, 4)}
	s.mu.Lock()
	s.subs[1] = sub
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			s.Enqueue(denialEvent(export.EventTypeFile, "prod", "nginx-1"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue blocked on a subscriber that is not reading")
	}

	assert.Len(t, sub.ch, 4, "the queue is bounded")
	assert.Equal(t, uint64(996), s.Dropped(),
		"every dropped event must be counted, or a gap looks like a quiet period")
}

// With nobody attached, publishing must be free and must not count drops.
func TestEnqueueWithNoSubscribers(t *testing.T) {
	s := New(Options{})
	assert.True(t, s.Enqueue(denialEvent(export.EventTypeFile, "prod", "p")))
	assert.Zero(t, s.Dropped())
	assert.Zero(t, s.Subscribers())
	assert.True(t, s.Enqueue(nil) == false, "a nil event is not publishable")
}

// A subscriber that goes away must be forgotten, or its queue pins retained
// events for the life of the agent.
func TestSubscriberIsRemovedOnDisconnect(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Subscribers() == 1 }, 5*time.Second, 10*time.Millisecond)

	cancel()
	_, _ = stream.Recv()
	assert.Eventually(t, func() bool { return s.Subscribers() == 0 },
		5*time.Second, 10*time.Millisecond, "the subscriber must be dropped when the client goes away")
}

// Status answers "is this working", which is a different question from "are
// there events". A fleet tracking containers and enforcing none is the
// quietest possible failure.
func TestGetStatus(t *testing.T) {
	s := New(Options{Status: func() Status {
		return Status{
			Node: "node-1", ContainersTracked: 7, ContainersLearning: 5,
			ContainersEnforcing: 2, Version: "v2.1.0",
		}
	}})
	client := dialServer(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	require.NoError(t, err)

	assert.Equal(t, "node-1", resp.GetNode())
	assert.Equal(t, int32(7), resp.GetContainersTracked())
	assert.Equal(t, int32(5), resp.GetContainersLearning())
	assert.Equal(t, int32(2), resp.GetContainersEnforcing())
	assert.Equal(t, "v2.1.0", resp.GetVersion())
}

// Without a status source the RPC must still answer rather than fail.
func TestGetStatusWithoutSource(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	require.NoError(t, err)
	assert.Zero(t, resp.GetContainersTracked())
}

// Two subscribers with different filters must each get their own view.
func TestMultipleSubscribersAreIndependent(t *testing.T) {
	s := New(Options{})
	client := dialServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	all, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
	require.NoError(t, err)
	files, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{
		Types: []apiv1alpha1.EventType{apiv1alpha1.EventType_EVENT_TYPE_FILE},
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Subscribers() == 2 }, 5*time.Second, 10*time.Millisecond)

	s.Enqueue(denialEvent(export.EventTypeNetwork, "prod", "p"))
	s.Enqueue(denialEvent(export.EventTypeFile, "prod", "p"))

	first, err := all.Recv()
	require.NoError(t, err)
	assert.Equal(t, apiv1alpha1.EventType_EVENT_TYPE_NETWORK, first.GetType())

	only, err := files.Recv()
	require.NoError(t, err)
	assert.Equal(t, apiv1alpha1.EventType_EVENT_TYPE_FILE, only.GetType())
}

// The server is an export.Sink, so it drops into the same pipeline as the file
// and webhook sinks rather than tapping the stream separately.
func TestServerSatisfiesTheExportSink(t *testing.T) {
	var _ interface{ Enqueue(*export.Event) bool } = New(Options{})
}

func BenchmarkEnqueueNoSubscribers(b *testing.B) {
	s := New(Options{})
	ev := denialEvent(export.EventTypeFile, "prod", "p")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Enqueue(ev)
	}
}

func BenchmarkEnqueueOneSubscriber(b *testing.B) {
	s := New(Options{QueueSize: 1 << 16})
	sub := &subscriber{ch: make(chan *apiv1alpha1.Event, 1<<16)}
	s.subs[1] = sub
	go func() {
		for range sub.ch {
		}
	}()
	ev := denialEvent(export.EventTypeFile, "prod", "p")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Enqueue(ev)
	}
}
