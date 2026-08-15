// Package grpcapi serves Pahlevan's event stream over gRPC.
//
// This is the integration surface. Until it existed, events reached a
// JSON-lines file and an HTTP webhook and nothing else, so integrating meant
// tailing a file on every node. A streaming API is what lets a collector, a
// SIEM shipper, or the CLI subscribe to an agent and receive events as they
// happen, which is the shape both comparators offer and the one every
// downstream tool already expects.
package grpcapi

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// DefaultSubscriberQueue is how many events a single subscriber may fall
// behind by before it starts losing them.
//
// The number is a deliberate compromise. Too small and a brief scheduling
// hiccup costs events; too large and a subscriber that has silently gone away
// pins megabytes of retained events per stream. 1024 events is roughly a
// second of a busy node.
const DefaultSubscriberQueue = 1024

// StatusFunc reports what the agent is currently doing. It is a function so the
// server does not need to know about the adaptive controller.
type StatusFunc func() Status

// Status is the answer to "is this thing working", which is a different
// question from "are there events".
type Status struct {
	Node                string
	ContainersTracked   int32
	ContainersLearning  int32
	ContainersEnforcing int32
	Version             string
}

// Server streams events to gRPC subscribers.
//
// It is also an export.Sink, so it plugs into the same pipeline as the file
// and webhook sinks rather than tapping the event stream separately. That
// matters: one path means every consumer sees the same event with the same
// attribution, instead of two representations drifting apart.
type Server struct {
	apiv1alpha1.UnimplementedEventServiceServer

	queueSize int
	status    StatusFunc

	mu     sync.RWMutex
	nextID uint64
	subs   map[uint64]*subscriber

	// dropped counts events a subscriber could not keep up with. A dropped
	// event must be countable, never silent, or a gap in a SIEM looks like a
	// quiet period.
	dropped atomic.Uint64
}

type subscriber struct {
	ch chan *apiv1alpha1.Event
	// The filter is flattened out of the request rather than holding the
	// protobuf message: a generated message embeds a MessageState containing a
	// mutex, so copying or storing one by value is a vet error and a real
	// hazard.
	filter filter
}

// filter is a subscription's criteria, extracted once at subscribe time so the
// hot path does no protobuf accessor calls per event per subscriber.
type filter struct {
	types       map[apiv1alpha1.EventType]struct{}
	denialsOnly bool
	namespace   string
	pod         string
}

func newFilter(req *apiv1alpha1.SubscribeRequest) filter {
	f := filter{
		denialsOnly: req.GetDenialsOnly(),
		namespace:   req.GetNamespace(),
		pod:         req.GetPod(),
	}
	if ts := req.GetTypes(); len(ts) > 0 {
		f.types = make(map[apiv1alpha1.EventType]struct{}, len(ts))
		for _, t := range ts {
			f.types[t] = struct{}{}
		}
	}
	return f
}

// matches applies the criteria to an event.
func (f *filter) matches(ev *apiv1alpha1.Event) bool {
	if f.denialsOnly && ev.GetAction() != apiv1alpha1.Action_ACTION_DENY {
		return false
	}
	if f.types != nil {
		if _, ok := f.types[ev.GetType()]; !ok {
			return false
		}
	}
	// A namespace or pod filter excludes events that could not be attributed:
	// an unattributed event is not evidence that it belongs to the namespace
	// asked for.
	if f.namespace != "" && ev.GetKubernetes().GetNamespace() != f.namespace {
		return false
	}
	if f.pod != "" && ev.GetKubernetes().GetPod() != f.pod {
		return false
	}
	return true
}

// Options configures a Server.
type Options struct {
	// QueueSize bounds how far one subscriber may fall behind. Zero uses
	// DefaultSubscriberQueue.
	QueueSize int
	// Status reports agent state for GetStatus. Nil reports zeroes.
	Status StatusFunc
}

// New returns a Server ready to be registered on a grpc.Server and attached to
// an export pipeline.
func New(opts Options) *Server {
	q := opts.QueueSize
	if q <= 0 {
		q = DefaultSubscriberQueue
	}
	return &Server{
		queueSize: q,
		status:    opts.Status,
		subs:      make(map[uint64]*subscriber),
	}
}

// Enqueue implements export.Enqueuer, so the server is just another sink on the
// existing pipeline.
//
// It never blocks. A subscriber that cannot keep up loses events and the loss
// is counted; stalling here would back-pressure all the way into the
// ring-buffer reader and cost every other consumer too.
func (s *Server) Enqueue(ev *export.Event) bool {
	if ev == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.subs) == 0 {
		return true
	}

	// Converted once and shared: the message is read-only from here on.
	msg := ToProto(ev)
	for _, sub := range s.subs {
		if !sub.filter.matches(msg) {
			continue
		}
		select {
		case sub.ch <- msg:
		default:
			s.dropped.Add(1)
		}
	}
	return true
}

// Dropped reports how many events subscribers have missed.
func (s *Server) Dropped() uint64 { return s.dropped.Load() }

// Subscribers reports how many streams are attached.
func (s *Server) Subscribers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

// Subscribe implements the streaming RPC.
func (s *Server) Subscribe(req *apiv1alpha1.SubscribeRequest, stream apiv1alpha1.EventService_SubscribeServer) error {
	if req == nil {
		req = &apiv1alpha1.SubscribeRequest{}
	}
	sub := &subscriber{
		ch:     make(chan *apiv1alpha1.Event, s.queueSize),
		filter: newFilter(req),
	}

	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = sub
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subs, id)
		s.mu.Unlock()
		// Not closed: Enqueue may still hold a reference under the read lock,
		// and sending on a closed channel would panic the data plane. Dropping
		// the reference is enough; the buffered events are garbage collected.
	}()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-sub.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// GetStatus implements the status RPC.
func (s *Server) GetStatus(_ context.Context, _ *apiv1alpha1.StatusRequest) (*apiv1alpha1.StatusResponse, error) {
	var st Status
	if s.status != nil {
		st = s.status()
	}
	return &apiv1alpha1.StatusResponse{
		Node:                st.Node,
		ContainersTracked:   st.ContainersTracked,
		ContainersLearning:  st.ContainersLearning,
		ContainersEnforcing: st.ContainersEnforcing,
		Subscribers:         int32(s.Subscribers()),
		EventsDropped:       s.Dropped(),
		Version:             st.Version,
	}, nil
}

// Serve registers the service on a new gRPC server and serves it on addr until
// the context is cancelled.
//
// Health and reflection are registered too: reflection is what lets grpcurl and
// generic collectors discover the service without the .proto, which is most of
// what makes an API integrable in practice.
func (s *Server) Serve(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	return s.serveListener(ctx, lis)
}

func (s *Server) serveListener(ctx context.Context, lis net.Listener) error {
	gs := grpc.NewServer()
	apiv1alpha1.RegisterEventServiceServer(gs, s)

	hs := health.NewServer()
	hs.SetServingStatus("pahlevan.v1alpha1.EventService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)
	reflection.Register(gs)

	done := make(chan error, 1)
	go func() { done <- gs.Serve(lis) }()

	select {
	case <-ctx.Done():
		// GracefulStop lets in-flight sends finish, so a subscriber does not
		// see a truncated stream on a normal shutdown.
		gs.GracefulStop()
		return nil
	case err := <-done:
		return err
	}
}
