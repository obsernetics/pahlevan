package netidentity

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
)

// Feeding the index.
//
// There are two ways in and the store needs both.
//
// Handler is the watch feed. It is the one that matters for correctness,
// because the whole point of this index is that a dead pod stops answering for
// its address before the CNI hands that address to somebody else, and that is
// a question of milliseconds rather than of a refresh interval.
//
// Sync is a periodic reconciliation against the informer cache. A watch feed
// alone is not enough: a dropped or mis-handled delete leaves a binding that
// nothing will ever remove, and a binding that outlives its pod is exactly the
// stale-identity failure. Sync is the thing that notices and fixes it.

// Handler adapts a Store to a client-go ResourceEventHandler. Register it on
// the Pod, Service, Node and Namespace informers; it dispatches on the object
// type, so one handler serves all four.
func (s *Store) Handler() toolscache.ResourceEventHandler {
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { s.observe(obj) },
		UpdateFunc: func(_, obj interface{}) { s.observe(obj) },
		DeleteFunc: func(obj interface{}) { s.forget(obj) },
	}
}

func (s *Store) observe(obj interface{}) {
	switch o := obj.(type) {
	case *corev1.Pod:
		s.UpsertPod(o)
	case *corev1.Service:
		s.UpsertService(o)
	case *corev1.Node:
		s.UpsertNode(o)
	case *corev1.Namespace:
		s.UpsertNamespace(o)
	}
}

// forget handles a delete, including the DeletedFinalStateUnknown wrapper the
// informer delivers when it missed the delete and noticed on relist. That
// wrapper is not an edge case to skip: it is precisely the case where a pod
// died and the watch did not say so, which is the one that leaves a dead
// identity answering for a recycled address.
func (s *Store) forget(obj interface{}) {
	if tomb, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	switch o := obj.(type) {
	case *corev1.Pod:
		s.DeletePod(o)
	case *corev1.Service:
		s.DeleteService(o)
	case *corev1.Node:
		s.DeleteNode(o)
	case *corev1.Namespace:
		s.DeleteNamespace(o)
	}
}

// Snapshot is the cluster state a Sync reconciles against. Taken as plain
// slices rather than as a client so this package is testable without a fake
// API server, and so the informer wiring stays in the one place that has it.
type Snapshot struct {
	Pods       []corev1.Pod
	Services   []corev1.Service
	Nodes      []corev1.Node
	Namespaces []corev1.Namespace
}

// Sync reconciles the index against a full listing.
//
// Everything present is upserted, and anything the index holds that the
// listing does not mention is withdrawn and tombstoned, exactly as a delete
// would. A partial snapshot would therefore withdraw live identities, so a
// caller whose List failed must not pass an empty slice for that kind: leave
// the field nil and Sync skips that kind entirely.
func (s *Store) Sync(snap Snapshot) {
	if snap.Namespaces != nil {
		live := make(map[string]struct{}, len(snap.Namespaces))
		for i := range snap.Namespaces {
			ns := &snap.Namespaces[i]
			live[ns.Name] = struct{}{}
			s.UpsertNamespace(ns)
		}
		s.mu.Lock()
		for name := range s.nsLabels {
			if _, ok := live[name]; !ok {
				delete(s.nsLabels, name)
			}
		}
		s.mu.Unlock()
	}

	if snap.Pods != nil {
		live := make(map[types.UID]struct{}, len(snap.Pods))
		for i := range snap.Pods {
			p := &snap.Pods[i]
			live[objectKey(PeerPod, p.Namespace, p.Name, p.UID)] = struct{}{}
			s.UpsertPod(p)
		}
		s.reapPods(live)
	}
	if snap.Services != nil {
		live := make(map[types.UID]struct{}, len(snap.Services))
		for i := range snap.Services {
			svc := &snap.Services[i]
			live[objectKey(PeerService, svc.Namespace, svc.Name, svc.UID)] = struct{}{}
			s.UpsertService(svc)
		}
		s.reapOwners(PeerService, live)
	}
	if snap.Nodes != nil {
		live := make(map[types.UID]struct{}, len(snap.Nodes))
		for i := range snap.Nodes {
			n := &snap.Nodes[i]
			live[objectKey(PeerNode, "", n.Name, n.UID)] = struct{}{}
			s.UpsertNode(n)
		}
		s.reapOwners(PeerNode, live)
	}
}

// reapPods withdraws every pod the listing did not mention. Pods are reaped
// from their own table rather than from the owner table because a pod with no
// address yet holds no claims but is still indexed for selector matching.
func (s *Store) reapPods(live map[types.UID]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []types.UID
	for uid := range s.pods {
		if _, ok := live[uid]; !ok {
			gone = append(gone, uid)
		}
	}
	for _, uid := range gone {
		delete(s.pods, uid)
		s.removeOwnerLocked(uid, nil)
	}
}

func (s *Store) reapOwners(kind PeerKind, live map[types.UID]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []types.UID
	for uid, o := range s.owned {
		if o.kind != kind {
			continue
		}
		if _, ok := live[uid]; !ok {
			gone = append(gone, uid)
		}
	}
	for _, uid := range gone {
		s.removeOwnerLocked(uid, nil)
	}
}
