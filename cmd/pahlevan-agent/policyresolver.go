package main

import (
	"context"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	"github.com/obsernetics/pahlevan/internal/policy"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/attribution"
)

// policyResolver answers, for a given cgroup/container, which PahlevanPolicy
// governs it and how (learning window + whether it enforces). It maps
// cgroup -> pod (via attribution) -> labels -> matching policy.
//
// It caches pods on this node and all policies, refreshed periodically, so
// Resolve is cheap and lock-safe to call from the adaptive control loop.
type policyResolver struct {
	c        client.Client
	nodeName string

	mu        sync.RWMutex
	podsByUID map[string]*corev1.Pod
	policies  []policyv1alpha1.PahlevanPolicy
	// nsLabels backs namespaceSelector matching.
	nsLabels map[string]map[string]string

	// warned de-duplicates translation warnings so an unrepresentable rule is
	// reported once rather than on every reconcile.
	warned sync.Map
}

func newPolicyResolver(c client.Client, nodeName string) *policyResolver {
	return &policyResolver{
		c:         c,
		nodeName:  nodeName,
		podsByUID: map[string]*corev1.Pod{},
		nsLabels:  map[string]map[string]string{},
	}
}

// Refresh reloads the node's pods and the cluster's policies into the cache.
func (r *policyResolver) Refresh(ctx context.Context) error {
	var pods corev1.PodList
	opts := []client.ListOption{}
	if r.nodeName != "" {
		opts = append(opts, client.MatchingFields{"spec.nodeName": r.nodeName})
	}
	if err := r.c.List(ctx, &pods, opts...); err != nil {
		return err
	}
	byUID := make(map[string]*corev1.Pod, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		byUID[string(p.UID)] = p
	}

	var policies policyv1alpha1.PahlevanPolicyList
	if err := r.c.List(ctx, &policies); err != nil {
		return err
	}

	// Namespace labels back namespaceSelector. Listing namespaces is cheap
	// relative to the pod list and only happens on the refresh tick.
	var namespaces corev1.NamespaceList
	nsLabels := map[string]map[string]string{}
	if err := r.c.List(ctx, &namespaces); err != nil {
		// A cluster that denies namespace list should still enforce the
		// unscoped policies, so degrade rather than fail the whole refresh.
		log.Log.WithName("policy").V(1).Info("cannot list namespaces; namespaceSelector will not match",
			"error", err.Error())
	} else {
		for i := range namespaces.Items {
			ns := &namespaces.Items[i]
			nsLabels[ns.Name] = ns.Labels
		}
	}

	r.mu.Lock()
	r.podsByUID = byUID
	r.policies = policies.Items
	if len(nsLabels) > 0 {
		r.nsLabels = nsLabels
	}
	r.mu.Unlock()
	return nil
}

// Resolve implements adaptive.PolicyResolver. The full spec is translated, not
// just the learning window and the mode; see internal/policy.
func (r *policyResolver) Resolve(_ uint64, ref attribution.ContainerRef) (adaptive.Decision, bool) {
	if ref.PodUID == "" {
		return adaptive.Decision{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	pod, ok := r.podsByUID[ref.PodUID]
	if !ok {
		return adaptive.Decision{}, false
	}
	for i := range r.policies {
		pol := &r.policies[i]
		if !r.selectorMatches(pol.Spec.Selector, pod) {
			continue
		}
		d, warnings := policy.Translate(pol.Name, pol.Spec, time.Now())
		r.noteWarnings(pol.Name, warnings)
		return d, true
	}
	return adaptive.Decision{}, false
}

// noteWarnings logs each translation warning once per policy generation. A
// policy whose rules cannot be represented must say so; repeating it on every
// reconcile would bury it instead. Callers must hold at least r.mu.RLock.
func (r *policyResolver) noteWarnings(name string, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	key := name + "\x00" + strings.Join(warnings, "\x00")
	if _, seen := r.warned.Load(key); seen {
		return
	}
	r.warned.Store(key, struct{}{})
	for _, w := range warnings {
		log.Log.WithName("policy").Info("policy rule is not fully representable",
			"policy", name, "warning", w)
	}
}

// selectorMatches evaluates a PahlevanPolicy LabelSelector (matchLabels +
// matchExpressions + namespace scoping) against a pod. Callers must hold r.mu.
func (r *policyResolver) selectorMatches(sel policyv1alpha1.LabelSelector, pod *corev1.Pod) bool {
	labels := pod.Labels
	for k, v := range sel.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, req := range sel.MatchExpressions {
		if !requirementMatches(req, labels) {
			return false
		}
	}
	// namespaceSelector was accepted by the CRD and then ignored, so a policy
	// scoped to one namespace silently governed the whole cluster. It matches
	// against the namespace's own labels; Kubernetes stamps every namespace
	// with kubernetes.io/metadata.name, so selecting by name works too.
	if sel.NamespaceSelector != nil {
		nsLabels, known := r.nsLabels[pod.Namespace]
		if !known {
			// Fail closed: an unknown namespace must not match a scoped policy.
			return false
		}
		for k, v := range sel.NamespaceSelector.MatchLabels {
			if nsLabels[k] != v {
				return false
			}
		}
		for _, req := range sel.NamespaceSelector.MatchExpressions {
			if !requirementMatches(req, nsLabels) {
				return false
			}
		}
	}
	return true
}

func requirementMatches(req policyv1alpha1.LabelSelectorRequirement, labels map[string]string) bool {
	val, has := labels[req.Key]
	switch req.Operator {
	case "In":
		if !has {
			return false
		}
		return contains(req.Values, val)
	case "NotIn":
		if !has {
			return true
		}
		return !contains(req.Values, val)
	case "Exists":
		return has
	case "DoesNotExist":
		return !has
	default:
		return false
	}
}

func contains(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// PodMeta resolves a pod UID to its namespace and name from the cached pods.
func (r *policyResolver) PodMeta(podUID string) (string, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.podsByUID[podUID]; ok {
		return p.Namespace, p.Name, true
	}
	return "", "", false
}

// PodDetail is what an exported event needs beyond a namespace and a name: the
// workload that owns the pod, and the labels a policy selected it by. A pod
// name is ephemeral, so a denial attributed only to one is hard to act on.
func (r *policyResolver) PodDetail(podUID string) (detail PodDetail, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, found := r.podsByUID[podUID]
	if !found {
		return PodDetail{}, false
	}
	if len(p.Labels) > 0 {
		// Copied: the caller keeps this in an exported event and the cache is
		// replaced wholesale on every refresh.
		detail.Labels = make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			detail.Labels[k] = v
		}
	}
	detail.WorkloadKind, detail.WorkloadName = ownerWorkload(p)
	return detail, true
}

// PodDetail is what an exported event needs beyond a namespace and a name.
type PodDetail struct {
	WorkloadKind string
	WorkloadName string
	Labels       map[string]string
	// Container and Image name the specific container inside the pod. Both
	// competitors put the image on every event, and it is often the first
	// thing an analyst asks for: a denial in "nginx:1.27" and one in a
	// hand-built image are very different findings.
	Container string
	Image     string
}

// ContainerDetail resolves the runtime container id the cgroup gave us to the
// container's name and image.
//
// The cgroup path yields a bare 64-hex id, while Kubernetes reports
// containerID as "<runtime>://<id>", so the scheme is stripped before
// comparing. Init and ephemeral containers are searched too, since a denial
// during init is exactly the kind of thing worth attributing precisely.
func (r *policyResolver) ContainerDetail(podUID, containerID string) (name, image string, ok bool) {
	if containerID == "" {
		return "", "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, found := r.podsByUID[podUID]
	if !found {
		return "", "", false
	}
	for _, list := range [][]corev1.ContainerStatus{
		p.Status.ContainerStatuses,
		p.Status.InitContainerStatuses,
		p.Status.EphemeralContainerStatuses,
	} {
		for i := range list {
			cs := &list[i]
			if runtimeContainerID(cs.ContainerID) != containerID {
				continue
			}
			// ImageID is the digest-pinned reference and is the more useful
			// answer, but it is empty until the image is pulled, so Image is
			// the fallback rather than the other way round.
			img := cs.Image
			if img == "" {
				img = cs.ImageID
			}
			return cs.Name, img, true
		}
	}
	return "", "", false
}

// runtimeContainerID strips the "<runtime>://" scheme Kubernetes prefixes onto
// containerID, leaving the bare id the cgroup path carries.
func runtimeContainerID(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

// ownerWorkload walks one level up from the pod's controller reference, and a
// second level for the ReplicaSet a Deployment owns, which is the only
// indirection worth unwinding: nobody thinks in ReplicaSets.
func ownerWorkload(p *corev1.Pod) (kind, name string) {
	for i := range p.OwnerReferences {
		ref := &p.OwnerReferences[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			// A ReplicaSet is named <deployment>-<pod-template-hash>. Trimming
			// the hash is how kubectl presents it too.
			if idx := strings.LastIndex(ref.Name, "-"); idx > 0 {
				return "Deployment", ref.Name[:idx]
			}
		}
		return ref.Kind, ref.Name
	}
	return "", ""
}
