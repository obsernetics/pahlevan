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
