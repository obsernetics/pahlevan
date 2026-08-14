package main

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
}

func newPolicyResolver(c client.Client, nodeName string) *policyResolver {
	return &policyResolver{c: c, nodeName: nodeName, podsByUID: map[string]*corev1.Pod{}}
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

	r.mu.Lock()
	r.podsByUID = byUID
	r.policies = policies.Items
	r.mu.Unlock()
	return nil
}

// Resolve implements adaptive.PolicyResolver.
func (r *policyResolver) Resolve(_ uint64, ref attribution.ContainerRef) (time.Duration, bool, bool) {
	if ref.PodUID == "" {
		return 0, false, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	pod, ok := r.podsByUID[ref.PodUID]
	if !ok {
		return 0, false, false
	}
	for i := range r.policies {
		pol := &r.policies[i]
		if !selectorMatches(pol.Spec.Selector, pod) {
			continue
		}
		window := time.Duration(0)
		if pol.Spec.LearningConfig.Duration != nil {
			window = pol.Spec.LearningConfig.Duration.Duration
		}
		blocking := pol.Spec.EnforcementConfig.Mode == policyv1alpha1.EnforcementModeBlocking &&
			!pol.Spec.EnforcementConfig.AlertOnly
		return window, blocking, true
	}
	return 0, false, false
}

// selectorMatches evaluates a PahlevanPolicy LabelSelector (matchLabels +
// matchExpressions + namespace scoping) against a pod.
func selectorMatches(sel policyv1alpha1.LabelSelector, pod *corev1.Pod) bool {
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
