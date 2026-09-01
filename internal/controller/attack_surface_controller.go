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

package controller

import (
	"context"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"
	"github.com/obsernetics/pahlevan/pkg/visualization"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// AttackSurfaceAnalyzerReconciler manages cluster-wide attack surface analysis
type AttackSurfaceAnalyzerReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	EBPFManager           *ebpf.Manager
	MetricsManager        *metrics.Manager
	ObservabilityManager  *observability.Manager
	AttackSurfaceAnalyzer *visualization.AttackSurfaceAnalyzer
	AnalysisInterval      time.Duration
	LastFullAnalysis      time.Time
}

//+kubebuilder:rbac:groups="",resources=pods;services;configmaps;secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=deployments;replicasets;daemonsets;statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies;ingresses,verbs=get;list;watch
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;update;patch

func (r *AttackSurfaceAnalyzerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// This controller performs cluster-wide analysis, so we don't reconcile specific resources
	// Instead, we trigger analysis based on timing and significant cluster changes

	shouldAnalyze := false

	// Check if enough time has passed since last analysis
	if time.Since(r.LastFullAnalysis) >= r.AnalysisInterval {
		shouldAnalyze = true
		logger.Info("Triggering attack surface analysis due to time interval")
	}

	// Check if this is a significant resource change that warrants immediate analysis
	if r.isSignificantChange(ctx, req) {
		shouldAnalyze = true
		logger.Info("Triggering attack surface analysis due to significant change", "resource", req.NamespacedName)
	}

	if shouldAnalyze {
		if err := r.performClusterAnalysis(ctx); err != nil {
			logger.Error(err, "Failed to perform cluster attack surface analysis")
			return ctrl.Result{RequeueAfter: 5 * time.Minute}, err
		}
		r.LastFullAnalysis = time.Now()
	}

	// Requeue for next analysis interval
	return ctrl.Result{RequeueAfter: r.AnalysisInterval}, nil
}

func (r *AttackSurfaceAnalyzerReconciler) performClusterAnalysis(ctx context.Context) error {
	logger := log.FromContext(ctx)
	logger.Info("Starting cluster-wide attack surface analysis")

	startTime := time.Now()

	// The analyzer is a required collaborator; without it there is no analysis to
	// run, so skip cleanly instead of panicking on a nil dereference.
	if r.AttackSurfaceAnalyzer == nil {
		logger.Info("Attack surface analyzer not configured; skipping analysis")
		return nil
	}

	// Perform comprehensive cluster analysis
	clusterGraph, err := r.AttackSurfaceAnalyzer.AnalyzeClusterAttackSurface()
	if err != nil {
		return err
	}

	// Analyze individual workloads
	if err := r.analyzeWorkloads(ctx); err != nil {
		logger.Error(err, "Failed to analyze workloads")
	}

	// Update metrics
	analysisTime := time.Since(startTime)
	logger.Info("Completed cluster attack surface analysis",
		"duration", analysisTime,
		"riskScore", clusterGraph.RiskAggregation.TotalRiskScore,
		"nodes", len(clusterGraph.Nodes),
		"edges", len(clusterGraph.Edges))

	r.exportAnalysisResults(ctx)

	return nil
}

func (r *AttackSurfaceAnalyzerReconciler) analyzeWorkloads(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Get all PahlevanPolicies to determine which workloads to analyze
	policies := &policyv1alpha1.PahlevanPolicyList{}
	if err := r.List(ctx, policies, &client.ListOptions{}); err != nil {
		return err
	}

	for _, policy := range policies.Items {
		// Find workloads targeted by this policy
		workloads, err := r.getTargetWorkloads(ctx, &policy)
		if err != nil {
			logger.Error(err, "Failed to get target workloads", "policy", policy.Name)
			continue
		}

		for _, workload := range workloads {
			workloadRef := learner.WorkloadReference{
				APIVersion: workload.GetObjectKind().GroupVersionKind().GroupVersion().String(),
				Kind:       workload.GetObjectKind().GroupVersionKind().Kind,
				Name:       workload.GetName(),
				Namespace:  workload.GetNamespace(),
				UID:        string(workload.GetUID()),
			}

			// Analyze attack surface for this workload
			surface, err := r.AttackSurfaceAnalyzer.AnalyzeWorkloadAttackSurface(workloadRef)
			if err != nil {
				logger.Error(err, "Failed to analyze workload attack surface", "workload", workloadRef.Name)
				continue
			}

			// Update policy status with attack surface information
			r.updatePolicyWithAttackSurface(&policy, surface)
		}

		// Update policy status
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error(err, "Failed to update policy status", "policy", policy.Name)
		}

		// Promote the computed surface to a first-class, inspectable AttackSurface CR.
		if err := r.upsertAttackSurface(ctx, &policy); err != nil {
			logger.V(1).Info("failed to upsert AttackSurface", "policy", policy.Name, "error", err.Error())
		}
	}

	return nil
}

// upsertAttackSurface creates/updates an AttackSurface CR mirroring the policy's
// computed attack-surface status, so users can inspect it as its own resource.
func (r *AttackSurfaceAnalyzerReconciler) upsertAttackSurface(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) error {
	if policy.Status.AttackSurface == nil {
		return nil
	}
	as := &policyv1alpha1.AttackSurface{
		ObjectMeta: metav1.ObjectMeta{Name: policy.Name, Namespace: policy.Namespace},
	}
	// Create if absent (ignore AlreadyExists), then set status from the policy.
	if err := r.Create(ctx, &policyv1alpha1.AttackSurface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/part-of": "pahlevan", "pahlevan.io/policy": policy.Name},
		},
		Spec: policyv1alpha1.AttackSurfaceSpec{PolicyRef: policy.Name, Namespace: policy.Namespace},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(as), as); err != nil {
		return err
	}
	as.Status = *policy.Status.AttackSurface
	return r.Status().Update(ctx, as)
}

func (r *AttackSurfaceAnalyzerReconciler) getTargetWorkloads(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) ([]client.Object, error) {
	var workloads []client.Object

	// Get Deployments
	deployments := &appsv1.DeploymentList{}
	if err := r.List(ctx, deployments, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, deployment := range deployments.Items {
		if r.matchesSelector(deployment.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &deployment)
		}
	}

	// Get StatefulSets
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.List(ctx, statefulSets, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, sts := range statefulSets.Items {
		if r.matchesSelector(sts.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &sts)
		}
	}

	// Get DaemonSets
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.List(ctx, daemonSets, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, ds := range daemonSets.Items {
		if r.matchesSelector(ds.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &ds)
		}
	}

	return workloads, nil
}

func (r *AttackSurfaceAnalyzerReconciler) updatePolicyWithAttackSurface(policy *policyv1alpha1.PahlevanPolicy, surface *visualization.WorkloadAttackSurface) {
	if policy.Status.AttackSurface == nil {
		policy.Status.AttackSurface = &policyv1alpha1.AttackSurfaceStatus{}
	}

	// Update exposed syscalls
	var exposedSyscalls []string
	for _, container := range surface.Containers {
		if container.SyscallExposure != nil {
			// Use the available syscall data from SyscallExposureAnalysis
			exposedSyscalls = append(exposedSyscalls, container.SyscallExposure.RiskySyscalls...)
		}
	}
	policy.Status.AttackSurface.ExposedSyscalls = exposedSyscalls

	// Update exposed ports
	var exposedPorts []int32
	if surface.ServiceExposure != nil {
		for _, port := range surface.ServiceExposure.Ports {
			exposedPorts = append(exposedPorts, port.Port)
		}
	}
	policy.Status.AttackSurface.ExposedPorts = exposedPorts

	// Update writable files
	var writableFiles []string
	for _, container := range surface.Containers {
		if container.FileSystemExposure != nil {
			writableFiles = append(writableFiles, container.FileSystemExposure.WritablePaths...)
		}
	}
	policy.Status.AttackSurface.WritableFiles = writableFiles

	// Update capabilities
	var capabilities []string
	for _, container := range surface.Containers {
		if container.CapabilityAnalysis != nil {
			capabilities = append(capabilities, container.CapabilityAnalysis.Added...)
			capabilities = append(capabilities, container.CapabilityAnalysis.Risky...)
		}
	}
	policy.Status.AttackSurface.Capabilities = capabilities

	// Update risk score
	riskScore := int32(surface.OverallRiskScore)
	policy.Status.AttackSurface.RiskScore = &riskScore

	// Update last analysis time
	now := metav1.Now()
	policy.Status.AttackSurface.LastAnalysis = &now
}

// exportAnalysisResults flushes the analysis to the observability pipeline.
//
// It used to serialize the whole cluster graph three times over - JSON,
// Grafana, Mermaid - and assign each result to the blank identifier. That was
// not a placeholder for future work in any useful sense: it ran on every
// analysis interval, cost a full graph walk per format, and the Grafana branch
// logged an error every time because ExportToFormat has never supported it.
// The export formats themselves are real and tested; they are reached through
// AttackSurfaceAnalyzer.ExportToFormat by a caller that actually wants the
// bytes, which this was not.
func (r *AttackSurfaceAnalyzerReconciler) exportAnalysisResults(ctx context.Context) {
	if r.ObservabilityManager == nil {
		return
	}
	if _, err := r.ObservabilityManager.ExportObservabilityData(); err != nil {
		log.FromContext(ctx).Error(err, "Failed to export observability data")
	}
}

func (r *AttackSurfaceAnalyzerReconciler) isSignificantChange(ctx context.Context, req ctrl.Request) bool {
	// Determine if this resource change is significant enough to trigger immediate analysis

	// Get the resource that changed
	var resource client.Object

	// Try different resource types
	pod := &corev1.Pod{}
	if r.Get(ctx, req.NamespacedName, pod) == nil {
		resource = pod
	} else {
		svc := &corev1.Service{}
		if r.Get(ctx, req.NamespacedName, svc) == nil {
			resource = svc
		} else {
			deployment := &appsv1.Deployment{}
			if r.Get(ctx, req.NamespacedName, deployment) == nil {
				resource = deployment
			} else {
				netpol := &networkingv1.NetworkPolicy{}
				if r.Get(ctx, req.NamespacedName, netpol) == nil {
					resource = netpol
				} else {
					policy := &policyv1alpha1.PahlevanPolicy{}
					if r.Get(ctx, req.NamespacedName, policy) == nil {
						resource = policy
					}
				}
			}
		}
	}

	if resource == nil {
		return false
	}

	// Check if this resource type warrants immediate analysis
	switch resource.(type) {
	case *corev1.Service:
		// Service changes can affect attack surface
		return true
	case *networkingv1.NetworkPolicy:
		// Network policy changes definitely affect attack surface
		return true
	case *policyv1alpha1.PahlevanPolicy:
		// Policy changes should trigger analysis
		return true
	case *appsv1.Deployment, *appsv1.StatefulSet, *appsv1.DaemonSet:
		// Workload changes might affect attack surface
		return true
	}

	return false
}

func (r *AttackSurfaceAnalyzerReconciler) matchesSelector(labels map[string]string, selector policyv1alpha1.LabelSelector) bool {
	// Check matchLabels
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}

	// Check matchExpressions
	for _, expr := range selector.MatchExpressions {
		labelValue, exists := labels[expr.Key]

		switch expr.Operator {
		case policyv1alpha1.LabelSelectorOpIn:
			if !exists {
				return false
			}
			found := false
			for _, value := range expr.Values {
				if labelValue == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case policyv1alpha1.LabelSelectorOpNotIn:
			if exists {
				for _, value := range expr.Values {
					if labelValue == value {
						return false
					}
				}
			}
		case policyv1alpha1.LabelSelectorOpExists:
			if !exists {
				return false
			}
		case policyv1alpha1.LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		}
	}

	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *AttackSurfaceAnalyzerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.AnalysisInterval == 0 {
		r.AnalysisInterval = 5 * time.Minute
	}

	// Named() is required: this reconciler and PahlevanPolicyReconciler both watch
	// PahlevanPolicy, so without distinct names controller-runtime derives the same
	// name ("pahlevanpolicy") for both and fails to start ("controller already exists").
	return ctrl.NewControllerManagedBy(mgr).
		Named("attacksurface").
		For(&policyv1alpha1.PahlevanPolicy{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&networkingv1.NetworkPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
