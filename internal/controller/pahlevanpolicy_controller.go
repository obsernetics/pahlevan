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
	"fmt"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// PahlevanPolicyReconciler reconciles a PahlevanPolicy object
type PahlevanPolicyReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	EBPFManager          *ebpf.Manager
	MetricsManager       *metrics.Manager
	ObservabilityManager *observability.Manager
	LearningWindow       time.Duration
	EnforcementDelay     time.Duration
}

//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments;replicasets;daemonsets;statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;update;patch

func (r *PahlevanPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PahlevanPolicy instance
	var policy policyv1alpha1.PahlevanPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("PahlevanPolicy resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get PahlevanPolicy")
		return ctrl.Result{}, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(&policy, "pahlevan.io/finalizer") {
		controllerutil.AddFinalizer(&policy, "pahlevan.io/finalizer")
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &policy)
	}

	// Initialize status if empty
	if policy.Status.Phase == "" {
		policy.Status.Phase = policyv1alpha1.PolicyPhaseInitializing
		policy.Status.Conditions = []policyv1alpha1.PolicyCondition{
			{
				Type:               policyv1alpha1.PolicyConditionReady,
				Status:             policyv1alpha1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
				Reason:             "Initializing",
				Message:            "Policy is being initialized",
			},
		}
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Main reconciliation logic
	result, err := r.reconcilePolicy(ctx, &policy)
	if err != nil {
		logger.Error(err, "Failed to reconcile PahlevanPolicy")
		r.updateCondition(&policy, policyv1alpha1.PolicyConditionError, policyv1alpha1.ConditionTrue, "ReconciliationFailed", err.Error())
		r.Status().Update(ctx, &policy)
		return result, err
	}

	return result, nil
}

func (r *PahlevanPolicyReconciler) reconcilePolicy(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	switch policy.Status.Phase {
	case policyv1alpha1.PolicyPhaseInitializing:
		return r.handleInitialization(ctx, policy)
	case policyv1alpha1.PolicyPhaseLearning:
		return r.handleLearning(ctx, policy)
	case policyv1alpha1.PolicyPhaseTransition:
		return r.handleTransition(ctx, policy)
	case policyv1alpha1.PolicyPhaseEnforcing:
		return r.handleEnforcement(ctx, policy)
	case policyv1alpha1.PolicyPhaseFailed:
		return r.handleFailure(ctx, policy)
	case policyv1alpha1.PolicyPhaseRollingBack:
		return r.handleRollback(ctx, policy)
	default:
		logger.Info("Unknown policy phase", "phase", policy.Status.Phase)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
}

func (r *PahlevanPolicyReconciler) handleInitialization(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Initializing PahlevanPolicy", "policy", policy.Name)

	// Discover target workloads
	workloads, err := r.discoverTargetWorkloads(ctx, policy)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to discover target workloads: %v", err)
	}

	if len(workloads) == 0 {
		logger.Info("No target workloads found, waiting...")
		r.updateCondition(policy, policyv1alpha1.PolicyConditionReady, policyv1alpha1.ConditionFalse, "NoTargets", "No target workloads found")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, r.Status().Update(ctx, policy)
	}

	// Initialize learning for each target workload
	for _, workload := range workloads {
		if _, err := r.getWorkloadContainers(ctx, workload); err != nil {
			logger.Error(err, "Failed to get containers for workload", "workload", workload.GetName())
			continue
		}

		// Start learning for this workload
		r.EBPFManager.AddEventHandler(&PolicyEventHandler{
			reconciler: r,
			policy:     policy,
		})
	}

	// Update status to learning phase
	policy.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	policy.Status.LearningStatus = &policyv1alpha1.LearningStatus{
		StartTime: &metav1.Time{Time: time.Now()},
		Progress:  func() *int32 { p := int32(0); return &p }(),
	}
	policy.Status.TargetWorkloads = r.workloadsToReferences(workloads)

	r.updateCondition(policy, policyv1alpha1.PolicyConditionLearning, policyv1alpha1.ConditionTrue, "LearningStarted", "Policy learning phase started")
	r.updateCondition(policy, policyv1alpha1.PolicyConditionReady, policyv1alpha1.ConditionTrue, "Initialized", "Policy successfully initialized")

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *PahlevanPolicyReconciler) handleLearning(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling learning phase", "policy", policy.Name)

	// Check if learning window has elapsed
	learningDuration := r.LearningWindow
	if policy.Spec.LearningConfig.Duration != nil {
		learningDuration = policy.Spec.LearningConfig.Duration.Duration
	}

	if policy.Status.LearningStatus != nil && policy.Status.LearningStatus.StartTime != nil {
		elapsed := time.Since(policy.Status.LearningStatus.StartTime.Time)
		progress := int32((elapsed.Seconds() / learningDuration.Seconds()) * 100)
		if progress > 100 {
			progress = 100
		}
		policy.Status.LearningStatus.Progress = &progress

		// Check if we should transition to enforcement
		if elapsed >= learningDuration ||
			(policy.Spec.LearningConfig.AutoTransition && r.shouldTransitionToEnforcement(policy)) {

			// Transition to enforcement
			policy.Status.Phase = policyv1alpha1.PolicyPhaseTransition
			policy.Status.LearningStatus.EndTime = &metav1.Time{Time: time.Now()}

			r.updateCondition(policy, policyv1alpha1.PolicyConditionLearning, policyv1alpha1.ConditionFalse, "LearningCompleted", "Learning phase completed")

			if err := r.Status().Update(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{Requeue: true}, nil
		}
	}

	// Update learning progress
	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *PahlevanPolicyReconciler) handleTransition(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling transition phase", "policy", policy.Name)

	// Generate enforcement policies based on learned behavior
	// This would integrate with the enforcement engine to generate policies

	// Wait for enforcement delay
	time.Sleep(r.EnforcementDelay)

	// Transition to enforcing phase
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	policy.Status.EnforcementStatus = &policyv1alpha1.EnforcementStatus{
		StartTime: &metav1.Time{Time: time.Now()},
	}

	r.updateCondition(policy, policyv1alpha1.PolicyConditionEnforcing, policyv1alpha1.ConditionTrue, "EnforcementStarted", "Policy enforcement started")

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

func (r *PahlevanPolicyReconciler) handleEnforcement(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling enforcement phase", "policy", policy.Name)

	// Monitor enforcement status and update metrics
	// This would integrate with the enforcement engine to get real-time stats

	// Check for self-healing triggers
	if policy.Spec.SelfHealing.Enabled && r.shouldTriggerSelfHealing(policy) {
		policy.Status.Phase = policyv1alpha1.PolicyPhaseRollingBack
		r.updateCondition(policy, policyv1alpha1.PolicyConditionHealthy, policyv1alpha1.ConditionFalse, "SelfHealingTriggered", "Self-healing rollback triggered")

		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

func (r *PahlevanPolicyReconciler) handleFailure(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling failure phase", "policy", policy.Name)

	// Implement failure recovery logic
	// Could transition back to learning or wait for manual intervention

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *PahlevanPolicyReconciler) handleRollback(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling rollback phase", "policy", policy.Name)

	// Implement rollback logic through self-healing manager
	// Restore previous working policy

	// After successful rollback, return to enforcement or learning
	policy.Status.Phase = policyv1alpha1.PolicyPhaseEnforcing
	if policy.Status.EnforcementStatus != nil {
		policy.Status.EnforcementStatus.RollbackCount++
	}

	r.updateCondition(policy, policyv1alpha1.PolicyConditionHealthy, policyv1alpha1.ConditionTrue, "RollbackCompleted", "Self-healing rollback completed")

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

func (r *PahlevanPolicyReconciler) handleDeletion(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling PahlevanPolicy deletion", "policy", policy.Name)

	// Clean up eBPF programs and policies for all target workloads
	for range policy.Status.TargetWorkloads {
		// Remove policies and eBPF programs
		// This would integrate with the enforcement engine
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(policy, "pahlevan.io/finalizer")
	if err := r.Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *PahlevanPolicyReconciler) discoverTargetWorkloads(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) ([]metav1.Object, error) {
	var workloads []metav1.Object

	// Discover Deployments
	deployments := &appsv1.DeploymentList{}
	if err := r.List(ctx, deployments, &client.ListOptions{
		Namespace: policy.Namespace,
	}); err != nil {
		return nil, err
	}

	for _, deployment := range deployments.Items {
		if r.matchesSelector(deployment.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &deployment)
		}
	}

	// Discover StatefulSets
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.List(ctx, statefulSets, &client.ListOptions{
		Namespace: policy.Namespace,
	}); err != nil {
		return nil, err
	}

	for _, sts := range statefulSets.Items {
		if r.matchesSelector(sts.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &sts)
		}
	}

	// Discover DaemonSets
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.List(ctx, daemonSets, &client.ListOptions{
		Namespace: policy.Namespace,
	}); err != nil {
		return nil, err
	}

	for _, ds := range daemonSets.Items {
		if r.matchesSelector(ds.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &ds)
		}
	}

	return workloads, nil
}

func (r *PahlevanPolicyReconciler) getWorkloadContainers(ctx context.Context, workload metav1.Object) ([]string, error) {
	// Get pods for the workload
	pods := &corev1.PodList{}

	// Get selector based on workload type - currently simplified
	_ = workload

	if err := r.List(ctx, pods, &client.ListOptions{
		Namespace: workload.GetNamespace(),
	}); err != nil {
		return nil, err
	}

	var containers []string
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.ContainerID != "" {
					containers = append(containers, containerStatus.ContainerID)
				}
			}
		}
	}

	return containers, nil
}

func (r *PahlevanPolicyReconciler) matchesSelector(labels map[string]string, selector policyv1alpha1.LabelSelector) bool {
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

func (r *PahlevanPolicyReconciler) shouldTransitionToEnforcement(policy *policyv1alpha1.PahlevanPolicy) bool {
	// Check if minimum samples have been collected
	if policy.Spec.LearningConfig.MinSamples != nil {
		if policy.Status.LearningStatus.SamplesCollected < int64(*policy.Spec.LearningConfig.MinSamples) {
			return false
		}
	}

	// Check learning progress
	if policy.Status.LearningStatus.Progress != nil && *policy.Status.LearningStatus.Progress >= 80 {
		return true
	}

	return false
}

func (r *PahlevanPolicyReconciler) shouldTriggerSelfHealing(policy *policyv1alpha1.PahlevanPolicy) bool {
	// Check enforcement status for failure indicators
	if policy.Status.EnforcementStatus == nil {
		return false
	}

	// Simple heuristic: if we have too many blocked events, consider rollback
	totalBlocked := policy.Status.EnforcementStatus.BlockedSyscalls +
		policy.Status.EnforcementStatus.BlockedNetworkConnections +
		policy.Status.EnforcementStatus.BlockedFileAccess

	// If blocking more than expected, trigger self-healing
	return totalBlocked > 1000 // Threshold can be configurable
}

func (r *PahlevanPolicyReconciler) workloadsToReferences(workloads []metav1.Object) []policyv1alpha1.WorkloadReference {
	var refs []policyv1alpha1.WorkloadReference

	for _, w := range workloads {
		ref := policyv1alpha1.WorkloadReference{
			Name:      w.GetName(),
			Namespace: w.GetNamespace(),
			UID:       string(w.GetUID()),
		}

		switch w.(type) {
		case *appsv1.Deployment:
			ref.APIVersion = "apps/v1"
			ref.Kind = "Deployment"
		case *appsv1.StatefulSet:
			ref.APIVersion = "apps/v1"
			ref.Kind = "StatefulSet"
		case *appsv1.DaemonSet:
			ref.APIVersion = "apps/v1"
			ref.Kind = "DaemonSet"
		}

		refs = append(refs, ref)
	}

	return refs
}

func (r *PahlevanPolicyReconciler) updateCondition(policy *policyv1alpha1.PahlevanPolicy, conditionType policyv1alpha1.PolicyConditionType, status policyv1alpha1.ConditionStatus, reason, message string) {
	condition := policyv1alpha1.PolicyCondition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}

	// Find existing condition and update or append
	for i, existingCondition := range policy.Status.Conditions {
		if existingCondition.Type == conditionType {
			if existingCondition.Status != status {
				policy.Status.Conditions[i] = condition
			}
			return
		}
	}

	policy.Status.Conditions = append(policy.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PahlevanPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.PahlevanPolicy{}).
		Owns(&corev1.Pod{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

// PolicyEventHandler handles eBPF events for policy management
type PolicyEventHandler struct {
	reconciler *PahlevanPolicyReconciler
	policy     *policyv1alpha1.PahlevanPolicy
}

func (h *PolicyEventHandler) HandleSyscallEvent(event *ebpf.SyscallEvent) error {
	// Update learning statistics
	if h.policy.Status.LearningStatus != nil {
		h.policy.Status.LearningStatus.SamplesCollected++
	}
	return nil
}

func (h *PolicyEventHandler) HandleNetworkEvent(event *ebpf.NetworkEvent) error {
	// Handle network events
	return nil
}

func (h *PolicyEventHandler) HandleFileEvent(event *ebpf.FileEvent) error {
	// Handle file events
	return nil
}
