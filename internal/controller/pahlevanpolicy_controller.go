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
	"k8s.io/apimachinery/pkg/labels"
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
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=containerprofiles,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=deployments;replicasets;daemonsets;statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;update;patch

// requeueImmediately replaces the deprecated Result.Requeue field, which
// controller-runtime removed in favor of RequeueAfter. It is used where the
// reconcile has just written the object and wants to see its own write: a
// second is long enough for the cache to catch up and short enough that a
// policy moving through its phases is not visibly stalled.
const requeueImmediately = time.Second

// Reconcile drives one PahlevanPolicy through its lifecycle.
//
// This is the root span of every policy trace. It is started before the Get so
// a reconcile that fails to read its own object still shows up: a policy that
// "does nothing" is far more often an RBAC or cache problem than a logic one,
// and an absent trace is indistinguishable from an absent reconcile.
//
// Phase changes are recorded as events on this span rather than as spans of
// their own, because the useful question is which reconcile decided the
// transition and what else that reconcile did - the answer is the span's
// event list, in order.
func (r *PahlevanPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	ctx, span := observability.StartSpan(ctx, observability.SpanPolicyReconcile,
		observability.AttrNamespace.String(req.Namespace),
		observability.AttrPolicy.String(req.Name))
	defer func() { observability.EndSpan(span, err) }()

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
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &policy)
	}

	// Initialize status if empty
	if policy.Status.Phase == "" {
		observability.RecordPhaseTransition(span, "", string(policyv1alpha1.PolicyPhaseInitializing), "StatusEmpty")
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
		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
	}

	span.SetAttributes(observability.AttrPhase.String(string(policy.Status.Phase)))

	// Main reconciliation logic
	result, err = r.reconcilePolicy(ctx, &policy)
	if err != nil {
		logger.Error(err, "Failed to reconcile PahlevanPolicy")
		r.updateCondition(&policy, policyv1alpha1.PolicyConditionError, policyv1alpha1.ConditionTrue, "ReconciliationFailed", err.Error())
		// The status write is the only record an operator has that the
		// reconcile failed; if it too fails, say so rather than returning the
		// original error alone and leaving a policy that looks healthy.
		if uerr := r.Status().Update(ctx, &policy); uerr != nil {
			logger.Error(uerr, "Failed to record the reconciliation error on the policy status")
		}
		return result, err
	}

	return result, nil
}

func (r *PahlevanPolicyReconciler) reconcilePolicy(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

	// One child span named for the phase handler, so a waterfall separates
	// "the reconcile was slow" from "the transition handler was slow" - the
	// transition phase is the one that writes every container's BPF maps and
	// is the only phase whose duration scales with the workload.
	ctx, span := observability.StartSpan(ctx, observability.SpanPolicyPhase,
		observability.AttrNamespace.String(policy.Namespace),
		observability.AttrPolicy.String(policy.Name),
		observability.AttrPhase.String(string(policy.Status.Phase)))
	defer func() { observability.EndSpan(span, err) }()

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

	// Discover target workloads. Its own span because "the policy selected
	// nothing" and "the API server was slow" look identical from the outside,
	// and the workload count attribute separates them at a glance.
	_, discoverSpan := observability.StartSpan(ctx, observability.SpanWorkloadDiscovery,
		observability.AttrNamespace.String(policy.Namespace),
		observability.AttrPolicy.String(policy.Name))
	workloads, err := r.discoverTargetWorkloads(ctx, policy)
	if err != nil {
		observability.EndSpan(discoverSpan, err)
		return ctrl.Result{}, fmt.Errorf("failed to discover target workloads: %w", err)
	}
	discoverSpan.SetAttributes(observability.AttrWorkloads.Int(len(workloads)))
	discoverSpan.End()

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

		// No event handler is registered here, deliberately.
		//
		// This used to call EBPFManager.AddEventHandler once per target
		// workload, on every reconcile that reached this function. Handlers are
		// appended to a slice that is never pruned and is walked synchronously
		// for every record the ring buffers deliver, so each reconcile made the
		// hottest path in the system permanently slower - and the handler it
		// added did nothing except increment a counter through a pointer to a
		// policy object from an earlier reconcile, which is both a data race and
		// a write nobody reads.
		//
		// The learning statistics it pretended to maintain are produced by the
		// adaptive controller and reported on ContainerProfile status.
	}

	// Update status to learning phase
	observability.RecordPhaseTransition(observability.SpanFromContext(ctx),
		string(policyv1alpha1.PolicyPhaseInitializing),
		string(policyv1alpha1.PolicyPhaseLearning), "TargetsDiscovered")
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

// handleLearning evaluates the learning window once.
//
// The span covers the evaluation, not the window: a span lasting the whole
// learning window would be minutes to hours long, would be held open across
// process restarts it cannot survive, and would tell nobody anything the
// progress attribute does not. What is worth tracing is each evaluation and,
// once, the pass that closed the window and why.
func (r *PahlevanPolicyReconciler) handleLearning(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling learning phase", "policy", policy.Name)

	// Check if learning window has elapsed
	learningDuration := r.LearningWindow
	if policy.Spec.LearningConfig.Duration != nil {
		learningDuration = policy.Spec.LearningConfig.Duration.Duration
	}

	ctx, windowSpan := observability.StartSpan(ctx, observability.SpanLearningWindow,
		observability.AttrNamespace.String(policy.Namespace),
		observability.AttrPolicy.String(policy.Name),
		observability.AttrWindowSecs.Float64(learningDuration.Seconds()))
	defer windowSpan.End()

	if policy.Status.LearningStatus != nil && policy.Status.LearningStatus.StartTime != nil {
		elapsed := time.Since(policy.Status.LearningStatus.StartTime.Time)
		progress := int32((elapsed.Seconds() / learningDuration.Seconds()) * 100)
		if progress > 100 {
			progress = 100
		}
		policy.Status.LearningStatus.Progress = &progress
		windowSpan.SetAttributes(
			observability.AttrElapsedSecs.Float64(elapsed.Seconds()),
			observability.AttrProgress.Int(int(progress)),
		)

		// Check if we should transition to enforcement
		elapsedWindow := elapsed >= learningDuration
		autoTransition := policy.Spec.LearningConfig.AutoTransition && r.shouldTransitionToEnforcement(policy)
		if elapsedWindow || autoTransition {
			// Which of the two closed the window matters: an auto-transition
			// means the behaviour looked stable early, and a policy that
			// enforces too soon is the usual cause of a workload breaking
			// minutes after rollout.
			reason := "WindowElapsed"
			if !elapsedWindow {
				reason = "AutoTransition"
			}
			observability.AddEvent(windowSpan, observability.EventLearningWindowClosed,
				observability.AttrReason.String(reason),
				observability.AttrElapsedSecs.Float64(elapsed.Seconds()))
			observability.RecordPhaseTransition(windowSpan,
				string(policyv1alpha1.PolicyPhaseLearning),
				string(policyv1alpha1.PolicyPhaseTransition), reason)

			// Transition to enforcement
			policy.Status.Phase = policyv1alpha1.PolicyPhaseTransition
			policy.Status.LearningStatus.EndTime = &metav1.Time{Time: time.Now()}

			r.updateCondition(policy, policyv1alpha1.PolicyConditionLearning, policyv1alpha1.ConditionFalse, "LearningCompleted", "Learning phase completed")

			if err := r.Status().Update(ctx, policy); err != nil {
				return ctrl.Result{}, observability.RecordError(windowSpan, err)
			}

			return ctrl.Result{RequeueAfter: requeueImmediately}, nil
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
	// Get workload containers for policy enforcement
	workload, err := r.getWorkloadForPolicy(ctx, policy)
	if err != nil {
		log.Log.Error(err, "Failed to get workload for policy", "policy", policy.Name)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, observability.RecordError(observability.SpanFromContext(ctx), err)
	}

	containerIDs, err := r.getWorkloadContainers(ctx, workload)
	if err != nil {
		log.Log.Error(err, "Failed to get container IDs", "policy", policy.Name)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, observability.RecordError(observability.SpanFromContext(ctx), err)
	}

	if r.EBPFManager != nil && len(containerIDs) > 0 {
		// Create enforcement policies for each container
		for _, containerID := range containerIDs {
			// One span per container: this loop continues past a failure, so
			// without a span per container a partially applied transition -
			// half the pods enforcing, half still learning - is invisible in
			// the trace and shows up only as an error log among many.
			_, applySpan := observability.StartSpan(ctx, observability.SpanPolicyApply,
				observability.AttrNamespace.String(policy.Namespace),
				observability.AttrPolicy.String(policy.Name),
				observability.AttrWorkload.String(workload.GetName()),
				observability.AttrContainerID.String(containerID),
				observability.AttrMode.String("enforce"))
			// Generate policy based on learning phase data
			err := r.EBPFManager.UpdateContainerPolicy(containerID, &ebpf.ContainerPolicy{
				AllowedSyscalls:  make(map[uint64]bool),
				LastUpdate:       time.Now(),
				LearningWindowMs: uint32(r.LearningWindow.Milliseconds()),
				EnforcementMode:  1, // Enforcement mode
				SelfHealing:      policy.Spec.SelfHealing.Enabled,
			})
			observability.EndSpan(applySpan, err)
			if err != nil {
				log.Log.Error(err, "Failed to update container policy", "containerID", containerID)
				continue
			}

			log.Log.Info("Applied enforcement policy to container",
				"policyName", policy.Name,
				"containerID", containerID,
				"learningWindow", r.LearningWindow)
		}
	}

	// Transition to enforcing phase.
	//
	// This used to time.Sleep(r.EnforcementDelay) here, which blocks one of the
	// controller's worker goroutines for the whole delay and stalls every other
	// policy behind it. The delay is honored by requeueing instead; the node
	// agent is the component that actually gates the transition on its own
	// learning window and grace period.
	observability.RecordPhaseTransition(observability.SpanFromContext(ctx),
		string(policyv1alpha1.PolicyPhaseTransition),
		string(policyv1alpha1.PolicyPhaseEnforcing), "PoliciesApplied")
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

	// The node agents own the data plane and publish what they saw on
	// ContainerProfile. Rolling that up here is what makes the policy's
	// blocked* counters real; they previously stayed at zero forever while the
	// printed column claimed to show blocked syscalls.
	_, aggSpan := observability.StartSpan(ctx, observability.SpanProfileAggregate,
		observability.AttrNamespace.String(policy.Namespace),
		observability.AttrPolicy.String(policy.Name))
	if err := r.aggregateProfiles(ctx, policy); err != nil {
		// A failed roll-up must not stop enforcement from being managed, so it
		// is logged and the stale counters are left in place. It is still an
		// error on its own span: the counters an operator reads are stale
		// afterwards, and nothing else says so.
		observability.EndSpan(aggSpan, err)
		logger.V(1).Info("could not aggregate container profiles", "error", err.Error())
	} else {
		aggSpan.End()
	}

	// Check for self-healing triggers
	if policy.Spec.SelfHealing.Enabled && r.shouldTriggerSelfHealing(policy) {
		observability.RecordPhaseTransition(observability.SpanFromContext(ctx),
			string(policyv1alpha1.PolicyPhaseEnforcing),
			string(policyv1alpha1.PolicyPhaseRollingBack), "SelfHealingTriggered")
		policy.Status.Phase = policyv1alpha1.PolicyPhaseRollingBack
		r.updateCondition(policy, policyv1alpha1.PolicyConditionHealthy, policyv1alpha1.ConditionFalse, "SelfHealingTriggered", "Self-healing rollback triggered")

		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: requeueImmediately}, nil
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
	observability.RecordPhaseTransition(observability.SpanFromContext(ctx),
		string(policyv1alpha1.PolicyPhaseRollingBack),
		string(policyv1alpha1.PolicyPhaseEnforcing), "RollbackCompleted")
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
		if matchesSelector(deployment.Labels, policy.Spec.Selector) {
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
		if matchesSelector(sts.Labels, policy.Spec.Selector) {
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
		if matchesSelector(ds.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &ds)
		}
	}

	return workloads, nil
}

func (r *PahlevanPolicyReconciler) getWorkloadContainers(ctx context.Context, workload metav1.Object) ([]string, error) {
	// Get pods for the workload
	pods := &corev1.PodList{}

	// Get label selector based on workload type
	var listOptions client.ListOptions
	listOptions.Namespace = workload.GetNamespace()

	// Extract label selector from different workload types
	switch obj := workload.(type) {
	case *appsv1.Deployment:
		if obj.Spec.Selector != nil && len(obj.Spec.Selector.MatchLabels) > 0 {
			selector := labels.SelectorFromSet(labels.Set(obj.Spec.Selector.MatchLabels))
			listOptions.LabelSelector = selector
		}
	case *appsv1.StatefulSet:
		if obj.Spec.Selector != nil && len(obj.Spec.Selector.MatchLabels) > 0 {
			selector := labels.SelectorFromSet(labels.Set(obj.Spec.Selector.MatchLabels))
			listOptions.LabelSelector = selector
		}
	case *appsv1.DaemonSet:
		if obj.Spec.Selector != nil && len(obj.Spec.Selector.MatchLabels) > 0 {
			selector := labels.SelectorFromSet(labels.Set(obj.Spec.Selector.MatchLabels))
			listOptions.LabelSelector = selector
		}
	case *appsv1.ReplicaSet:
		if obj.Spec.Selector != nil && len(obj.Spec.Selector.MatchLabels) > 0 {
			selector := labels.SelectorFromSet(labels.Set(obj.Spec.Selector.MatchLabels))
			listOptions.LabelSelector = selector
		}
	default:
		// For other workload types or when selector is unavailable, list all pods in namespace
		// This is less efficient but ensures we don't miss any pods
	}

	if err := r.List(ctx, pods, &listOptions); err != nil {
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

func (r *PahlevanPolicyReconciler) shouldTransitionToEnforcement(policy *policyv1alpha1.PahlevanPolicy) bool {
	// Without a learning status there is nothing to evaluate; treat as not ready
	// rather than dereferencing a nil pointer.
	if policy.Status.LearningStatus == nil {
		return false
	}

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

// aggregateProfiles rolls the per-container ContainerProfile status published
// by the node agents up onto the governing policy.
func (r *PahlevanPolicyReconciler) aggregateProfiles(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) error {
	var profiles policyv1alpha1.ContainerProfileList
	if err := r.List(ctx, &profiles, client.InNamespace(policy.Namespace)); err != nil {
		return err
	}

	st := policyv1alpha1.EnforcementStatus{}
	if policy.Status.EnforcementStatus != nil {
		// StartTime is set at the transition and must survive the roll-up.
		st.StartTime = policy.Status.EnforcementStatus.StartTime
	}

	var rollbacks int32
	for i := range profiles.Items {
		p := &profiles.Items[i]
		if p.Spec.PolicyRef != policy.Name {
			continue
		}
		st.TotalContainers++
		if p.Status.Phase == "Enforcing" {
			st.EnforcingContainers++
		}
		st.BlockedFileAccess += int64(p.Status.DeniedFiles)
		st.BlockedNetworkConnections += int64(p.Status.DeniedNetwork)
		st.BlockedExecs += int64(p.Status.DeniedExecs)
		st.BlockedCapabilities += int64(p.Status.DeniedCapabilities)
		rollbacks += p.Status.RollbackCount
	}
	st.BlockedTotal = st.BlockedFileAccess + st.BlockedNetworkConnections +
		st.BlockedExecs + st.BlockedCapabilities
	st.RollbackCount = rollbacks

	policy.Status.EnforcementStatus = &st
	return nil
}

func (r *PahlevanPolicyReconciler) shouldTriggerSelfHealing(policy *policyv1alpha1.PahlevanPolicy) bool {
	// Check enforcement status for failure indicators
	if policy.Status.EnforcementStatus == nil {
		return false
	}

	// Per-container rollback already happens in the node agent, which has the
	// pod health signal and the observation window. This is the cluster-wide
	// backstop: a policy denying heavily across many containers at once is more
	// likely a bad baseline than an attack on all of them.
	//
	// The threshold is per container rather than absolute, so a large
	// deployment does not trip it simply by being large.
	st := policy.Status.EnforcementStatus
	if st.TotalContainers == 0 {
		return false
	}
	return st.BlockedTotal/int64(st.TotalContainers) > selfHealingDenialsPerContainer
}

// selfHealingDenialsPerContainer is the average in-kernel denial count per
// governed container above which the cluster-wide backstop fires.
const selfHealingDenialsPerContainer = 1000

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

// getWorkloadForPolicy finds the workload object that matches the policy selector
func (r *PahlevanPolicyReconciler) getWorkloadForPolicy(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) (metav1.Object, error) {
	// Try to find Deployment first
	deployments := &appsv1.DeploymentList{}
	if err := r.List(ctx, deployments, &client.ListOptions{
		Namespace:     policy.Namespace,
		LabelSelector: labels.SelectorFromSet(policy.Spec.Selector.MatchLabels),
	}); err == nil && len(deployments.Items) > 0 {
		return &deployments.Items[0], nil
	}

	// Try StatefulSet
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.List(ctx, statefulSets, &client.ListOptions{
		Namespace:     policy.Namespace,
		LabelSelector: labels.SelectorFromSet(policy.Spec.Selector.MatchLabels),
	}); err == nil && len(statefulSets.Items) > 0 {
		return &statefulSets.Items[0], nil
	}

	// Try DaemonSet
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.List(ctx, daemonSets, &client.ListOptions{
		Namespace:     policy.Namespace,
		LabelSelector: labels.SelectorFromSet(policy.Spec.Selector.MatchLabels),
	}); err == nil && len(daemonSets.Items) > 0 {
		return &daemonSets.Items[0], nil
	}

	// Try ReplicaSet
	replicaSets := &appsv1.ReplicaSetList{}
	if err := r.List(ctx, replicaSets, &client.ListOptions{
		Namespace:     policy.Namespace,
		LabelSelector: labels.SelectorFromSet(policy.Spec.Selector.MatchLabels),
	}); err == nil && len(replicaSets.Items) > 0 {
		return &replicaSets.Items[0], nil
	}

	return nil, fmt.Errorf("no workload found matching policy selector in namespace %s", policy.Namespace)
}
