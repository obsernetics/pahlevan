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
	"strings"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ContainerLearnerReconciler manages container learning lifecycle
type ContainerLearnerReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	EBPFManager          *ebpf.Manager
	MetricsManager       *metrics.Manager
	ObservabilityManager *observability.Manager
	SyscallLearner       *learner.SyscallLearner
	TrackedContainers    map[string]*ContainerTrackingInfo
}

// ContainerTrackingInfo holds information about tracked containers
type ContainerTrackingInfo struct {
	ContainerID        string
	PodName            string
	PodNamespace       string
	WorkloadName       string
	WorkloadKind       string
	StartTime          time.Time
	LastActivity       time.Time
	LearningStarted    bool
	PolicyApplied      bool
	ApplicablePolicies []types.NamespacedName
}

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;update;patch
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=get;list;watch

func (r *ContainerLearnerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Pod
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if errors.IsNotFound(err) {
			// Pod was deleted, clean up tracking info
			r.handlePodDeletion(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Pod")
		return ctrl.Result{}, err
	}

	// Handle pod based on its phase
	switch pod.Status.Phase {
	case corev1.PodPending:
		return r.handlePodPending(ctx, &pod)
	case corev1.PodRunning:
		return r.handlePodRunning(ctx, &pod)
	case corev1.PodSucceeded, corev1.PodFailed:
		return r.handlePodTerminated(ctx, &pod)
	default:
		logger.Info("Pod in unknown phase", "phase", pod.Status.Phase)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
}

func (r *ContainerLearnerReconciler) handlePodPending(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling pending pod", "pod", pod.Name)

	// For pending pods, we just track them and wait for them to start
	r.trackPod(pod)

	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *ContainerLearnerReconciler) handlePodRunning(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling running pod", "pod", pod.Name)

	// Track the pod if not already tracked
	r.trackPod(pod)

	// Find applicable policies for this pod
	policies, err := r.findApplicablePolicies(ctx, pod)
	if err != nil {
		logger.Error(err, "Failed to find applicable policies")
		return ctrl.Result{}, err
	}

	if len(policies) == 0 {
		logger.Info("No applicable policies found for pod", "pod", pod.Name)
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Start learning for each container in the pod
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running == nil {
			continue // Container not running yet
		}

		containerID := r.extractContainerID(containerStatus.ContainerID)
		if containerID == "" {
			logger.Info("Could not extract container ID", "containerStatus", containerStatus.ContainerID)
			continue
		}

		// Check if we're already tracking this container
		trackingInfo, exists := r.TrackedContainers[containerID]
		if !exists {
			// Create new tracking info
			trackingInfo = &ContainerTrackingInfo{
				ContainerID:        containerID,
				PodName:            pod.Name,
				PodNamespace:       pod.Namespace,
				StartTime:          containerStatus.State.Running.StartedAt.Time,
				LastActivity:       time.Now(),
				LearningStarted:    false,
				PolicyApplied:      false,
				ApplicablePolicies: r.policiesToNamespacedNames(policies),
			}

			// Determine workload information
			if ownerRef := r.getWorkloadOwnerReference(pod); ownerRef != nil {
				trackingInfo.WorkloadName = ownerRef.Name
				trackingInfo.WorkloadKind = ownerRef.Kind
			}

			r.TrackedContainers[containerID] = trackingInfo
		}

		// Start learning if not already started
		if !trackingInfo.LearningStarted {
			if err := r.startLearningForContainer(ctx, containerID, trackingInfo, policies); err != nil {
				logger.Error(err, "Failed to start learning for container", "containerID", containerID)
				continue
			}
			trackingInfo.LearningStarted = true
		}

		// Update last activity
		trackingInfo.LastActivity = time.Now()
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *ContainerLearnerReconciler) handlePodTerminated(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling terminated pod", "pod", pod.Name, "phase", pod.Status.Phase)

	// Stop learning for all containers in this pod
	for _, containerStatus := range pod.Status.ContainerStatuses {
		containerID := r.extractContainerID(containerStatus.ContainerID)
		if containerID == "" {
			continue
		}

		if err := r.stopLearningForContainer(ctx, containerID); err != nil {
			logger.Error(err, "Failed to stop learning for container", "containerID", containerID)
		}

		// Remove from tracking
		delete(r.TrackedContainers, containerID)
	}

	return ctrl.Result{}, nil
}

func (r *ContainerLearnerReconciler) handlePodDeletion(namespacedName types.NamespacedName) {
	// Clean up any tracking info for containers in this pod
	for containerID, trackingInfo := range r.TrackedContainers {
		if trackingInfo.PodName == namespacedName.Name && trackingInfo.PodNamespace == namespacedName.Namespace {
			// Stop learning
			r.stopLearningForContainer(context.Background(), containerID)
			delete(r.TrackedContainers, containerID)
		}
	}
}

func (r *ContainerLearnerReconciler) trackPod(pod *corev1.Pod) {
	// Basic pod tracking logic
	// This could be expanded to maintain more detailed pod lifecycle information
}

func (r *ContainerLearnerReconciler) findApplicablePolicies(ctx context.Context, pod *corev1.Pod) ([]*policyv1alpha1.PahlevanPolicy, error) {
	var policies []*policyv1alpha1.PahlevanPolicy

	// List all PahlevanPolicies in the pod's namespace
	policyList := &policyv1alpha1.PahlevanPolicyList{}
	if err := r.List(ctx, policyList, &client.ListOptions{
		Namespace: pod.Namespace,
	}); err != nil {
		return nil, err
	}

	// Check which policies apply to this pod
	for _, policy := range policyList.Items {
		if r.policyAppliesToPod(&policy, pod) {
			// Make a copy to avoid issues with range variable
			policyCopy := policy
			policies = append(policies, &policyCopy)
		}
	}

	return policies, nil
}

func (r *ContainerLearnerReconciler) policyAppliesToPod(policy *policyv1alpha1.PahlevanPolicy, pod *corev1.Pod) bool {
	// Check if policy selector matches pod labels
	return r.matchesSelector(pod.Labels, policy.Spec.Selector)
}

func (r *ContainerLearnerReconciler) matchesSelector(labels map[string]string, selector policyv1alpha1.LabelSelector) bool {
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

func (r *ContainerLearnerReconciler) startLearningForContainer(
	ctx context.Context,
	containerID string,
	trackingInfo *ContainerTrackingInfo,
	policies []*policyv1alpha1.PahlevanPolicy,
) error {
	logger := log.FromContext(ctx)
	logger.Info("Starting learning for container", "containerID", containerID)

	// Create workload reference
	workloadRef := learner.WorkloadReference{
		Name:      trackingInfo.WorkloadName,
		Namespace: trackingInfo.PodNamespace,
		Kind:      trackingInfo.WorkloadKind,
	}

	// Start learning with the syscall learner
	for _, policy := range policies {
		if err := r.SyscallLearner.StartLearning(ctx, containerID, workloadRef, policy); err != nil {
			return fmt.Errorf("failed to start learning: %v", err)
		}
	}

	// Record lifecycle event
	if err := r.SyscallLearner.RecordLifecycleEvent(
		containerID,
		learner.EventContainerStarted,
		map[string]string{
			"pod":       trackingInfo.PodName,
			"namespace": trackingInfo.PodNamespace,
			"workload":  trackingInfo.WorkloadName,
		},
	); err != nil {
		logger.Error(err, "Failed to record lifecycle event")
	}

	return nil
}

func (r *ContainerLearnerReconciler) stopLearningForContainer(ctx context.Context, containerID string) error {
	logger := log.FromContext(ctx)
	logger.Info("Stopping learning for container", "containerID", containerID)

	// Stop learning with the syscall learner
	if err := r.SyscallLearner.StopLearning(containerID); err != nil {
		return fmt.Errorf("failed to stop learning: %v", err)
	}

	return nil
}

func (r *ContainerLearnerReconciler) extractContainerID(fullContainerID string) string {
	// Container ID format is typically: docker://abcd1234...
	// or containerd://abcd1234...
	parts := strings.Split(fullContainerID, "://")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func (r *ContainerLearnerReconciler) getWorkloadOwnerReference(pod *corev1.Pod) *corev1.ObjectReference {
	// Look through owner references to find the workload
	for _, ownerRef := range pod.OwnerReferences {
		switch ownerRef.Kind {
		case "ReplicaSet":
			// For Deployments, we need to trace back through ReplicaSet
			return &corev1.ObjectReference{
				Kind: "Deployment", // Assume it's a Deployment
				Name: r.getDeploymentNameFromReplicaSet(ownerRef.Name),
			}
		case "StatefulSet", "DaemonSet", "Job", "CronJob":
			return &corev1.ObjectReference{
				Kind: ownerRef.Kind,
				Name: ownerRef.Name,
			}
		}
	}
	return nil
}

func (r *ContainerLearnerReconciler) getDeploymentNameFromReplicaSet(replicaSetName string) string {
	// ReplicaSet names are typically in format: <deployment-name>-<hash>
	// This is a simple heuristic - in production, you might want to query the ReplicaSet
	parts := strings.Split(replicaSetName, "-")
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return replicaSetName
}

func (r *ContainerLearnerReconciler) policiesToNamespacedNames(policies []*policyv1alpha1.PahlevanPolicy) []types.NamespacedName {
	var names []types.NamespacedName
	for _, policy := range policies {
		names = append(names, types.NamespacedName{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		})
	}
	return names
}

// SetupWithManager sets up the controller with the Manager.
func (r *ContainerLearnerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.TrackedContainers == nil {
		r.TrackedContainers = make(map[string]*ContainerTrackingInfo)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(predicate.Funcs{
			// Only watch for pod status changes
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldPod, ok1 := e.ObjectOld.(*corev1.Pod)
				newPod, ok2 := e.ObjectNew.(*corev1.Pod)
				if !ok1 || !ok2 {
					return false
				}
				// Watch for phase changes or container status changes
				return oldPod.Status.Phase != newPod.Status.Phase ||
					len(oldPod.Status.ContainerStatuses) != len(newPod.Status.ContainerStatuses)
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return true // Always process deletions
			},
			CreateFunc: func(e event.CreateEvent) bool {
				return true // Always process creations
			},
		}).
		Complete(r)
}
