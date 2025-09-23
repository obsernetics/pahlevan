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

package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ContainerInfo holds detailed information about a discovered container
type ContainerInfo struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Image           string               `json:"image"`
	ImagePullPolicy corev1.PullPolicy    `json:"imagePullPolicy"`
	PodName         string               `json:"podName"`
	PodNamespace    string               `json:"podNamespace"`
	PodUID          string               `json:"podUID"`
	NodeName        string               `json:"nodeName"`
	WorkloadInfo    *WorkloadInfo        `json:"workloadInfo,omitempty"`
	Labels          map[string]string    `json:"labels"`
	Annotations     map[string]string    `json:"annotations"`
	SecurityContext *SecurityContextInfo `json:"securityContext,omitempty"`
	ResourceLimits  *ResourceInfo        `json:"resourceLimits,omitempty"`
	State           ContainerState       `json:"state"`
	CreatedAt       time.Time            `json:"createdAt"`
	StartedAt       *time.Time           `json:"startedAt,omitempty"`
	FinishedAt      *time.Time           `json:"finishedAt,omitempty"`
	RestartCount    int32                `json:"restartCount"`
	LastUpdate      time.Time            `json:"lastUpdate"`
	RuntimeInfo     *RuntimeInfo         `json:"runtimeInfo,omitempty"`
}

// WorkloadInfo contains information about the workload that owns the container
type WorkloadInfo struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	UID        string            `json:"uid"`
	Labels     map[string]string `json:"labels"`
}

// SecurityContextInfo contains security-related information
type SecurityContextInfo struct {
	RunAsUser           *int64                                `json:"runAsUser,omitempty"`
	RunAsGroup          *int64                                `json:"runAsGroup,omitempty"`
	RunAsNonRoot        *bool                                 `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFS      *bool                                 `json:"readOnlyRootFS,omitempty"`
	AllowPrivilegeEsc   *bool                                 `json:"allowPrivilegeEscalation,omitempty"`
	Privileged          *bool                                 `json:"privileged,omitempty"`
	Capabilities        *corev1.Capabilities                  `json:"capabilities,omitempty"`
	SELinuxOptions      *corev1.SELinuxOptions                `json:"seLinuxOptions,omitempty"`
	WindowsOptions      *corev1.WindowsSecurityContextOptions `json:"windowsOptions,omitempty"`
	FSGroup             *int64                                `json:"fsGroup,omitempty"`
	FSGroupChangePolicy *corev1.PodFSGroupChangePolicy        `json:"fsGroupChangePolicy,omitempty"`
	SeccompProfile      *corev1.SeccompProfile                `json:"seccompProfile,omitempty"`
	SupplementalGroups  []int64                               `json:"supplementalGroups,omitempty"`
}

// ResourceInfo contains resource constraints and usage
type ResourceInfo struct {
	Requests corev1.ResourceList `json:"requests,omitempty"`
	Limits   corev1.ResourceList `json:"limits,omitempty"`
}

// RuntimeInfo contains runtime-specific information
type RuntimeInfo struct {
	Runtime    string            `json:"runtime"` // docker, containerd, cri-o
	Version    string            `json:"version"`
	CgroupPath string            `json:"cgroupPath"`
	PID        int32             `json:"pid"`
	ExtraInfo  map[string]string `json:"extraInfo,omitempty"`
}

// ContainerState represents the current state of a container
type ContainerState string

const (
	ContainerStatePending    ContainerState = "Pending"
	ContainerStateRunning    ContainerState = "Running"
	ContainerStateStopped    ContainerState = "Stopped"
	ContainerStatePaused     ContainerState = "Paused"
	ContainerStateTerminated ContainerState = "Terminated"
	ContainerStateUnknown    ContainerState = "Unknown"
)

// ContainerEvent represents a container lifecycle event
type ContainerEvent struct {
	Type      ContainerEventType `json:"type"`
	Container *ContainerInfo     `json:"container"`
	Timestamp time.Time          `json:"timestamp"`
	Source    string             `json:"source"`
	Reason    string             `json:"reason,omitempty"`
	Message   string             `json:"message,omitempty"`
}

// ContainerEventType represents the type of container event
type ContainerEventType string

const (
	ContainerEventCreated    ContainerEventType = "Created"
	ContainerEventStarted    ContainerEventType = "Started"
	ContainerEventStopped    ContainerEventType = "Stopped"
	ContainerEventTerminated ContainerEventType = "Terminated"
	ContainerEventUpdated    ContainerEventType = "Updated"
	ContainerEventError      ContainerEventType = "Error"
)

// ContainerTracker manages discovery and tracking of containers across the cluster
type ContainerTracker struct {
	client          client.Client
	metricsManager  *metrics.Manager
	containers      map[string]*ContainerInfo
	eventHandlers   []ContainerEventHandler
	stopCh          chan struct{}
	mu              sync.RWMutex
	logger          logr.Logger
	refreshInterval time.Duration
	retryInterval   time.Duration
}

// ContainerEventHandler defines the interface for handling container events
type ContainerEventHandler interface {
	HandleContainerEvent(event *ContainerEvent) error
}

// ContainerFilter defines filters for container discovery
type ContainerFilter struct {
	Namespaces    []string          `json:"namespaces,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	ExcludeLabels map[string]string `json:"excludeLabels,omitempty"`
	States        []ContainerState  `json:"states,omitempty"`
	WorkloadKinds []string          `json:"workloadKinds,omitempty"`
	NodeNames     []string          `json:"nodeNames,omitempty"`
}

// NewContainerTracker creates a new container tracker
func NewContainerTracker(client client.Client, metricsManager *metrics.Manager) *ContainerTracker {
	return &ContainerTracker{
		client:          client,
		metricsManager:  metricsManager,
		containers:      make(map[string]*ContainerInfo),
		eventHandlers:   make([]ContainerEventHandler, 0),
		stopCh:          make(chan struct{}),
		refreshInterval: 30 * time.Second,
		retryInterval:   5 * time.Second,
		logger:          log.Log.WithName("container-tracker"),
	}
}

// Start begins container discovery and tracking
func (ct *ContainerTracker) Start(ctx context.Context) error {
	ct.logger.Info("Starting container tracker")

	// Initial discovery
	if err := ct.discoverExistingContainers(ctx); err != nil {
		ct.logger.Error(err, "Failed to discover existing containers")
		return err
	}

	// Start watch goroutine
	go ct.watchContainers(ctx)

	// Start periodic refresh
	go ct.periodicRefresh(ctx)

	return nil
}

// Stop stops the container tracker
func (ct *ContainerTracker) Stop() {
	ct.logger.Info("Stopping container tracker")
	close(ct.stopCh)
}

// RegisterEventHandler registers a container event handler
func (ct *ContainerTracker) RegisterEventHandler(handler ContainerEventHandler) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.eventHandlers = append(ct.eventHandlers, handler)
}

// GetContainer retrieves information about a specific container
func (ct *ContainerTracker) GetContainer(containerID string) (*ContainerInfo, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	container, exists := ct.containers[containerID]
	return container, exists
}

// GetContainers retrieves all tracked containers, optionally filtered
func (ct *ContainerTracker) GetContainers(filter *ContainerFilter) []*ContainerInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var result []*ContainerInfo
	for _, container := range ct.containers {
		if ct.matchesFilter(container, filter) {
			result = append(result, container)
		}
	}
	return result
}

// GetContainersByPod retrieves all containers for a specific pod
func (ct *ContainerTracker) GetContainersByPod(podNamespace, podName string) []*ContainerInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var result []*ContainerInfo
	for _, container := range ct.containers {
		if container.PodNamespace == podNamespace && container.PodName == podName {
			result = append(result, container)
		}
	}
	return result
}

// GetContainersByWorkload retrieves all containers for a specific workload
func (ct *ContainerTracker) GetContainersByWorkload(namespace, workloadKind, workloadName string) []*ContainerInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var result []*ContainerInfo
	for _, container := range ct.containers {
		if container.PodNamespace == namespace &&
			container.WorkloadInfo != nil &&
			container.WorkloadInfo.Kind == workloadKind &&
			container.WorkloadInfo.Name == workloadName {
			result = append(result, container)
		}
	}
	return result
}

// GetStats returns tracking statistics
func (ct *ContainerTracker) GetStats() map[string]interface{} {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_containers"] = len(ct.containers)

	stateCount := make(map[ContainerState]int)
	runtimeCount := make(map[string]int)
	namespaceCount := make(map[string]int)

	for _, container := range ct.containers {
		stateCount[container.State]++
		if container.RuntimeInfo != nil {
			runtimeCount[container.RuntimeInfo.Runtime]++
		}
		namespaceCount[container.PodNamespace]++
	}

	stats["by_state"] = stateCount
	stats["by_runtime"] = runtimeCount
	stats["by_namespace"] = namespaceCount
	stats["event_handlers"] = len(ct.eventHandlers)

	return stats
}

// discoverExistingContainers performs initial discovery of existing containers
func (ct *ContainerTracker) discoverExistingContainers(ctx context.Context) error {
	ct.logger.Info("Discovering existing containers")

	podList := &corev1.PodList{}
	if err := ct.client.List(ctx, podList); err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	for _, pod := range podList.Items {
		if err := ct.processPodContainers(ctx, &pod); err != nil {
			ct.logger.Error(err, "Failed to process pod containers", "pod", pod.Name, "namespace", pod.Namespace)
		}
	}

	ct.logger.Info("Container discovery completed", "containers", len(ct.containers))
	return nil
}

// watchContainers watches for container changes via pod events
func (ct *ContainerTracker) watchContainers(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ct.stopCh:
			return
		default:
			if err := ct.startWatch(ctx); err != nil {
				ct.logger.Error(err, "Pod watch failed, retrying")
				time.Sleep(ct.retryInterval)
			}
		}
	}
}

// startWatch starts periodic discovery of pod containers
func (ct *ContainerTracker) startWatch(ctx context.Context) error {
	ticker := time.NewTicker(ct.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ct.stopCh:
			return nil
		case <-ticker.C:
			if err := ct.discoverExistingContainers(ctx); err != nil {
				ct.logger.Error(err, "Failed to discover containers during periodic scan")
			}
		}
	}
}

// processPodContainers processes containers in a pod
func (ct *ContainerTracker) processPodContainers(ctx context.Context, pod *corev1.Pod) error {
	workloadInfo := ct.extractWorkloadInfo(ctx, pod)

	// Process all container specs
	for i, containerSpec := range pod.Spec.Containers {
		var containerStatus *corev1.ContainerStatus

		// Find matching status
		for j := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[j].Name == containerSpec.Name {
				containerStatus = &pod.Status.ContainerStatuses[j]
				break
			}
		}

		containerInfo := ct.buildContainerInfo(pod, &containerSpec, containerStatus, workloadInfo, i == 0)
		ct.updateContainer(containerInfo)
	}

	// Process init containers
	for _, containerSpec := range pod.Spec.InitContainers {
		var containerStatus *corev1.ContainerStatus

		// Find matching status
		for j := range pod.Status.InitContainerStatuses {
			if pod.Status.InitContainerStatuses[j].Name == containerSpec.Name {
				containerStatus = &pod.Status.InitContainerStatuses[j]
				break
			}
		}

		containerInfo := ct.buildContainerInfo(pod, &containerSpec, containerStatus, workloadInfo, false)
		containerInfo.Name = "init-" + containerInfo.Name
		ct.updateContainer(containerInfo)
	}

	return nil
}

// buildContainerInfo constructs ContainerInfo from pod and container data
func (ct *ContainerTracker) buildContainerInfo(
	pod *corev1.Pod,
	containerSpec *corev1.Container,
	containerStatus *corev1.ContainerStatus,
	workloadInfo *WorkloadInfo,
	isMainContainer bool,
) *ContainerInfo {
	info := &ContainerInfo{
		Name:            containerSpec.Name,
		Image:           containerSpec.Image,
		ImagePullPolicy: containerSpec.ImagePullPolicy,
		PodName:         pod.Name,
		PodNamespace:    pod.Namespace,
		PodUID:          string(pod.UID),
		NodeName:        pod.Spec.NodeName,
		WorkloadInfo:    workloadInfo,
		Labels:          pod.Labels,
		Annotations:     pod.Annotations,
		CreatedAt:       pod.CreationTimestamp.Time,
		LastUpdate:      time.Now(),
		State:           ct.determineContainerState(pod, containerStatus),
	}

	// Extract container ID if available
	if containerStatus != nil {
		info.ID = ct.extractContainerID(containerStatus.ContainerID)
		info.RestartCount = containerStatus.RestartCount

		if containerStatus.State.Running != nil {
			startTime := containerStatus.State.Running.StartedAt.Time
			info.StartedAt = &startTime
		}
		if containerStatus.State.Terminated != nil {
			finishTime := containerStatus.State.Terminated.FinishedAt.Time
			info.FinishedAt = &finishTime
		}
	}

	// Build security context info
	info.SecurityContext = ct.buildSecurityContextInfo(pod, containerSpec)

	// Build resource info
	info.ResourceLimits = &ResourceInfo{
		Requests: containerSpec.Resources.Requests,
		Limits:   containerSpec.Resources.Limits,
	}

	// Build runtime info (simplified)
	if info.ID != "" {
		info.RuntimeInfo = ct.buildRuntimeInfo(info.ID, containerStatus)
	}

	return info
}

// extractWorkloadInfo extracts workload information from pod owner references
func (ct *ContainerTracker) extractWorkloadInfo(ctx context.Context, pod *corev1.Pod) *WorkloadInfo {
	for _, ownerRef := range pod.OwnerReferences {
		switch ownerRef.Kind {
		case "ReplicaSet":
			// For Deployments, we need to trace back through ReplicaSet
			return &WorkloadInfo{
				Name:       ct.getDeploymentNameFromReplicaSet(ownerRef.Name),
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				UID:        string(ownerRef.UID),
			}
		case "StatefulSet", "DaemonSet", "Job", "CronJob":
			return &WorkloadInfo{
				Name:       ownerRef.Name,
				Kind:       ownerRef.Kind,
				APIVersion: ownerRef.APIVersion,
				UID:        string(ownerRef.UID),
			}
		}
	}
	return nil
}

// buildSecurityContextInfo builds security context information
func (ct *ContainerTracker) buildSecurityContextInfo(pod *corev1.Pod, containerSpec *corev1.Container) *SecurityContextInfo {
	info := &SecurityContextInfo{}

	// Container-level security context
	if containerSpec.SecurityContext != nil {
		ctx := containerSpec.SecurityContext
		info.RunAsUser = ctx.RunAsUser
		info.RunAsGroup = ctx.RunAsGroup
		info.RunAsNonRoot = ctx.RunAsNonRoot
		info.ReadOnlyRootFS = ctx.ReadOnlyRootFilesystem
		info.AllowPrivilegeEsc = ctx.AllowPrivilegeEscalation
		info.Privileged = ctx.Privileged
		info.Capabilities = ctx.Capabilities
		info.SELinuxOptions = ctx.SELinuxOptions
		info.WindowsOptions = ctx.WindowsOptions
		info.SeccompProfile = ctx.SeccompProfile
	}

	// Pod-level security context
	if pod.Spec.SecurityContext != nil {
		podCtx := pod.Spec.SecurityContext
		if info.RunAsUser == nil {
			info.RunAsUser = podCtx.RunAsUser
		}
		if info.RunAsGroup == nil {
			info.RunAsGroup = podCtx.RunAsGroup
		}
		if info.RunAsNonRoot == nil {
			info.RunAsNonRoot = podCtx.RunAsNonRoot
		}
		info.FSGroup = podCtx.FSGroup
		info.FSGroupChangePolicy = podCtx.FSGroupChangePolicy
		if info.SELinuxOptions == nil {
			info.SELinuxOptions = podCtx.SELinuxOptions
		}
		if info.WindowsOptions == nil {
			info.WindowsOptions = podCtx.WindowsOptions
		}
		if info.SeccompProfile == nil {
			info.SeccompProfile = podCtx.SeccompProfile
		}
		info.SupplementalGroups = podCtx.SupplementalGroups
	}

	return info
}

// buildRuntimeInfo builds runtime-specific information
func (ct *ContainerTracker) buildRuntimeInfo(containerID string, containerStatus *corev1.ContainerStatus) *RuntimeInfo {
	info := &RuntimeInfo{
		ExtraInfo: make(map[string]string),
	}

	if containerStatus != nil {
		// Extract runtime type from container ID
		if strings.HasPrefix(containerStatus.ContainerID, "docker://") {
			info.Runtime = "docker"
		} else if strings.HasPrefix(containerStatus.ContainerID, "containerd://") {
			info.Runtime = "containerd"
		} else if strings.HasPrefix(containerStatus.ContainerID, "cri-o://") {
			info.Runtime = "cri-o"
		} else {
			info.Runtime = "unknown"
		}

		// In a real implementation, you would query the runtime for more details
		info.CgroupPath = fmt.Sprintf("/sys/fs/cgroup/docker/%s", containerID)
	}

	return info
}

// determineContainerState determines the current state of a container
func (ct *ContainerTracker) determineContainerState(pod *corev1.Pod, containerStatus *corev1.ContainerStatus) ContainerState {
	if containerStatus == nil {
		switch pod.Status.Phase {
		case corev1.PodPending:
			return ContainerStatePending
		case corev1.PodSucceeded, corev1.PodFailed:
			return ContainerStateTerminated
		default:
			return ContainerStateUnknown
		}
	}

	if containerStatus.State.Running != nil {
		return ContainerStateRunning
	}
	if containerStatus.State.Terminated != nil {
		return ContainerStateTerminated
	}
	if containerStatus.State.Waiting != nil {
		return ContainerStatePending
	}

	return ContainerStateUnknown
}

// extractContainerID extracts the actual container ID from the full container ID string
func (ct *ContainerTracker) extractContainerID(fullContainerID string) string {
	parts := strings.Split(fullContainerID, "://")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// getDeploymentNameFromReplicaSet extracts deployment name from ReplicaSet name
func (ct *ContainerTracker) getDeploymentNameFromReplicaSet(replicaSetName string) string {
	parts := strings.Split(replicaSetName, "-")
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return replicaSetName
}

// updateContainer updates or creates a container in the tracker
func (ct *ContainerTracker) updateContainer(container *ContainerInfo) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	oldContainer, exists := ct.containers[container.ID]
	ct.containers[container.ID] = container

	// Emit appropriate event
	var eventType ContainerEventType
	if !exists {
		eventType = ContainerEventCreated
		if ct.metricsManager != nil {
			ct.metricsManager.UpdateContainerCounts(float64(len(ct.containers)), 0, 0)
		}
	} else {
		eventType = ContainerEventUpdated
		// Check for state transitions
		if oldContainer.State != container.State {
			switch container.State {
			case ContainerStateRunning:
				eventType = ContainerEventStarted
			case ContainerStateTerminated:
				eventType = ContainerEventStopped
			}
		}
	}

	ct.emitEvent(&ContainerEvent{
		Type:      eventType,
		Container: container,
		Timestamp: time.Now(),
		Source:    "container-tracker",
	})
}

// handlePodDeletion handles pod deletion events
func (ct *ContainerTracker) handlePodDeletion(pod *corev1.Pod) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	var deletedContainers []*ContainerInfo
	for containerID, container := range ct.containers {
		if container.PodNamespace == pod.Namespace && container.PodName == pod.Name {
			deletedContainers = append(deletedContainers, container)
			delete(ct.containers, containerID)
		}
	}

	// Emit termination events
	for _, container := range deletedContainers {
		ct.emitEvent(&ContainerEvent{
			Type:      ContainerEventTerminated,
			Container: container,
			Timestamp: time.Now(),
			Source:    "container-tracker",
			Reason:    "PodDeleted",
		})
	}
}

// emitEvent sends an event to all registered handlers
func (ct *ContainerTracker) emitEvent(event *ContainerEvent) {
	for _, handler := range ct.eventHandlers {
		go func(h ContainerEventHandler) {
			if err := h.HandleContainerEvent(event); err != nil {
				ct.logger.Error(err, "Handler failed to process container event",
					"event", event.Type, "container", event.Container.ID)
			}
		}(handler)
	}
}

// matchesFilter checks if a container matches the given filter
func (ct *ContainerTracker) matchesFilter(container *ContainerInfo, filter *ContainerFilter) bool {
	if filter == nil {
		return true
	}

	// Check namespaces
	if len(filter.Namespaces) > 0 {
		found := false
		for _, ns := range filter.Namespaces {
			if container.PodNamespace == ns {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check labels
	for key, value := range filter.Labels {
		if container.Labels[key] != value {
			return false
		}
	}

	// Check exclude labels
	for key, value := range filter.ExcludeLabels {
		if container.Labels[key] == value {
			return false
		}
	}

	// Check states
	if len(filter.States) > 0 {
		found := false
		for _, state := range filter.States {
			if container.State == state {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check workload kinds
	if len(filter.WorkloadKinds) > 0 && container.WorkloadInfo != nil {
		found := false
		for _, kind := range filter.WorkloadKinds {
			if container.WorkloadInfo.Kind == kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check node names
	if len(filter.NodeNames) > 0 {
		found := false
		for _, nodeName := range filter.NodeNames {
			if container.NodeName == nodeName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// periodicRefresh performs periodic refresh of container information
func (ct *ContainerTracker) periodicRefresh(ctx context.Context) {
	ticker := time.NewTicker(ct.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ct.stopCh:
			return
		case <-ticker.C:
			if err := ct.discoverExistingContainers(ctx); err != nil {
				ct.logger.Error(err, "Periodic container refresh failed")
			}
		}
	}
}
