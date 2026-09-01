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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/obsernetics/pahlevan/pkg/metrics"
)

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, nil
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme, err := newScheme()
	require.NoError(t, err)
	return scheme
}

func newTestTracker(t *testing.T, objs ...client.Object) *ContainerTracker {
	t.Helper()
	fc := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(objs...).Build()
	return NewContainerTracker(fc, metrics.NewManager())
}

func newBenchTracker(b *testing.B) *ContainerTracker {
	b.Helper()
	scheme, err := newScheme()
	if err != nil {
		b.Fatal(err)
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	return NewContainerTracker(fc, metrics.NewManager())
}

// recordingHandler collects every event it receives, synchronized for use
// from the emitEvent goroutines.
type recordingHandler struct {
	mu     sync.Mutex
	events []*ContainerEvent
	err    error
}

func (h *recordingHandler) HandleContainerEvent(event *ContainerEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
	return h.err
}

func (h *recordingHandler) snapshot() []*ContainerEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*ContainerEvent, len(h.events))
	copy(out, h.events)
	return out
}

func TestNewContainerTracker(t *testing.T) {
	tracker := newTestTracker(t)
	require.NotNil(t, tracker)
	assert.NotNil(t, tracker.containers)
	assert.Empty(t, tracker.containers)
	assert.NotNil(t, tracker.eventHandlers)
	assert.Empty(t, tracker.eventHandlers)
	assert.NotNil(t, tracker.stopCh)
	assert.Equal(t, 30*time.Second, tracker.refreshInterval)
	assert.Equal(t, 5*time.Second, tracker.retryInterval)
}

func TestContainerTracker_RegisterEventHandler(t *testing.T) {
	tracker := newTestTracker(t)
	h1 := &recordingHandler{}
	h2 := &recordingHandler{}

	tracker.RegisterEventHandler(h1)
	tracker.RegisterEventHandler(h2)

	assert.Len(t, tracker.eventHandlers, 2)
}

func TestContainerTracker_GetContainer(t *testing.T) {
	tracker := newTestTracker(t)

	_, ok := tracker.GetContainer("missing")
	assert.False(t, ok)

	want := &ContainerInfo{ID: "c1", Name: "nginx"}
	tracker.updateContainer(want)

	got, ok := tracker.GetContainer("c1")
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestContainerTracker_GetContainers(t *testing.T) {
	tracker := newTestTracker(t)
	tracker.updateContainer(&ContainerInfo{ID: "c1", PodNamespace: "default", State: ContainerStateRunning})
	tracker.updateContainer(&ContainerInfo{ID: "c2", PodNamespace: "kube-system", State: ContainerStateStopped})

	all := tracker.GetContainers(nil)
	assert.Len(t, all, 2)

	filtered := tracker.GetContainers(&ContainerFilter{Namespaces: []string{"default"}})
	require.Len(t, filtered, 1)
	assert.Equal(t, "c1", filtered[0].ID)

	none := tracker.GetContainers(&ContainerFilter{Namespaces: []string{"nonexistent"}})
	assert.Empty(t, none)
}

func TestContainerTracker_GetContainersByPod(t *testing.T) {
	tracker := newTestTracker(t)
	tracker.updateContainer(&ContainerInfo{ID: "c1", PodNamespace: "default", PodName: "web-1"})
	tracker.updateContainer(&ContainerInfo{ID: "c2", PodNamespace: "default", PodName: "web-2"})
	tracker.updateContainer(&ContainerInfo{ID: "c3", PodNamespace: "other", PodName: "web-1"})

	result := tracker.GetContainersByPod("default", "web-1")
	require.Len(t, result, 1)
	assert.Equal(t, "c1", result[0].ID)

	assert.Empty(t, tracker.GetContainersByPod("default", "nonexistent"))
}

func TestContainerTracker_GetContainersByWorkload(t *testing.T) {
	tracker := newTestTracker(t)
	tracker.updateContainer(&ContainerInfo{
		ID: "c1", PodNamespace: "default",
		WorkloadInfo: &WorkloadInfo{Kind: "Deployment", Name: "web"},
	})
	tracker.updateContainer(&ContainerInfo{
		ID: "c2", PodNamespace: "default",
		WorkloadInfo: &WorkloadInfo{Kind: "StatefulSet", Name: "db"},
	})
	tracker.updateContainer(&ContainerInfo{ID: "c3", PodNamespace: "default"}) // no WorkloadInfo

	result := tracker.GetContainersByWorkload("default", "Deployment", "web")
	require.Len(t, result, 1)
	assert.Equal(t, "c1", result[0].ID)

	assert.Empty(t, tracker.GetContainersByWorkload("default", "Deployment", "nonexistent"))
	assert.Empty(t, tracker.GetContainersByWorkload("other-ns", "Deployment", "web"))
}

func TestContainerTracker_GetStats(t *testing.T) {
	tracker := newTestTracker(t)

	empty := tracker.GetStats()
	assert.Equal(t, 0, empty["total_containers"])

	tracker.updateContainer(&ContainerInfo{
		ID: "c1", PodNamespace: "default", State: ContainerStateRunning,
		RuntimeInfo: &RuntimeInfo{Runtime: "containerd"},
	})
	tracker.updateContainer(&ContainerInfo{
		ID: "c2", PodNamespace: "default", State: ContainerStateStopped,
		RuntimeInfo: &RuntimeInfo{Runtime: "containerd"},
	})
	tracker.RegisterEventHandler(&recordingHandler{})

	stats := tracker.GetStats()
	assert.Equal(t, 2, stats["total_containers"])
	byState, ok := stats["by_state"].(map[ContainerState]int)
	require.True(t, ok)
	assert.Equal(t, 1, byState[ContainerStateRunning])
	assert.Equal(t, 1, byState[ContainerStateStopped])
	byRuntime, ok := stats["by_runtime"].(map[string]int)
	require.True(t, ok)
	assert.Equal(t, 2, byRuntime["containerd"])
	assert.Equal(t, 1, stats["event_handlers"])
}

func TestContainerTracker_MatchesFilter(t *testing.T) {
	tracker := newTestTracker(t)
	container := &ContainerInfo{
		Name:         "nginx",
		PodNamespace: "default",
		NodeName:     "node-1",
		State:        ContainerStateRunning,
		Labels:       map[string]string{"app": "web", "tier": "frontend"},
		WorkloadInfo: &WorkloadInfo{Kind: "Deployment", Name: "web"},
	}

	assert.True(t, tracker.matchesFilter(container, nil))

	cases := []struct {
		name     string
		filter   *ContainerFilter
		expected bool
	}{
		{"namespace match", &ContainerFilter{Namespaces: []string{"default"}}, true},
		{"namespace mismatch", &ContainerFilter{Namespaces: []string{"other"}}, false},
		{"label match", &ContainerFilter{Labels: map[string]string{"app": "web"}}, true},
		{"label mismatch", &ContainerFilter{Labels: map[string]string{"app": "db"}}, false},
		{"exclude label match excludes", &ContainerFilter{ExcludeLabels: map[string]string{"tier": "frontend"}}, false},
		{"exclude label mismatch keeps", &ContainerFilter{ExcludeLabels: map[string]string{"tier": "backend"}}, true},
		{"state match", &ContainerFilter{States: []ContainerState{ContainerStateRunning}}, true},
		{"state mismatch", &ContainerFilter{States: []ContainerState{ContainerStateStopped}}, false},
		{"workload kind match", &ContainerFilter{WorkloadKinds: []string{"Deployment"}}, true},
		{"workload kind mismatch", &ContainerFilter{WorkloadKinds: []string{"StatefulSet"}}, false},
		{"node match", &ContainerFilter{NodeNames: []string{"node-1"}}, true},
		{"node mismatch", &ContainerFilter{NodeNames: []string{"node-2"}}, false},
		{"empty filter", &ContainerFilter{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tracker.matchesFilter(container, tc.filter))
		})
	}

	t.Run("workload kind filter with nil WorkloadInfo does not exclude", func(t *testing.T) {
		// The workload-kind check only applies when WorkloadInfo is present, so
		// a container with none set passes through this filter unfiltered.
		noWorkload := &ContainerInfo{PodNamespace: "default"}
		assert.True(t, tracker.matchesFilter(noWorkload, &ContainerFilter{WorkloadKinds: []string{"Deployment"}}))
	})
}

func TestContainerKey(t *testing.T) {
	withID := &ContainerInfo{ID: "container-1", PodUID: "uid-1", Name: "nginx"}
	assert.Equal(t, "container-1", containerKey(withID))

	withoutID := &ContainerInfo{PodUID: "uid-1", Name: "nginx"}
	assert.Equal(t, "uid-1/nginx", containerKey(withoutID))

	empty := &ContainerInfo{}
	assert.Equal(t, "/", containerKey(empty))
}

func TestContainerTracker_UpdateContainer(t *testing.T) {
	t.Run("nil container is a no-op", func(t *testing.T) {
		tracker := newTestTracker(t)
		tracker.updateContainer(nil)
		assert.Empty(t, tracker.containers)
	})

	t.Run("new container emits Created", func(t *testing.T) {
		tracker := newTestTracker(t)
		h := &recordingHandler{}
		tracker.RegisterEventHandler(h)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStatePending})

		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)
		assert.Equal(t, ContainerEventCreated, h.snapshot()[0].Type)
	})

	t.Run("state transition to running emits Started", func(t *testing.T) {
		tracker := newTestTracker(t)
		h := &recordingHandler{}
		tracker.RegisterEventHandler(h)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStatePending})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStateRunning})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 2 }, time.Second, time.Millisecond)
		assert.Equal(t, ContainerEventStarted, h.snapshot()[1].Type)
	})

	t.Run("state transition to terminated emits Stopped", func(t *testing.T) {
		tracker := newTestTracker(t)
		h := &recordingHandler{}
		tracker.RegisterEventHandler(h)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStateRunning})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStateTerminated})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 2 }, time.Second, time.Millisecond)
		assert.Equal(t, ContainerEventStopped, h.snapshot()[1].Type)
	})

	t.Run("unrelated field change emits Updated", func(t *testing.T) {
		tracker := newTestTracker(t)
		h := &recordingHandler{}
		tracker.RegisterEventHandler(h)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStateRunning, RestartCount: 0})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)

		tracker.updateContainer(&ContainerInfo{ID: "c1", State: ContainerStateRunning, RestartCount: 1})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 2 }, time.Second, time.Millisecond)
		assert.Equal(t, ContainerEventUpdated, h.snapshot()[1].Type)
	})

	t.Run("handler error is not fatal", func(t *testing.T) {
		tracker := newTestTracker(t)
		h := &recordingHandler{err: errors.New("boom")}
		tracker.RegisterEventHandler(h)

		assert.NotPanics(t, func() {
			tracker.updateContainer(&ContainerInfo{ID: "c1"})
		})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)
	})
}

func TestContainerTracker_EmitEvent(t *testing.T) {
	tracker := newTestTracker(t)

	t.Run("nil event is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() { tracker.emitEvent(nil) })
	})

	t.Run("no handlers is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() {
			tracker.emitEvent(&ContainerEvent{Type: ContainerEventCreated})
		})
	})

	t.Run("event with nil container reaches handlers", func(t *testing.T) {
		h := &recordingHandler{}
		tracker.RegisterEventHandler(h)
		tracker.emitEvent(&ContainerEvent{Type: ContainerEventCreated, Container: nil})
		require.Eventually(t, func() bool { return len(h.snapshot()) == 1 }, time.Second, time.Millisecond)
	})
}

func TestDetermineContainerState(t *testing.T) {
	ct := &ContainerTracker{}

	cases := []struct {
		name     string
		pod      *corev1.Pod
		status   *corev1.ContainerStatus
		expected ContainerState
	}{
		{
			name:     "nil status, pod pending",
			pod:      &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}},
			status:   nil,
			expected: ContainerStatePending,
		},
		{
			name:     "nil status, pod succeeded",
			pod:      &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
			status:   nil,
			expected: ContainerStateTerminated,
		},
		{
			name:     "nil status, pod failed",
			pod:      &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed}},
			status:   nil,
			expected: ContainerStateTerminated,
		},
		{
			name:     "nil status, pod running phase but no container status",
			pod:      &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			status:   nil,
			expected: ContainerStateUnknown,
		},
		{
			name:     "container running",
			pod:      &corev1.Pod{},
			status:   &corev1.ContainerStatus{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			expected: ContainerStateRunning,
		},
		{
			name:     "container terminated",
			pod:      &corev1.Pod{},
			status:   &corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}},
			expected: ContainerStateTerminated,
		},
		{
			name:     "container waiting",
			pod:      &corev1.Pod{},
			status:   &corev1.ContainerStatus{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}}},
			expected: ContainerStatePending,
		},
		{
			name:     "container status with no state set",
			pod:      &corev1.Pod{},
			status:   &corev1.ContainerStatus{},
			expected: ContainerStateUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ct.determineContainerState(tc.pod, tc.status))
		})
	}
}

func TestExtractContainerID(t *testing.T) {
	ct := &ContainerTracker{}

	assert.Equal(t, "abc123", ct.extractContainerID("containerd://abc123"))
	assert.Equal(t, "", ct.extractContainerID(""))
	assert.Equal(t, "", ct.extractContainerID("no-scheme-here"))
	assert.Equal(t, "", ct.extractContainerID("a://b://c"))
}

func TestGetDeploymentNameFromReplicaSet(t *testing.T) {
	ct := &ContainerTracker{}

	assert.Equal(t, "web", ct.getDeploymentNameFromReplicaSet("web-abc123"))
	assert.Equal(t, "my-app", ct.getDeploymentNameFromReplicaSet("my-app-xyz789"))
	assert.Equal(t, "noSuffix", ct.getDeploymentNameFromReplicaSet("noSuffix"))
	assert.Equal(t, "", ct.getDeploymentNameFromReplicaSet(""))
}

func TestContainerTracker_ExtractWorkloadInfo(t *testing.T) {
	ct := &ContainerTracker{}

	t.Run("no owner references", func(t *testing.T) {
		pod := &corev1.Pod{}
		assert.Nil(t, ct.extractWorkloadInfo(pod))
	})

	t.Run("ReplicaSet owner resolves to Deployment", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: "web-abc123", UID: "rs-uid"},
				},
			},
		}
		info := ct.extractWorkloadInfo(pod)
		require.NotNil(t, info)
		assert.Equal(t, "Deployment", info.Kind)
		assert.Equal(t, "web", info.Name)
		assert.Equal(t, "apps/v1", info.APIVersion)
		assert.Equal(t, "rs-uid", info.UID)
	})

	for _, kind := range []string{"StatefulSet", "DaemonSet", "Job", "CronJob"} {
		t.Run(kind+" owner is used as-is", func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: kind, Name: "workload-1", APIVersion: "v1", UID: "uid-1"},
					},
				},
			}
			info := ct.extractWorkloadInfo(pod)
			require.NotNil(t, info)
			assert.Equal(t, kind, info.Kind)
			assert.Equal(t, "workload-1", info.Name)
		})
	}

	t.Run("unrecognized owner kind is ignored", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ConfigMap", Name: "irrelevant"},
				},
			},
		}
		assert.Nil(t, ct.extractWorkloadInfo(pod))
	})
}

func TestContainerTracker_BuildSecurityContextInfo(t *testing.T) {
	ct := &ContainerTracker{}
	trueVal := true
	uid := int64(1000)

	t.Run("nil security contexts", func(t *testing.T) {
		info := ct.buildSecurityContextInfo(&corev1.Pod{}, &corev1.Container{})
		require.NotNil(t, info)
		assert.Nil(t, info.RunAsUser)
	})

	t.Run("container-level takes precedence over pod-level", func(t *testing.T) {
		pod := &corev1.Pod{
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsUser: func() *int64 { v := int64(2000); return &v }(),
				},
			},
		}
		containerSpec := &corev1.Container{
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:    &uid,
				Privileged:   &trueVal,
				RunAsNonRoot: &trueVal,
			},
		}
		info := ct.buildSecurityContextInfo(pod, containerSpec)
		require.NotNil(t, info.RunAsUser)
		assert.Equal(t, uid, *info.RunAsUser)
		require.NotNil(t, info.Privileged)
		assert.True(t, *info.Privileged)
	})

	t.Run("pod-level fills gaps left by container-level", func(t *testing.T) {
		pod := &corev1.Pod{
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsUser: &uid,
					FSGroup:   &uid,
				},
			},
		}
		info := ct.buildSecurityContextInfo(pod, &corev1.Container{})
		require.NotNil(t, info.RunAsUser)
		assert.Equal(t, uid, *info.RunAsUser)
		require.NotNil(t, info.FSGroup)
		assert.Equal(t, uid, *info.FSGroup)
	})
}

func TestContainerTracker_BuildContainerInfo(t *testing.T) {
	ct := &ContainerTracker{}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-1",
			Namespace: "default",
			UID:       "pod-uid",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
		},
	}
	containerSpec := &corev1.Container{
		Name:            "nginx",
		Image:           "nginx:latest",
		ImagePullPolicy: corev1.PullAlways,
	}
	status := &corev1.ContainerStatus{
		ContainerID:  "containerd://abcdef0123456789abcdef0123456789",
		RestartCount: 2,
		State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
	}

	info := ct.buildContainerInfo(pod, containerSpec, status, nil, true)
	require.NotNil(t, info)
	assert.Equal(t, "nginx", info.Name)
	assert.Equal(t, "nginx:latest", info.Image)
	assert.Equal(t, "web-1", info.PodName)
	assert.Equal(t, "default", info.PodNamespace)
	assert.Equal(t, "abcdef0123456789abcdef0123456789", info.ID)
	assert.Equal(t, int32(2), info.RestartCount)
	assert.Equal(t, ContainerStateRunning, info.State)
	assert.True(t, info.IsMainContainer)
	assert.NotNil(t, info.StartedAt)
	require.NotNil(t, info.RuntimeInfo)
	assert.Equal(t, "containerd", info.RuntimeInfo.Runtime)

	t.Run("terminated container records FinishedAt", func(t *testing.T) {
		terminated := &corev1.ContainerStatus{
			ContainerID: "containerd://abcdef0123456789abcdef0123456789",
			State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: metav1.Now()}},
		}
		info := ct.buildContainerInfo(pod, containerSpec, terminated, nil, false)
		assert.NotNil(t, info.FinishedAt)
		assert.False(t, info.IsMainContainer)
	})

	t.Run("nil container status leaves ID empty", func(t *testing.T) {
		info := ct.buildContainerInfo(pod, containerSpec, nil, nil, false)
		assert.Empty(t, info.ID)
		assert.Nil(t, info.RuntimeInfo)
	})
}

func TestContainerTracker_ProcessPodContainers(t *testing.T) {
	tracker := newTestTracker(t)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default", UID: "pod-uid"},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "nginx"}, {Name: "sidecar"}},
			InitContainers: []corev1.Container{{Name: "init-migrate"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "nginx", ContainerID: "containerd://c1"},
				{Name: "sidecar", ContainerID: "containerd://c2"},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init-migrate", ContainerID: "containerd://c3"},
			},
		},
	}

	tracker.processPodContainers(pod)

	containers := tracker.GetContainers(nil)
	require.Len(t, containers, 3)

	byName := make(map[string]*ContainerInfo, len(containers))
	for _, c := range containers {
		byName[c.Name] = c
	}
	require.Contains(t, byName, "nginx")
	assert.True(t, byName["nginx"].IsMainContainer)
	require.Contains(t, byName, "sidecar")
	assert.False(t, byName["sidecar"].IsMainContainer)
	require.Contains(t, byName, "init-init-migrate")
	assert.True(t, byName["init-init-migrate"].IsInitContainer)
}

func TestContainerTracker_DiscoverExistingContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx"}}},
	}
	tracker := newTestTracker(t, pod)

	require.NoError(t, tracker.discoverExistingContainers(context.Background()))

	containers := tracker.GetContainers(nil)
	require.Len(t, containers, 1)
	assert.Equal(t, "nginx", containers[0].Name)
}

func TestContainerTracker_StartAndStop(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx"}}},
	}
	tracker := newTestTracker(t, pod)
	tracker.refreshInterval = time.Millisecond
	tracker.retryInterval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, tracker.Start(ctx))

	require.Eventually(t, func() bool {
		_, ok := tracker.GetContainer("")
		containers := tracker.GetContainers(nil)
		return len(containers) == 1 || ok
	}, time.Second, time.Millisecond)

	assert.NotPanics(t, tracker.Stop)
}

func BenchmarkContainerTracker_UpdateContainer(b *testing.B) {
	tracker := newBenchTracker(b)
	container := &ContainerInfo{ID: "bench-container", PodNamespace: "default", State: ContainerStateRunning}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.updateContainer(container)
	}
}

func BenchmarkContainerTracker_GetContainers(b *testing.B) {
	tracker := newBenchTracker(b)
	for i := 0; i < 1000; i++ {
		ns := "default"
		if i%2 == 0 {
			ns = "other"
		}
		tracker.updateContainer(&ContainerInfo{
			ID:           "container-" + string(rune('a'+i%26)) + string(rune(i)),
			PodNamespace: ns,
			State:        ContainerStateRunning,
		})
	}
	filter := &ContainerFilter{Namespaces: []string{"default"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tracker.GetContainers(filter)
	}
}

func BenchmarkContainerTracker_MatchesFilter(b *testing.B) {
	tracker := &ContainerTracker{}
	container := &ContainerInfo{
		Name:         "nginx",
		PodNamespace: "default",
		NodeName:     "node-1",
		State:        ContainerStateRunning,
		Labels:       map[string]string{"app": "web", "tier": "frontend"},
		WorkloadInfo: &WorkloadInfo{Kind: "Deployment", Name: "web"},
	}
	filter := &ContainerFilter{
		Namespaces:    []string{"default"},
		Labels:        map[string]string{"app": "web"},
		States:        []ContainerState{ContainerStateRunning},
		WorkloadKinds: []string{"Deployment"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.matchesFilter(container, filter)
	}
}

func TestContainerTracker_StartDiscoveryFailure(t *testing.T) {
	// A tracker with no client set makes discoverExistingContainers fail
	// (List against a nil client panics in the real client, so use a
	// scheme with no registered types instead to force a List error).
	fc := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	tracker := NewContainerTracker(fc, metrics.NewManager())

	err := tracker.Start(context.Background())
	assert.Error(t, err)
}
