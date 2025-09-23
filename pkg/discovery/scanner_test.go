package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerScanner_NewContainerScanner(t *testing.T) {
	scanner := NewContainerScanner(5*time.Second, 100)

	require.NotNil(t, scanner)
	assert.Equal(t, 5*time.Second, scanner.scanInterval)
	assert.Equal(t, 100, scanner.maxContainers)
	assert.NotNil(t, scanner.containers)
	assert.NotNil(t, scanner.watchers)
}

func TestContainerInfo_IsRunning(t *testing.T) {
	tests := []struct {
		name      string
		container *ContainerInfo
		expected  bool
	}{
		{
			name: "running container",
			container: &ContainerInfo{
				ID:     "container-123",
				Name:   "test-container",
				Status: ContainerStatusRunning,
			},
			expected: true,
		},
		{
			name: "stopped container",
			container: &ContainerInfo{
				ID:     "container-456",
				Name:   "stopped-container",
				Status: ContainerStatusStopped,
			},
			expected: false,
		},
		{
			name: "paused container",
			container: &ContainerInfo{
				ID:     "container-789",
				Name:   "paused-container",
				Status: ContainerStatusPaused,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			running := tt.container.IsRunning()
			assert.Equal(t, tt.expected, running)
		})
	}
}

func TestContainerInfo_HasLabel(t *testing.T) {
	container := &ContainerInfo{
		ID:   "test-container",
		Name: "test",
		Labels: map[string]string{
			"app":     "nginx",
			"version": "1.0",
			"env":     "production",
		},
	}

	tests := []struct {
		name     string
		key      string
		value    string
		expected bool
	}{
		{
			name:     "existing label exact match",
			key:      "app",
			value:    "nginx",
			expected: true,
		},
		{
			name:     "existing label wrong value",
			key:      "app",
			value:    "apache",
			expected: false,
		},
		{
			name:     "non-existing label",
			key:      "nonexistent",
			value:    "value",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasLabel := container.HasLabel(tt.key, tt.value)
			assert.Equal(t, tt.expected, hasLabel)
		})
	}
}

func TestContainerInfo_GetAge(t *testing.T) {
	container := &ContainerInfo{
		ID:        "test-container",
		StartTime: time.Now().Add(-2 * time.Hour),
	}

	age := container.GetAge()
	assert.True(t, age >= 2*time.Hour)
	assert.True(t, age < 3*time.Hour)
}

func TestPodInfo_IsReady(t *testing.T) {
	tests := []struct {
		name     string
		pod      *PodInfo
		expected bool
	}{
		{
			name: "ready pod",
			pod: &PodInfo{
				Name:      "test-pod",
				Namespace: "default",
				Phase:     PodPhaseRunning,
				Ready:     true,
			},
			expected: true,
		},
		{
			name: "not ready pod",
			pod: &PodInfo{
				Name:      "test-pod",
				Namespace: "default",
				Phase:     PodPhaseRunning,
				Ready:     false,
			},
			expected: false,
		},
		{
			name: "pending pod",
			pod: &PodInfo{
				Name:      "test-pod",
				Namespace: "default",
				Phase:     PodPhasePending,
				Ready:     false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ready := tt.pod.IsReady()
			assert.Equal(t, tt.expected, ready)
		})
	}
}

func TestPodInfo_GetContainerByName(t *testing.T) {
	pod := &PodInfo{
		Name:      "test-pod",
		Namespace: "default",
		Containers: []*ContainerInfo{
			{
				ID:   "container-1",
				Name: "nginx",
			},
			{
				ID:   "container-2",
				Name: "sidecar",
			},
		},
	}

	// Test existing container
	container := pod.GetContainerByName("nginx")
	require.NotNil(t, container)
	assert.Equal(t, "container-1", container.ID)
	assert.Equal(t, "nginx", container.Name)

	// Test non-existing container
	notFound := pod.GetContainerByName("nonexistent")
	assert.Nil(t, notFound)
}

func TestNodeInfo_IsReady(t *testing.T) {
	tests := []struct {
		name     string
		node     *NodeInfo
		expected bool
	}{
		{
			name: "ready node",
			node: &NodeInfo{
				Name:   "node-1",
				Ready:  true,
				Taints: []string{},
			},
			expected: true,
		},
		{
			name: "not ready node",
			node: &NodeInfo{
				Name:   "node-2",
				Ready:  false,
				Taints: []string{"node.kubernetes.io/not-ready"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ready := tt.node.IsReady()
			assert.Equal(t, tt.expected, ready)
		})
	}
}

func TestNodeInfo_HasTaint(t *testing.T) {
	node := &NodeInfo{
		Name: "test-node",
		Taints: []string{
			"node.kubernetes.io/not-ready",
			"node.kubernetes.io/disk-pressure",
		},
	}

	tests := []struct {
		name     string
		taint    string
		expected bool
	}{
		{
			name:     "existing taint",
			taint:    "node.kubernetes.io/not-ready",
			expected: true,
		},
		{
			name:     "non-existing taint",
			taint:    "node.kubernetes.io/memory-pressure",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasTaint := node.HasTaint(tt.taint)
			assert.Equal(t, tt.expected, hasTaint)
		})
	}
}

func TestDiscoveryEvent_IsContainerEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    *DiscoveryEvent
		expected bool
	}{
		{
			name: "container added event",
			event: &DiscoveryEvent{
				Type:     EventTypeContainerAdded,
				Resource: ResourceTypeContainer,
			},
			expected: true,
		},
		{
			name: "pod added event",
			event: &DiscoveryEvent{
				Type:     EventTypePodAdded,
				Resource: ResourceTypePod,
			},
			expected: false,
		},
		{
			name: "container removed event",
			event: &DiscoveryEvent{
				Type:     EventTypeContainerRemoved,
				Resource: ResourceTypeContainer,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isContainer := tt.event.IsContainerEvent()
			assert.Equal(t, tt.expected, isContainer)
		})
	}
}

func TestDiscoveryEvent_IsPodEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    *DiscoveryEvent
		expected bool
	}{
		{
			name: "pod added event",
			event: &DiscoveryEvent{
				Type:     EventTypePodAdded,
				Resource: ResourceTypePod,
			},
			expected: true,
		},
		{
			name: "container event",
			event: &DiscoveryEvent{
				Type:     EventTypeContainerAdded,
				Resource: ResourceTypeContainer,
			},
			expected: false,
		},
		{
			name: "pod updated event",
			event: &DiscoveryEvent{
				Type:     EventTypePodUpdated,
				Resource: ResourceTypePod,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isPod := tt.event.IsPodEvent()
			assert.Equal(t, tt.expected, isPod)
		})
	}
}

func TestEventWatcher_AddListener(t *testing.T) {
	watcher := &EventWatcher{
		listeners: make([]EventListener, 0),
		eventChan: make(chan *DiscoveryEvent, 100),
	}

	listener := &MockEventListener{
		events: make([]*DiscoveryEvent, 0),
	}

	watcher.AddListener(listener)

	assert.Len(t, watcher.listeners, 1)
	assert.Equal(t, listener, watcher.listeners[0])
}

func TestEventWatcher_RemoveListener(t *testing.T) {
	watcher := &EventWatcher{
		listeners: make([]EventListener, 0),
		eventChan: make(chan *DiscoveryEvent, 100),
	}

	listener1 := &MockEventListener{}
	listener2 := &MockEventListener{}

	watcher.AddListener(listener1)
	watcher.AddListener(listener2)
	assert.Len(t, watcher.listeners, 2)

	watcher.RemoveListener(listener1)
	assert.Len(t, watcher.listeners, 1)
	assert.Equal(t, listener2, watcher.listeners[0])
}

// MockEventListener for testing
type MockEventListener struct {
	events []*DiscoveryEvent
}

func (m *MockEventListener) OnEvent(event *DiscoveryEvent) {
	m.events = append(m.events, event)
}

func TestResourceFilter_Matches(t *testing.T) {
	tests := []struct {
		name      string
		filter    *ResourceFilter
		container *ContainerInfo
		expected  bool
	}{
		{
			name: "matches all criteria",
			filter: &ResourceFilter{
				Names:      []string{"nginx", "apache"},
				Labels:     map[string]string{"app": "web"},
				Namespaces: []string{"default", "production"},
			},
			container: &ContainerInfo{
				Name:      "nginx",
				Namespace: "default",
				Labels:    map[string]string{"app": "web", "version": "1.0"},
			},
			expected: true,
		},
		{
			name: "name doesn't match",
			filter: &ResourceFilter{
				Names:      []string{"apache"},
				Labels:     map[string]string{"app": "web"},
				Namespaces: []string{"default"},
			},
			container: &ContainerInfo{
				Name:      "nginx",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			expected: false,
		},
		{
			name: "label doesn't match",
			filter: &ResourceFilter{
				Names:      []string{"nginx"},
				Labels:     map[string]string{"app": "database"},
				Namespaces: []string{"default"},
			},
			container: &ContainerInfo{
				Name:      "nginx",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := tt.filter.Matches(tt.container)
			assert.Equal(t, tt.expected, matches)
		})
	}
}

func TestClusterState_AddContainer(t *testing.T) {
	state := &ClusterState{
		Containers: make(map[string]*ContainerInfo),
		Pods:       make(map[string]*PodInfo),
		Nodes:      make(map[string]*NodeInfo),
		LastUpdate: time.Now(),
	}

	container := &ContainerInfo{
		ID:        "container-123",
		Name:      "test-container",
		Namespace: "default",
		Status:    ContainerStatusRunning,
	}

	state.AddContainer(container)

	assert.Len(t, state.Containers, 1)
	assert.Equal(t, container, state.Containers["container-123"])
}

func TestClusterState_RemoveContainer(t *testing.T) {
	state := &ClusterState{
		Containers: make(map[string]*ContainerInfo),
	}

	container := &ContainerInfo{
		ID: "container-123",
	}
	state.Containers["container-123"] = container

	state.RemoveContainer("container-123")

	assert.Len(t, state.Containers, 0)
	assert.Nil(t, state.Containers["container-123"])
}

func TestClusterState_GetRunningContainers(t *testing.T) {
	state := &ClusterState{
		Containers: map[string]*ContainerInfo{
			"container-1": {
				ID:     "container-1",
				Status: ContainerStatusRunning,
			},
			"container-2": {
				ID:     "container-2",
				Status: ContainerStatusStopped,
			},
			"container-3": {
				ID:     "container-3",
				Status: ContainerStatusRunning,
			},
		},
	}

	running := state.GetRunningContainers()

	assert.Len(t, running, 2)
	runningIDs := make([]string, len(running))
	for i, container := range running {
		runningIDs[i] = container.ID
	}
	assert.Contains(t, runningIDs, "container-1")
	assert.Contains(t, runningIDs, "container-3")
	assert.NotContains(t, runningIDs, "container-2")
}

func TestBenchmarkContainerScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	scanner := NewContainerScanner(1*time.Second, 1000)
	state := &ClusterState{
		Containers: make(map[string]*ContainerInfo),
	}

	// Add many containers
	for i := 0; i < 1000; i++ {
		container := &ContainerInfo{
			ID:        "container-" + string(rune(i)),
			Name:      "test-container-" + string(rune(i)),
			Status:    ContainerStatusRunning,
			StartTime: time.Now(),
		}
		state.AddContainer(container)
	}

	start := time.Now()
	running := state.GetRunningContainers()
	duration := time.Since(start)

	assert.Len(t, running, 1000)
	assert.Less(t, duration, 10*time.Millisecond, "Container scanning should be fast")
	t.Logf("Scanned 1000 containers in %v", duration)
}

func TestDiscoveryMetrics(t *testing.T) {
	metrics := &DiscoveryMetrics{
		ContainersDiscovered: 0,
		PodsDiscovered:       0,
		NodesDiscovered:      0,
		ScanDuration:         0,
		LastScanTime:         time.Time{},
		EventsProcessed:      0,
	}

	// Test metrics updating
	metrics.ContainersDiscovered = 10
	metrics.PodsDiscovered = 5
	metrics.NodesDiscovered = 3
	metrics.ScanDuration = 500 * time.Millisecond
	metrics.LastScanTime = time.Now()
	metrics.EventsProcessed = 25

	assert.Equal(t, uint64(10), metrics.ContainersDiscovered)
	assert.Equal(t, uint64(5), metrics.PodsDiscovered)
	assert.Equal(t, uint64(3), metrics.NodesDiscovered)
	assert.Equal(t, 500*time.Millisecond, metrics.ScanDuration)
	assert.Equal(t, uint64(25), metrics.EventsProcessed)
	assert.False(t, metrics.LastScanTime.IsZero())
}

func TestRateLimiter(t *testing.T) {
	limiter := &RateLimiter{
		MaxRequests: 10,
		Window:      1 * time.Second,
		requests:    make([]time.Time, 0),
	}

	// Test that we can make requests within limit
	for i := 0; i < 10; i++ {
		allowed := limiter.Allow()
		assert.True(t, allowed, "Request %d should be allowed", i)
	}

	// Test that we're rate limited after exceeding
	allowed := limiter.Allow()
	assert.False(t, allowed, "Request should be rate limited")

	// Test that we can make requests again after window expires
	time.Sleep(1100 * time.Millisecond)
	allowed = limiter.Allow()
	assert.True(t, allowed, "Request should be allowed after window reset")
}