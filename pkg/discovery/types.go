package discovery

import "time"

// Container discovery types

type ContainerScanner struct {
	scanInterval  time.Duration
	maxContainers int
	containers    map[string]*ContainerInfo
	watchers      []EventWatcher
}


type PodInfo struct {
	Name       string
	Namespace  string
	Phase      PodPhase
	Ready      bool
	Containers []*ContainerInfo
	Labels     map[string]string
	StartTime  time.Time
}

type NodeInfo struct {
	Name      string
	Ready     bool
	Taints    []string
	Labels    map[string]string
	Resources map[string]string
}

type ContainerStatus string

const (
	ContainerStatusRunning ContainerStatus = "Running"
	ContainerStatusStopped ContainerStatus = "Stopped"
	ContainerStatusPaused  ContainerStatus = "Paused"
)

type PodPhase string

const (
	PodPhasePending   PodPhase = "Pending"
	PodPhaseRunning   PodPhase = "Running"
	PodPhaseSucceeded PodPhase = "Succeeded"
	PodPhaseFailed    PodPhase = "Failed"
	PodPhaseUnknown   PodPhase = "Unknown"
)

type DiscoveryEvent struct {
	Type      EventType
	Resource  ResourceType
	Object    interface{}
	Timestamp time.Time
}

type EventType string

const (
	EventTypeContainerAdded   EventType = "ContainerAdded"
	EventTypeContainerRemoved EventType = "ContainerRemoved"
	EventTypeContainerUpdated EventType = "ContainerUpdated"
	EventTypePodAdded         EventType = "PodAdded"
	EventTypePodRemoved       EventType = "PodRemoved"
	EventTypePodUpdated       EventType = "PodUpdated"
)

type ResourceType string

const (
	ResourceTypeContainer ResourceType = "Container"
	ResourceTypePod       ResourceType = "Pod"
	ResourceTypeNode      ResourceType = "Node"
)

type EventWatcher struct {
	listeners []EventListener
	eventChan chan *DiscoveryEvent
}

type EventListener interface {
	OnEvent(event *DiscoveryEvent)
}

type ResourceFilter struct {
	Names      []string
	Labels     map[string]string
	Namespaces []string
}

type ClusterState struct {
	Containers map[string]*ContainerInfo
	Pods       map[string]*PodInfo
	Nodes      map[string]*NodeInfo
	LastUpdate time.Time
}

type DiscoveryMetrics struct {
	ContainersDiscovered uint64
	PodsDiscovered       uint64
	NodesDiscovered      uint64
	ScanDuration         time.Duration
	LastScanTime         time.Time
	EventsProcessed      uint64
}

type RateLimiter struct {
	MaxRequests int
	Window      time.Duration
	requests    []time.Time
}

// Constructor
func NewContainerScanner(interval time.Duration, maxContainers int) *ContainerScanner {
	return &ContainerScanner{
		scanInterval:  interval,
		maxContainers: maxContainers,
		containers:    make(map[string]*ContainerInfo),
		watchers:      make([]EventWatcher, 0),
	}
}

// Methods
func (ci *ContainerInfo) IsRunning() bool {
	return ci.State == ContainerStateRunning
}

func (ci *ContainerInfo) HasLabel(key, value string) bool {
	if ci.Labels == nil {
		return false
	}
	v, exists := ci.Labels[key]
	return exists && v == value
}

func (ci *ContainerInfo) GetAge() time.Duration {
	if ci.StartedAt != nil {
		return time.Since(*ci.StartedAt)
	}
	return time.Since(ci.CreatedAt)
}

func (pi *PodInfo) IsReady() bool {
	return pi.Ready && pi.Phase == PodPhaseRunning
}

func (pi *PodInfo) GetContainerByName(name string) *ContainerInfo {
	for _, container := range pi.Containers {
		if container.Name == name {
			return container
		}
	}
	return nil
}

func (ni *NodeInfo) IsReady() bool {
	return ni.Ready
}

func (ni *NodeInfo) HasTaint(taint string) bool {
	for _, t := range ni.Taints {
		if t == taint {
			return true
		}
	}
	return false
}

func (de *DiscoveryEvent) IsContainerEvent() bool {
	return de.Resource == ResourceTypeContainer
}

func (de *DiscoveryEvent) IsPodEvent() bool {
	return de.Resource == ResourceTypePod
}

func (ew *EventWatcher) AddListener(listener EventListener) {
	ew.listeners = append(ew.listeners, listener)
}

func (ew *EventWatcher) RemoveListener(listener EventListener) {
	for i, l := range ew.listeners {
		if l == listener {
			ew.listeners = append(ew.listeners[:i], ew.listeners[i+1:]...)
			break
		}
	}
}

func (rf *ResourceFilter) Matches(container *ContainerInfo) bool {
	// Check names
	if len(rf.Names) > 0 {
		found := false
		for _, name := range rf.Names {
			if name == container.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check labels
	for key, value := range rf.Labels {
		if !container.HasLabel(key, value) {
			return false
		}
	}

	// Check namespaces
	if len(rf.Namespaces) > 0 {
		found := false
		for _, ns := range rf.Namespaces {
			if ns == container.PodNamespace {
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

func (cs *ClusterState) AddContainer(container *ContainerInfo) {
	cs.Containers[container.ID] = container
	cs.LastUpdate = time.Now()
}

func (cs *ClusterState) RemoveContainer(id string) {
	delete(cs.Containers, id)
	cs.LastUpdate = time.Now()
}

func (cs *ClusterState) GetRunningContainers() []*ContainerInfo {
	var running []*ContainerInfo
	for _, container := range cs.Containers {
		if container.IsRunning() {
			running = append(running, container)
		}
	}
	return running
}

func (rl *RateLimiter) Allow() bool {
	now := time.Now()

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, req := range rl.requests {
		if now.Sub(req) <= rl.Window {
			validRequests = append(validRequests, req)
		}
	}
	rl.requests = validRequests

	// Check if we can make a new request
	if len(rl.requests) >= rl.MaxRequests {
		return false
	}

	// Add new request
	rl.requests = append(rl.requests, now)
	return true
}