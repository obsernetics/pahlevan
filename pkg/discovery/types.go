package discovery

import "time"

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
