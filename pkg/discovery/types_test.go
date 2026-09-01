package discovery

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerInfo_IsRunning(t *testing.T) {
	tests := []struct {
		name      string
		container *ContainerInfo
		expected  bool
	}{
		{
			name: "running container",
			container: &ContainerInfo{
				ID:    "container-123",
				Name:  "test-container",
				State: ContainerStateRunning,
			},
			expected: true,
		},
		{
			name: "stopped container",
			container: &ContainerInfo{
				ID:    "container-456",
				Name:  "stopped-container",
				State: ContainerStateStopped,
			},
			expected: false,
		},
		{
			name: "paused container",
			container: &ContainerInfo{
				ID:    "container-789",
				Name:  "paused-container",
				State: ContainerStatePaused,
			},
			expected: false,
		},
		{
			name:      "zero-value container",
			container: &ContainerInfo{},
			expected:  false,
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
		{
			name:     "empty key and value",
			key:      "",
			value:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasLabel := container.HasLabel(tt.key, tt.value)
			assert.Equal(t, tt.expected, hasLabel)
		})
	}

	t.Run("nil labels map", func(t *testing.T) {
		nilLabelContainer := &ContainerInfo{ID: "nil-labels"}
		assert.False(t, nilLabelContainer.HasLabel("app", "nginx"))
	})
}

func TestContainerInfo_GetAge(t *testing.T) {
	t.Run("uses StartedAt when set", func(t *testing.T) {
		started := time.Now().Add(-2 * time.Hour)
		container := &ContainerInfo{
			ID:        "test-container",
			StartedAt: &started,
		}

		age := container.GetAge()
		assert.True(t, age >= 2*time.Hour)
		assert.True(t, age < 3*time.Hour)
	})

	t.Run("falls back to CreatedAt when StartedAt is nil", func(t *testing.T) {
		created := time.Now().Add(-30 * time.Minute)
		container := &ContainerInfo{
			ID:        "test-container",
			CreatedAt: created,
		}

		age := container.GetAge()
		require.True(t, age >= 30*time.Minute)
		assert.True(t, age < 31*time.Minute)
	})
}
