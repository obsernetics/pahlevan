package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCapabilityChecker(t *testing.T) {
	checker := NewCapabilityChecker()
	assert.NotNil(t, checker)
	assert.NotNil(t, checker.logger)
}

func TestSystemCapabilities_RequireFeature(t *testing.T) {
	tests := []struct {
		name         string
		caps         *SystemCapabilities
		feature      string
		expectError  bool
		errorContains string
	}{
		{
			name: "ebpf_supported",
			caps: &SystemCapabilities{
				HasEBPFSupport: true,
			},
			feature:     "ebpf",
			expectError: false,
		},
		{
			name: "ebpf_not_supported",
			caps: &SystemCapabilities{
				HasEBPFSupport: false,
			},
			feature:       "ebpf",
			expectError:   true,
			errorContains: "eBPF support is required",
		},
		{
			name: "tc_supported",
			caps: &SystemCapabilities{
				HasTCSupport: true,
			},
			feature:     "tc",
			expectError: false,
		},
		{
			name: "tc_not_supported",
			caps: &SystemCapabilities{
				HasTCSupport: false,
			},
			feature:       "tc",
			expectError:   true,
			errorContains: "TC (traffic control) support is required",
		},
		{
			name: "tracepoints_supported",
			caps: &SystemCapabilities{
				HasTracepointSupport: true,
			},
			feature:     "tracepoints",
			expectError: false,
		},
		{
			name: "tracepoints_not_supported",
			caps: &SystemCapabilities{
				HasTracepointSupport: false,
			},
			feature:       "tracepoints",
			expectError:   true,
			errorContains: "tracepoint support is required",
		},
		{
			name: "kprobes_supported",
			caps: &SystemCapabilities{
				HasKProbeSupport: true,
			},
			feature:     "kprobes",
			expectError: false,
		},
		{
			name: "kprobes_not_supported",
			caps: &SystemCapabilities{
				HasKProbeSupport: false,
			},
			feature:       "kprobes",
			expectError:   true,
			errorContains: "kprobe support is required",
		},
		{
			name: "uprobes_supported",
			caps: &SystemCapabilities{
				HasUProbeSupport: true,
			},
			feature:     "uprobes",
			expectError: false,
		},
		{
			name: "uprobes_not_supported",
			caps: &SystemCapabilities{
				HasUProbeSupport: false,
			},
			feature:       "uprobes",
			expectError:   true,
			errorContains: "uprobe support is required",
		},
		{
			name: "cgroups_supported",
			caps: &SystemCapabilities{
				HasCGroupSupport: true,
			},
			feature:     "cgroups",
			expectError: false,
		},
		{
			name: "cgroups_not_supported",
			caps: &SystemCapabilities{
				HasCGroupSupport: false,
			},
			feature:       "cgroups",
			expectError:   true,
			errorContains: "cgroup eBPF support is required",
		},
		{
			name: "netlink_supported",
			caps: &SystemCapabilities{
				HasNetlinkSupport: true,
			},
			feature:     "netlink",
			expectError: false,
		},
		{
			name: "netlink_not_supported",
			caps: &SystemCapabilities{
				HasNetlinkSupport: false,
			},
			feature:       "netlink",
			expectError:   true,
			errorContains: "netlink support is required",
		},
		{
			name: "unknown_feature",
			caps: &SystemCapabilities{},
			feature:       "unknown",
			expectError:   true,
			errorContains: "unknown feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.caps.RequireFeature(tt.feature)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSystemCapabilities_GetFallbackMode(t *testing.T) {
	tests := []struct {
		name     string
		caps     *SystemCapabilities
		expected string
	}{
		{
			name: "no_ebpf_support",
			caps: &SystemCapabilities{
				HasEBPFSupport: false,
			},
			expected: "disabled",
		},
		{
			name: "full_support",
			caps: &SystemCapabilities{
				HasEBPFSupport:       true,
				HasTCSupport:         true,
				HasTracepointSupport: true,
				HasKProbeSupport:     true,
			},
			expected: "full",
		},
		{
			name: "limited_support_tracepoints_only",
			caps: &SystemCapabilities{
				HasEBPFSupport:       true,
				HasTCSupport:         false,
				HasTracepointSupport: true,
				HasKProbeSupport:     false,
			},
			expected: "limited",
		},
		{
			name: "limited_support_kprobes_only",
			caps: &SystemCapabilities{
				HasEBPFSupport:       true,
				HasTCSupport:         false,
				HasTracepointSupport: false,
				HasKProbeSupport:     true,
			},
			expected: "limited",
		},
		{
			name: "minimal_support",
			caps: &SystemCapabilities{
				HasEBPFSupport:       true,
				HasTCSupport:         false,
				HasTracepointSupport: false,
				HasKProbeSupport:     false,
			},
			expected: "minimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.caps.GetFallbackMode()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCapabilityChecker_commandExists(t *testing.T) {
	checker := NewCapabilityChecker()

	// Test with a command that should exist
	exists := checker.commandExists("sh")
	assert.True(t, exists, "sh command should exist on most systems")

	// Test with a command that should not exist
	exists = checker.commandExists("nonexistent-command-12345")
	assert.False(t, exists, "nonexistent command should not be found")
}

// Integration test - only runs when system supports the features
func TestCapabilityChecker_CheckSystemCapabilities_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	checker := NewCapabilityChecker()
	caps, err := checker.CheckSystemCapabilities()

	// In test environments, eBPF might not be supported
	if err != nil {
		t.Logf("System capabilities check failed (expected in test environments): %v", err)
		// If the system doesn't support eBPF at all, that's acceptable for unit tests
		assert.Contains(t, err.Error(), "eBPF is not supported")
		return
	}

	require.NotNil(t, caps)

	// Basic validations
	assert.NotEmpty(t, caps.KernelVersion)
	assert.NotNil(t, caps.MissingFeatures)
	assert.NotNil(t, caps.Warnings)

	// eBPF should be detected on most modern systems
	if caps.HasEBPFSupport {
		t.Log("System has eBPF support")
	} else {
		t.Log("System does not have eBPF support")
	}

	// Log capabilities for debugging
	t.Logf("System capabilities: eBPF=%v, TC=%v, Tracepoints=%v, KProbes=%v, UProbes=%v, CGroups=%v, Netlink=%v",
		caps.HasEBPFSupport,
		caps.HasTCSupport,
		caps.HasTracepointSupport,
		caps.HasKProbeSupport,
		caps.HasUProbeSupport,
		caps.HasCGroupSupport,
		caps.HasNetlinkSupport,
	)

	if len(caps.MissingFeatures) > 0 {
		t.Logf("Missing features: %v", caps.MissingFeatures)
	}

	if len(caps.Warnings) > 0 {
		t.Logf("Warnings: %v", caps.Warnings)
	}
}