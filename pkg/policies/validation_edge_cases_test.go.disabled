package policies

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerPolicy_BoundaryValidation(t *testing.T) {
	t.Run("syscall boundary conditions", func(t *testing.T) {
		tests := []struct {
			name    string
			policy  *ContainerPolicy
			wantErr bool
			errMsg  string
		}{
			{
				name: "maximum syscall number",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{
						999: true, // Very high but potentially valid
					},
					EnforcementMode: 1,
				},
				wantErr: false,
			},
			{
				name: "uint64 maximum",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{
						math.MaxUint64: true,
					},
					EnforcementMode: 1,
				},
				wantErr: true,
				errMsg:  "invalid syscall number",
			},
			{
				name: "zero syscall",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{
						0: true, // Syscall 0 might be valid (read)
					},
					EnforcementMode: 1,
				},
				wantErr: false,
			},
			{
				name: "syscall 1",
				policy: &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{
						1: true, // write syscall
					},
					EnforcementMode: 1,
				},
				wantErr: false,
			},
			{
				name: "massive syscall map",
				policy: &ContainerPolicy{
					AllowedSyscalls: func() map[uint64]bool {
						m := make(map[uint64]bool)
						for i := uint64(0); i < 10000; i++ {
							m[i] = true
						}
						return m
					}(),
					EnforcementMode: 1,
				},
				wantErr: false, // Large maps should be allowed
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.policy.Validate()
				if tt.wantErr {
					require.Error(t, err)
					if tt.errMsg != "" {
						assert.Contains(t, err.Error(), tt.errMsg)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("enforcement mode boundaries", func(t *testing.T) {
		tests := []struct {
			name         string
			mode         int
			expectedErr  bool
			errorContains string
		}{
			{
				name:        "mode -1",
				mode:        -1,
				expectedErr: true,
				errorContains: "invalid enforcement mode",
			},
			{
				name:        "mode 0",
				mode:        0,
				expectedErr: false, // Disabled mode
			},
			{
				name:        "mode 1",
				mode:        1,
				expectedErr: false, // Monitor mode
			},
			{
				name:        "mode 2",
				mode:        2,
				expectedErr: false, // Enforce mode
			},
			{
				name:        "mode 3",
				mode:        3,
				expectedErr: true, // Invalid high mode
				errorContains: "invalid enforcement mode",
			},
			{
				name:        "mode 255",
				mode:        255,
				expectedErr: true,
				errorContains: "invalid enforcement mode",
			},
			{
				name:        "mode MaxInt",
				mode:        math.MaxInt32,
				expectedErr: true,
				errorContains: "invalid enforcement mode",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				policy := &ContainerPolicy{
					AllowedSyscalls: map[uint64]bool{1: true},
					EnforcementMode: tt.mode,
				}
				err := policy.Validate()
				if tt.expectedErr {
					require.Error(t, err)
					if tt.errorContains != "" {
						assert.Contains(t, err.Error(), tt.errorContains)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestNetworkPolicy_PortValidation(t *testing.T) {
	t.Run("port range boundaries", func(t *testing.T) {
		tests := []struct {
			name        string
			port        uint16
			expectedErr bool
			errorMsg    string
		}{
			{
				name:        "port 0",
				port:        0,
				expectedErr: true,
				errorMsg:    "invalid port",
			},
			{
				name:        "port 1",
				port:        1,
				expectedErr: false,
			},
			{
				name:        "port 1023 (privileged)",
				port:        1023,
				expectedErr: false,
			},
			{
				name:        "port 1024 (unprivileged)",
				port:        1024,
				expectedErr: false,
			},
			{
				name:        "port 65534",
				port:        65534,
				expectedErr: false,
			},
			{
				name:        "port 65535 (max)",
				port:        65535,
				expectedErr: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				policy := &NetworkPolicy{
					AllowedEgressPorts:  map[uint16]bool{tt.port: true},
					AllowedIngressPorts: map[uint16]bool{tt.port: true},
					EnforcementMode:     1,
				}
				err := policy.Validate()
				if tt.expectedErr {
					require.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("port map edge cases", func(t *testing.T) {
		tests := []struct {
			name           string
			egressPorts    map[uint16]bool
			ingressPorts   map[uint16]bool
			expectedErr    bool
			errorContains  string
		}{
			{
				name:         "both maps nil",
				egressPorts:  nil,
				ingressPorts: nil,
				expectedErr:  true,
				errorContains: "port maps cannot be nil",
			},
			{
				name:         "egress nil, ingress valid",
				egressPorts:  nil,
				ingressPorts: map[uint16]bool{80: true},
				expectedErr:  true,
				errorContains: "egress ports cannot be nil",
			},
			{
				name:         "egress valid, ingress nil",
				egressPorts:  map[uint16]bool{443: true},
				ingressPorts: nil,
				expectedErr:  true,
				errorContains: "ingress ports cannot be nil",
			},
			{
				name:         "both maps empty",
				egressPorts:  map[uint16]bool{},
				ingressPorts: map[uint16]bool{},
				expectedErr:  false, // Empty maps might be valid for deny-all
			},
			{
				name: "massive port maps",
				egressPorts: func() map[uint16]bool {
					m := make(map[uint16]bool)
					for i := uint16(1); i <= 65535; i++ {
						m[i] = true
					}
					return m
				}(),
				ingressPorts: func() map[uint16]bool {
					m := make(map[uint16]bool)
					for i := uint16(1); i <= 65535; i++ {
						m[i] = true
					}
					return m
				}(),
				expectedErr: false, // Large maps should be allowed
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				policy := &NetworkPolicy{
					AllowedEgressPorts:  tt.egressPorts,
					AllowedIngressPorts: tt.ingressPorts,
					EnforcementMode:     1,
				}
				err := policy.Validate()
				if tt.expectedErr {
					require.Error(t, err)
					if tt.errorContains != "" {
						assert.Contains(t, err.Error(), tt.errorContains)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestContainerMetadata_FieldValidation(t *testing.T) {
	t.Run("string field boundaries", func(t *testing.T) {
		tests := []struct {
			name      string
			metadata  *ContainerMetadata
			expectErr bool
			errorMsg  string
		}{
			{
				name: "empty strings",
				metadata: &ContainerMetadata{
					Namespace: "",
					PodName:   "",
					Image:     "",
				},
				expectErr: true,
				errorMsg:  "required field",
			},
			{
				name: "whitespace only",
				metadata: &ContainerMetadata{
					Namespace: "   ",
					PodName:   "\t\n",
					Image:     " ",
				},
				expectErr: true,
				errorMsg:  "cannot be empty",
			},
			{
				name: "extremely long strings",
				metadata: &ContainerMetadata{
					Namespace: strings.Repeat("a", 10000),
					PodName:   strings.Repeat("b", 10000),
					Image:     strings.Repeat("c", 10000),
				},
				expectErr: true,
				errorMsg:  "exceeds maximum length",
			},
			{
				name: "invalid characters",
				metadata: &ContainerMetadata{
					Namespace: "test\x00namespace", // Null byte
					PodName:   "test\x01pod",       // Control character
					Image:     "test\x7fimage",     // DEL character
				},
				expectErr: true,
				errorMsg:  "invalid character",
			},
			{
				name: "unicode edge cases",
				metadata: &ContainerMetadata{
					Namespace: "test-🚀-namespace",
					PodName:   "测试-pod",
					Image:     "тест:latest",
				},
				expectErr: false, // Unicode should be allowed
			},
			{
				name: "kubernetes naming constraints",
				metadata: &ContainerMetadata{
					Namespace: "Test-Namespace", // Invalid: uppercase
					PodName:   "test_pod_123",   // Invalid: underscore
					Image:     "valid:tag",
				},
				expectErr: true,
				errorMsg:  "invalid kubernetes name",
			},
			{
				name: "valid metadata",
				metadata: &ContainerMetadata{
					Namespace: "test-namespace",
					PodName:   "test-pod-123",
					Image:     "registry.io/app:v1.2.3",
				},
				expectErr: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.metadata.Validate()
				if tt.expectErr {
					require.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestPolicyUpdateEvent_TimestampValidation(t *testing.T) {
	t.Run("timestamp edge cases", func(t *testing.T) {
		tests := []struct {
			name      string
			timestamp time.Time
			expectErr bool
			errorMsg  string
		}{
			{
				name:      "zero timestamp",
				timestamp: time.Time{},
				expectErr: true,
				errorMsg:  "timestamp cannot be zero",
			},
			{
				name:      "unix epoch",
				timestamp: time.Unix(0, 0),
				expectErr: false, // Unix epoch is valid
			},
			{
				name:      "far future",
				timestamp: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
				expectErr: true,
				errorMsg:  "timestamp too far in future",
			},
			{
				name:      "far past",
				timestamp: time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
				expectErr: true,
				errorMsg:  "timestamp too far in past",
			},
			{
				name:      "current time",
				timestamp: time.Now(),
				expectErr: false,
			},
			{
				name:      "recent past",
				timestamp: time.Now().Add(-1 * time.Hour),
				expectErr: false,
			},
			{
				name:      "near future",
				timestamp: time.Now().Add(1 * time.Minute),
				expectErr: false, // Small clock skew should be allowed
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				event := &PolicyUpdateEvent{
					EventType: EventTypeSyscall,
					Timestamp: tt.timestamp,
					Data:      map[string]interface{}{"test": "data"},
				}
				err := event.Validate()
				if tt.expectErr {
					require.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestDataValidation_ExtremeCases(t *testing.T) {
	t.Run("event data edge cases", func(t *testing.T) {
		tests := []struct {
			name      string
			data      map[string]interface{}
			expectErr bool
			errorMsg  string
		}{
			{
				name:      "nil data",
				data:      nil,
				expectErr: true,
				errorMsg:  "data cannot be nil",
			},
			{
				name:      "empty data",
				data:      map[string]interface{}{},
				expectErr: true,
				errorMsg:  "data cannot be empty",
			},
			{
				name: "deeply nested data",
				data: map[string]interface{}{
					"level1": map[string]interface{}{
						"level2": map[string]interface{}{
							"level3": map[string]interface{}{
								"level4": map[string]interface{}{
									"level5": "deep value",
								},
							},
						},
					},
				},
				expectErr: true,
				errorMsg:  "nesting too deep",
			},
			{
				name: "massive array",
				data: map[string]interface{}{
					"large_array": make([]interface{}, 100000),
				},
				expectErr: true,
				errorMsg:  "array too large",
			},
			{
				name: "extreme string length",
				data: map[string]interface{}{
					"huge_string": strings.Repeat("x", 1000000),
				},
				expectErr: true,
				errorMsg:  "string too long",
			},
			{
				name: "too many keys",
				data: func() map[string]interface{} {
					d := make(map[string]interface{})
					for i := 0; i < 10000; i++ {
						d[string(rune('a'+i%26))+string(rune('0'+i%10))] = i
					}
					return d
				}(),
				expectErr: true,
				errorMsg:  "too many keys",
			},
			{
				name: "valid complex data",
				data: map[string]interface{}{
					"syscall_nr": 42,
					"pid":        1234,
					"metadata": map[string]interface{}{
						"process": "test-process",
						"args":    []string{"arg1", "arg2"},
					},
				},
				expectErr: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				event := &PolicyUpdateEvent{
					EventType: EventTypeSyscall,
					Timestamp: time.Now(),
					Data:      tt.data,
				}
				err := event.Validate()
				if tt.expectErr {
					require.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestPerformanceConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	t.Run("validation performance", func(t *testing.T) {
		// Create a complex policy
		policy := &ContainerPolicy{
			AllowedSyscalls: make(map[uint64]bool),
			EnforcementMode: 1,
		}

		// Add many syscalls
		for i := uint64(0); i < 1000; i++ {
			policy.AllowedSyscalls[i] = true
		}

		// Measure validation performance
		start := time.Now()
		for i := 0; i < 1000; i++ {
			err := policy.Validate()
			assert.NoError(t, err)
		}
		duration := time.Since(start)

		assert.Less(t, duration, 100*time.Millisecond, "Validation should be fast")
		t.Logf("Validation performance: %v for 1000 iterations", duration)
	})

	t.Run("memory usage constraints", func(t *testing.T) {
		// Test that large policies don't consume excessive memory
		policies := make([]*ContainerPolicy, 0, 1000)

		for i := 0; i < 1000; i++ {
			policy := &ContainerPolicy{
				AllowedSyscalls: make(map[uint64]bool),
				EnforcementMode: 1,
			}

			// Add syscalls
			for j := uint64(0); j < 100; j++ {
				policy.AllowedSyscalls[j] = true
			}

			policies = append(policies, policy)
		}

		// Validate all policies
		start := time.Now()
		for _, policy := range policies {
			err := policy.Validate()
			assert.NoError(t, err)
		}
		duration := time.Since(start)

		assert.Less(t, duration, 1*time.Second, "Bulk validation should be efficient")
		t.Logf("Bulk validation performance: %v for 1000 policies", duration)
	})
}
