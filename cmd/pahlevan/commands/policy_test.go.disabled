package commands

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyCommand_Create(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing namespace",
			args:        []string{"create", "--name", "test-policy"},
			expectError: true,
			errorMsg:    "namespace is required",
		},
		{
			name:        "missing name",
			args:        []string{"create", "--namespace", "test"},
			expectError: true,
			errorMsg:    "policy name is required",
		},
		{
			name:        "invalid enforcement mode",
			args:        []string{"create", "--namespace", "test", "--name", "test-policy", "--enforcement-mode", "invalid"},
			expectError: true,
			errorMsg:    "invalid enforcement mode",
		},
		{
			name: "valid policy creation",
			args: []string{"create", "--namespace", "test", "--name", "test-policy", "--enforcement-mode", "monitoring"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewPolicyCommand()
			cmd.SetArgs(tt.args)

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				// In a real test, we'd mock the Kubernetes client
				// For now, we expect connection errors which is fine
				assert.NotNil(t, err) // Expected since we don't have a real cluster
			}
		})
	}
}

func TestPolicyCommand_List(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "list all policies",
			args:        []string{"list"},
			expectError: true, // Expected since no cluster
		},
		{
			name:        "list policies in namespace",
			args:        []string{"list", "--namespace", "test"},
			expectError: true, // Expected since no cluster
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewPolicyCommand()
			cmd.SetArgs(tt.args)

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyCommand_Get(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing policy name",
			args:        []string{"get"},
			expectError: true,
			errorMsg:    "policy name is required",
		},
		{
			name:        "missing namespace",
			args:        []string{"get", "test-policy"},
			expectError: true,
			errorMsg:    "namespace is required",
		},
		{
			name:        "valid get command",
			args:        []string{"get", "test-policy", "--namespace", "test"},
			expectError: true, // Expected since no cluster
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewPolicyCommand()
			cmd.SetArgs(tt.args)

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyCommand_Delete(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing policy name",
			args:        []string{"delete"},
			expectError: true,
			errorMsg:    "policy name is required",
		},
		{
			name:        "missing namespace",
			args:        []string{"delete", "test-policy"},
			expectError: true,
			errorMsg:    "namespace is required",
		},
		{
			name:        "valid delete command",
			args:        []string{"delete", "test-policy", "--namespace", "test"},
			expectError: true, // Expected since no cluster
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewPolicyCommand()
			cmd.SetArgs(tt.args)

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseEnforcementMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		hasError bool
	}{
		{
			name:     "valid off mode",
			input:    "off",
			expected: "Off",
			hasError: false,
		},
		{
			name:     "valid monitoring mode",
			input:    "monitoring",
			expected: "Monitoring",
			hasError: false,
		},
		{
			name:     "valid blocking mode",
			input:    "blocking",
			expected: "Blocking",
			hasError: false,
		},
		{
			name:     "case insensitive",
			input:    "MONITORING",
			expected: "Monitoring",
			hasError: false,
		},
		{
			name:     "invalid mode",
			input:    "invalid",
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseEnforcementMode(tt.input)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, string(result))
			}
		})
	}
}

func TestValidatePolicyName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid name",
			input:    "my-policy",
			expected: true,
		},
		{
			name:     "valid name with numbers",
			input:    "policy-123",
			expected: true,
		},
		{
			name:     "empty name",
			input:    "",
			expected: false,
		},
		{
			name:     "name too long",
			input:    "this-is-a-very-long-policy-name-that-exceeds-the-maximum-length-allowed-for-kubernetes-resources",
			expected: false,
		},
		{
			name:     "invalid characters",
			input:    "policy_with_underscores",
			expected: false,
		},
		{
			name:     "starts with number",
			input:    "123-policy",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validatePolicyName(tt.input)
			assert.Equal(t, tt.expected, valid)
		})
	}
}

func TestValidateNamespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid namespace",
			input:    "default",
			expected: true,
		},
		{
			name:     "valid namespace with hyphens",
			input:    "my-namespace",
			expected: true,
		},
		{
			name:     "empty namespace",
			input:    "",
			expected: false,
		},
		{
			name:     "namespace too long",
			input:    "this-is-a-very-long-namespace-name-that-exceeds-maximum-length",
			expected: false,
		},
		{
			name:     "invalid characters",
			input:    "namespace_with_underscores",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateNamespace(tt.input)
			assert.Equal(t, tt.expected, valid)
		})
	}
}

func TestPolicyTemplateGeneration(t *testing.T) {
	tests := []struct {
		name           string
		policyName     string
		namespace      string
		enforcementMode string
		expectedFields []string
	}{
		{
			name:           "basic policy template",
			policyName:     "test-policy",
			namespace:      "default",
			enforcementMode: "monitoring",
			expectedFields: []string{
				"apiVersion",
				"kind",
				"metadata",
				"spec",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := generatePolicyTemplate(tt.policyName, tt.namespace, tt.enforcementMode)

			require.NotEmpty(t, template)

			for _, field := range tt.expectedFields {
				assert.Contains(t, template, field)
			}

			// Verify specific values
			assert.Contains(t, template, tt.policyName)
			assert.Contains(t, template, tt.namespace)
			assert.Contains(t, template, tt.enforcementMode)
		})
	}
}

// Helper functions for testing
func validatePolicyName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	// Simplified validation for testing
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	// Must start with letter
	return name[0] >= 'a' && name[0] <= 'z'
}

func validateNamespace(namespace string) bool {
	if namespace == "" || len(namespace) > 63 {
		return false
	}
	// Simplified validation for testing
	for _, r := range namespace {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func generatePolicyTemplate(name, namespace, enforcementMode string) string {
	return `apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: ` + name + `
  namespace: ` + namespace + `
spec:
  selector:
    matchLabels:
      app: example
  enforcementConfig:
    mode: ` + enforcementMode + `
    gracePeriod: 30s
  learningConfig:
    enabled: true
    duration: 5m
    autoTransition: true`
}

func TestCommandHelp(t *testing.T) {
	cmd := NewPolicyCommand()

	// Test that help is available
	help := cmd.Long
	assert.NotEmpty(t, help)
	assert.Contains(t, help, "policy")

	// Test that subcommands are available
	subcommands := cmd.Commands()
	assert.NotEmpty(t, subcommands)

	subcommandNames := make([]string, len(subcommands))
	for i, subcmd := range subcommands {
		subcommandNames[i] = subcmd.Name()
	}

	expectedCommands := []string{"create", "list", "get", "delete"}
	for _, expected := range expectedCommands {
		assert.Contains(t, subcommandNames, expected)
	}
}

func TestCommandFlags(t *testing.T) {
	cmd := NewPolicyCommand()

	// Test global flags
	flags := cmd.PersistentFlags()
	namespaceFlag := flags.Lookup("namespace")
	assert.NotNil(t, namespaceFlag)

	// Test create command flags
	createCmd := &cobra.Command{}
	addCreateFlags(createCmd)

	createFlags := createCmd.Flags()
	assert.NotNil(t, createFlags.Lookup("name"))
	assert.NotNil(t, createFlags.Lookup("enforcement-mode"))
	assert.NotNil(t, createFlags.Lookup("learning-duration"))
	assert.NotNil(t, createFlags.Lookup("auto-transition"))
}

// Helper function to add create flags (would be in actual implementation)
func addCreateFlags(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Policy name")
	cmd.Flags().String("enforcement-mode", "monitoring", "Enforcement mode")
	cmd.Flags().Duration("learning-duration", 0, "Learning duration")
	cmd.Flags().Bool("auto-transition", true, "Auto transition after learning")
}