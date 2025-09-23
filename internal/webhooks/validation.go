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

package webhooks

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-policy-pahlevan-io-v1alpha1-pahlevanpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=create;update,versions=v1alpha1,name=vpahlevanpolicy.kb.io,admissionReviewVersions=v1

// PahlevanPolicyValidator validates PahlevanPolicy resources
type PahlevanPolicyValidator struct {
	client.Client
	decoder *admission.Decoder
}

// NewPahlevanPolicyValidator creates a new policy validator
func NewPahlevanPolicyValidator(client client.Client) *PahlevanPolicyValidator {
	return &PahlevanPolicyValidator{
		Client: client,
	}
}

// Handle implements admission.Handler
func (v *PahlevanPolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithName("webhook").WithName("validation")

	policy := &policyv1alpha1.PahlevanPolicy{}
	if err := (*v.decoder).Decode(req, policy); err != nil {
		logger.Error(err, "Failed to decode PahlevanPolicy")
		return admission.Errored(http.StatusBadRequest, err)
	}

	logger.Info("Validating PahlevanPolicy", "policy", policy.Name, "namespace", policy.Namespace)

	// Perform validation
	if err := v.validatePahlevanPolicy(ctx, policy, string(req.Operation)); err != nil {
		logger.Error(err, "PahlevanPolicy validation failed", "policy", policy.Name)
		return admission.Denied(err.Error())
	}

	logger.Info("PahlevanPolicy validation successful", "policy", policy.Name)
	return admission.Allowed("")
}

// InjectDecoder implements admission.DecoderInjector
func (v *PahlevanPolicyValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

// validatePahlevanPolicy performs comprehensive validation of a PahlevanPolicy
func (v *PahlevanPolicyValidator) validatePahlevanPolicy(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy, operation string) error {
	var allErrors []string

	// Validate selector
	if err := v.validateSelector(policy.Spec.Selector); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("selector validation failed: %v", err))
	}

	// Validate learning configuration
	if err := v.validateLearningConfig(policy.Spec.LearningConfig); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("learning configuration validation failed: %v", err))
	}

	// Validate enforcement configuration
	if err := v.validateEnforcementConfig(policy.Spec.EnforcementConfig); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("enforcement configuration validation failed: %v", err))
	}

	// Validate self-healing configuration
	if err := v.validateSelfHealingConfig(policy.Spec.SelfHealing); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("self-healing configuration validation failed: %v", err))
	}

	// Validate observability configuration
	if err := v.validateObservabilityConfig(policy.Spec.ObservabilityConfig); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("observability configuration validation failed: %v", err))
	}

	// Validate naming and labels
	if err := v.validateMetadata(policy); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("metadata validation failed: %v", err))
	}

	// Check for conflicts with existing policies
	if err := v.validateNoConflicts(ctx, policy, operation); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("conflict validation failed: %v", err))
	}

	// Validate lifecycle transitions (for updates)
	if operation == "UPDATE" {
		if err := v.validateLifecycleTransition(ctx, policy); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("lifecycle transition validation failed: %v", err))
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(allErrors, "; "))
	}

	return nil
}

// validateSelector validates the label selector
func (v *PahlevanPolicyValidator) validateSelector(selector policyv1alpha1.LabelSelector) error {
	// Must have at least one selector
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return fmt.Errorf("selector must have at least one matchLabels or matchExpressions")
	}

	// Validate match labels
	for key, value := range selector.MatchLabels {
		if key == "" {
			return fmt.Errorf("empty label key not allowed")
		}
		if value == "" {
			return fmt.Errorf("empty label value not allowed for key %s", key)
		}
		if err := validateLabelKey(key); err != nil {
			return fmt.Errorf("invalid label key %s: %v", key, err)
		}
		if err := validateLabelValue(value); err != nil {
			return fmt.Errorf("invalid label value %s for key %s: %v", value, key, err)
		}
	}

	// Validate match expressions
	for _, expr := range selector.MatchExpressions {
		if expr.Key == "" {
			return fmt.Errorf("empty expression key not allowed")
		}
		if err := validateLabelKey(expr.Key); err != nil {
			return fmt.Errorf("invalid expression key %s: %v", expr.Key, err)
		}

		switch expr.Operator {
		case policyv1alpha1.LabelSelectorOpIn, policyv1alpha1.LabelSelectorOpNotIn:
			if len(expr.Values) == 0 {
				return fmt.Errorf("operator %s requires at least one value", expr.Operator)
			}
			for _, value := range expr.Values {
				if value == "" {
					return fmt.Errorf("empty value not allowed for operator %s", expr.Operator)
				}
				if err := validateLabelValue(value); err != nil {
					return fmt.Errorf("invalid value %s for operator %s: %v", value, expr.Operator, err)
				}
			}
		case policyv1alpha1.LabelSelectorOpExists, policyv1alpha1.LabelSelectorOpDoesNotExist:
			if len(expr.Values) > 0 {
				return fmt.Errorf("operator %s should not have values", expr.Operator)
			}
		default:
			return fmt.Errorf("unknown operator: %s", expr.Operator)
		}
	}

	return nil
}

// validateLearningConfig validates the learning configuration
func (v *PahlevanPolicyValidator) validateLearningConfig(config policyv1alpha1.LearningConfig) error {
	// Validate duration
	if config.Duration != nil {
		if config.Duration.Duration <= 0 {
			return fmt.Errorf("duration must be positive")
		}
		if config.Duration.Duration > 24*time.Hour {
			return fmt.Errorf("duration cannot exceed 24 hours")
		}
	}

	// Validate window size
	if config.WindowSize != nil {
		if config.WindowSize.Duration <= 0 {
			return fmt.Errorf("window size must be positive")
		}
		if config.WindowSize.Duration > time.Hour {
			return fmt.Errorf("window size cannot exceed 1 hour")
		}
	}

	// Validate min samples
	if config.MinSamples != nil && *config.MinSamples <= 0 {
		return fmt.Errorf("min samples must be positive")
	}

	return nil
}

// validateEnforcementConfig validates the enforcement configuration
func (v *PahlevanPolicyValidator) validateEnforcementConfig(config policyv1alpha1.EnforcementConfig) error {
	// Validate mode
	switch config.Mode {
	case policyv1alpha1.EnforcementModeOff, policyv1alpha1.EnforcementModeMonitoring, policyv1alpha1.EnforcementModeBlocking:
		// Valid modes
	default:
		return fmt.Errorf("invalid enforcement mode: %s", config.Mode)
	}

	// Validate grace period
	if config.GracePeriod != nil {
		if config.GracePeriod.Duration < 0 {
			return fmt.Errorf("grace period cannot be negative")
		}
		if config.GracePeriod.Duration > time.Hour {
			return fmt.Errorf("grace period cannot exceed 1 hour")
		}
	}

	// Validate exceptions
	for i, exception := range config.Exceptions {
		if err := v.validateException(exception); err != nil {
			return fmt.Errorf("exception %d validation failed: %v", i, err)
		}
	}

	return nil
}

// validateException validates a policy exception
func (v *PahlevanPolicyValidator) validateException(exception policyv1alpha1.EnforcementException) error {
	// Validate type
	switch exception.Type {
	case policyv1alpha1.ExceptionTypeSyscall, policyv1alpha1.ExceptionTypeNetwork, policyv1alpha1.ExceptionTypeFile:
		// Valid types
	default:
		return fmt.Errorf("invalid exception type: %s", exception.Type)
	}

	// Validate patterns
	if len(exception.Patterns) == 0 {
		return fmt.Errorf("exception must have at least one pattern")
	}

	for _, pattern := range exception.Patterns {
		if pattern == "" {
			return fmt.Errorf("empty pattern not allowed")
		}
		// Additional pattern validation could be added here
	}

	// Validate reason
	if exception.Reason == "" {
		return fmt.Errorf("exception reason is required")
	}

	// Validate expiration
	if exception.Temporary && exception.ExpiresAt != nil {
		now := metav1.Now()
		if exception.ExpiresAt.Before(&now) {
			return fmt.Errorf("exception cannot expire in the past")
		}
		future := metav1.NewTime(now.Add(30 * 24 * time.Hour))
		if exception.ExpiresAt.After(future.Time) {
			return fmt.Errorf("exception cannot expire more than 30 days in the future")
		}
	}

	return nil
}

// validateSelfHealingConfig validates the self-healing configuration
func (v *PahlevanPolicyValidator) validateSelfHealingConfig(config policyv1alpha1.SelfHealingConfig) error {
	// Validate rollback threshold
	if config.RollbackThreshold <= 0 {
		return fmt.Errorf("rollback threshold must be positive")
	}
	if config.RollbackThreshold > 100 {
		return fmt.Errorf("rollback threshold cannot exceed 100")
	}

	// Validate rollback window
	if config.RollbackWindow != nil {
		if config.RollbackWindow.Duration <= 0 {
			return fmt.Errorf("rollback window must be positive")
		}
		if config.RollbackWindow.Duration > 24*time.Hour {
			return fmt.Errorf("rollback window cannot exceed 24 hours")
		}
	}

	// Validate recovery strategy
	switch config.RecoveryStrategy {
	case policyv1alpha1.RecoveryStrategyRollback, policyv1alpha1.RecoveryStrategyRelax, policyv1alpha1.RecoveryStrategyMaintenance:
		// Valid strategies
	default:
		return fmt.Errorf("invalid recovery strategy: %s", config.RecoveryStrategy)
	}

	return nil
}

// validateObservabilityConfig validates the observability configuration
func (v *PahlevanPolicyValidator) validateObservabilityConfig(config policyv1alpha1.ObservabilityConfig) error {
	// Validate metrics configuration
	if err := v.validateMetricsConfig(config.Metrics); err != nil {
		return fmt.Errorf("metrics config validation failed: %v", err)
	}

	// Validate tracing configuration
	if err := v.validateTracingConfig(config.Tracing); err != nil {
		return fmt.Errorf("tracing config validation failed: %v", err)
	}

	return nil
}

// validateMetricsConfig validates metrics configuration
func (v *PahlevanPolicyValidator) validateMetricsConfig(config policyv1alpha1.MetricsConfig) error {
	// Validate exporters
	if len(config.Exporters) == 0 && config.Enabled {
		return fmt.Errorf("at least one exporter required when metrics are enabled")
	}

	for i, exporter := range config.Exporters {
		if err := v.validateMetricsExporter(exporter); err != nil {
			return fmt.Errorf("exporter %d validation failed: %v", i, err)
		}
	}

	return nil
}

// validateMetricsExporter validates a metrics exporter
func (v *PahlevanPolicyValidator) validateMetricsExporter(exporter policyv1alpha1.MetricsExporter) error {
	// Validate type
	switch exporter.Type {
	case "prometheus", "datadog", "grafana", "otlp":
		// Valid types
	default:
		return fmt.Errorf("invalid exporter type: %s", exporter.Type)
	}

	// Type-specific validation
	switch exporter.Type {
	case "datadog":
		if exporter.Endpoint == "" {
			return fmt.Errorf("datadog exporter requires endpoint")
		}
		// Config validation would require unmarshaling the RawExtension
		// Simplified validation for now
	case "otlp":
		if exporter.Endpoint == "" {
			return fmt.Errorf("otlp exporter requires endpoint")
		}
	}

	return nil
}

// validateTracingConfig validates tracing configuration
func (v *PahlevanPolicyValidator) validateTracingConfig(config policyv1alpha1.TracingConfig) error {
	// Validate sampling rate
	if config.SamplingRate != nil {
		if rate, err := strconv.ParseFloat(*config.SamplingRate, 64); err != nil {
			return fmt.Errorf("sampling rate must be a valid float: %v", err)
		} else if rate < 0.0 || rate > 1.0 {
			return fmt.Errorf("sampling rate must be between 0.0 and 1.0")
		}
	}

	// Validate exporter
	if config.Enabled && config.Exporter.Endpoint == "" {
		return fmt.Errorf("endpoint required when tracing is enabled")
	}

	return nil
}

// validateMetadata validates policy metadata
func (v *PahlevanPolicyValidator) validateMetadata(policy *policyv1alpha1.PahlevanPolicy) error {
	// Validate name
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	// Check for reserved names
	reservedNames := []string{"default", "system", "pahlevan-system"}
	for _, reserved := range reservedNames {
		if policy.Name == reserved {
			return fmt.Errorf("policy name %s is reserved", reserved)
		}
	}

	// Validate namespace
	if policy.Namespace == "" {
		return fmt.Errorf("policy namespace is required")
	}

	// Check for system namespace usage
	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, sysNs := range systemNamespaces {
		if policy.Namespace == sysNs {
			return fmt.Errorf("policies not allowed in system namespace %s", sysNs)
		}
	}

	return nil
}

// validateNoConflicts checks for conflicts with existing policies
func (v *PahlevanPolicyValidator) validateNoConflicts(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy, operation string) error {
	// List existing policies in the same namespace
	existingPolicies := &policyv1alpha1.PahlevanPolicyList{}
	if err := v.List(ctx, existingPolicies, client.InNamespace(policy.Namespace)); err != nil {
		return fmt.Errorf("failed to list existing policies: %v", err)
	}

	for _, existing := range existingPolicies.Items {
		// Skip self when updating
		if operation == "UPDATE" && existing.Name == policy.Name {
			continue
		}

		// Check for selector overlap
		if v.selectorsOverlap(policy.Spec.Selector, existing.Spec.Selector) {
			return fmt.Errorf("policy selector overlaps with existing policy %s", existing.Name)
		}
	}

	return nil
}

// selectorsOverlap checks if two selectors could select the same pods
func (v *PahlevanPolicyValidator) selectorsOverlap(selector1, selector2 policyv1alpha1.LabelSelector) bool {
	// For simplicity, this is a basic overlap check
	// In a production implementation, you might want more sophisticated overlap detection

	// Check if all matchLabels in selector1 are compatible with selector2
	for key, value := range selector1.MatchLabels {
		if selector2Value, exists := selector2.MatchLabels[key]; exists {
			if selector2Value == value {
				return true // Direct overlap
			}
		}
	}

	// This is a simplified check - a full implementation would need to consider
	// matchExpressions and complex label selector logic
	return false
}

// validateLifecycleTransition validates transitions between policy phases
func (v *PahlevanPolicyValidator) validateLifecycleTransition(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) error {
	// Get the current policy state
	currentPolicy := &policyv1alpha1.PahlevanPolicy{}
	if err := v.Get(ctx, client.ObjectKeyFromObject(policy), currentPolicy); err != nil {
		return fmt.Errorf("failed to get current policy state: %v", err)
	}

	// Validate phase transitions
	currentPhase := currentPolicy.Status.Phase
	newEnforcementMode := policy.Spec.EnforcementConfig.Mode

	// Certain transitions are not allowed
	if currentPhase == policyv1alpha1.PolicyPhaseEnforcing {
		if newEnforcementMode == policyv1alpha1.EnforcementModeOff {
			return fmt.Errorf("cannot transition from enforcing to off without going through monitoring first")
		}
	}

	// Don't allow changing selector on enforcing policies
	if currentPhase == policyv1alpha1.PolicyPhaseEnforcing {
		if !v.selectorsEqual(currentPolicy.Spec.Selector, policy.Spec.Selector) {
			return fmt.Errorf("cannot change selector on enforcing policy")
		}
	}

	return nil
}

// selectorsEqual checks if two selectors are equal
func (v *PahlevanPolicyValidator) selectorsEqual(selector1, selector2 policyv1alpha1.LabelSelector) bool {
	// Compare matchLabels
	if len(selector1.MatchLabels) != len(selector2.MatchLabels) {
		return false
	}
	for key, value := range selector1.MatchLabels {
		if selector2.MatchLabels[key] != value {
			return false
		}
	}

	// Compare matchExpressions
	if len(selector1.MatchExpressions) != len(selector2.MatchExpressions) {
		return false
	}
	// For full comparison, we'd need to check each expression
	// This is simplified for this example

	return true
}

// validateLabelKey validates a Kubernetes label key
func validateLabelKey(key string) error {
	if len(key) == 0 {
		return fmt.Errorf("label key cannot be empty")
	}
	if len(key) > 253 {
		return fmt.Errorf("label key cannot be longer than 253 characters")
	}
	// Additional validation rules for Kubernetes label keys would go here
	return nil
}

// validateLabelValue validates a Kubernetes label value
func validateLabelValue(value string) error {
	if len(value) > 63 {
		return fmt.Errorf("label value cannot be longer than 63 characters")
	}
	// Additional validation rules for Kubernetes label values would go here
	return nil
}
