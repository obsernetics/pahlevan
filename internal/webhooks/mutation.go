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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/mutate-policy-pahlevan-io-v1alpha1-pahlevanpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=create;update,versions=v1alpha1,name=mpahlevanpolicy.kb.io,admissionReviewVersions=v1

// PahlevanPolicyMutator mutates PahlevanPolicy resources to set defaults and apply best practices
type PahlevanPolicyMutator struct {
	client.Client
	decoder *admission.Decoder
}

// NewPahlevanPolicyMutator creates a new policy mutator
func NewPahlevanPolicyMutator(client client.Client) *PahlevanPolicyMutator {
	return &PahlevanPolicyMutator{
		Client: client,
	}
}

// Handle implements admission.Handler
func (m *PahlevanPolicyMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithName("webhook").WithName("mutation")

	policy := &policyv1alpha1.PahlevanPolicy{}
	if err := (*m.decoder).Decode(req, policy); err != nil {
		logger.Error(err, "Failed to decode PahlevanPolicy")
		return admission.Errored(http.StatusBadRequest, err)
	}

	logger.Info("Mutating PahlevanPolicy", "policy", policy.Name, "namespace", policy.Namespace)

	// Create a copy for mutation
	mutatedPolicy := policy.DeepCopy()

	// Apply default values and mutations
	if err := m.mutatePahlevanPolicy(ctx, mutatedPolicy, string(req.Operation)); err != nil {
		logger.Error(err, "Failed to mutate PahlevanPolicy", "policy", policy.Name)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Marshal the mutated policy
	mutatedBytes, err := json.Marshal(mutatedPolicy)
	if err != nil {
		logger.Error(err, "Failed to marshal mutated policy")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Return the admission response with patches
	return admission.PatchResponseFromRaw(req.Object.Raw, mutatedBytes)
}

// InjectDecoder implements admission.DecoderInjector
func (m *PahlevanPolicyMutator) InjectDecoder(d *admission.Decoder) error {
	m.decoder = d
	return nil
}

// mutatePahlevanPolicy applies mutations to the policy
func (m *PahlevanPolicyMutator) mutatePahlevanPolicy(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy, operation string) error {
	logger := log.FromContext(ctx).WithName("mutator")

	// Apply default labels
	m.applyDefaultLabels(policy)

	// Apply default annotations
	m.applyDefaultAnnotations(policy)

	// Apply default learning configuration
	m.applyDefaultLearningConfig(&policy.Spec.LearningConfig)

	// Apply default enforcement configuration
	m.applyDefaultEnforcementConfig(&policy.Spec.EnforcementConfig)

	// Apply default self-healing configuration
	m.applyDefaultSelfHealingConfig(&policy.Spec.SelfHealing)

	// Apply default observability configuration
	m.applyDefaultObservabilityConfig(&policy.Spec.ObservabilityConfig)

	// Initialize status for new policies
	if operation == "CREATE" {
		m.initializeStatus(policy)
	}

	// Apply security best practices
	if err := m.applySecurityBestPractices(ctx, policy); err != nil {
		return fmt.Errorf("failed to apply security best practices: %v", err)
	}

	logger.Info("Policy mutation completed", "policy", policy.Name)
	return nil
}

// applyDefaultLabels applies default labels to the policy
func (m *PahlevanPolicyMutator) applyDefaultLabels(policy *policyv1alpha1.PahlevanPolicy) {
	if policy.Labels == nil {
		policy.Labels = make(map[string]string)
	}

	// Add managed-by label if not present
	if _, exists := policy.Labels["app.kubernetes.io/managed-by"]; !exists {
		policy.Labels["app.kubernetes.io/managed-by"] = "pahlevan-operator"
	}

	// Add component label if not present
	if _, exists := policy.Labels["app.kubernetes.io/component"]; !exists {
		policy.Labels["app.kubernetes.io/component"] = "security-policy"
	}

	// Add version label if not present
	if _, exists := policy.Labels["app.kubernetes.io/version"]; !exists {
		policy.Labels["app.kubernetes.io/version"] = "v1alpha1"
	}
}

// applyDefaultAnnotations applies default annotations to the policy
func (m *PahlevanPolicyMutator) applyDefaultAnnotations(policy *policyv1alpha1.PahlevanPolicy) {
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}

	// Add documentation annotation if not present
	if _, exists := policy.Annotations["policy.pahlevan.io/documentation"]; !exists {
		policy.Annotations["policy.pahlevan.io/documentation"] = "https://docs.pahlevan.io/policies"
	}

	// Add policy type annotation
	if _, exists := policy.Annotations["policy.pahlevan.io/type"]; !exists {
		policy.Annotations["policy.pahlevan.io/type"] = "adaptive-security"
	}
}

// applyDefaultLearningConfig applies default learning configuration
func (m *PahlevanPolicyMutator) applyDefaultLearningConfig(config *policyv1alpha1.LearningConfig) {
	// Set default duration if not specified
	if config.Duration == nil {
		config.Duration = &metav1.Duration{Duration: 5 * time.Minute}
	}

	// Set default window size if not specified
	if config.WindowSize == nil {
		config.WindowSize = &metav1.Duration{Duration: 30 * time.Second}
	}

	// Set default min samples if not specified
	if config.MinSamples == nil {
		defaultMinSamples := int32(100)
		config.MinSamples = &defaultMinSamples
	}

	// Enable auto transition by default if not set
	if !config.AutoTransition {
		config.AutoTransition = true
	}

	// Enable lifecycle awareness by default if not set
	if !config.LifecycleAware {
		config.LifecycleAware = true
	}
}

// applyDefaultEnforcementConfig applies default enforcement configuration
func (m *PahlevanPolicyMutator) applyDefaultEnforcementConfig(config *policyv1alpha1.EnforcementConfig) {
	// Set default mode if not specified
	if config.Mode == "" {
		config.Mode = policyv1alpha1.EnforcementModeMonitoring
	}

	// Set default grace period if not specified
	if config.GracePeriod == nil {
		config.GracePeriod = &metav1.Duration{Duration: 30 * time.Second}
	}

	// Initialize exceptions slice if nil
	if config.Exceptions == nil {
		config.Exceptions = make([]policyv1alpha1.EnforcementException, 0)
	}
}

// applyDefaultSelfHealingConfig applies default self-healing configuration
func (m *PahlevanPolicyMutator) applyDefaultSelfHealingConfig(config *policyv1alpha1.SelfHealingConfig) {
	// Set default rollback threshold
	if config.RollbackThreshold == 0 {
		config.RollbackThreshold = 5
	}

	// Set default rollback window
	if config.RollbackWindow == nil {
		config.RollbackWindow = &metav1.Duration{Duration: 10 * time.Minute}
	}

	// Set default recovery strategy
	if config.RecoveryStrategy == "" {
		config.RecoveryStrategy = policyv1alpha1.RecoveryStrategyRollback
	}
}

// applyDefaultObservabilityConfig applies default observability configuration
func (m *PahlevanPolicyMutator) applyDefaultObservabilityConfig(config *policyv1alpha1.ObservabilityConfig) {
	// Enable metrics by default
	config.Metrics.Enabled = true

	// Enable basic tracing
	config.Tracing.Enabled = true
}

// initializeStatus initializes the status for new policies
func (m *PahlevanPolicyMutator) initializeStatus(policy *policyv1alpha1.PahlevanPolicy) {
	now := metav1.Now()

	policy.Status = policyv1alpha1.PahlevanPolicyStatus{
		Phase: policyv1alpha1.PolicyPhaseInitializing,
		Conditions: []policyv1alpha1.PolicyCondition{
			{
				Type:               policyv1alpha1.PolicyConditionReady,
				Status:             policyv1alpha1.ConditionFalse,
				LastTransitionTime: now,
				Reason:             "Initializing",
				Message:            "Policy is being initialized",
			},
		},
		LastUpdated: &now,
		AttackSurface: &policyv1alpha1.AttackSurfaceStatus{
			ExposedSyscalls: []string{},
			ExposedPorts:    []int32{},
			WritableFiles:   []string{},
			Capabilities:    []string{},
		},
	}
}

// applySecurityBestPractices applies security best practices to the policy
func (m *PahlevanPolicyMutator) applySecurityBestPractices(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) error {
	// Ensure high-risk namespaces have stricter policies
	if m.isHighRiskNamespace(policy.Namespace) {
		m.applyHighRiskDefaults(policy)
	}

	// Apply workload-specific defaults based on selector
	if err := m.applyWorkloadSpecificDefaults(ctx, policy); err != nil {
		return fmt.Errorf("failed to apply workload-specific defaults: %v", err)
	}

	// Ensure compliance requirements are met
	m.applyComplianceDefaults(policy)

	return nil
}

// isHighRiskNamespace checks if a namespace is considered high-risk
func (m *PahlevanPolicyMutator) isHighRiskNamespace(namespace string) bool {
	highRiskNamespaces := []string{
		"default",
		"production",
		"prod",
		"finance",
		"banking",
		"payment",
		"auth",
		"security",
	}

	for _, highRisk := range highRiskNamespaces {
		if namespace == highRisk {
			return true
		}
	}
	return false
}

// applyHighRiskDefaults applies stricter defaults for high-risk namespaces
func (m *PahlevanPolicyMutator) applyHighRiskDefaults(policy *policyv1alpha1.PahlevanPolicy) {
	// Reduce learning duration for faster enforcement
	if policy.Spec.LearningConfig.Duration != nil && policy.Spec.LearningConfig.Duration.Duration == 5*time.Minute {
		policy.Spec.LearningConfig.Duration = &metav1.Duration{Duration: 2 * time.Minute}
	}

	// Skip confidence threshold - field doesn't exist in current type

	// Set stricter enforcement mode
	if policy.Spec.EnforcementConfig.Mode == policyv1alpha1.EnforcementModeMonitoring {
		policy.Spec.EnforcementConfig.Mode = policyv1alpha1.EnforcementModeBlocking
	}

	// Reduce rollback threshold for faster healing
	if policy.Spec.SelfHealing.RollbackThreshold == 5 { // default value
		policy.Spec.SelfHealing.RollbackThreshold = 3
	}

	// Add high-risk annotation
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations["policy.pahlevan.io/risk-level"] = "high"
}

// applyWorkloadSpecificDefaults applies defaults based on workload characteristics
func (m *PahlevanPolicyMutator) applyWorkloadSpecificDefaults(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) error {
	// Check for common workload patterns in selector
	selector := policy.Spec.Selector

	// Database workloads
	if m.isWorkloadType(selector, "database") {
		m.applyDatabaseDefaults(policy)
	}

	// Web application workloads
	if m.isWorkloadType(selector, "web") || m.isWorkloadType(selector, "api") {
		m.applyWebAppDefaults(policy)
	}

	// Batch/job workloads
	if m.isWorkloadType(selector, "batch") || m.isWorkloadType(selector, "job") {
		m.applyBatchDefaults(policy)
	}

	return nil
}

// isWorkloadType checks if the selector indicates a specific workload type
func (m *PahlevanPolicyMutator) isWorkloadType(selector policyv1alpha1.LabelSelector, workloadType string) bool {
	// Check matchLabels
	for key, value := range selector.MatchLabels {
		if (key == "app" || key == "component" || key == "tier") &&
			containsIgnoreCase(value, workloadType) {
			return true
		}
	}

	// Check matchExpressions
	for _, expr := range selector.MatchExpressions {
		if expr.Key == "app" || expr.Key == "component" || expr.Key == "tier" {
			for _, value := range expr.Values {
				if containsIgnoreCase(value, workloadType) {
					return true
				}
			}
		}
	}

	return false
}

// applyDatabaseDefaults applies defaults for database workloads
func (m *PahlevanPolicyMutator) applyDatabaseDefaults(policy *policyv1alpha1.PahlevanPolicy) {
	// Longer learning duration for databases due to complex startup patterns
	if policy.Spec.LearningConfig.Duration != nil && policy.Spec.LearningConfig.Duration.Duration == 5*time.Minute {
		policy.Spec.LearningConfig.Duration = &metav1.Duration{Duration: 10 * time.Minute}
	}

	// Add database-specific annotation
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations["policy.pahlevan.io/workload-type"] = "database"

	// Skip confidence threshold - field doesn't exist in current type
}

// applyWebAppDefaults applies defaults for web application workloads
func (m *PahlevanPolicyMutator) applyWebAppDefaults(policy *policyv1alpha1.PahlevanPolicy) {
	// Web apps typically have predictable patterns, shorter learning
	if policy.Spec.LearningConfig.Duration != nil && policy.Spec.LearningConfig.Duration.Duration == 5*time.Minute {
		policy.Spec.LearningConfig.Duration = &metav1.Duration{Duration: 3 * time.Minute}
	}

	// Add web app annotation
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations["policy.pahlevan.io/workload-type"] = "web-application"

	// Enable network monitoring for web apps
	policy.Annotations["policy.pahlevan.io/monitor-network"] = "true"
}

// applyBatchDefaults applies defaults for batch/job workloads
func (m *PahlevanPolicyMutator) applyBatchDefaults(policy *policyv1alpha1.PahlevanPolicy) {
	// Batch jobs may have varied patterns, longer learning
	if policy.Spec.LearningConfig.Duration != nil && policy.Spec.LearningConfig.Duration.Duration == 5*time.Minute {
		policy.Spec.LearningConfig.Duration = &metav1.Duration{Duration: 15 * time.Minute}
	}

	// Add batch workload annotation
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations["policy.pahlevan.io/workload-type"] = "batch"

	// Batch jobs may not need auto-transition due to short lifecycle
	if policy.Spec.LearningConfig.AutoTransition {
		policy.Spec.LearningConfig.AutoTransition = false
	}
}

// applyComplianceDefaults applies defaults to meet compliance requirements
func (m *PahlevanPolicyMutator) applyComplianceDefaults(policy *policyv1alpha1.PahlevanPolicy) {
	// Ensure audit logging is enabled
	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	if _, exists := policy.Annotations["policy.pahlevan.io/audit-level"]; !exists {
		policy.Annotations["policy.pahlevan.io/audit-level"] = "standard"
	}

	// Ensure retention policy is set
	if _, exists := policy.Annotations["policy.pahlevan.io/retention-days"]; !exists {
		policy.Annotations["policy.pahlevan.io/retention-days"] = "90"
	}

	// Add compliance framework annotations if in compliance namespace
	complianceFrameworks := []string{"pci", "hipaa", "soc2", "fedramp"}
	for _, framework := range complianceFrameworks {
		if containsIgnoreCase(policy.Namespace, framework) {
			policy.Annotations["policy.pahlevan.io/compliance-framework"] = framework
			break
		}
	}
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}
