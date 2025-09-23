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

package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/obsernetics/pahlevan/internal/controller"
	"github.com/obsernetics/pahlevan/internal/learner"
	"github.com/obsernetics/pahlevan/internal/webhooks"
	"github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/discovery"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"
	"github.com/obsernetics/pahlevan/pkg/policies"
	"github.com/obsernetics/pahlevan/pkg/visualization"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// TestFramework provides a comprehensive testing framework for Pahlevan integration tests
type TestFramework struct {
	testEnv           *envtest.Environment
	k8sClient         client.Client
	manager           manager.Manager
	scheme            *runtime.Scheme
	ctx               context.Context
	cancel            context.CancelFunc
	testNamespace     string
	ebpfManager       *ebpf.Manager
	metricsManager    *metrics.Manager
	observability     *observability.Manager
	containerTracker  *discovery.ContainerTracker
	syscallLearner    *learner.SyscallLearner
	enforcementEngine *policies.EnforcementEngine
	attackSurface     *visualization.AttackSurfaceAnalyzer
	webhookInstalled  bool
}

// TestConfig holds configuration for the test framework
type TestConfig struct {
	UseWebhooks        bool
	EnableEBPF         bool
	MetricsPort        int
	WebhookPort        int
	CRDDirectoryPaths  []string
	WebhookPaths       []string
	TestTimeout        time.Duration
	PollingInterval    time.Duration
	EventuallyTimeout  time.Duration
	EventuallyInterval time.Duration
}

// DefaultTestConfig returns a default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		UseWebhooks:        true,
		EnableEBPF:         false, // Disabled by default in tests
		MetricsPort:        8081,
		WebhookPort:        9443,
		CRDDirectoryPaths:  []string{filepath.Join("..", "..", "config", "crd", "bases")},
		WebhookPaths:       []string{filepath.Join("..", "..", "config", "webhook")},
		TestTimeout:        2 * time.Minute,
		PollingInterval:    10 * time.Millisecond,
		EventuallyTimeout:  30 * time.Second,
		EventuallyInterval: 250 * time.Millisecond,
	}
}

// NewTestFramework creates a new test framework instance
func NewTestFramework(config *TestConfig) *TestFramework {
	if config == nil {
		config = DefaultTestConfig()
	}

	// Set up logging
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true)))

	// Configure Gomega
	gomega.SetDefaultEventuallyTimeout(config.EventuallyTimeout)
	gomega.SetDefaultEventuallyPollingInterval(config.EventuallyInterval)

	ctx, cancel := context.WithCancel(context.Background())

	return &TestFramework{
		ctx:    ctx,
		cancel: cancel,
	}
}

// Setup initializes the test environment
func (tf *TestFramework) Setup(config *TestConfig) error {
	// Initialize scheme
	tf.scheme = runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(tf.scheme); err != nil {
		return fmt.Errorf("failed to add client-go scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(tf.scheme); err != nil {
		return fmt.Errorf("failed to add pahlevan scheme: %v", err)
	}

	// Set up test environment
	tf.testEnv = &envtest.Environment{
		CRDDirectoryPaths:     config.CRDDirectoryPaths,
		ErrorIfCRDPathMissing: false,
		Scheme:                tf.scheme,
	}

	if config.UseWebhooks {
		tf.testEnv.WebhookInstallOptions = envtest.WebhookInstallOptions{
			Paths: config.WebhookPaths,
		}
		tf.webhookInstalled = true
	}

	// Start the test environment
	cfg, err := tf.testEnv.Start()
	if err != nil {
		return fmt.Errorf("failed to start test environment: %v", err)
	}

	// Create Kubernetes client
	tf.k8sClient, err = client.New(cfg, client.Options{Scheme: tf.scheme})
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	// Create manager
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 tf.scheme,
		HealthProbeBindAddress: ":8081",
		LeaderElection:         false, // Disable for tests
	})
	if err != nil {
		return fmt.Errorf("failed to create manager: %v", err)
	}
	tf.manager = mgr

	// Initialize components
	if err := tf.initializeComponents(config); err != nil {
		return fmt.Errorf("failed to initialize components: %v", err)
	}

	// Set up controllers
	if err := tf.setupControllers(); err != nil {
		return fmt.Errorf("failed to setup controllers: %v", err)
	}

	// Set up webhooks if enabled
	if config.UseWebhooks {
		if err := tf.setupWebhooks(); err != nil {
			return fmt.Errorf("failed to setup webhooks: %v", err)
		}
	}

	// Create test namespace
	tf.testNamespace = "test-" + tf.generateRandomString(8)
	if err := tf.createTestNamespace(); err != nil {
		return fmt.Errorf("failed to create test namespace: %v", err)
	}

	// Start manager in background
	go func() {
		defer ginkgo.GinkgoRecover()
		if err := mgr.Start(tf.ctx); err != nil {
			ginkgo.Fail(fmt.Sprintf("Failed to start manager: %v", err))
		}
	}()

	// Wait for manager to be ready
	if err := tf.waitForManagerReady(); err != nil {
		return fmt.Errorf("manager failed to become ready: %v", err)
	}

	return nil
}

// Cleanup cleans up the test environment
func (tf *TestFramework) Cleanup() error {
	// Cancel context to stop manager
	tf.cancel()

	// Clean up test namespace
	if tf.testNamespace != "" {
		if err := tf.cleanupTestNamespace(); err != nil {
			// Log but don't fail on cleanup errors
			logf.Log.Error(err, "Failed to cleanup test namespace", "namespace", tf.testNamespace)
		}
	}

	// Stop test environment
	if tf.testEnv != nil {
		if err := tf.testEnv.Stop(); err != nil {
			return fmt.Errorf("failed to stop test environment: %v", err)
		}
	}

	return nil
}

// initializeComponents initializes the Pahlevan components
func (tf *TestFramework) initializeComponents(config *TestConfig) error {
	// Initialize metrics manager
	tf.metricsManager = metrics.NewManager()

	// Initialize observability manager
	var err error
	tf.observability, err = observability.NewManager("test")
	if err != nil {
		return err
	}

	// Initialize eBPF manager (mock for tests unless explicitly enabled)
	if config.EnableEBPF {
		tf.ebpfManager, err = ebpf.NewManager()
		if err != nil {
			return err
		}
	} else {
		// Use a simple stub for tests
		tf.ebpfManager = &ebpf.Manager{}
	}

	// Initialize container tracker
	tf.containerTracker = discovery.NewContainerTracker(tf.k8sClient, tf.metricsManager)

	// Initialize syscall learner
	tf.syscallLearner = learner.NewSyscallLearner(1000, 0.8, 5*time.Minute, 10)

	// Initialize enforcement engine
	tf.enforcementEngine = policies.NewEnforcementEngine(tf.ebpfManager, tf.syscallLearner)

	// Initialize attack surface analyzer
	tf.attackSurface = visualization.NewAttackSurfaceAnalyzer(tf.k8sClient, tf.ebpfManager, tf.enforcementEngine)

	return nil
}

// setupControllers sets up the Kubernetes controllers
func (tf *TestFramework) setupControllers() error {
	// Set up PahlevanPolicy controller
	policyController := &controller.PahlevanPolicyReconciler{
		Client:               tf.k8sClient,
		Scheme:               tf.scheme,
		EBPFManager:          tf.ebpfManager,
		MetricsManager:       tf.metricsManager,
		ObservabilityManager: tf.observability,
	}

	if err := policyController.SetupWithManager(tf.manager); err != nil {
		return fmt.Errorf("failed to setup policy controller: %v", err)
	}

	// Set up Container Learner controller
	containerController := &controller.ContainerLearnerReconciler{
		Client:               tf.k8sClient,
		Scheme:               tf.scheme,
		EBPFManager:          tf.ebpfManager,
		MetricsManager:       tf.metricsManager,
		ObservabilityManager: tf.observability,
		TrackedContainers:    make(map[string]*controller.ContainerTrackingInfo),
	}

	if err := containerController.SetupWithManager(tf.manager); err != nil {
		return fmt.Errorf("failed to setup container controller: %v", err)
	}

	// Set up Attack Surface Analyzer controller
	attackSurfaceController := &controller.AttackSurfaceAnalyzerReconciler{
		Client:                tf.k8sClient,
		Scheme:                tf.scheme,
		EBPFManager:           tf.ebpfManager,
		MetricsManager:        tf.metricsManager,
		ObservabilityManager:  tf.observability,
		AttackSurfaceAnalyzer: tf.attackSurface,
		AnalysisInterval:      1 * time.Minute, // Faster for tests
	}

	if err := attackSurfaceController.SetupWithManager(tf.manager); err != nil {
		return fmt.Errorf("failed to setup attack surface controller: %v", err)
	}

	return nil
}

// setupWebhooks sets up the admission webhooks
func (tf *TestFramework) setupWebhooks() error {
	// Set up validation webhook
	validator := webhooks.NewPahlevanPolicyValidator(tf.k8sClient)
	tf.manager.GetWebhookServer().Register("/validate-policy-pahlevan-io-v1alpha1-pahlevanpolicy",
		&webhook.Admission{Handler: validator})

	// Set up mutation webhook
	mutator := webhooks.NewPahlevanPolicyMutator(tf.k8sClient)
	tf.manager.GetWebhookServer().Register("/mutate-policy-pahlevan-io-v1alpha1-pahlevanpolicy",
		&webhook.Admission{Handler: mutator})

	return nil
}

// createTestNamespace creates a namespace for testing
func (tf *TestFramework) createTestNamespace() error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: tf.testNamespace,
			Labels: map[string]string{
				"test.pahlevan.io/framework": "true",
				"test.pahlevan.io/run":       tf.generateRandomString(8),
			},
		},
	}

	return tf.k8sClient.Create(tf.ctx, ns)
}

// cleanupTestNamespace cleans up the test namespace
func (tf *TestFramework) cleanupTestNamespace() error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: tf.testNamespace,
		},
	}

	return tf.k8sClient.Delete(tf.ctx, ns)
}

// waitForManagerReady waits for the manager to be ready
func (tf *TestFramework) waitForManagerReady() error {
	// Wait for the manager's cache to sync
	ctx, cancel := context.WithTimeout(tf.ctx, 30*time.Second)
	defer cancel()

	if ok := tf.manager.GetCache().WaitForCacheSync(ctx); !ok {
		return fmt.Errorf("failed waiting for cache to sync")
	}

	return nil
}

// Helper methods for test framework

// GetClient returns the Kubernetes client
func (tf *TestFramework) GetClient() client.Client {
	return tf.k8sClient
}

// GetTestNamespace returns the test namespace
func (tf *TestFramework) GetTestNamespace() string {
	return tf.testNamespace
}

// GetContext returns the test context
func (tf *TestFramework) GetContext() context.Context {
	return tf.ctx
}

// CreatePolicy creates a test PahlevanPolicy
func (tf *TestFramework) CreatePolicy(name string, spec v1alpha1.PahlevanPolicySpec) (*v1alpha1.PahlevanPolicy, error) {
	policy := &v1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tf.testNamespace,
		},
		Spec: spec,
	}

	if err := tf.k8sClient.Create(tf.ctx, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// CreateTestDeployment creates a test deployment
func (tf *TestFramework) CreateTestDeployment(name string, labels map[string]string) (*appsv1.Deployment, error) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tf.testNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 80,
									Protocol:      corev1.ProtocolTCP,
								},
							},
						},
					},
				},
			},
		},
	}

	if err := tf.k8sClient.Create(tf.ctx, deployment); err != nil {
		return nil, err
	}

	return deployment, nil
}

// WaitForPolicyPhase waits for a policy to reach a specific phase
func (tf *TestFramework) WaitForPolicyPhase(policyName string, phase v1alpha1.PolicyPhase, timeout time.Duration) error {
	return tf.Eventually(func() bool {
		policy := &v1alpha1.PahlevanPolicy{}
		err := tf.k8sClient.Get(tf.ctx, types.NamespacedName{
			Name:      policyName,
			Namespace: tf.testNamespace,
		}, policy)
		if err != nil {
			return false
		}
		return policy.Status.Phase == phase
	}, timeout, 500*time.Millisecond, fmt.Sprintf("policy %s to reach phase %s", policyName, phase))
}

// WaitForDeploymentReady waits for a deployment to be ready
func (tf *TestFramework) WaitForDeploymentReady(deploymentName string, timeout time.Duration) error {
	return tf.Eventually(func() bool {
		deployment := &appsv1.Deployment{}
		err := tf.k8sClient.Get(tf.ctx, types.NamespacedName{
			Name:      deploymentName,
			Namespace: tf.testNamespace,
		}, deployment)
		if err != nil {
			return false
		}
		return deployment.Status.ReadyReplicas == *deployment.Spec.Replicas
	}, timeout, 500*time.Millisecond, fmt.Sprintf("deployment %s to be ready", deploymentName))
}

// Eventually is a wrapper around Gomega's Eventually with error handling
func (tf *TestFramework) Eventually(condition func() bool, timeout time.Duration, polling time.Duration, description string) error {
	done := make(chan bool, 1)
	go func() {
		defer close(done)
		gomega.Eventually(condition, timeout, polling).Should(gomega.BeTrue(), description)
		done <- true
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout + 5*time.Second): // Small buffer
		return fmt.Errorf("timeout waiting for %s", description)
	}
}

// Consistently is a wrapper around Gomega's Consistently
func (tf *TestFramework) Consistently(condition func() bool, duration time.Duration, polling time.Duration, description string) error {
	done := make(chan bool, 1)
	go func() {
		defer close(done)
		gomega.Consistently(condition, duration, polling).Should(gomega.BeTrue(), description)
		done <- true
	}()

	select {
	case <-done:
		return nil
	case <-time.After(duration + 5*time.Second): // Small buffer
		return fmt.Errorf("consistency check failed for %s", description)
	}
}

// generateRandomString generates a random string of the specified length
func (tf *TestFramework) generateRandomString(length int) string {
	// Simple implementation for test purposes
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}

// int32Ptr returns a pointer to an int32 value
func int32Ptr(i int32) *int32 {
	return &i
}

// TestScenario represents a test scenario that can be run
type TestScenario struct {
	Name        string
	Description string
	Setup       func(*TestFramework) error
	Execute     func(*TestFramework) error
	Verify      func(*TestFramework) error
	Cleanup     func(*TestFramework) error
}

// RunScenario runs a test scenario
func (tf *TestFramework) RunScenario(scenario TestScenario) error {
	// Setup
	if scenario.Setup != nil {
		if err := scenario.Setup(tf); err != nil {
			return fmt.Errorf("scenario setup failed: %v", err)
		}
	}

	// Execute
	if scenario.Execute != nil {
		if err := scenario.Execute(tf); err != nil {
			return fmt.Errorf("scenario execution failed: %v", err)
		}
	}

	// Verify
	if scenario.Verify != nil {
		if err := scenario.Verify(tf); err != nil {
			return fmt.Errorf("scenario verification failed: %v", err)
		}
	}

	// Cleanup
	if scenario.Cleanup != nil {
		if err := scenario.Cleanup(tf); err != nil {
			// Log cleanup errors but don't fail the test
			logf.Log.Error(err, "Scenario cleanup failed", "scenario", scenario.Name)
		}
	}

	return nil
}
