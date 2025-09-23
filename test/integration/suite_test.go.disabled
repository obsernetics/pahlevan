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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Integration Test Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")

	ctx = context.Background()

	// Set up the test environment
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
		},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = policyv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// Start the manager
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("Integration Test Suite Setup", func() {
	Context("Test Environment", func() {
		It("Should have a working Kubernetes client", func() {
			Expect(k8sClient).NotTo(BeNil())
		})

		It("Should have CRDs installed", func() {
			// Verify that our CRDs are available
			policies := &policyv1alpha1.PahlevanPolicyList{}
			err := k8sClient.List(ctx, policies)
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should be able to create namespaces", func() {
			// This test verifies basic cluster functionality
			testNs := "integration-test-setup"
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNs,
				},
			}

			err := k8sClient.Create(ctx, ns)
			Expect(err).NotTo(HaveOccurred())

			// Clean up
			err = k8sClient.Delete(ctx, ns)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Framework Validation", func() {
		var framework *TestFramework

		BeforeEach(func() {
			config := DefaultTestConfig()
			config.EnableEBPF = false // Use mock for setup tests
			framework = NewTestFramework(config)
		})

		AfterEach(func() {
			if framework != nil {
				_ = framework.Cleanup()
			}
		})

		It("Should initialize framework correctly", func() {
			config := DefaultTestConfig()
			err := framework.Setup(config)
			Expect(err).NotTo(HaveOccurred())

			Expect(framework.GetClient()).NotTo(BeNil())
			Expect(framework.GetTestNamespace()).NotTo(BeEmpty())
			Expect(framework.GetContext()).NotTo(BeNil())
		})

		It("Should create test resources", func() {
			config := DefaultTestConfig()
			err := framework.Setup(config)
			Expect(err).NotTo(HaveOccurred())

			// Test policy creation
			spec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"test": "framework",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 1 * time.Minute},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			policy, err := framework.CreatePolicy("test-framework-policy", spec)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy).NotTo(BeNil())
			Expect(policy.Name).To(Equal("test-framework-policy"))
			Expect(policy.Namespace).To(Equal(framework.GetTestNamespace()))

			// Test deployment creation
			deployment, err := framework.CreateTestDeployment("test-deployment", map[string]string{
				"test": "framework",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(deployment).NotTo(BeNil())
			Expect(deployment.Name).To(Equal("test-deployment"))
		})
	})
})

// Test data and scenarios for comprehensive testing
var _ = Describe("Comprehensive Integration Scenarios", func() {
	var framework *TestFramework

	BeforeEach(func() {
		config := DefaultTestConfig()
		config.EnableEBPF = false
		framework = NewTestFramework(config)
		Expect(framework.Setup(config)).To(Succeed())
	})

	AfterEach(func() {
		if framework != nil {
			Expect(framework.Cleanup()).To(Succeed())
		}
	})

	Context("Real-world Scenarios", func() {
		It("Should handle a typical microservice deployment", func() {
			scenario := TestScenario{
				Name:        "Microservice Learning and Enforcement",
				Description: "Deploy a microservice, learn its behavior, and enforce policies",
				Setup: func(tf *TestFramework) error {
					// Create a policy for microservices
					spec := v1alpha1.PahlevanPolicySpec{
						Selector: v1alpha1.LabelSelector{
							MatchLabels: map[string]string{
								"tier": "microservice",
							},
						},
						LearningConfig: v1alpha1.LearningConfig{
							Duration:       &metav1.Duration{Duration: 45 * time.Second},
							AutoTransition: true,
						},
						EnforcementConfig: v1alpha1.EnforcementConfig{
							Mode:         v1alpha1.EnforcementModeMonitoring,
							GracePeriod:  &metav1.Duration{Duration: 15 * time.Second},
							BlockUnknown: true,
						},
						SelfHealing: v1alpha1.SelfHealingConfig{
							Enabled:           true,
							RollbackThreshold: 3,
							RecoveryStrategy:  v1alpha1.RecoveryStrategyRollback,
						},
					}

					_, err := tf.CreatePolicy("microservice-policy", spec)
					return err
				},
				Execute: func(tf *TestFramework) error {
					// Deploy microservice
					_, err := tf.CreateTestDeployment("api-service", map[string]string{
						"tier":    "microservice",
						"service": "api",
						"version": "v1",
					})
					if err != nil {
						return err
					}

					// Wait for deployment
					return tf.WaitForDeploymentReady("api-service", 2*time.Minute)
				},
				Verify: func(tf *TestFramework) error {
					// Verify policy progresses through lifecycle
					if err := tf.WaitForPolicyPhase("microservice-policy", v1alpha1.PolicyPhaseLearning, 1*time.Minute); err != nil {
						return fmt.Errorf("policy failed to reach learning phase: %v", err)
					}

					// Verify attack surface analysis
					return tf.Eventually(func() bool {
						policy := &v1alpha1.PahlevanPolicy{}
						err := tf.GetClient().Get(tf.GetContext(),
							types.NamespacedName{Name: "microservice-policy", Namespace: tf.GetTestNamespace()},
							policy)
						return err == nil && policy.Status.AttackSurface != nil
					}, 1*time.Minute, 5*time.Second, "attack surface analysis to complete")
				},
			}

			Expect(framework.RunScenario(scenario)).To(Succeed())
		})

		It("Should handle database workload with longer learning period", func() {
			scenario := TestScenario{
				Name:        "Database Workload Learning",
				Description: "Deploy a database workload with extended learning requirements",
				Setup: func(tf *TestFramework) error {
					spec := v1alpha1.PahlevanPolicySpec{
						Selector: v1alpha1.LabelSelector{
							MatchLabels: map[string]string{
								"component": "database",
							},
						},
						LearningConfig: v1alpha1.LearningConfig{
							Duration:   &metav1.Duration{Duration: 2 * time.Minute}, // Longer for databases
							WindowSize: &metav1.Duration{Duration: 30 * time.Second},
							MinSamples: int32Ptr(50),
						},
						EnforcementConfig: v1alpha1.EnforcementConfig{
							Mode:        v1alpha1.EnforcementModeMonitoring,
							GracePeriod: &metav1.Duration{Duration: 30 * time.Second}, // Longer grace period
						},
					}

					_, err := tf.CreatePolicy("database-policy", spec)
					return err
				},
				Execute: func(tf *TestFramework) error {
					_, err := tf.CreateTestDeployment("postgres-db", map[string]string{
						"component": "database",
						"database":  "postgres",
					})
					return err
				},
				Verify: func(tf *TestFramework) error {
					return tf.WaitForPolicyPhase("database-policy", v1alpha1.PolicyPhaseLearning, 1*time.Minute)
				},
			}

			Expect(framework.RunScenario(scenario)).To(Succeed())
		})
	})

	Context("Error Recovery Scenarios", func() {
		It("Should recover from policy conflicts", func() {
			// Create first policy
			spec1 := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "conflict-test",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 1 * time.Minute},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			policy1, err := framework.CreatePolicy("conflict-policy-1", spec1)
			Expect(err).NotTo(HaveOccurred())

			// If webhooks are enabled, creating a conflicting policy should fail
			if framework.webhookInstalled {
				spec2 := spec1 // Same selector - should conflict
				_, err = framework.CreatePolicy("conflict-policy-2", spec2)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("overlap"))
			}

			// Original policy should remain functional
			Expect(policy1.Name).To(Equal("conflict-policy-1"))

			// Verify policy is still manageable
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "conflict-policy-1", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				return err == nil && updatedPolicy.Status.Phase != ""
			}, 30*time.Second, 1*time.Second).Should(BeTrue())
		})
	})
})

// Helper function to check if running in CI/GitHub Actions
func isCI() bool {
	return os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true"
}

// Helper function to skip tests that require special setup
func skipIfCI(reason string) {
	if isCI() {
		Skip(fmt.Sprintf("Skipping in CI: %s", reason))
	}
}
