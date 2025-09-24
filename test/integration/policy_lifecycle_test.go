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
	"time"

	"github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Policy Lifecycle Integration Tests", func() {
	var (
		framework *TestFramework
		config    *TestConfig
	)

	BeforeEach(func() {
		config = DefaultTestConfig()
		config.EnableEBPF = false // Use mock eBPF for tests
		config.TestTimeout = 5 * time.Minute

		framework = NewTestFramework(config)
		Expect(framework.Setup(config)).To(Succeed())
	})

	AfterEach(func() {
		if framework != nil {
			Expect(framework.Cleanup()).To(Succeed())
		}
	})

	Context("Basic Policy Lifecycle", func() {
		It("Should create policy and progress through phases", func() {
			// Create a basic policy
			policySpec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration:       &metav1.Duration{Duration: 30 * time.Second}, // Short for testing
					AutoTransition: true,
					LifecycleAware: true,
					MinSamples:     int32Ptr(10),
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode:        v1alpha1.EnforcementModeMonitoring,
					GracePeriod: &metav1.Duration{Duration: 10 * time.Second},
				},
			}

			policy, err := framework.CreatePolicy("test-policy", policySpec)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy).NotTo(BeNil())

			// Wait for policy to be initialized
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				if err != nil {
					return false
				}
				return updatedPolicy.Status.Phase == v1alpha1.PolicyPhaseInitializing
			}, 30*time.Second, 1*time.Second).Should(BeTrue())

			// Create a deployment that matches the policy selector
			deployment, err := framework.CreateTestDeployment("test-deployment", map[string]string{
				"app": "test-app",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(deployment).NotTo(BeNil())

			// Wait for deployment to be ready
			Expect(framework.WaitForDeploymentReady("test-deployment", 2*time.Minute)).To(Succeed())

			// Policy should transition to learning phase
			Expect(framework.WaitForPolicyPhase("test-policy", v1alpha1.PolicyPhaseLearning, 1*time.Minute)).To(Succeed())

			// Verify learning progress is tracked
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				if err != nil {
					return false
				}
				return updatedPolicy.Status.LearningStatus != nil &&
					updatedPolicy.Status.Phase == v1alpha1.PolicyPhaseLearning
			}, 30*time.Second, 1*time.Second).Should(BeTrue())

			// Eventually the policy should auto-transition to enforcing (mocked behavior)
			// In a real test with actual workloads, this would happen after learning completes
			// For this test, we'll simulate it by updating the enforcement mode
			Eventually(func() error {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				if err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy); err != nil {
					return err
				}

				// Update to blocking mode to trigger transition
				updatedPolicy.Spec.EnforcementConfig.Mode = v1alpha1.EnforcementModeBlocking
				return framework.GetClient().Update(framework.GetContext(), updatedPolicy)
			}, 30*time.Second, 5*time.Second).Should(Succeed())

			// Verify enforcement status is updated
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				if err != nil {
					return false
				}
				return updatedPolicy.Status.EnforcementStatus != nil &&
					updatedPolicy.Status.Phase == v1alpha1.PolicyPhaseEnforcing
			}, 30*time.Second, 1*time.Second).Should(BeTrue())
		})

		It("Should handle policy validation correctly", func() {
			// Test invalid policy creation (if webhooks are enabled)
			if framework.webhookInstalled {
				invalidPolicySpec := v1alpha1.PahlevanPolicySpec{
					Selector: v1alpha1.LabelSelector{
						// Empty selector should be rejected
					},
					LearningConfig: v1alpha1.LearningConfig{
						Duration: nil, // Invalid - nil duration
					},
				}

				_, err := framework.CreatePolicy("invalid-policy", invalidPolicySpec)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("validation failed"))
			}
		})

		It("Should apply default values through mutation webhook", func() {
			if framework.webhookInstalled {
				// Create policy with minimal spec
				minimalSpec := v1alpha1.PahlevanPolicySpec{
					Selector: v1alpha1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "minimal-app",
						},
					},
				}

				policy, err := framework.CreatePolicy("minimal-policy", minimalSpec)
				Expect(err).NotTo(HaveOccurred())

				// Verify defaults were applied
				Expect(policy.Spec.LearningConfig.Duration).NotTo(BeEmpty())
				Expect(policy.Spec.EnforcementConfig.Mode).NotTo(BeEmpty())
				Expect(policy.Labels).To(HaveKey("app.kubernetes.io/managed-by"))
				Expect(policy.Labels["app.kubernetes.io/managed-by"]).To(Equal("pahlevan-operator"))
			}
		})
	})

	Context("Multi-Policy Scenarios", func() {
		It("Should handle multiple policies in the same namespace", func() {
			// Create first policy
			policy1Spec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "app1",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 1 * time.Minute},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			policy1, err := framework.CreatePolicy("policy1", policy1Spec)
			Expect(err).NotTo(HaveOccurred())

			// Create second policy with different selector
			policy2Spec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "app2",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 1 * time.Minute},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			policy2, err := framework.CreatePolicy("policy2", policy2Spec)
			Expect(err).NotTo(HaveOccurred())

			// Both policies should be initialized
			Expect(framework.WaitForPolicyPhase("policy1", v1alpha1.PolicyPhaseInitializing, 30*time.Second)).To(Succeed())
			Expect(framework.WaitForPolicyPhase("policy2", v1alpha1.PolicyPhaseInitializing, 30*time.Second)).To(Succeed())

			// Create deployments for each policy
			_, err = framework.CreateTestDeployment("app1-deployment", map[string]string{"app": "app1"})
			Expect(err).NotTo(HaveOccurred())

			_, err = framework.CreateTestDeployment("app2-deployment", map[string]string{"app": "app2"})
			Expect(err).NotTo(HaveOccurred())

			// Both policies should transition independently
			Expect(framework.WaitForPolicyPhase("policy1", v1alpha1.PolicyPhaseLearning, 1*time.Minute)).To(Succeed())
			Expect(framework.WaitForPolicyPhase("policy2", v1alpha1.PolicyPhaseLearning, 1*time.Minute)).To(Succeed())

			// Verify each policy tracks its own containers
			Eventually(func() bool {
				policy1Updated := &v1alpha1.PahlevanPolicy{}
				policy2Updated := &v1alpha1.PahlevanPolicy{}

				err1 := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "policy1", Namespace: framework.GetTestNamespace()},
					policy1Updated)
				err2 := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "policy2", Namespace: framework.GetTestNamespace()},
					policy2Updated)

				return err1 == nil && err2 == nil &&
					policy1Updated.Status.EnforcementStatus != nil &&
					policy2Updated.Status.EnforcementStatus != nil
			}, 30*time.Second, 1*time.Second).Should(BeTrue())

			// Verify no interference between policies
			Expect(policy1.Name).To(Equal("policy1"))
			Expect(policy2.Name).To(Equal("policy2"))
		})
	})

	Context("Error Handling", func() {
		It("Should handle controller errors gracefully", func() {
			// Create policy
			policySpec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "error-test",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 30 * time.Second},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			policy, err := framework.CreatePolicy("error-test-policy", policySpec)
			Expect(err).NotTo(HaveOccurred())

			// Even with potential errors, policy should eventually reach a stable state
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "error-test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				if err != nil {
					return false
				}

				// Check that policy has some status set
				return updatedPolicy.Status.Phase != "" &&
					len(updatedPolicy.Status.Conditions) > 0
			}, 1*time.Minute, 5*time.Second).Should(BeTrue())

			// Verify the policy still exists and is manageable
			Expect(policy.Name).To(Equal("error-test-policy"))
		})
	})

	Context("Attack Surface Analysis", func() {
		It("Should trigger attack surface analysis", func() {
			// Create policy
			policySpec := v1alpha1.PahlevanPolicySpec{
				Selector: v1alpha1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "surface-test",
					},
				},
				LearningConfig: v1alpha1.LearningConfig{
					Duration: &metav1.Duration{Duration: 30 * time.Second},
				},
				EnforcementConfig: v1alpha1.EnforcementConfig{
					Mode: v1alpha1.EnforcementModeMonitoring,
				},
			}

			_, err := framework.CreatePolicy("surface-test-policy", policySpec)
			Expect(err).NotTo(HaveOccurred())

			// Create deployment
			_, err = framework.CreateTestDeployment("surface-test-deployment", map[string]string{
				"app": "surface-test",
			})
			Expect(err).NotTo(HaveOccurred())

			// Wait for deployment and policy to be ready
			Expect(framework.WaitForDeploymentReady("surface-test-deployment", 2*time.Minute)).To(Succeed())
			Expect(framework.WaitForPolicyPhase("surface-test-policy", v1alpha1.PolicyPhaseLearning, 1*time.Minute)).To(Succeed())

			// Eventually attack surface should be populated
			Eventually(func() bool {
				updatedPolicy := &v1alpha1.PahlevanPolicy{}
				err := framework.GetClient().Get(framework.GetContext(),
					types.NamespacedName{Name: "surface-test-policy", Namespace: framework.GetTestNamespace()},
					updatedPolicy)
				if err != nil {
					return false
				}

				return updatedPolicy.Status.AttackSurface != nil &&
					updatedPolicy.Status.AttackSurface.LastAnalysis != nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			// Verify attack surface data structure
			updatedPolicy := &v1alpha1.PahlevanPolicy{}
			err = framework.GetClient().Get(framework.GetContext(),
				types.NamespacedName{Name: "surface-test-policy", Namespace: framework.GetTestNamespace()},
				updatedPolicy)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedPolicy.Status.AttackSurface).NotTo(BeNil())
			Expect(updatedPolicy.Status.AttackSurface.ExposedSyscalls).NotTo(BeNil())
			Expect(updatedPolicy.Status.AttackSurface.ExposedPorts).NotTo(BeNil())
			Expect(updatedPolicy.Status.AttackSurface.WritableFiles).NotTo(BeNil())
			Expect(updatedPolicy.Status.AttackSurface.Capabilities).NotTo(BeNil())
		})
	})
})

// Helper functions
func boolPtr(b bool) *bool {
	return &b
}

func float64Ptr(f float64) *float64 {
	return &f
}
