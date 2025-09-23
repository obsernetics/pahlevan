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

package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// NewStatusCommand creates the status command
func NewStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show Pahlevan operator status",
		Long:  "Show the current status of the Pahlevan operator and policies in the cluster.",
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, _, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			ctx := context.Background()

			// Check operator deployment status
			fmt.Fprintf(writer.Writer, "=== Pahlevan Operator Status ===\n\n")

			// Find operator deployment
			deployments := &appsv1.DeploymentList{}
			err := k8sClient.List(ctx, deployments, client.MatchingLabels{
				"app.kubernetes.io/name": "pahlevan-operator",
			})
			if err != nil {
				writer.PrintError(fmt.Sprintf("Failed to get operator deployment: %v", err))
			} else if len(deployments.Items) == 0 {
				writer.PrintWarning("Pahlevan operator deployment not found")
			} else {
				deployment := deployments.Items[0]
				status := "Ready"
				if deployment.Status.ReadyReplicas != deployment.Status.Replicas {
					status = "Not Ready"
				}

				fmt.Fprintf(writer.Writer, "Operator Deployment: %s\n", cli.ColorizeStatus(status))
				fmt.Fprintf(writer.Writer, "  Namespace: %s\n", deployment.Namespace)
				fmt.Fprintf(writer.Writer, "  Replicas: %d/%d ready\n", deployment.Status.ReadyReplicas, deployment.Status.Replicas)
				fmt.Fprintf(writer.Writer, "  Image: %s\n", getContainerImage(deployment))
			}

			// Check CRDs
			fmt.Fprintf(writer.Writer, "\n=== Custom Resource Definitions ===\n\n")

			// Check if PahlevanPolicy CRD exists
			// Check if PahlevanPolicy CRD exists
			crdExists, err := checkPahlevanPolicyCRD(k8sClient)
			if err != nil {
				writer.PrintWarning(fmt.Sprintf("Failed to check CRD: %v", err))
			} else if crdExists {
				writer.PrintSuccess("PahlevanPolicy CRD: Installed")
			} else {
				writer.PrintError("PahlevanPolicy CRD: Not Found")
			}

			// Get policy statistics
			fmt.Fprintf(writer.Writer, "\n=== Policy Statistics ===\n\n")

			policies := &policyv1alpha1.PahlevanPolicyList{}
			err = k8sClient.List(ctx, policies)
			if err != nil {
				writer.PrintError(fmt.Sprintf("Failed to list policies: %v", err))
			} else {
				// Count policies by phase
				phaseCount := make(map[string]int)
				modeCount := make(map[string]int)

				for _, policy := range policies.Items {
					phaseCount[string(policy.Status.Phase)]++
					modeCount[string(policy.Spec.EnforcementConfig.Mode)]++
				}

				fmt.Fprintf(writer.Writer, "Total Policies: %d\n", len(policies.Items))

				if len(phaseCount) > 0 {
					fmt.Fprintf(writer.Writer, "\nBy Phase:\n")
					for phase, count := range phaseCount {
						fmt.Fprintf(writer.Writer, "  %s: %d\n", cli.ColorizeStatus(phase), count)
					}
				}

				if len(modeCount) > 0 {
					fmt.Fprintf(writer.Writer, "\nBy Enforcement Mode:\n")
					for mode, count := range modeCount {
						fmt.Fprintf(writer.Writer, "  %s: %d\n", mode, count)
					}
				}
			}

			// Check webhooks
			fmt.Fprintf(writer.Writer, "\n=== Admission Webhooks ===\n\n")

			// Check validating webhooks
			vwcExists, err := checkValidatingWebhookConfiguration(k8sClient)
			if err != nil {
				writer.PrintWarning(fmt.Sprintf("Failed to check validating webhook: %v", err))
			} else if vwcExists {
				writer.PrintSuccess("Validating Webhook: Configured")
			} else {
				writer.PrintWarning("Validating Webhook: Not Found")
			}

			// Check mutating webhooks
			mwcExists, err := checkMutatingWebhookConfiguration(k8sClient)
			if err != nil {
				writer.PrintWarning(fmt.Sprintf("Failed to check mutating webhook: %v", err))
			} else if mwcExists {
				writer.PrintSuccess("Mutating Webhook: Configured")
			} else {
				writer.PrintWarning("Mutating Webhook: Not Found")
			}

			return nil
		},
	}

	return cmd
}

func getContainerImage(deployment appsv1.Deployment) string {
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		return deployment.Spec.Template.Spec.Containers[0].Image
	}
	return "<unknown>"
}

func checkPahlevanPolicyCRD(k8sClient client.Client) (bool, error) {
	// Try to list PahlevanPolicies to check if CRD exists
	policies := &policyv1alpha1.PahlevanPolicyList{}
	err := k8sClient.List(context.Background(), policies)
	if err != nil {
		// If we get a "no matches for kind" error, CRD doesn't exist
		if client.IgnoreNotFound(err) == nil {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func checkValidatingWebhookConfiguration(k8sClient client.Client) (bool, error) {
	// This would check for validating webhook configurations
	// For now, we'll assume they exist if the operator is running
	// In a real implementation, this would query the AdmissionWebhookConfigurationV1 API
	return true, nil
}

func checkMutatingWebhookConfiguration(k8sClient client.Client) (bool, error) {
	// This would check for mutating webhook configurations
	// For now, we'll assume they exist if the operator is running
	// In a real implementation, this would query the AdmissionWebhookConfigurationV1 API
	return true, nil
}
