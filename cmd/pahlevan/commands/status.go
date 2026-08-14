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
	"strings"

	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
			k8sClient, kubeClient, _, _, ready := GetClients()
			writer := cli.NewOutputWriter("table")

			if !ready || k8sClient == nil {
				return fmt.Errorf("kubernetes clients are not initialized; check your kubeconfig and cluster connectivity")
			}

			ctx := context.Background()

			// Operator + agent workloads
			fmt.Fprintf(writer.Writer, "=== Pahlevan Workloads ===\n\n")
			reportDeployment(ctx, writer, k8sClient, "pahlevan-operator")
			reportDaemonSet(ctx, writer, k8sClient, "pahlevan-agent")

			// Check CRDs
			fmt.Fprintf(writer.Writer, "\n=== Custom Resource Definitions ===\n\n")
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

			// Admission control: webhooks
			fmt.Fprintf(writer.Writer, "\n=== Admission Webhooks ===\n\n")
			reportValidatingWebhooks(ctx, writer, k8sClient)
			reportMutatingWebhooks(ctx, writer, k8sClient)

			// Admission control: ValidatingAdmissionPolicy (admissionregistration.k8s.io)
			fmt.Fprintf(writer.Writer, "\n=== Validating Admission Policies ===\n\n")
			reportValidatingAdmissionPolicies(ctx, writer, k8sClient, kubeClient)

			return nil
		},
	}

	return cmd
}

// reportDeployment finds a Deployment by app.kubernetes.io/name and prints readiness.
func reportDeployment(ctx context.Context, writer *cli.OutputWriter, k8sClient client.Client, appName string) {
	deployments := &appsv1.DeploymentList{}
	err := k8sClient.List(ctx, deployments, client.MatchingLabels{"app.kubernetes.io/name": appName})
	if err != nil {
		writer.PrintError(fmt.Sprintf("Failed to get %s deployment: %v", appName, err))
		return
	}
	if len(deployments.Items) == 0 {
		writer.PrintWarning(fmt.Sprintf("%s deployment not found", appName))
		return
	}

	d := deployments.Items[0]
	status := "Ready"
	if d.Status.ReadyReplicas != d.Status.Replicas || d.Status.Replicas == 0 {
		status = "Not Ready"
	}
	fmt.Fprintf(writer.Writer, "Deployment %s: %s\n", appName, cli.ColorizeStatus(status))
	fmt.Fprintf(writer.Writer, "  Namespace: %s\n", d.Namespace)
	fmt.Fprintf(writer.Writer, "  Replicas: %d/%d ready\n", d.Status.ReadyReplicas, d.Status.Replicas)
	fmt.Fprintf(writer.Writer, "  Image: %s\n", getContainerImage(d))
}

// reportDaemonSet finds a DaemonSet by app.kubernetes.io/name and prints readiness.
func reportDaemonSet(ctx context.Context, writer *cli.OutputWriter, k8sClient client.Client, appName string) {
	daemonSets := &appsv1.DaemonSetList{}
	err := k8sClient.List(ctx, daemonSets, client.MatchingLabels{"app.kubernetes.io/name": appName})
	if err != nil {
		writer.PrintError(fmt.Sprintf("Failed to get %s daemonset: %v", appName, err))
		return
	}
	if len(daemonSets.Items) == 0 {
		writer.PrintWarning(fmt.Sprintf("%s daemonset not found", appName))
		return
	}

	ds := daemonSets.Items[0]
	status := "Ready"
	if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled || ds.Status.DesiredNumberScheduled == 0 {
		status = "Not Ready"
	}
	fmt.Fprintf(writer.Writer, "DaemonSet %s: %s\n", appName, cli.ColorizeStatus(status))
	fmt.Fprintf(writer.Writer, "  Namespace: %s\n", ds.Namespace)
	fmt.Fprintf(writer.Writer, "  Nodes: %d/%d ready (%d available)\n",
		ds.Status.NumberReady, ds.Status.DesiredNumberScheduled, ds.Status.NumberAvailable)
	fmt.Fprintf(writer.Writer, "  Image: %s\n", getDaemonSetContainerImage(ds))
}

func getContainerImage(deployment appsv1.Deployment) string {
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		return deployment.Spec.Template.Spec.Containers[0].Image
	}
	return "<unknown>"
}

func getDaemonSetContainerImage(ds appsv1.DaemonSet) string {
	if len(ds.Spec.Template.Spec.Containers) > 0 {
		return ds.Spec.Template.Spec.Containers[0].Image
	}
	return "<unknown>"
}

func checkPahlevanPolicyCRD(k8sClient client.Client) (bool, error) {
	// Try to list PahlevanPolicies to check if CRD exists.
	policies := &policyv1alpha1.PahlevanPolicyList{}
	err := k8sClient.List(context.Background(), policies)
	if err != nil {
		// A missing CRD surfaces as a NoKindMatchError or NotFound.
		if apierrors.IsNotFound(err) || isNoKindMatch(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isNoKindMatch reports whether the error indicates the resource kind is not
// registered in the cluster (i.e. the CRD is not installed).
func isNoKindMatch(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no matches for kind") ||
		strings.Contains(msg, "no kind is registered") ||
		strings.Contains(msg, "the server could not find the requested resource")
}

// reportValidatingWebhooks lists Pahlevan validating webhook configurations.
func reportValidatingWebhooks(ctx context.Context, writer *cli.OutputWriter, k8sClient client.Client) {
	list := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := k8sClient.List(ctx, list); err != nil {
		writer.PrintWarning(fmt.Sprintf("Failed to check validating webhook: %v", err))
		return
	}
	names := filterPahlevanNames(webhookConfigNames(list))
	if len(names) > 0 {
		writer.PrintSuccess(fmt.Sprintf("Validating Webhook: Configured (%s)", strings.Join(names, ", ")))
	} else {
		writer.PrintWarning("Validating Webhook: Not Found")
	}
}

// reportMutatingWebhooks lists Pahlevan mutating webhook configurations.
func reportMutatingWebhooks(ctx context.Context, writer *cli.OutputWriter, k8sClient client.Client) {
	list := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := k8sClient.List(ctx, list); err != nil {
		writer.PrintWarning(fmt.Sprintf("Failed to check mutating webhook: %v", err))
		return
	}
	var allNames []string
	for i := range list.Items {
		allNames = append(allNames, list.Items[i].Name)
	}
	names := filterPahlevanNames(allNames)
	if len(names) > 0 {
		writer.PrintSuccess(fmt.Sprintf("Mutating Webhook: Configured (%s)", strings.Join(names, ", ")))
	} else {
		writer.PrintWarning("Mutating Webhook: Not Found")
	}
}

func webhookConfigNames(list *admissionregistrationv1.ValidatingWebhookConfigurationList) []string {
	var names []string
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}
	return names
}

// reportValidatingAdmissionPolicies queries the real ValidatingAdmissionPolicy
// API (admissionregistration.k8s.io) and reports installed Pahlevan policies and
// their bindings.
func reportValidatingAdmissionPolicies(ctx context.Context, writer *cli.OutputWriter, k8sClient client.Client, kubeClient kubernetes.Interface) {
	list := &admissionregistrationv1.ValidatingAdmissionPolicyList{}
	err := k8sClient.List(ctx, list)
	if err != nil {
		// Older clusters (<1.30) may not serve this API; report gracefully.
		if isNoKindMatch(err) || apierrors.IsNotFound(err) {
			writer.PrintWarning("ValidatingAdmissionPolicy API not available on this cluster")
			return
		}
		writer.PrintWarning(fmt.Sprintf("Failed to check validating admission policies: %v", err))
		return
	}

	var names []string
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}
	policyNames := filterPahlevanNames(names)

	if len(policyNames) == 0 {
		writer.PrintWarning("ValidatingAdmissionPolicy: Not Found")
		return
	}
	writer.PrintSuccess(fmt.Sprintf("ValidatingAdmissionPolicy: Installed (%s)", strings.Join(policyNames, ", ")))

	// Report bindings for the discovered policies.
	bindings := &admissionregistrationv1.ValidatingAdmissionPolicyBindingList{}
	if err := k8sClient.List(ctx, bindings); err != nil {
		writer.PrintWarning(fmt.Sprintf("Failed to list admission policy bindings: %v", err))
		return
	}
	boundPolicies := make(map[string]int)
	for i := range bindings.Items {
		boundPolicies[bindings.Items[i].Spec.PolicyName]++
	}
	for _, name := range policyNames {
		if count := boundPolicies[name]; count > 0 {
			fmt.Fprintf(writer.Writer, "  %s: %d binding(s)\n", name, count)
		} else {
			fmt.Fprintf(writer.Writer, "  %s: %s\n", name, cli.ColorizeStatus("warning")+" no bindings")
		}
	}

	// Confirm the API is reachable via client-go as well (belt-and-suspenders
	// verification against the typed clientset).
	if kubeClient != nil {
		if _, err := kubeClient.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
			writer.PrintWarning(fmt.Sprintf("client-go admission API check failed: %v", err))
		}
	}
}

// filterPahlevanNames returns the subset of names that relate to Pahlevan.
func filterPahlevanNames(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "pahlevan") {
			out = append(out, n)
		}
	}
	return out
}
