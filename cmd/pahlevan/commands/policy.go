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
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// NewPolicyCommand creates the policy command
func NewPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Pahlevan security policies",
		Long: `Manage Pahlevan security policies for container behavior learning and enforcement.

Policies define how containers should be monitored, what behavior should be learned,
and how violations should be handled.`,
	}

	cmd.AddCommand(
		NewPolicyListCommand(),
		NewPolicyGetCommand(),
		NewPolicyDescribeCommand(),
		NewPolicyCreateCommand(),
		NewPolicyDeleteCommand(),
		NewPolicyUpdateCommand(),
		NewPolicyStatusCommand(),
	)

	return cmd
}

// NewPolicyListCommand creates the policy list command
func NewPolicyListCommand() *cobra.Command {
	var (
		allNamespaces bool
		selector      string
		output        string
	)

	cmd := &cobra.Command{
		Use:     "list [flags]",
		Short:   "List Pahlevan policies",
		Long:    "List Pahlevan policies in the current or specified namespace.",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter(output)

			// Prepare list options
			listOpts := []client.ListOption{}
			if !allNamespaces {
				listOpts = append(listOpts, client.InNamespace(namespace))
			}
			if selector != "" {
				labelSelector, err := metav1.ParseToLabelSelector(selector)
				if err != nil {
					return fmt.Errorf("invalid selector: %v", err)
				}
				selector, err := metav1.LabelSelectorAsSelector(labelSelector)
				if err != nil {
					return fmt.Errorf("failed to convert label selector: %v", err)
				}
				listOpts = append(listOpts, client.MatchingLabelsSelector{
					Selector: selector,
				})
			}

			// Get policies
			policies := &policyv1alpha1.PahlevanPolicyList{}
			if err := k8sClient.List(context.Background(), policies, listOpts...); err != nil {
				return fmt.Errorf("failed to list policies: %v", err)
			}

			// Handle output format
			if output == "json" || output == "yaml" {
				return writer.WriteObject(policies)
			}

			// Prepare table data
			table := cli.NewTableData()
			if allNamespaces {
				table.Headers = []string{"NAMESPACE", "NAME", "PHASE", "MODE", "PROGRESS", "VIOLATIONS", "AGE"}
			} else {
				table.Headers = []string{"NAME", "PHASE", "MODE", "PROGRESS", "VIOLATIONS", "AGE"}
			}

			for _, policy := range policies.Items {
				phase := string(policy.Status.Phase)
				mode := string(policy.Spec.EnforcementConfig.Mode)
				progress := formatProgress(&policy)
				violations := formatViolations(&policy)
				age := cli.FormatTimestamp(policy.CreationTimestamp.Time)

				if allNamespaces {
					table.AddRow(
						policy.Namespace,
						policy.Name,
						cli.ColorizeStatus(phase),
						mode,
						progress,
						violations,
						age,
					)
				} else {
					table.AddRow(
						policy.Name,
						cli.ColorizeStatus(phase),
						mode,
						progress,
						violations,
						age,
					)
				}
			}

			return table.Render(writer)
		},
	}

	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "List policies across all namespaces")
	cmd.Flags().StringVarP(&selector, "selector", "l", "", "Label selector to filter policies")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// NewPolicyGetCommand creates the policy get command
func NewPolicyGetCommand() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "get <policy-name>",
		Short: "Get a specific Pahlevan policy",
		Long:  "Get detailed information about a specific Pahlevan policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter(output)

			policyName := args[0]

			// Get the policy
			policy := &policyv1alpha1.PahlevanPolicy{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      policyName,
				Namespace: namespace,
			}, policy)
			if err != nil {
				return fmt.Errorf("failed to get policy %s: %v", policyName, err)
			}

			return writer.WriteObject(policy)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "yaml", "Output format (json, yaml)")

	return cmd
}

// NewPolicyDescribeCommand creates the policy describe command
func NewPolicyDescribeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe <policy-name>",
		Short: "Describe a Pahlevan policy",
		Long:  "Show detailed information about a Pahlevan policy including status and events.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, kubeClient, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			policyName := args[0]

			// Get the policy
			policy := &policyv1alpha1.PahlevanPolicy{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      policyName,
				Namespace: namespace,
			}, policy)
			if err != nil {
				return fmt.Errorf("failed to get policy %s: %v", policyName, err)
			}

			// Print policy details
			fmt.Fprintf(writer.Writer, "Name:\t\t%s\n", policy.Name)
			fmt.Fprintf(writer.Writer, "Namespace:\t%s\n", policy.Namespace)
			fmt.Fprintf(writer.Writer, "Labels:\t\t%s\n", formatLabels(policy.Labels))
			fmt.Fprintf(writer.Writer, "Annotations:\t%s\n", formatAnnotations(policy.Annotations))
			fmt.Fprintf(writer.Writer, "Created:\t%s\n", cli.FormatTimestamp(policy.CreationTimestamp.Time))
			fmt.Fprintf(writer.Writer, "\n")

			// Spec section
			fmt.Fprintf(writer.Writer, "Spec:\n")
			fmt.Fprintf(writer.Writer, "  Selector:\n")
			if len(policy.Spec.Selector.MatchLabels) > 0 {
				fmt.Fprintf(writer.Writer, "    Match Labels:\t%s\n", formatLabels(policy.Spec.Selector.MatchLabels))
			}
			if len(policy.Spec.Selector.MatchExpressions) > 0 {
				fmt.Fprintf(writer.Writer, "    Match Expressions:\t%d expressions\n", len(policy.Spec.Selector.MatchExpressions))
			}
			fmt.Fprintf(writer.Writer, "  Learning Config:\n")
			fmt.Fprintf(writer.Writer, "    Duration:\t\t%s\n", policy.Spec.LearningConfig.Duration)
			fmt.Fprintf(writer.Writer, "    Auto Transition:\t%t\n", policy.Spec.LearningConfig.AutoTransition)
			fmt.Fprintf(writer.Writer, "    Lifecycle Aware:\t%t\n", policy.Spec.LearningConfig.LifecycleAware)
			fmt.Fprintf(writer.Writer, "  Enforcement Config:\n")
			fmt.Fprintf(writer.Writer, "    Mode:\t\t%s\n", policy.Spec.EnforcementConfig.Mode)
			fmt.Fprintf(writer.Writer, "    Block Unknown:\t%t\n", policy.Spec.EnforcementConfig.BlockUnknown)
			fmt.Fprintf(writer.Writer, "\n")

			// Status section
			fmt.Fprintf(writer.Writer, "Status:\n")
			fmt.Fprintf(writer.Writer, "  Phase:\t\t%s\n", cli.ColorizeStatus(string(policy.Status.Phase)))
			// Skip observed generation - field doesn't exist in current status type

			// Skip learning progress - field doesn't exist in current status type

			// Skip enforcement status - fields don't exist in current status type

			if policy.Status.AttackSurface != nil {
				fmt.Fprintf(writer.Writer, "  Attack Surface:\n")
				fmt.Fprintf(writer.Writer, "    Risk Score:\t\t%s\n", formatRiskScore(policy.Status.AttackSurface.RiskScore))
				fmt.Fprintf(writer.Writer, "    Exposed Syscalls:\t%s\n", cli.FormatList(policy.Status.AttackSurface.ExposedSyscalls))
				fmt.Fprintf(writer.Writer, "    Exposed Ports:\t%s\n", formatPorts(policy.Status.AttackSurface.ExposedPorts))
				fmt.Fprintf(writer.Writer, "    Writable Files:\t%s\n", cli.FormatList(policy.Status.AttackSurface.WritableFiles))
				fmt.Fprintf(writer.Writer, "    Capabilities:\t%s\n", cli.FormatList(policy.Status.AttackSurface.Capabilities))
			}

			// Conditions
			if len(policy.Status.Conditions) > 0 {
				fmt.Fprintf(writer.Writer, "\nConditions:\n")
				table := cli.NewTableData("TYPE", "STATUS", "LAST TRANSITION", "REASON", "MESSAGE")
				for _, condition := range policy.Status.Conditions {
					table.AddRow(
						string(condition.Type),
						string(condition.Status),
						cli.FormatTimestamp(condition.LastTransitionTime.Time),
						condition.Reason,
						cli.TruncateString(condition.Message, 50),
					)
				}
				_ = table.Render(writer)
			}

			// TODO: Implement events listing when kubeClient type is fixed
			_ = namespace
			_ = kubeClient

			return nil
		},
	}

	return cmd
}

// NewPolicyCreateCommand creates the policy create command
func NewPolicyCreateCommand() *cobra.Command {
	var (
		filename        string
		learningTime    string
		enforcementMode string
		selector        string
		dryRun          bool
	)

	cmd := &cobra.Command{
		Use:   "create [flags]",
		Short: "Create a Pahlevan policy",
		Long:  "Create a new Pahlevan policy from file or command line options.",
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			var policy *policyv1alpha1.PahlevanPolicy
			var err error

			if filename != "" {
				// Create policy from file
				policy, err = createPolicyFromFile(filename)
				if err != nil {
					return fmt.Errorf("failed to create policy from file: %v", err)
				}
			} else {
				// Create policy from command line flags
				policy, err = createPolicyFromFlags(learningTime, enforcementMode, selector, namespace)
				if err != nil {
					return fmt.Errorf("failed to create policy from flags: %v", err)
				}
			}

			// Set namespace if not specified in policy
			if policy.Namespace == "" {
				policy.Namespace = namespace
			}

			// Validate the policy
			if err := validatePolicy(policy); err != nil {
				return fmt.Errorf("policy validation failed: %v", err)
			}

			if dryRun {
				writer.PrintInfo("Dry run: Policy would be created")
				return writer.WriteObject(policy)
			}

			// Create the policy in the cluster
			if err := k8sClient.Create(context.Background(), policy); err != nil {
				return fmt.Errorf("failed to create policy: %v", err)
			}

			writer.PrintSuccess(fmt.Sprintf("Policy %s/%s created", policy.Namespace, policy.Name))
			return nil
		},
	}

	cmd.Flags().StringVarP(&filename, "filename", "f", "", "File containing the policy definition")
	cmd.Flags().StringVar(&learningTime, "learning-time", "5m", "Learning duration")
	cmd.Flags().StringVar(&enforcementMode, "enforcement-mode", "Monitoring", "Enforcement mode (Off, Monitoring, Blocking)")
	cmd.Flags().StringVarP(&selector, "selector", "l", "", "Label selector for workloads")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Perform a dry run without creating the policy")

	return cmd
}

// NewPolicyDeleteCommand creates the policy delete command
func NewPolicyDeleteCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <policy-name>",
		Short: "Delete a Pahlevan policy",
		Long:  "Delete a Pahlevan policy from the cluster.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			policyName := args[0]

			// Get the policy first
			policy := &policyv1alpha1.PahlevanPolicy{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      policyName,
				Namespace: namespace,
			}, policy)
			if err != nil {
				return fmt.Errorf("failed to get policy %s: %v", policyName, err)
			}

			// Delete the policy
			if err := k8sClient.Delete(context.Background(), policy); err != nil {
				return fmt.Errorf("failed to delete policy %s: %v", policyName, err)
			}

			writer.PrintSuccess(fmt.Sprintf("Policy %s deleted", policyName))
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Force delete without confirmation")

	return cmd
}

// NewPolicyUpdateCommand creates the policy update command
func NewPolicyUpdateCommand() *cobra.Command {
	var (
		learningTime    string
		enforcementMode string
		blockUnknown    bool
		autoTransition  bool
		lifecycleAware  bool
	)

	cmd := &cobra.Command{
		Use:   "update <policy-name>",
		Short: "Update a Pahlevan policy",
		Long:  "Update an existing Pahlevan policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			policyName := args[0]

			// Get the existing policy
			policy := &policyv1alpha1.PahlevanPolicy{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      policyName,
				Namespace: namespace,
			}, policy)
			if err != nil {
				return fmt.Errorf("failed to get policy %s: %v", policyName, err)
			}

			// Update fields if flags were provided
			updated := false

			if cmd.Flags().Changed("learning-time") {
				duration, err := parseDuration(learningTime)
				if err != nil {
					return fmt.Errorf("invalid learning time: %v", err)
				}
				policy.Spec.LearningConfig.Duration = duration
				updated = true
			}

			if cmd.Flags().Changed("enforcement-mode") {
				mode, err := parseEnforcementMode(enforcementMode)
				if err != nil {
					return fmt.Errorf("invalid enforcement mode: %v", err)
				}
				policy.Spec.EnforcementConfig.Mode = mode
				updated = true
			}

			if cmd.Flags().Changed("block-unknown") {
				policy.Spec.EnforcementConfig.BlockUnknown = blockUnknown
				updated = true
			}

			if cmd.Flags().Changed("auto-transition") {
				policy.Spec.LearningConfig.AutoTransition = autoTransition
				updated = true
			}

			if cmd.Flags().Changed("lifecycle-aware") {
				policy.Spec.LearningConfig.LifecycleAware = lifecycleAware
				updated = true
			}

			if !updated {
				writer.PrintInfo("No changes specified. Use flags to specify what to update.")
				return nil
			}

			// Update the policy
			if err := k8sClient.Update(context.Background(), policy); err != nil {
				return fmt.Errorf("failed to update policy %s: %v", policyName, err)
			}

			writer.PrintSuccess(fmt.Sprintf("Policy %s updated", policyName))
			return nil
		},
	}

	cmd.Flags().StringVar(&learningTime, "learning-time", "", "Learning duration")
	cmd.Flags().StringVar(&enforcementMode, "enforcement-mode", "", "Enforcement mode (Off, Monitoring, Blocking)")
	cmd.Flags().BoolVar(&blockUnknown, "block-unknown", false, "Block unknown behavior")
	cmd.Flags().BoolVar(&autoTransition, "auto-transition", false, "Enable automatic transition")
	cmd.Flags().BoolVar(&lifecycleAware, "lifecycle-aware", false, "Enable lifecycle awareness")

	return cmd
}

// NewPolicyStatusCommand creates the policy status command
func NewPolicyStatusCommand() *cobra.Command {
	var watch bool

	cmd := &cobra.Command{
		Use:   "status <policy-name>",
		Short: "Show policy status",
		Long:  "Show the current status and progress of a Pahlevan policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, _, _, namespace, _ := GetClients()
			writer := cli.NewOutputWriter("table")

			policyName := args[0]

			if watch {
				return watchPolicyStatus(k8sClient, policyName, namespace, writer)
			}

			// Get the policy
			policy := &policyv1alpha1.PahlevanPolicy{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      policyName,
				Namespace: namespace,
			}, policy)
			if err != nil {
				return fmt.Errorf("failed to get policy %s: %v", policyName, err)
			}

			// Display status information
			fmt.Fprintf(writer.Writer, "Policy: %s/%s\n", policy.Namespace, policy.Name)
			fmt.Fprintf(writer.Writer, "Phase: %s\n", cli.ColorizeStatus(string(policy.Status.Phase)))

			// Skip learning progress - field doesn't exist in current status type

			// Skip enforcement status - fields don't exist in current status type

			return nil
		},
	}

	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Watch for changes")

	return cmd
}

// Helper functions

func formatProgress(policy *policyv1alpha1.PahlevanPolicy) string {
	// Skip learning progress - field doesn't exist in current status type
	return "N/A"
}

func formatViolations(policy *policyv1alpha1.PahlevanPolicy) string {
	// Skip violations count - field doesn't exist in current status type
	return "N/A"
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "<none>"
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}

func formatAnnotations(annotations map[string]string) string {
	if len(annotations) == 0 {
		return "<none>"
	}
	count := 0
	for range annotations {
		count++
	}
	return fmt.Sprintf("%d annotations", count)
}

func formatRiskScore(score *int32) string {
	if score == nil {
		return "<none>"
	}
	return fmt.Sprintf("%d", *score)
}

func formatPorts(ports []int32) string {
	if len(ports) == 0 {
		return "<none>"
	}
	var strPorts []string
	for _, port := range ports {
		strPorts = append(strPorts, fmt.Sprintf("%d", port))
	}
	return cli.FormatList(strPorts)
}

// GetClients returns the global clients - this would be imported from main
func GetClients() (client.Client, interface{}, interface{}, string, bool) {
	// This is a placeholder - in the real implementation, this would
	// import the GetClients function from the main package
	return nil, nil, nil, "default", false
}

// Helper functions for policy creation

func createPolicyFromFile(filename string) (*policyv1alpha1.PahlevanPolicy, error) {
	// This would read and parse a YAML/JSON file
	// For now, return a basic error
	return nil, fmt.Errorf("policy creation from file not yet implemented")
}

func createPolicyFromFlags(learningTime, enforcementMode, selector, namespace string) (*policyv1alpha1.PahlevanPolicy, error) {
	// Parse learning duration
	duration, err := parseDuration(learningTime)
	if err != nil {
		return nil, fmt.Errorf("invalid learning time: %v", err)
	}

	// Parse enforcement mode
	mode, err := parseEnforcementMode(enforcementMode)
	if err != nil {
		return nil, fmt.Errorf("invalid enforcement mode: %v", err)
	}

	// Parse selector
	matchLabels, err := parseSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("invalid selector: %v", err)
	}

	// Generate a policy name if not provided
	policyName := fmt.Sprintf("pahlevan-policy-%d", getCurrentTimestamp())

	policy := &policyv1alpha1.PahlevanPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "policy.obsernetics.com/v1alpha1",
			Kind:       "PahlevanPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: namespace,
		},
		Spec: policyv1alpha1.PahlevanPolicySpec{
			Selector: policyv1alpha1.LabelSelector{
				MatchLabels: matchLabels,
			},
			LearningConfig: policyv1alpha1.LearningConfig{
				Duration:       duration,
				AutoTransition: true,
				LifecycleAware: true,
			},
			EnforcementConfig: policyv1alpha1.EnforcementConfig{
				Mode:         mode,
				BlockUnknown: mode == "Blocking",
			},
		},
	}

	return policy, nil
}

func validatePolicy(policy *policyv1alpha1.PahlevanPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if policy.Namespace == "" {
		return fmt.Errorf("policy namespace is required")
	}
	if policy.Spec.LearningConfig.Duration == nil {
		return fmt.Errorf("learning duration is required")
	}
	if policy.Spec.EnforcementConfig.Mode == "" {
		return fmt.Errorf("enforcement mode is required")
	}
	return nil
}

func getCurrentTimestamp() int64 {
	return 12345 // Placeholder timestamp
}

func watchPolicyStatus(k8sClient client.Client, policyName, namespace string, writer *cli.OutputWriter) error {
	writer.PrintInfo(fmt.Sprintf("Watching policy %s/%s for changes (Ctrl+C to stop)...", namespace, policyName))

	// This would implement watching using controller-runtime client
	// For now, just simulate with a simple loop
	for i := 0; i < 5; i++ {
		policy := &policyv1alpha1.PahlevanPolicy{}
		err := k8sClient.Get(context.Background(), types.NamespacedName{
			Name:      policyName,
			Namespace: namespace,
		}, policy)
		if err != nil {
			return fmt.Errorf("failed to get policy %s: %v", policyName, err)
		}

		fmt.Fprintf(writer.Writer, "[%s] Policy: %s/%s, Phase: %s\n",
			getCurrentTimeString(),
			policy.Namespace,
			policy.Name,
			cli.ColorizeStatus(string(policy.Status.Phase)))

		// In a real implementation, this would use a proper watch mechanism
		// time.Sleep(5 * time.Second)
		break // For now, just show one update
	}

	return nil
}

func getCurrentTimeString() string {
	return time.Now().Format("15:04:05")
}

// Helper functions for type conversions

func parseDuration(durationStr string) (*metav1.Duration, error) {
	if durationStr == "" {
		return nil, fmt.Errorf("duration cannot be empty")
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return nil, fmt.Errorf("invalid duration format: %v", err)
	}

	return &metav1.Duration{Duration: duration}, nil
}

func parseEnforcementMode(modeStr string) (policyv1alpha1.EnforcementMode, error) {
	switch strings.ToLower(modeStr) {
	case "off":
		return policyv1alpha1.EnforcementModeOff, nil
	case "monitoring":
		return policyv1alpha1.EnforcementModeMonitoring, nil
	case "blocking":
		return policyv1alpha1.EnforcementModeBlocking, nil
	default:
		return "", fmt.Errorf("invalid enforcement mode: %s (valid options: off, monitoring, blocking)", modeStr)
	}
}

func parseSelector(selectorStr string) (map[string]string, error) {
	if selectorStr == "" {
		return make(map[string]string), nil
	}

	matchLabels := make(map[string]string)
	pairs := strings.Split(selectorStr, ",")

	for _, pair := range pairs {
		kv := strings.Split(strings.TrimSpace(pair), "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid selector format: %s (expected key=value)", pair)
		}
		matchLabels[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	return matchLabels, nil
}
