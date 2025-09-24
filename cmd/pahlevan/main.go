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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/obsernetics/pahlevan/cmd/pahlevan/commands"
	"github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

func main() {
	ctx := context.Background()

	// Create root command
	rootCmd := NewRootCommand()

	// Execute command
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// NewRootCommand creates the root command for the Pahlevan CLI
func NewRootCommand() *cobra.Command {
	var (
		output  string
		verbose bool
	)

	// Create Kubernetes configuration flags
	configFlags := genericclioptions.NewConfigFlags(true)

	cmd := &cobra.Command{
		Use:   "pahlevan",
		Short: "Pahlevan CLI - eBPF-based Kubernetes Security Operator",
		Long: `Pahlevan CLI provides command-line interface for managing eBPF-based Kubernetes security policies.

The Pahlevan operator provides proactive attack surface minimization through adaptive learning,
enforcement, and real-time monitoring of container behavior using eBPF technology.`,
		Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildDate, gitCommit),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Initialize global configuration using configFlags
			kubeconfig := ""
			if configFlags.KubeConfig != nil && *configFlags.KubeConfig != "" {
				kubeconfig = *configFlags.KubeConfig
			}
			namespace := ""
			if configFlags.Namespace != nil && *configFlags.Namespace != "" {
				namespace = *configFlags.Namespace
			}
			return initializeClients(kubeconfig, namespace, verbose)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	flags := cmd.PersistentFlags()
	flags.StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml)")
	flags.BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add Kubernetes configuration flags (includes kubeconfig and namespace)
	configFlags.AddFlags(flags)

	// Add subcommands
	cmd.AddCommand(
		commands.NewPolicyCommand(),
		commands.NewAttackSurfaceCommand(),
		commands.NewStatusCommand(),
		commands.NewLogsCommand(),
		commands.NewMetricsCommand(),
		commands.NewDebugCommand(),
		commands.NewCompletionCommand(),
		commands.NewVersionCommand(version, buildDate, gitCommit),
	)

	return cmd
}

// Global variables for shared clients
var (
	k8sClient       client.Client
	kubeClient      kubernetes.Interface
	restConfig      *rest.Config
	globalNamespace string
	globalVerbose   bool
)

// initializeClients initializes Kubernetes clients and global configuration
func initializeClients(kubeconfig, namespace string, verbose bool) error {
	// Store global configuration
	globalNamespace = namespace
	globalVerbose = verbose

	// Get Kubernetes config
	var err error
	if kubeconfig != "" {
		restConfig, err = config.GetConfigWithContext(kubeconfig)
	} else {
		restConfig, err = config.GetConfig()
	}
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes config: %v", err)
	}

	// Create controller-runtime client
	scheme := cli.GetScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("failed to add Pahlevan scheme: %v", err)
	}

	k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	// Create standard Kubernetes client
	kubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %v", err)
	}

	// Set default namespace if not provided
	if globalNamespace == "" {
		globalNamespace = "default"
	}

	return nil
}

// GetClients returns the initialized clients
func GetClients() (client.Client, kubernetes.Interface, *rest.Config, string, bool) {
	return k8sClient, kubeClient, restConfig, globalNamespace, globalVerbose
}
