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

	"github.com/obsernetics/pahlevan/cmd/pahlevan/commands"
)

var (
	// Overridden at build time by the Dockerfile's -ldflags. The default is
	// "dev" rather than a version number: a binary built from a working tree
	// has no release identity, and one that claims v1.0.0 is lying to whoever
	// is trying to work out what they are running.
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
			// A command that reads a file or prints a constant must not need a
			// cluster. `pahlevan version` failing with "no configuration has
			// been provided" on a laptop is the first thing a new user sees,
			// and it says the tool is broken when it is not.
			if commands.IsOffline(cmd) {
				return nil
			}
			// Initialize global configuration using configFlags
			kubeconfig := ""
			if configFlags.KubeConfig != nil && *configFlags.KubeConfig != "" {
				kubeconfig = *configFlags.KubeConfig
			}
			namespace := ""
			if configFlags.Namespace != nil && *configFlags.Namespace != "" {
				namespace = *configFlags.Namespace
			}
			return commands.InitializeClients(kubeconfig, namespace, verbose)
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
		commands.NewProfileCommand(),
		commands.NewStatusCommand(),
		commands.NewEventsCommand(),
		commands.NewLogsCommand(),
		commands.NewMetricsCommand(),
		commands.NewDebugCommand(),
		// Neither touches the cluster: one writes a shell script, the other
		// prints constants compiled into the binary.
		commands.Offline(commands.NewCompletionCommand()),
		commands.Offline(commands.NewVersionCommand(version, buildDate, gitCommit)),
	)

	return cmd
}
