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

// Command groups, in the order they appear in help.
//
// The split is by the question being asked, not by implementation. "Is it
// running and what is it doing right now" (watch) and "what has it decided
// about my workloads" (inspect) are the two reasons anybody opens this tool,
// and they want different commands each time. An ungrouped list of twelve
// commands made a reader scan all twelve to find either one.
//
// debug sits in the watch group rather than with the analysis commands because
// that is what it reads: it is status, logs, metrics and events collected in
// one pass, and it shares the pod-discovery code in components.go with logs
// and metrics. Someone reaching for it has a deployment that is misbehaving,
// which is the same drawer they reached into for the others.
const (
	groupWatch   = "watch"
	groupInspect = "inspect"
	groupUtility = "utility"
)

// grouped stamps a group on each command, so the group is stated once next to
// the list rather than repeated inside every constructor. A command whose
// GroupID names no registered group makes cobra panic on execute, which the
// surface test catches before a user ever sees it.
func grouped(id string, cmds ...*cobra.Command) []*cobra.Command {
	for _, c := range cmds {
		c.GroupID = id
	}
	return cmds
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
enforcement, and real-time monitoring of container behavior using eBPF technology.

Run with no arguments in a terminal to open the interactive console. Piped or
redirected, the same invocation prints this help, so scripts keep working.`,
		Example: `  # Open the console (piped or redirected, this prints help instead)
  pahlevan

  # Is Pahlevan installed and healthy in this cluster?
  pahlevan status

  # What a policy file would actually enforce - no cluster needed
  pahlevan policy explain -f examples/policies/web-application.yaml`,
		Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildDate, gitCommit),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// The root itself either opens the console - which reads an
			// agent's event stream, never the API server - or prints help.
			// Demanding a kubeconfig for that would mean a bare `pahlevan` on
			// a laptop answers with a cluster error instead of showing the
			// tool. This is deliberately not the offline annotation: IsOffline
			// walks parents, so marking the root would exempt every
			// subcommand along with it.
			if !cmd.HasParent() {
				return nil
			}
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
			// --context is registered by genericclioptions like the other
			// kubectl flags, so it has to be forwarded or it is a flag that
			// appears in help and does nothing.
			kubeContext := ""
			if configFlags.Context != nil && *configFlags.Context != "" {
				kubeContext = *configFlags.Context
			}
			return commands.InitializeClients(kubeconfig, kubeContext, namespace, verbose)
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

	cmd.AddGroup(
		&cobra.Group{ID: groupWatch, Title: "Watch a running deployment:"},
		&cobra.Group{ID: groupInspect, Title: "Inspect policies and workloads:"},
		&cobra.Group{ID: groupUtility, Title: "Other commands:"},
	)
	// The help command is generated by cobra, so it has no group of its own
	// and would land under a stray "Additional Commands" heading below the
	// three real ones.
	cmd.SetHelpCommandGroupID(groupUtility)

	// The interactive view reads the agent's gRPC stream or a replay file
	// and never the API server, so it must not demand a kubeconfig: an
	// operator debugging a node should not need cluster credentials to
	// look at what that node's agent is reporting.
	uiCmd := commands.Offline(commands.NewUICommand())

	// Add subcommands
	cmd.AddCommand(grouped(groupWatch,
		uiCmd,
		commands.NewStatusCommand(),
		commands.NewEventsCommand(),
		commands.NewLogsCommand(),
		commands.NewMetricsCommand(),
		commands.NewDebugCommand(),
	)...)
	cmd.AddCommand(grouped(groupInspect,
		commands.NewPolicyCommand(),
		commands.NewProfileCommand(),
		commands.NewNetpolCommand(),
		commands.NewAttackSurfaceCommand(),
		commands.NewCoverageCommand(),
	)...)
	cmd.AddCommand(grouped(groupUtility,
		// Neither touches the cluster: one writes a shell script, the other
		// prints constants compiled into the binary.
		commands.Offline(commands.NewCompletionCommand()),
		commands.Offline(commands.NewVersionCommand(version, buildDate, gitCommit)),
	)...)

	// Running the tool shows the tool. Cobra leaves a root command with no Run
	// printing help, which is the right answer for a script and the wrong one
	// for a person.
	cmd.RunE = func(c *cobra.Command, args []string) error {
		return runRoot(c, args, uiCmd)
	}

	return cmd
}

// runRoot is what a bare `pahlevan` does: open the console for a person, print
// help for everything else.
func runRoot(cmd *cobra.Command, args []string, console *cobra.Command) error {
	if !opensConsole(cmd, args) {
		return cmd.Help()
	}
	// Reuse the ui command rather than a second copy of its wiring, so the
	// console a bare invocation opens cannot drift from `pahlevan ui`.
	console.SetContext(cmd.Context())
	return console.RunE(console, nil)
}

// opensConsole is the decision, split from runRoot so it can be tested without
// a pseudo-terminal.
//
// Two things have to be true. There must be nothing else on the command line:
// cobra rejects an unknown subcommand before RunE, but `pahlevan --namespace
// prod` reaches here, and it is a half-typed command line rather than a
// request to draw - swallowing it into a full-screen view loses what the user
// was in the middle of typing. And stdout must be a terminal, decided by the
// same commands.Interactive that `pahlevan ui` uses, so `pahlevan | head` and
// `pahlevan > file` keep printing help exactly as they do today.
func opensConsole(cmd *cobra.Command, args []string) bool {
	if len(args) > 0 || cmd.Flags().NFlag() > 0 {
		return false
	}
	return commands.Interactive(cmd.OutOrStdout())
}
