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
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/obsernetics/pahlevan/pkg/cli"
)

// NewVersionCommand creates the version command
func NewVersionCommand(version, buildDate, gitCommit string) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display version information for the Pahlevan CLI and operator.",
		RunE: func(cmd *cobra.Command, args []string) error {
			writer := cli.NewOutputWriter(output)

			versionInfo := map[string]interface{}{
				"version":   version,
				"buildDate": buildDate,
				"gitCommit": gitCommit,
				"goVersion": runtime.Version(),
				"compiler":  runtime.Compiler,
				"platform":  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			}

			if output == "json" || output == "yaml" {
				return writer.WriteObject(versionInfo)
			}

			// Table format
			fmt.Fprintf(writer.Writer, "Pahlevan CLI Version Information:\n")
			fmt.Fprintf(writer.Writer, "  Version:\t%s\n", version)
			fmt.Fprintf(writer.Writer, "  Build Date:\t%s\n", buildDate)
			fmt.Fprintf(writer.Writer, "  Git Commit:\t%s\n", gitCommit)
			fmt.Fprintf(writer.Writer, "  Go Version:\t%s\n", runtime.Version())
			fmt.Fprintf(writer.Writer, "  Compiler:\t%s\n", runtime.Compiler)
			fmt.Fprintf(writer.Writer, "  Platform:\t%s/%s\n", runtime.GOOS, runtime.GOARCH)

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// NewCompletionCommand creates the completion command
func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `Generate shell completion scripts for Pahlevan CLI.

To load completions:

Bash:
  $ source <(pahlevan completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ pahlevan completion bash > /etc/bash_completion.d/pahlevan
  # macOS:
  $ pahlevan completion bash > /usr/local/etc/bash_completion.d/pahlevan

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ pahlevan completion zsh > "${fpath[1]}/_pahlevan"

  # You will need to start a new shell for this setup to take effect.

fish:
  $ pahlevan completion fish | source

  # To load completions for each session, execute once:
  $ pahlevan completion fish > ~/.config/fish/completions/pahlevan.fish

PowerShell:
  PS> pahlevan completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> pahlevan completion powershell > pahlevan.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				_ = cmd.Root().GenBashCompletion(cmd.OutOrStdout()) //nolint:errcheck // Completion errors are not critical
			case "zsh":
				_ = cmd.Root().GenZshCompletion(cmd.OutOrStdout()) //nolint:errcheck // Completion errors are not critical
			case "fish":
				_ = cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true) //nolint:errcheck // Completion errors are not critical
			case "powershell":
				_ = cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout()) //nolint:errcheck // Completion errors are not critical
			}
		},
	}

	return cmd
}
