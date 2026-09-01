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
	"strings"

	"github.com/spf13/cobra"

	"github.com/obsernetics/pahlevan/pkg/cli"
	"github.com/obsernetics/pahlevan/pkg/coverage"
)

// NewCoverageCommand creates the coverage command.
//
// ROADMAP.md used to have no way to answer "what does this cover" short of
// reading bpf/*.c one file at a time. This prints Pahlevan's own mapping of
// its seven eBPF programs to the MITRE ATT&CK techniques their observations
// can help an analyst confirm or rule out - not a claim that the technique is
// blocked, and not an official MITRE mapping.
func NewCoverageCommand() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show what Pahlevan's eBPF detectors observe, mapped to MITRE ATT&CK",
		Long: `Print Pahlevan's seven eBPF detectors, the kernel hook each attaches to, and
the MITRE ATT&CK techniques their observations can help an analyst confirm or
rule out.

This is Pahlevan's own reading of what each detector's data is useful for,
not an official MITRE mapping: a listed technique means the detector's
allow-set decisions and event fields give an analyst evidence for that
technique, not that the technique is blocked. See https://attack.mitre.org
for the authoritative technique definitions.

Reads nothing but the binary's own compiled-in table - no cluster required.`,
		Example: `  # The full table.
  pahlevan coverage

  # Machine-readable, for scripting against.
  pahlevan coverage -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCoverage(cmd, output)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml)")

	// Reads only the table compiled into this binary.
	return Offline(cmd)
}

func runCoverage(cmd *cobra.Command, output string) error {
	if err := validateOutputFormat(output, "table", "json", "yaml"); err != nil {
		return err
	}

	writer := cli.NewOutputWriter(output)
	writer.Writer = cmd.OutOrStdout()

	switch output {
	case "json", "yaml":
		return writer.WriteObject(coverage.Table)
	default:
		headers := []string{"DETECTOR", "HOOK", "NEEDS LSM", "TECHNIQUES"}
		rows := make([][]string, 0, len(coverage.Table))
		for _, e := range coverage.Table {
			ids := make([]string, 0, len(e.Techniques))
			for _, t := range e.Techniques {
				ids = append(ids, t.ID)
			}
			rows = append(rows, []string{
				string(e.Detector), e.Hook, fmt.Sprintf("%t", e.NeedsLSM), strings.Join(ids, ", "),
			})
		}
		if err := writer.WriteTable(headers, rows); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d technique(s) across %d detector(s). Details: pahlevan coverage -o json\n",
			len(coverage.Techniques()), len(coverage.Table))
		return nil
	}
}
