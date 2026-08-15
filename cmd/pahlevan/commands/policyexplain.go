package commands

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	"github.com/obsernetics/pahlevan/internal/policy"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// `pahlevan policy explain` answers a question the tool previously made you
// find out the hard way: what does this policy actually do?
//
// A PahlevanPolicy is not applied literally. It is translated into the
// decision the agent acts on, and parts of it cannot be represented at all -
// an ingress rule, a CIDR too wide to enumerate, a glob, a DNS name. Those are
// reported as warnings on the policy's status, which means the author finds out
// after applying to a cluster, running `kubectl describe`, and knowing to look.
//
// Worse, the API server prunes fields the CRD does not have rather than
// rejecting them, so a policy with a misspelled key applies cleanly and does
// less than it says. Neither failure produces an error anywhere the author is
// looking.
//
// This runs the same translation offline, against a file, and prints both the
// result and every warning. No cluster, no apply.

func newPolicyExplainCommand() *cobra.Command {
	var (
		filename string
		strict   bool
	)

	cmd := &cobra.Command{
		Use:   "explain -f POLICY.yaml",
		Short: "Show what a policy translates to, and what it cannot express",
		Long: `Translate a PahlevanPolicy offline and print the result.

A policy is not enforced literally. It becomes a decision the agent acts on,
and anything the data plane cannot represent is dropped with a warning - an
ingress rule, a CIDR wider than a host, a glob, a DNS name, a port range past
1024 entries. Normally those warnings land on the policy's status, so the
author sees them only after applying to a cluster and knowing to look.

This shows them against a file, before anything is applied.`,
		Example: `  # What will this policy actually enforce?
  pahlevan policy explain -f examples/policies/web-application.yaml

  # Fail if the policy contains anything unrepresentable (for CI).
  pahlevan policy explain -f policy.yaml --strict`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyExplain(cmd.OutOrStdout(), filename, strict)
		},
	}

	cmd.Flags().StringVarP(&filename, "filename", "f", "", "policy file to explain (required)")
	cmd.Flags().BoolVar(&strict, "strict", false,
		"exit non-zero if any part of the policy cannot be enforced")
	_ = cmd.MarkFlagRequired("filename")
	// Reads a file and computes an answer. Needing a cluster to explain a
	// policy would make it useless in CI and useless while writing one.
	return Offline(cmd)
}

func runPolicyExplain(out io.Writer, filename string, strict bool) error {
	data, err := os.ReadFile(filename) // #nosec G304 -- reading the file the operator named is the point
	if err != nil {
		return fmt.Errorf("reading %s: %w", filename, err)
	}

	docs := splitYAMLDocuments(data)
	if len(docs) == 0 {
		return fmt.Errorf("%s contains no YAML documents", filename)
	}

	total, unrepresentable := 0, 0
	for _, doc := range docs {
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal(doc, &probe); err != nil {
			return fmt.Errorf("%s: %w", filename, err)
		}
		if probe.Kind != "PahlevanPolicy" {
			continue
		}

		var p policyv1alpha1.PahlevanPolicy
		// Strict, so a field the CRD does not have is an error here rather
		// than something the API server silently prunes on apply.
		if err := yaml.UnmarshalStrict(doc, &p); err != nil {
			// The trailing guidance matters more than the convention here: the
			// whole point is that this failure mode is otherwise invisible.
			fmt.Fprintf(out,
				"\nNote: a field the CRD does not have is not rejected by the API server -\n"+
					"it is pruned. This policy would apply cleanly and do less than it says.\n")
			return fmt.Errorf("%s: %w", filename, err)
		}

		total++
		n := explainOne(out, &p)
		unrepresentable += n
	}

	if total == 0 {
		return fmt.Errorf("%s contains no PahlevanPolicy documents", filename)
	}
	if strict && unrepresentable > 0 {
		return fmt.Errorf("%d part(s) of this policy cannot be enforced", unrepresentable)
	}
	return nil
}

// explainOne prints one policy and returns how many warnings it produced.
func explainOne(out io.Writer, p *policyv1alpha1.PahlevanPolicy) int {
	d, warnings := policy.Translate(p.Name, p.Spec, time.Now())

	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	fmt.Fprintf(out, "%s\n%s\n\n", name, strings.Repeat("=", len(name)))

	fmt.Fprintf(out, "  mode              %s\n", modeDescription(d.Mode))
	fmt.Fprintf(out, "  learning window   %s\n", durationOrDefault(d.Window))
	fmt.Fprintf(out, "  grace period      %s\n", durationOrDefault(d.GracePeriod))
	if d.SelfHealing.Enabled {
		fmt.Fprintf(out, "  self-healing      after %d denials within %s, return to learning\n",
			d.SelfHealing.Threshold, durationOrDefault(d.SelfHealing.Window))
	} else {
		fmt.Fprintf(out, "  self-healing      off - a wrong baseline stays wrong\n")
	}
	fmt.Fprintln(out)

	o := d.Overrides
	if o.Empty() {
		fmt.Fprintf(out, "  No allow or deny lists: the enforced set is entirely what the\n"+
			"  workload is observed doing during the learning window.\n\n")
	} else {
		fmt.Fprintf(out, "  Written into the kernel allow-sets before enforcement begins:\n\n")
		printEntries(out, "allow  read", o.AllowedFiles)
		printEntries(out, "allow  write", o.AllowedWriteFiles)
		printEntries(out, "deny   read", o.DeniedFiles)
		printEntries(out, "deny   write", o.DeniedWriteFiles)
		printEntries(out, "allow  exec", o.AllowedExecs)
		printEntries(out, "deny   exec", o.DeniedExecs)
		printEntries(out, "allow  syscall", o.AllowedSyscalls)
		printEntries(out, "deny   syscall", o.DeniedSyscalls)
		printEntries(out, "allow  capability", capabilityNames(o.AllowedCapabilities))
		printEntries(out, "deny   capability", capabilityNames(o.DeniedCapabilities))
		printEntries(out, "allow  destination", destinationStrings(o.AllowedDestinations))
		printEntries(out, "deny   destination", destinationStrings(o.DeniedDestinations))

		if f := o.ProcFilter; !f.Empty() {
			fmt.Fprintf(out, "  Process filter (%s) - constrains who may exec, not what:\n",
				ebpf.FilterMaskString(f.Mask()))
			printEntries(out, "  parent", f.ParentProcesses)
			printEntries(out, "  uid", uintStrings(f.UIDs))
			printEntries(out, "  gid", uintStrings(f.GIDs))
		}
		fmt.Fprintln(out)
	}

	if len(warnings) == 0 {
		fmt.Fprintf(out, "  Every part of this policy can be enforced.\n\n")
		return 0
	}

	fmt.Fprintf(out, "  %d part(s) of this policy will NOT be enforced:\n\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(out, "    - %s\n", w)
	}
	fmt.Fprintf(out, "\n  These are dropped silently at runtime and reported on the policy's\n"+
		"  status. A policy with warnings is doing less than it says.\n\n")
	return len(warnings)
}

func printEntries(out io.Writer, label string, entries []string) {
	if len(entries) == 0 {
		return
	}
	sorted := append([]string(nil), entries...)
	sort.Strings(sorted)
	for _, e := range sorted {
		fmt.Fprintf(out, "    %-20s %s\n", label, e)
	}
}

func modeDescription(m adaptive.Mode) string {
	switch m {
	case adaptive.ModeBlocking:
		return "Blocking - unlearned behavior is denied in-kernel with EPERM"
	case adaptive.ModeMonitoring:
		return "Monitoring - denials are counted, nothing is blocked"
	case adaptive.ModeOff:
		return "Off - this policy governs nothing"
	default:
		return string(m)
	}
}

func durationOrDefault(d time.Duration) string {
	if d == 0 {
		return "(the agent's default)"
	}
	return d.String()
}

func capabilityNames(nums []uint32) []string {
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, fmt.Sprintf("%s (%d)", ebpf.CapabilityName(n), n))
	}
	return out
}

func destinationStrings(dests []adaptive.Destination) []string {
	out := make([]string, 0, len(dests))
	for _, d := range dests {
		out = append(out, fmt.Sprintf("%s:%d", d.IP, d.Port))
	}
	return out
}

func uintStrings(vals []uint32) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// splitYAMLDocuments splits on the document separator. A policy file commonly
// holds several, and explaining only the first would quietly ignore the rest.
func splitYAMLDocuments(data []byte) [][]byte {
	var docs [][]byte
	var cur []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimRight(line, " \t\r") == "---" {
			if doc := strings.TrimSpace(strings.Join(cur, "\n")); doc != "" {
				docs = append(docs, []byte(strings.Join(cur, "\n")))
			}
			cur = nil
			continue
		}
		cur = append(cur, line)
	}
	if doc := strings.TrimSpace(strings.Join(cur, "\n")); doc != "" {
		docs = append(docs, []byte(strings.Join(cur, "\n")))
	}
	return docs
}
