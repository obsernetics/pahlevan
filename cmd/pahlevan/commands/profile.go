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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// NewProfileCommand exposes the seccomp profiles the agents generate from what
// each container was observed to do.
//
// The agents write these to a node-local directory and, until now, said nothing
// about where. A pod's seccompProfile cannot be changed after admission and the
// operator deliberately runs without a mutating webhook, so applying a profile
// is necessarily the operator's action on the next rollout. This command is
// what makes that action possible without knowing the agent's flags or going
// looking on a node.
func NewProfileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect the seccomp profiles generated from learned behaviour",
		Long: `Inspect the seccomp profiles Pahlevan generates from each container's
learned syscall set.

A profile is written by the agent on the node where the container ran, and is
reported on the container's ContainerProfile. Because a pod's seccompProfile
cannot be changed after admission, applying one is a change you make to the
workload and roll out; "pahlevan profile patch" prints exactly that change.`,
	}
	cmd.AddCommand(
		newProfileListCommand(),
		newProfileGetCommand(),
		newProfilePatchCommand(),
	)
	return cmd
}

// profileRow is one container's generated profile, flattened for output.
type profileRow struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Pod              string `json:"pod,omitempty"`
	Node             string `json:"node,omitempty"`
	Phase            string `json:"phase,omitempty"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
	Path             string `json:"path,omitempty"`
	Allowed          int32  `json:"allowedSyscalls"`
	Total            int32  `json:"totalSyscalls"`
	SkippedUnknown   int32  `json:"skippedUnknown,omitempty"`
	// ReductionPercent is the share of the syscall table the profile denies.
	// This is the number that justifies applying it.
	ReductionPercent float64 `json:"reductionPercent"`
}

func collectProfiles(ctx context.Context, c client.Client, namespace string, allNamespaces bool) ([]profileRow, error) {
	var list policyv1alpha1.ContainerProfileList
	var opts []client.ListOption
	if !allNamespaces && namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := c.List(ctx, &list, opts...); err != nil {
		return nil, fmt.Errorf("listing container profiles: %w", err)
	}

	rows := make([]profileRow, 0, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		s := p.Status.Seccomp
		if s == nil {
			// A container with no generated profile has nothing to show here.
			// It means the agent was started without --seccomp-dir, or the
			// container has not reached enforcement yet.
			continue
		}
		row := profileRow{
			Namespace:        p.Namespace,
			Name:             p.Name,
			Pod:              p.Spec.PodName,
			Node:             s.Node,
			Phase:            p.Status.Phase,
			LocalhostProfile: s.LocalhostProfile,
			Path:             s.Path,
			Allowed:          s.AllowedSyscalls,
			Total:            s.TotalSyscalls,
			SkippedUnknown:   s.SkippedUnknown,
		}
		if s.TotalSyscalls > 0 {
			row.ReductionPercent = 100 * (1 - float64(s.AllowedSyscalls)/float64(s.TotalSyscalls))
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, nil
}

func newProfileListCommand() *cobra.Command {
	var (
		namespace     string
		allNamespaces bool
		output        string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List generated seccomp profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, _, defaultNS, ok := GetClients()
			if !ok {
				return fmt.Errorf("no Kubernetes client: check your kubeconfig")
			}
			if namespace == "" {
				namespace = defaultNS
			}
			rows, err := collectProfiles(cmd.Context(), c, namespace, allNamespaces)
			if err != nil {
				return err
			}

			w := cli.NewOutputWriter(output)
			w.Writer = cmd.OutOrStdout()

			if len(rows) == 0 {
				// Say why it is empty. "No resources found" sends people
				// looking in the wrong place.
				fmt.Fprintln(cmd.OutOrStdout(),
					"No generated seccomp profiles.\n\n"+
						"Profiles are written when a container transitions to enforcing, and only\n"+
						"if the agent was started with --seccomp-dir. Check `pahlevan status` for\n"+
						"whether any container has reached enforcement.")
				return nil
			}

			switch strings.ToLower(output) {
			case "json", "yaml":
				return w.WriteObject(rows)
			}

			table := make([][]string, 0, len(rows))
			for _, r := range rows {
				profile := r.LocalhostProfile
				if profile == "" {
					// Outside the kubelet's seccomp root, so it cannot be
					// referenced as-is. Say so rather than print a blank.
					profile = "(outside kubelet seccomp root)"
				}
				table = append(table, []string{
					r.Namespace, r.Name, r.Node, r.Phase,
					fmt.Sprintf("%d/%d", r.Allowed, r.Total),
					fmt.Sprintf("%.1f%%", r.ReductionPercent),
					profile,
				})
			}
			return w.WriteTable(
				[]string{"NAMESPACE", "NAME", "NODE", "PHASE", "ALLOWED", "REDUCTION", "LOCALHOST PROFILE"},
				table)
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to list")
	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "List across all namespaces")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml)")
	return cmd
}

func newProfileGetCommand() *cobra.Command {
	var (
		namespace string
		output    string
	)
	cmd := &cobra.Command{
		Use:   "get <container-profile>",
		Short: "Show the generated profile for one container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, _, defaultNS, ok := GetClients()
			if !ok {
				return fmt.Errorf("no Kubernetes client: check your kubeconfig")
			}
			if namespace == "" {
				namespace = defaultNS
			}

			var p policyv1alpha1.ContainerProfile
			if err := c.Get(cmd.Context(), client.ObjectKey{Namespace: namespace, Name: args[0]}, &p); err != nil {
				return fmt.Errorf("getting container profile %s/%s: %w", namespace, args[0], err)
			}
			if p.Status.Seccomp == nil {
				return fmt.Errorf("container profile %s/%s has no generated seccomp profile; "+
					"it is in phase %q and the agent needs --seccomp-dir to emit one",
					namespace, args[0], p.Status.Phase)
			}

			w := cli.NewOutputWriter(output)
			w.Writer = cmd.OutOrStdout()
			return w.WriteObject(p.Status.Seccomp)
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the container profile")
	cmd.Flags().StringVarP(&output, "output", "o", "yaml", "Output format (json, yaml)")
	return cmd
}

// SeccompPatch is the securityContext change that applies a generated profile.
type SeccompPatch struct {
	Spec struct {
		Template struct {
			Spec struct {
				SecurityContext struct {
					SeccompProfile struct {
						Type             string `json:"type"`
						LocalhostProfile string `json:"localhostProfile"`
					} `json:"seccompProfile"`
				} `json:"securityContext"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// BuildSeccompPatch renders the strategic-merge patch that points a workload at
// a generated profile.
func BuildSeccompPatch(localhostProfile string) SeccompPatch {
	var p SeccompPatch
	p.Spec.Template.Spec.SecurityContext.SeccompProfile.Type = "Localhost"
	p.Spec.Template.Spec.SecurityContext.SeccompProfile.LocalhostProfile = localhostProfile
	return p
}

func newProfilePatchCommand() *cobra.Command {
	var (
		namespace string
		output    string
	)
	cmd := &cobra.Command{
		Use:   "patch <container-profile>",
		Short: "Print the workload patch that applies a generated profile",
		Long: `Print the securityContext patch that points a workload at its generated
seccomp profile.

Nothing is applied. A pod's seccompProfile cannot be changed after admission, so
this is a change to the workload's pod template that takes effect on the next
rollout, and it is deliberately yours to review and apply.

Two things to check before you do. The profile file lives on the node that wrote
it, so every node that can schedule the workload needs a copy. And the profile
only permits what the container was observed doing during its learning window;
a code path that did not run in that window will be denied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, _, defaultNS, ok := GetClients()
			if !ok {
				return fmt.Errorf("no Kubernetes client: check your kubeconfig")
			}
			if namespace == "" {
				namespace = defaultNS
			}

			var p policyv1alpha1.ContainerProfile
			if err := c.Get(cmd.Context(), client.ObjectKey{Namespace: namespace, Name: args[0]}, &p); err != nil {
				return fmt.Errorf("getting container profile %s/%s: %w", namespace, args[0], err)
			}
			s := p.Status.Seccomp
			if s == nil {
				return fmt.Errorf("container profile %s/%s has no generated seccomp profile", namespace, args[0])
			}
			if s.LocalhostProfile == "" {
				return fmt.Errorf("the profile for %s/%s is at %q, which is outside the kubelet's "+
					"seccomp root, so it cannot be referenced as a localhostProfile. Start the "+
					"agent with --seccomp-dir under --seccomp-root",
					namespace, args[0], s.Path)
			}

			patch := BuildSeccompPatch(s.LocalhostProfile)
			var data []byte
			var err error
			if strings.EqualFold(output, "json") {
				data, err = json.MarshalIndent(patch, "", "  ")
			} else {
				data, err = yaml.Marshal(patch)
			}
			if err != nil {
				return fmt.Errorf("rendering patch: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "# Generated from %s/%s on node %s.\n", namespace, args[0], s.Node)
			fmt.Fprintf(out, "# Allows %d of %d syscalls (%.1f%% of the table denied).\n",
				s.AllowedSyscalls, s.TotalSyscalls,
				100*(1-float64(s.AllowedSyscalls)/float64(max32(s.TotalSyscalls, 1))))
			if s.SkippedUnknown > 0 {
				fmt.Fprintf(out, "# %d observed syscall numbers have no name on this architecture "+
					"and are NOT in the profile.\n", s.SkippedUnknown)
			}
			fmt.Fprintf(out, "# The file lives on %s only; copy it to every node that can run this workload.\n", s.Node)
			fmt.Fprintln(out, "#")
			fmt.Fprintf(out, "# kubectl -n %s patch deployment <name> --patch-file <this file>\n", namespace)
			fmt.Fprintln(out, "")
			_, err = out.Write(data)
			return err
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the container profile")
	cmd.Flags().StringVarP(&output, "output", "o", "yaml", "Patch format (yaml, json)")
	return cmd
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
