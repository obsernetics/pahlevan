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
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
	"github.com/obsernetics/pahlevan/pkg/cycle"
	"github.com/obsernetics/pahlevan/pkg/netpol"
)

// `pahlevan netpol` hands an operator the NetworkPolicy their learned baseline
// actually supports.
//
// Everything else in this tool reports. This is the one command whose output a
// person applies to a cluster, and a NetworkPolicy is not an additive control:
// the moment one selects a pod, every connection in a named direction that no
// rule permits is dropped. A generated policy that is one rule short does not
// degrade, it takes the workload down - and a generated policy that is one
// selector too wide silently permits traffic nobody ever watched.
//
// So this command prints and never applies, states that consequence before it
// states anything else, and refuses to write a selector it cannot justify
// against the pods in the namespace. See pkg/netpol.

// NewNetpolCommand creates the netpol command.
func NewNetpolCommand() *cobra.Command {
	var (
		namespace     string
		allNamespaces bool
		output        string
		direction     string
		showDiff      bool
		namePrefix    string
	)

	cmd := &cobra.Command{
		Use:   "netpol",
		Short: "Generate a Kubernetes NetworkPolicy from the traffic that was actually observed",
		Long: `Turn a learned network baseline into a networking.k8s.io/v1 NetworkPolicy.

Only what was observed becomes a rule. A destination that resolved to no
Kubernetes identity becomes an ipBlock, never an inferred selector. A label
set that would also select pods nobody watched is refused, and the pods that
made it unsafe are named, rather than being written into a policy that quietly
permits more than the evidence supports.

Read the consequences before applying anything. A NetworkPolicy is allow-only:
selecting a pod denies every connection in that direction no rule permits,
including connections that were working a second ago and connections that
happen less often than the learning window is long. This command prints; it
applies nothing.`,
		Example: `  # Review what the baseline supports, in the current namespace
  pahlevan netpol

  # Every namespace
  pahlevan netpol --all-namespaces

  # What would change against the policies already in the cluster
  pahlevan netpol --diff

  # The manifests alone, once the review is done
  pahlevan netpol -o yaml | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateOutputFormat(output, "report", "yaml", "json"); err != nil {
				return err
			}
			egress, ingress, err := parseDirection(direction)
			if err != nil {
				return err
			}

			c, _, _, defaultNS, ok := GetClients()
			if !ok || c == nil {
				return errClientsNotReady()
			}
			if namespace == "" {
				namespace = defaultNS
			}

			obs, roster, err := collectBaseline(cmd.Context(), c, namespace, allNamespaces)
			if err != nil {
				return err
			}
			res := netpol.Generate(obs, netpol.Options{
				Roster: roster,
				// Until pkg/netidentity is wired in this knows only what the
				// pod listing already said, so a Service ClusterIP, a node
				// address and an internet address all resolve to nothing and
				// become ipBlocks with a finding attached. That is the honest
				// answer from this input, and it is the single line that
				// changes when the identity index lands.
				Resolver:   netpol.NewRosterResolver(roster),
				Egress:     egress,
				Ingress:    ingress,
				NamePrefix: namePrefix,
			})

			return writeNetpol(cmd.Context(), cmd.OutOrStdout(), c, res, output, showDiff, len(obs))
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to read baselines from")
	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Read every namespace")
	cmd.Flags().StringVarP(&output, "output", "o", "report",
		"Output format (report, yaml, json). yaml prints the manifests alone")
	cmd.Flags().StringVar(&direction, "direction", "both", "Which directions to generate (both, egress, ingress)")
	cmd.Flags().BoolVar(&showDiff, "diff", false,
		"Show what applying this would change against the NetworkPolicies already in the cluster")
	cmd.Flags().StringVar(&namePrefix, "name-prefix", netpol.DefaultNamePrefix, "Prefix for generated policy names")

	return cmd
}

// parseDirection turns the flag into the pair pkg/netpol takes.
func parseDirection(s string) (egress, ingress bool, err error) {
	switch strings.ToLower(s) {
	case "both", "":
		return true, true, nil
	case "egress":
		return true, false, nil
	case "ingress":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid --direction %q: expected one of both, egress, ingress", s)
	}
}

// writeNetpol renders the result in the requested form.
//
// The default is the review rather than the manifests. The manifests are what
// somebody pipes into kubectl, and the whole argument of this command is that
// they should not be piped anywhere unread.
func writeNetpol(ctx context.Context, out io.Writer, c client.Client, res netpol.Result,
	output string, showDiff bool, subjects int,
) error {
	switch strings.ToLower(output) {
	case "yaml":
		b, err := res.YAML()
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err

	case "json":
		w := cli.NewOutputWriter("json")
		w.Writer = out
		return w.WriteObject(netpolJSON(res))
	}

	if subjects == 0 {
		fmt.Fprintln(out, "No learned network baseline to read.\n\n"+
			"A baseline is written once a container has been observed for a learning window.\n"+
			"Check `pahlevan profile list -A` for whether any container has one yet.")
		return nil
	}

	if err := res.Report(out); err != nil {
		return err
	}
	if !showDiff {
		return nil
	}

	changes, err := diffAgainstCluster(ctx, c, res)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nAgainst the NetworkPolicies already in the cluster:\n\n")
	_, err = io.WriteString(out, netpol.RenderChanges(changes))
	return err
}

// netpolResult is the machine-readable shape of a run, for -o json.
type netpolResult struct {
	Policies []networkingv1.NetworkPolicy `json:"policies"`
	Subjects []netpolSubject              `json:"subjects"`
}

type netpolSubject struct {
	Namespace string   `json:"namespace"`
	Workload  string   `json:"workload"`
	Policy    string   `json:"policy,omitempty"`
	Selector  string   `json:"selector,omitempty"`
	Observed  int      `json:"observedDestinations"`
	Expressed int      `json:"expressedDestinations"`
	Egress    int      `json:"egressRules"`
	Ingress   int      `json:"ingressRules"`
	Window    string   `json:"learningWindow,omitempty"`
	Capped    bool     `json:"learningWindowCapped,omitempty"`
	Findings  []string `json:"findings,omitempty"`
}

func netpolJSON(res netpol.Result) netpolResult {
	out := netpolResult{Policies: res.Policies}
	for _, s := range res.Subjects {
		row := netpolSubject{
			Namespace: s.Namespace,
			Workload:  s.Workload,
			Policy:    s.Policy,
			Observed:  s.Observed,
			Expressed: s.Expressed,
			Egress:    s.EgressRules,
			Ingress:   s.IngressRules,
			Capped:    s.Window.Capped(),
		}
		if s.Selector.OK() {
			row.Selector = s.Selector.String()
		}
		if s.Window.Window > 0 {
			row.Window = s.Window.Window.String()
		}
		for _, f := range s.Findings {
			row.Findings = append(row.Findings, f.Level.String()+": "+f.Message)
		}
		out.Subjects = append(out.Subjects, row)
	}
	return out
}

// diffAgainstCluster answers the question that the YAML alone cannot: what
// does applying this displace? A generated policy with the same name as one
// somebody wrote by hand replaces rules a human reasoned about with rules
// derived from one learning window, and nothing in the manifest says so.
func diffAgainstCluster(ctx context.Context, c client.Client, res netpol.Result) ([]netpol.Change, error) {
	changes := make([]netpol.Change, 0, len(res.Policies))
	for i := range res.Policies {
		p := &res.Policies[i]
		change := netpol.Change{Namespace: p.Namespace, Name: p.Name}

		var existing networkingv1.NetworkPolicy
		err := c.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, &existing)
		if err != nil {
			// Anything that is not "it is there" is treated as "it is not
			// there yet", because the alternative is failing the whole review
			// over one unreadable object.
			change.Created = true
			changes = append(changes, change)
			continue
		}

		// Compared as rendered manifests rather than as objects: the reviewer
		// is going to apply YAML, so the diff has to be in the thing they
		// will read. Server-set fields are stripped so a policy that is
		// materially identical does not diff on its resourceVersion.
		before, err := renderForDiff(&existing)
		if err != nil {
			return nil, err
		}
		after, err := renderForDiff(p)
		if err != nil {
			return nil, err
		}
		change.Lines = netpol.Diff(before, after)
		changes = append(changes, change)
	}
	return changes, nil
}

// renderForDiff strips the fields the API server owns, so a diff shows what
// the policy says and not when it was written.
func renderForDiff(p *networkingv1.NetworkPolicy) (string, error) {
	clean := p.DeepCopy()
	clean.APIVersion = "networking.k8s.io/v1"
	clean.Kind = "NetworkPolicy"
	clean.ResourceVersion = ""
	clean.UID = ""
	clean.Generation = 0
	clean.CreationTimestamp = metav1.Time{}
	clean.ManagedFields = nil
	clean.SelfLink = ""
	b, err := yaml.Marshal(clean)
	if err != nil {
		return "", fmt.Errorf("rendering %s/%s: %w", p.Namespace, p.Name, err)
	}
	return string(b), nil
}

// collectBaseline reads what the agents learned, and the pods that evidence
// has to be checked against.
func collectBaseline(ctx context.Context, c client.Client, namespace string, allNamespaces bool) (
	[]netpol.Observation, netpol.Roster, error,
) {
	var opts []client.ListOption
	if !allNamespaces && namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}

	var profiles policyv1alpha1.ContainerProfileList
	if err := c.List(ctx, &profiles, opts...); err != nil {
		return nil, nil, fmt.Errorf("listing container profiles: %w", err)
	}

	roster, err := buildRoster(ctx, c, opts)
	if err != nil {
		return nil, nil, err
	}

	obs := foldProfiles(ctx, c, profiles.Items)
	return obs, roster, nil
}

// foldProfiles collapses one ContainerProfile per container into one
// Observation per workload. A pod's containers share its network namespace, so
// their learned destinations are one workload's traffic and not several.
func foldProfiles(ctx context.Context, c client.Client, items []policyv1alpha1.ContainerProfile) []netpol.Observation {
	type acc struct {
		obs   netpol.Observation
		pods  map[string]bool
		dests map[netpol.Destination]bool
	}
	byWorkload := map[string]*acc{}
	var order []string

	windows := newWindowLookup(c)
	for i := range items {
		p := &items[i]
		ns, workload := workloadOf(p)
		if ns == "" || workload == "" {
			continue
		}
		key := ns + "/" + workload
		a, ok := byWorkload[key]
		if !ok {
			a = &acc{
				obs:   netpol.Observation{Namespace: ns, Workload: workload},
				pods:  map[string]bool{},
				dests: map[netpol.Destination]bool{},
			}
			byWorkload[key] = a
			order = append(order, key)
			a.obs.Window, a.obs.Schedule = windows.for_(ctx, p)
		}
		if p.Spec.PodName != "" {
			a.pods[p.Spec.PodName] = true
		}
		for _, raw := range p.Status.LearnedNetworkDestinations {
			if d, ok := parseDestination(raw); ok {
				a.dests[d] = true
			}
		}
	}

	sort.Strings(order)
	out := make([]netpol.Observation, 0, len(order))
	for _, key := range order {
		a := byWorkload[key]
		for name := range a.pods {
			a.obs.Pods = append(a.obs.Pods, name)
		}
		sort.Strings(a.obs.Pods)
		for d := range a.dests {
			a.obs.Destinations = append(a.obs.Destinations, d)
		}
		sort.Slice(a.obs.Destinations, func(i, j int) bool {
			if a.obs.Destinations[i].IP != a.obs.Destinations[j].IP {
				return a.obs.Destinations[i].IP < a.obs.Destinations[j].IP
			}
			return a.obs.Destinations[i].Port < a.obs.Destinations[j].Port
		})
		out = append(out, a.obs)
	}
	return out
}

// workloadOf names the owner a policy should be written for. The pod name is
// not it: a policy outlives a rollout and a pod name does not.
func workloadOf(p *policyv1alpha1.ContainerProfile) (namespace, workload string) {
	namespace = p.Spec.Namespace
	if namespace == "" {
		namespace = p.Namespace
	}
	if w := p.Spec.Workload; w != nil && w.Kind != "" && w.Name != "" {
		if w.Namespace != "" {
			namespace = w.Namespace
		}
		return namespace, w.Kind + "/" + w.Name
	}
	if p.Spec.PodName != "" {
		// A pod with no owner is its own workload. It is also one that never
		// comes back under that name, which the generated policy's findings
		// will say.
		return namespace, "Pod/" + p.Spec.PodName
	}
	return "", ""
}

// parseDestination reads the "ip:port" form the agents write. Anything else is
// dropped rather than guessed at: a malformed entry that became a rule would
// be a rule nobody can trace back to an observation.
func parseDestination(raw string) (netpol.Destination, bool) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return netpol.Destination{}, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return netpol.Destination{}, false
	}
	if net.ParseIP(host) == nil {
		return netpol.Destination{}, false
	}
	return netpol.Destination{IP: host, Port: int32(port), Protocol: corev1.ProtocolTCP}, true
}

// windowLookup answers "how long was this workload watched, and does it have a
// cycle nobody waited for", once per workload rather than once per container.
type windowLookup struct {
	c        client.Client
	policies map[string]time.Duration
	seen     map[string]bool
}

func newWindowLookup(c client.Client) *windowLookup {
	return &windowLookup{c: c, policies: map[string]time.Duration{}, seen: map[string]bool{}}
}

// for_ reports the declared learning window and the cron expression that
// governs the workload, if any.
//
// The schedule is what makes the window meaningful. A window of fifty minutes
// on a workload whose CronJob fires nightly has not seen the workload do its
// job even once, so a policy generated from it denies the job. pkg/cycle turns
// the pair into a verdict and pkg/netpol puts that verdict in the report.
func (w *windowLookup) for_(ctx context.Context, p *policyv1alpha1.ContainerProfile) (time.Duration, string) {
	var window time.Duration
	if ref := p.Spec.PolicyRef; ref != "" {
		ns := p.Spec.Namespace
		if ns == "" {
			ns = p.Namespace
		}
		key := ns + "/" + ref
		if !w.seen[key] {
			w.seen[key] = true
			var pol policyv1alpha1.PahlevanPolicy
			if err := w.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref}, &pol); err == nil {
				if lc := pol.Spec.LearningConfig; lc.Duration != nil {
					w.policies[key] = lc.Duration.Duration
				}
			}
		}
		window = w.policies[key]
	}

	if p.Spec.PodName == "" {
		return window, ""
	}
	ns := p.Spec.Namespace
	if ns == "" {
		ns = p.Namespace
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: p.Spec.PodName}}
	if err := w.c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		// No pod, no owner chain. The window stands on its own, which is what
		// this command did before pkg/cycle existed.
		return window, ""
	}
	sched, err := cycle.Find(ctx, w.c, pod)
	if err != nil || !sched.Found {
		return window, ""
	}
	return window, sched.Expression
}

// buildRoster lists the pods a selector has to be checked against, with the
// owning workload resolved exactly rather than guessed from the pod's name.
func buildRoster(ctx context.Context, c client.Client, opts []client.ListOption) (netpol.Roster, error) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, opts...); err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	// A ReplicaSet's name carries its Deployment's name plus a hash, and
	// splitting on the last hyphen is the usual shortcut. It is also wrong for
	// a Deployment whose name ends in something hash-shaped, and the failure
	// is a policy attached to a workload that does not exist. One list per
	// kind resolves it exactly instead.
	owners := map[string]string{}
	var replicaSets appsv1.ReplicaSetList
	if err := c.List(ctx, &replicaSets, opts...); err == nil {
		for i := range replicaSets.Items {
			rs := &replicaSets.Items[i]
			if o := metav1.GetControllerOf(rs); o != nil {
				owners["ReplicaSet/"+rs.Namespace+"/"+rs.Name] = o.Kind + "/" + o.Name
			}
		}
	}
	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, opts...); err == nil {
		for i := range jobs.Items {
			j := &jobs.Items[i]
			if o := metav1.GetControllerOf(j); o != nil {
				// A Job created by a CronJob has a per-firing name. Grouping
				// by it would make every nightly run its own workload and
				// every generated policy a single-use one.
				owners["Job/"+j.Namespace+"/"+j.Name] = o.Kind + "/" + o.Name
			}
		}
	}

	roster := make(netpol.Roster, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		roster = append(roster, netpol.Pod{
			Namespace: p.Namespace,
			Name:      p.Name,
			IP:        p.Status.PodIP,
			Workload:  workloadOfPod(p, owners),
			Labels:    p.Labels,
		})
	}
	return roster, nil
}

// workloadOfPod walks one hop past the pod's controller, which is where the
// workload a person reasons about actually lives.
func workloadOfPod(p *corev1.Pod, owners map[string]string) string {
	o := metav1.GetControllerOf(p)
	if o == nil {
		return ""
	}
	if up, ok := owners[o.Kind+"/"+p.Namespace+"/"+o.Name]; ok {
		return up
	}
	return o.Kind + "/" + o.Name
}
