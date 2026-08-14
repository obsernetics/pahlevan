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
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// lsmFailureMarker is the message the agent logs when a BPF LSM hook cannot be
// attached. Its presence is direct evidence that the node was not booted with
// the bpf LSM active; the data plane degrades to observation only.
const lsmFailureMarker = "attach failed"

// minBPFLSMKernel is the first kernel release with BPF LSM support
// (CONFIG_BPF_LSM landed in 5.7).
var minBPFLSMKernel = [2]int{5, 7}

// debugLogTailLines is how much of each agent log the bundle inspects for LSM
// attach failures. Enough to cover startup on a recently restarted pod without
// pulling a whole log into memory.
const debugLogTailLines = 300

// BPF LSM states reported per node.
const (
	lsmStateDisabled = "Disabled"
	lsmStateLikelyOn = "Likely enabled"
	lsmStateUnknown  = "Unknown"
	lsmStateTooOld   = "Unsupported kernel"
)

// debugOptions holds the parsed flags of `pahlevan debug`.
type debugOptions struct {
	namespace string
	component string
	output    string
	file      string
	events    int
	skipLogs  bool

	fetch  podLogFetcher
	scrape metricsScraper
}

// componentPodReport is the per-pod section of the bundle.
type componentPodReport struct {
	Component string `json:"component"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Node      string `json:"node"`
	Phase     string `json:"phase"`
	Ready     string `json:"ready"`
	Restarts  int32  `json:"restarts"`
	Image     string `json:"image"`
	Age       string `json:"age"`
	Reason    string `json:"reason,omitempty"`
}

// nodeReport is the per-node section of the bundle.
type nodeReport struct {
	Name          string `json:"name"`
	Ready         bool   `json:"ready"`
	KernelVersion string `json:"kernelVersion"`
	OSImage       string `json:"osImage"`
	Runtime       string `json:"containerRuntime"`
	Architecture  string `json:"architecture"`
	AgentPod      string `json:"agentPod,omitempty"`
	BPFLSM        string `json:"bpfLSM"`
	BPFLSMDetail  string `json:"bpfLSMDetail,omitempty"`
}

// crdReport records whether a Pahlevan CRD is served and how many objects it
// holds.
type crdReport struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Count     int    `json:"count"`
	Error     string `json:"error,omitempty"`
}

// eventReport is one recent Kubernetes Event related to Pahlevan.
type eventReport struct {
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Object    string `json:"object"`
	Message   string `json:"message"`
	Count     int32  `json:"count"`
	Last      string `json:"lastSeen"`
}

// debugBundle is the support bundle the command produces.
type debugBundle struct {
	GeneratedAt string               `json:"generatedAt"`
	Scope       string               `json:"scope"`
	Components  []componentPodReport `json:"components"`
	Nodes       []nodeReport         `json:"nodes"`
	CRDs        []crdReport          `json:"crds"`
	Events      []eventReport        `json:"events"`
	Metrics     []metricHighlight    `json:"metricHighlights"`
	Warnings    []string             `json:"warnings,omitempty"`
	Notes       []string             `json:"notes,omitempty"`
}

// NewDebugCommand creates the debug command
func NewDebugCommand() *cobra.Command {
	opts := &debugOptions{
		component: componentAll,
		output:    "table",
		events:    20,
	}

	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Collect a Pahlevan support bundle",
		Long: `Collect the state a Pahlevan problem report needs, in one command.

The bundle contains:
  - every component pod: phase, readiness, restart count, image and age
  - every node: kernel version, OS image, container runtime and whether the
    BPF LSM looks active there
  - the Pahlevan CRDs: whether each is served and how many objects it holds
  - recent Kubernetes Events involving Pahlevan objects or component pods
  - the pahlevan_* metric highlights scraped from each component

BPF LSM detection is inferential, because the kernel does not expose its LSM
list through the Kubernetes API. A node is reported Disabled when its agent
logged an LSM attach failure, Unsupported kernel when the kernel predates
CONFIG_BPF_LSM (5.7), and Likely enabled when a ready agent on a new enough
kernel logged no attach failure in the inspected window. Pass --skip-logs to
omit the log inspection entirely.

The bundle never reads Secrets, ServiceAccount tokens or container environment
variables.`,
		Example: `  # Print the bundle
  pahlevan debug

  # Save a JSON bundle to attach to an issue
  pahlevan debug -o json --file pahlevan-debug.json

  # Only the agent, without reading logs
  pahlevan debug --component agent --skip-logs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			k8sClient, kube, _, _, ready := GetClients()
			if !ready || kube == nil || k8sClient == nil {
				return errClientsNotReady()
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runDebug(ctx, k8sClient, kube, opts, cmd.OutOrStdout())
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.namespace, "namespace", "n", "", "Namespace the components run in (default: autodetect, "+defaultComponentNamespace+" in a standard install)")
	flags.StringVar(&opts.component, "component", opts.component, "Which component to inspect (agent, operator, all)")
	flags.StringVarP(&opts.output, "output", "o", opts.output, "Output format (table, json, yaml)")
	flags.StringVar(&opts.file, "file", "", "Write the bundle to this file instead of stdout")
	flags.IntVar(&opts.events, "events", opts.events, "How many recent Pahlevan-related Kubernetes Events to include")
	flags.BoolVar(&opts.skipLogs, "skip-logs", false, "Do not read component logs (skips BPF LSM detection)")

	return cmd
}

// runDebug is the testable body of the debug command.
func runDebug(ctx context.Context, k8sClient client.Client, kube kubernetes.Interface, opts *debugOptions, out io.Writer) error {
	if _, err := componentAppNames(opts.component); err != nil {
		return err
	}
	if err := validateOutputFormat(opts.output, "table", "json", "yaml"); err != nil {
		return err
	}
	if opts.events < 0 {
		return fmt.Errorf("invalid --events %d: expected zero or a positive number", opts.events)
	}

	bundle, err := collectDebugBundle(ctx, k8sClient, kube, opts)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	writer := cli.NewOutputWriter(opts.output)
	writer.Writer = &buf
	if opts.output == "json" || opts.output == "yaml" {
		if err := writer.WriteObject(bundle); err != nil {
			return err
		}
	} else {
		writeDebugTable(writer, bundle)
	}

	if opts.file == "" {
		_, err := out.Write(buf.Bytes())
		return err
	}
	if err := writeReportFile(opts.file, buf.Bytes()); err != nil {
		return err
	}
	confirm := cli.NewOutputWriter("table")
	confirm.Writer = out
	confirm.PrintSuccess(fmt.Sprintf("Debug bundle written to %s (%s)", opts.file, cli.FormatBytes(int64(buf.Len()))))
	return nil
}

// collectDebugBundle gathers every section of the bundle. Individual sections
// degrade to a warning rather than failing the whole collection, because a
// bundle is most valuable exactly when part of the system is broken.
func collectDebugBundle(ctx context.Context, k8sClient client.Client, kube kubernetes.Interface, opts *debugOptions) (*debugBundle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	namespace := resolveComponentNamespace(opts.namespace)

	bundle := &debugBundle{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scope:       scopeLabel(namespace),
		Notes: []string{
			"Secrets, ServiceAccount tokens and container environment variables are never read by this command.",
			"BPF LSM state is inferred from agent logs and kernel version; see the command help for how each state is decided.",
		},
	}

	pods, err := findComponentPods(ctx, kube, namespace, opts.component, "")
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		bundle.Warnings = append(bundle.Warnings, noComponentPodsError(namespace, opts.component, "").Error())
	}
	for _, p := range pods {
		bundle.Components = append(bundle.Components, newComponentPodReport(p))
	}

	// Agent logs feed the BPF LSM inference; one read serves every node.
	lsmByNode := map[string]lsmFinding{}
	if !opts.skipLogs {
		fetch := opts.fetch
		if fetch == nil {
			fetch = clientsetLogFetcher(kube)
		}
		lsmByNode = detectBPFLSM(ctx, pods, fetch)
	}

	nodes, warn := collectNodeReports(ctx, kube, pods, lsmByNode, opts.skipLogs)
	bundle.Nodes = nodes
	bundle.Warnings = append(bundle.Warnings, warn...)

	bundle.CRDs = collectCRDReports(ctx, k8sClient)

	events, warn := collectPahlevanEvents(ctx, kube, namespace, pods, opts.events)
	bundle.Events = events
	bundle.Warnings = append(bundle.Warnings, warn...)

	scrape := opts.scrape
	if scrape == nil {
		scrape = clientsetMetricsScraper(kube)
	}
	highlights, warn := collectMetricHighlights(ctx, pods, scrape)
	bundle.Metrics = highlights
	bundle.Warnings = append(bundle.Warnings, warn...)

	return bundle, nil
}

func newComponentPodReport(p componentPod) componentPodReport {
	report := componentPodReport{
		Component: p.Component,
		Namespace: p.Pod.Namespace,
		Name:      p.Pod.Name,
		Node:      p.Node(),
		Phase:     string(p.Pod.Status.Phase),
		Ready:     p.ReadyString(),
		Restarts:  p.Restarts(),
		Image:     p.Image(),
	}
	if !p.Pod.CreationTimestamp.IsZero() {
		report.Age = cli.FormatDuration(time.Since(p.Pod.CreationTimestamp.Time))
	}
	report.Reason = podProblemReason(p.Pod)
	return report
}

// podProblemReason surfaces the first waiting/terminated reason on the pod, so
// a CrashLoopBackOff is visible without digging into the pod spec.
func podProblemReason(pod corev1.Pod) string {
	if pod.Status.Reason != "" {
		return pod.Status.Reason
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
			return cs.State.Terminated.Reason
		}
		if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason != "" {
			return "last exit: " + cs.LastTerminationState.Terminated.Reason
		}
	}
	return ""
}

// lsmFinding is what the log inspection concluded for one node.
type lsmFinding struct {
	state  string
	detail string
}

// detectBPFLSM reads the tail of each agent log and looks for the LSM attach
// failure the data plane logs when the kernel was not booted with lsm=...,bpf.
func detectBPFLSM(ctx context.Context, pods []componentPod, fetch podLogFetcher) map[string]lsmFinding {
	out := map[string]lsmFinding{}
	tail := int64(debugLogTailLines)
	for _, p := range pods {
		if p.Component != componentAgent || p.Pod.Spec.NodeName == "" {
			continue
		}
		rc, err := fetch(ctx, p.Pod.Namespace, p.Pod.Name, containerFor(p, ""), &corev1.PodLogOptions{TailLines: &tail})
		if err != nil {
			out[p.Pod.Spec.NodeName] = lsmFinding{state: lsmStateUnknown, detail: fmt.Sprintf("agent log unreadable: %v", err)}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, 4<<20))
		_ = rc.Close()
		if readErr != nil {
			out[p.Pod.Spec.NodeName] = lsmFinding{state: lsmStateUnknown, detail: fmt.Sprintf("agent log unreadable: %v", readErr)}
			continue
		}
		out[p.Pod.Spec.NodeName] = classifyLSMLog(string(data), p.Ready())
	}
	return out
}

// classifyLSMLog turns an agent log window into a BPF LSM verdict.
func classifyLSMLog(logText string, agentReady bool) lsmFinding {
	for _, line := range strings.Split(logText, "\n") {
		if !strings.Contains(line, "lsm/") || !strings.Contains(line, lsmFailureMarker) {
			continue
		}
		hook := line[strings.Index(line, "lsm/"):]
		if idx := strings.IndexAny(hook, " \t"); idx > 0 {
			hook = hook[:idx]
		}
		return lsmFinding{
			state:  lsmStateDisabled,
			detail: fmt.Sprintf("agent logged %s attach failure; boot the node with lsm=...,bpf to enable in-kernel enforcement", hook),
		}
	}
	if !agentReady {
		return lsmFinding{state: lsmStateUnknown, detail: "agent is not ready; no attach result logged yet"}
	}
	return lsmFinding{state: lsmStateLikelyOn, detail: "no LSM attach failure in the inspected log window"}
}

// collectNodeReports lists the nodes and folds in the agent placement and the
// BPF LSM verdict.
func collectNodeReports(ctx context.Context, kube kubernetes.Interface, pods []componentPod, lsmByNode map[string]lsmFinding, skipLogs bool) ([]nodeReport, []string) {
	list, err := kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to list nodes: %v", err)}
	}

	agentByNode := map[string]string{}
	for _, p := range pods {
		if p.Component == componentAgent && p.Pod.Spec.NodeName != "" {
			agentByNode[p.Pod.Spec.NodeName] = p.Pod.Name
		}
	}

	reports := make([]nodeReport, 0, len(list.Items))
	for i := range list.Items {
		n := list.Items[i]
		report := nodeReport{
			Name:          n.Name,
			Ready:         nodeIsReady(n),
			KernelVersion: n.Status.NodeInfo.KernelVersion,
			OSImage:       n.Status.NodeInfo.OSImage,
			Runtime:       n.Status.NodeInfo.ContainerRuntimeVersion,
			Architecture:  n.Status.NodeInfo.Architecture,
			AgentPod:      agentByNode[n.Name],
		}
		report.BPFLSM, report.BPFLSMDetail = resolveLSMState(report, lsmByNode, skipLogs)
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports, nil
}

// resolveLSMState combines the kernel version prerequisite with the log-derived
// finding into the state reported for a node.
func resolveLSMState(node nodeReport, lsmByNode map[string]lsmFinding, skipLogs bool) (string, string) {
	if ok, parsed := kernelAtLeast(node.KernelVersion, minBPFLSMKernel); parsed && !ok {
		return lsmStateTooOld, fmt.Sprintf("kernel %s predates CONFIG_BPF_LSM (%d.%d)", node.KernelVersion, minBPFLSMKernel[0], minBPFLSMKernel[1])
	}
	if node.AgentPod == "" {
		return lsmStateUnknown, "no Pahlevan agent pod on this node"
	}
	if skipLogs {
		return lsmStateUnknown, "log inspection skipped (--skip-logs)"
	}
	if finding, ok := lsmByNode[node.Name]; ok {
		return finding.state, finding.detail
	}
	return lsmStateUnknown, "no agent log available for this node"
}

// kernelAtLeast compares a uname-style kernel release against a minimum. The
// second return reports whether the version could be parsed at all.
func kernelAtLeast(version string, min [2]int) (bool, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return false, false
	}
	parts := strings.FieldsFunc(version, func(r rune) bool { return r < '0' || r > '9' })
	if len(parts) < 2 {
		return false, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, false
	}
	if major != min[0] {
		return major > min[0], true
	}
	return minor >= min[1], true
}

func nodeIsReady(n corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// pahlevanKinds are the CRDs the bundle probes for presence and object count.
var pahlevanKinds = []string{"PahlevanPolicy", "ContainerProfile", "AttackSurface"}

// collectCRDReports probes each Pahlevan CRD by listing it: a NoKindMatch means
// the CRD is not installed, anything else is reported as an error.
func collectCRDReports(ctx context.Context, k8sClient client.Client) []crdReport {
	reports := make([]crdReport, 0, len(pahlevanKinds))
	for _, kind := range pahlevanKinds {
		report := crdReport{Kind: kind}
		var count int
		var err error
		switch kind {
		case "PahlevanPolicy":
			list := &policyv1alpha1.PahlevanPolicyList{}
			err = k8sClient.List(ctx, list)
			count = len(list.Items)
		case "ContainerProfile":
			list := &policyv1alpha1.ContainerProfileList{}
			err = k8sClient.List(ctx, list)
			count = len(list.Items)
		case "AttackSurface":
			list := &policyv1alpha1.AttackSurfaceList{}
			err = k8sClient.List(ctx, list)
			count = len(list.Items)
		}
		switch {
		case err == nil:
			report.Installed = true
			report.Count = count
		case isNoKindMatch(err):
			report.Installed = false
		default:
			report.Error = err.Error()
		}
		reports = append(reports, report)
	}
	return reports
}

// collectPahlevanEvents returns the most recent Kubernetes Events that involve
// a Pahlevan object or a component pod.
func collectPahlevanEvents(ctx context.Context, kube kubernetes.Interface, namespace string, pods []componentPod, limit int) ([]eventReport, []string) {
	if limit == 0 {
		return nil, nil
	}
	list, err := kube.CoreV1().Events(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to list events: %v", err)}
	}

	podNames := make(map[string]struct{}, len(pods))
	for _, p := range pods {
		podNames[p.Pod.Name] = struct{}{}
	}

	// Keep the real timestamp alongside the rendered row: sorting the humanised
	// "2.0h ago" string would order events alphabetically, not chronologically.
	type timedEvent struct {
		report eventReport
		at     time.Time
	}
	var timed []timedEvent
	for i := range list.Items {
		e := &list.Items[i]
		if !eventIsPahlevanRelated(e, podNames, namespace) {
			continue
		}
		at := latestEventTime(e)
		timed = append(timed, timedEvent{
			at: at,
			report: eventReport{
				Namespace: e.Namespace,
				Type:      e.Type,
				Reason:    e.Reason,
				Object:    fmt.Sprintf("%s/%s", e.InvolvedObject.Kind, e.InvolvedObject.Name),
				Message:   strings.TrimSpace(e.Message),
				Count:     e.Count,
				Last:      cli.FormatTimestamp(at),
			},
		})
	}

	sort.Slice(timed, func(i, j int) bool {
		if !timed[i].at.Equal(timed[j].at) {
			return timed[i].at.Before(timed[j].at)
		}
		return timed[i].report.Object < timed[j].report.Object
	})
	// Keep the tail: the events closest to now are the useful ones.
	if len(timed) > limit {
		timed = timed[len(timed)-limit:]
	}
	reports := make([]eventReport, 0, len(timed))
	for _, t := range timed {
		reports = append(reports, t.report)
	}
	if len(reports) == 0 {
		return nil, nil
	}
	return reports, nil
}

// eventIsPahlevanRelated matches events about a Pahlevan custom resource, about
// a component pod, or emitted inside the component namespace.
func eventIsPahlevanRelated(e *corev1.Event, podNames map[string]struct{}, namespace string) bool {
	for _, kind := range pahlevanKinds {
		if e.InvolvedObject.Kind == kind {
			return true
		}
	}
	if _, ok := podNames[e.InvolvedObject.Name]; ok {
		return true
	}
	if namespace != "" && e.Namespace == namespace {
		return true
	}
	if strings.Contains(strings.ToLower(e.InvolvedObject.Name), "pahlevan") {
		return true
	}
	return strings.Contains(strings.ToLower(e.Source.Component), "pahlevan")
}

// latestEventTime picks the most recent timestamp an Event carries. It extends
// the shared eventTime helper with the series field an aggregated event uses.
func latestEventTime(e *corev1.Event) time.Time {
	if e.Series != nil && !e.Series.LastObservedTime.IsZero() {
		return e.Series.LastObservedTime.Time
	}
	return eventTime(e)
}

// collectMetricHighlights scrapes each component pod and keeps the series that
// say whether enforcement is happening.
func collectMetricHighlights(ctx context.Context, pods []componentPod, scrape metricsScraper) ([]metricHighlight, []string) {
	var (
		out      []metricHighlight
		warnings []string
	)
	for _, p := range pods {
		source := fmt.Sprintf("%s/%s", p.Component, p.Pod.Name)
		body, err := scrape(ctx, p.Pod.Namespace, p.Pod.Name, defaultMetricsPort, "/metrics")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("metrics scrape of %s failed: %v", source, err))
			continue
		}
		families, err := parsePrometheusText(bytes.NewReader(body))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("metrics scrape of %s unparseable: %v", source, err))
			continue
		}
		out = append(out, extractHighlights(families, source)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Metric != out[j].Metric {
			return out[i].Metric < out[j].Metric
		}
		return out[i].Source < out[j].Source
	})
	return out, warnings
}

// writeDebugTable renders the bundle as human readable text.
func writeDebugTable(writer *cli.OutputWriter, bundle *debugBundle) {
	w := writer.Writer
	fmt.Fprintf(w, "=== Pahlevan Debug Bundle ===\n\n")
	fmt.Fprintf(w, "Generated: %s\n", bundle.GeneratedAt)
	fmt.Fprintf(w, "Scope:     %s\n\n", bundle.Scope)

	fmt.Fprintf(w, "--- Component pods ---\n")
	if len(bundle.Components) == 0 {
		fmt.Fprintf(w, "<none>\n")
	} else {
		table := cli.NewTableData("COMPONENT", "NAMESPACE", "POD", "NODE", "PHASE", "READY", "RESTARTS", "AGE", "REASON")
		for _, c := range bundle.Components {
			// Deliberately uncoloured: the bundle is often written to a file
			// with --file, and ANSI escapes in a pasted support bundle are noise.
			table.AddRow(c.Component, c.Namespace, c.Name, c.Node,
				fmt.Sprintf("%s %s", cli.StatusIcon(c.Phase), c.Phase),
				c.Ready, formatRestarts(c.Restarts), orNone(c.Age), orNone(c.Reason))
		}
		_ = table.Render(writer)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "--- Nodes ---\n")
	if len(bundle.Nodes) == 0 {
		fmt.Fprintf(w, "<none>\n")
	} else {
		table := cli.NewTableData("NODE", "READY", "KERNEL", "OS", "RUNTIME", "ARCH", "AGENT", "BPF LSM")
		for _, n := range bundle.Nodes {
			table.AddRow(n.Name, boolLabel(n.Ready), orNone(n.KernelVersion), orNone(n.OSImage),
				orNone(n.Runtime), orNone(n.Architecture), orNone(n.AgentPod), n.BPFLSM)
		}
		_ = table.Render(writer)
		for _, n := range bundle.Nodes {
			if n.BPFLSMDetail != "" {
				fmt.Fprintf(w, "  %s: %s\n", n.Name, n.BPFLSMDetail)
			}
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "--- Custom resource definitions ---\n")
	table := cli.NewTableData("KIND", "INSTALLED", "OBJECTS", "ERROR")
	for _, c := range bundle.CRDs {
		table.AddRow(c.Kind, boolLabel(c.Installed), strconv.Itoa(c.Count), orNone(c.Error))
	}
	_ = table.Render(writer)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "--- Recent Pahlevan events ---\n")
	if len(bundle.Events) == 0 {
		fmt.Fprintf(w, "<none>\n")
	} else {
		et := cli.NewTableData("LAST", "TYPE", "REASON", "OBJECT", "COUNT", "MESSAGE")
		for _, e := range bundle.Events {
			et.AddRow(e.Last, e.Type, e.Reason, e.Object, strconv.Itoa(int(e.Count)), cli.TruncateString(e.Message, 80))
		}
		_ = et.Render(writer)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "--- Metric highlights ---\n")
	if len(bundle.Metrics) == 0 {
		fmt.Fprintf(w, "<none>\n")
	} else {
		mt := cli.NewTableData("METRIC", "LABELS", "VALUE", "SOURCE")
		for _, m := range bundle.Metrics {
			mt.AddRow(m.Metric, orNone(m.Labels), formatMetricValue(m.Value), m.Source)
		}
		_ = mt.Render(writer)
	}
	fmt.Fprintln(w)

	if len(bundle.Warnings) > 0 {
		fmt.Fprintf(w, "--- Warnings ---\n")
		for _, warning := range bundle.Warnings {
			writer.PrintWarning(warning)
		}
		fmt.Fprintln(w)
	}
	for _, note := range bundle.Notes {
		writer.PrintInfo(note)
	}
}

func boolLabel(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
