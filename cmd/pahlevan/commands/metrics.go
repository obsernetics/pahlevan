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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	"github.com/obsernetics/pahlevan/pkg/cli"
)

// defaultMetricFilter is the prefix every metric this project exports carries.
const defaultMetricFilter = "pahlevan_"

// metricsScraper fetches the raw exposition text of one pod's /metrics
// endpoint. It is a field on the options so tests can substitute a static
// payload for the API server proxy.
type metricsScraper func(ctx context.Context, namespace, pod, port, path string) ([]byte, error)

// metricsOptions holds the parsed flags of `pahlevan metrics`.
type metricsOptions struct {
	namespace string
	component string
	node      string
	filter    string
	output    string
	port      string
	path      string
	watch     bool
	interval  time.Duration

	scrape metricsScraper
}

// podMetrics is one pod's scrape result.
type podMetrics struct {
	Component string       `json:"component"`
	Namespace string       `json:"namespace"`
	Pod       string       `json:"pod"`
	Node      string       `json:"node"`
	Error     string       `json:"error,omitempty"`
	Families  []promFamily `json:"families,omitempty"`

	raw []byte
}

// metricsDocument is what the command emits in json form.
type metricsDocument struct {
	ScrapedAt string       `json:"scrapedAt"`
	Filter    string       `json:"filter"`
	Targets   []podMetrics `json:"targets"`
}

// NewMetricsCommand creates the metrics command
func NewMetricsCommand() *cobra.Command {
	opts := &metricsOptions{
		component: componentAll,
		filter:    defaultMetricFilter,
		output:    "table",
		port:      defaultMetricsPort,
		path:      "/metrics",
		interval:  5 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Scrape and display Pahlevan component metrics",
		Long: `Scrape the /metrics endpoint of the Pahlevan agents and operator and print
the pahlevan_* series.

The scrape goes through the API server's pod proxy, so it works from anywhere
kubectl works: no port-forward, no Service, no node access. Every pod of the
selected component is scraped and the results are grouped per pod, because the
agent is a DaemonSet and its counters are per node.

By default only metrics whose name starts with "pahlevan_" are shown; pass
--filter to narrow further (a prefix or any substring of the metric name) or
--filter="" to see everything the endpoint exposes, including the Go and
process collectors.`,
		Example: `  # Every pahlevan_ metric from every component pod
  pahlevan metrics

  # Enforcement counters from the agent on one node, refreshing
  pahlevan metrics --component agent --node worker-2 --filter blocked --watch

  # Raw exposition text, suitable for piping into promtool
  pahlevan metrics --component operator -o raw

  # Machine readable
  pahlevan metrics -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, kube, _, _, ready := GetClients()
			if !ready || kube == nil {
				return errClientsNotReady()
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if opts.watch {
				var stop context.CancelFunc
				ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
				defer stop()
			}
			return runMetrics(ctx, kube, opts, cmd.OutOrStdout())
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.namespace, "namespace", "n", "", "Namespace the components run in (default: autodetect, "+defaultComponentNamespace+" in a standard install)")
	flags.StringVar(&opts.component, "component", opts.component, "Which component to scrape (agent, operator, all)")
	flags.StringVar(&opts.node, "node", "", "Only scrape the agent pod running on this node")
	flags.StringVar(&opts.filter, "filter", opts.filter, "Only show metrics whose name has this prefix or contains it (empty shows everything)")
	flags.StringVarP(&opts.output, "output", "o", opts.output, "Output format (table, json, raw)")
	flags.StringVar(&opts.port, "port", opts.port, "Container port serving /metrics")
	flags.StringVar(&opts.path, "path", opts.path, "HTTP path of the metrics endpoint")
	flags.BoolVarP(&opts.watch, "watch", "w", false, "Re-scrape on an interval until interrupted")
	flags.DurationVar(&opts.interval, "interval", opts.interval, "Interval between scrapes when --watch is set")

	return cmd
}

// validateMetricsOptions checks the flags before any API call.
func validateMetricsOptions(opts *metricsOptions) error {
	if _, err := componentAppNames(opts.component); err != nil {
		return err
	}
	if err := validateOutputFormat(opts.output, "table", "json", "raw"); err != nil {
		return err
	}
	if opts.port == "" {
		return fmt.Errorf("invalid --port: expected the container port serving /metrics, for example %s", defaultMetricsPort)
	}
	if opts.path == "" {
		return fmt.Errorf("invalid --path: expected the metrics HTTP path, for example /metrics")
	}
	if opts.watch && opts.interval <= 0 {
		return fmt.Errorf("invalid --interval %s: expected a positive duration", opts.interval)
	}
	return nil
}

// runMetrics is the testable body of the metrics command.
func runMetrics(ctx context.Context, kube kubernetes.Interface, opts *metricsOptions, out io.Writer) error {
	if err := validateMetricsOptions(opts); err != nil {
		return err
	}

	namespace := resolveComponentNamespace(opts.namespace)
	pods, err := findComponentPods(ctx, kube, namespace, opts.component, opts.node)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return noComponentPodsError(namespace, opts.component, opts.node)
	}

	scrape := opts.scrape
	if scrape == nil {
		scrape = clientsetMetricsScraper(kube)
	}

	for {
		doc := scrapeAll(ctx, pods, opts, scrape)
		if opts.watch {
			fmt.Fprintf(out, "=== %s (every %s, ctrl-c to stop) ===\n", doc.ScrapedAt, opts.interval)
		}
		if err := renderMetrics(out, opts.output, doc); err != nil {
			return err
		}
		if allTargetsFailed(doc) {
			return fmt.Errorf("could not scrape metrics from any Pahlevan pod; see the errors above.\n"+
				"The scrape uses the API server pod proxy, which needs the pods/proxy permission and a component "+
				"serving %s on port %s", opts.path, opts.port)
		}
		if !opts.watch {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.interval):
		}
	}
}

// allTargetsFailed reports whether every scrape in the document errored.
func allTargetsFailed(doc *metricsDocument) bool {
	if len(doc.Targets) == 0 {
		return true
	}
	for _, t := range doc.Targets {
		if t.Error == "" {
			return false
		}
	}
	return true
}

// scrapeAll scrapes each pod in turn and parses the result.
func scrapeAll(ctx context.Context, pods []componentPod, opts *metricsOptions, scrape metricsScraper) *metricsDocument {
	doc := &metricsDocument{
		ScrapedAt: time.Now().UTC().Format(time.RFC3339),
		Filter:    opts.filter,
		Targets:   make([]podMetrics, 0, len(pods)),
	}
	for _, p := range pods {
		target := podMetrics{
			Component: p.Component,
			Namespace: p.Pod.Namespace,
			Pod:       p.Pod.Name,
			Node:      p.Node(),
		}
		body, err := scrape(ctx, p.Pod.Namespace, p.Pod.Name, opts.port, opts.path)
		if err != nil {
			target.Error = err.Error()
			doc.Targets = append(doc.Targets, target)
			continue
		}
		families, err := parsePrometheusText(bytes.NewReader(body))
		if err != nil {
			target.Error = fmt.Sprintf("parse metrics: %v", err)
			doc.Targets = append(doc.Targets, target)
			continue
		}
		families = filterFamilies(families, opts.filter)
		sortFamilies(families)
		target.Families = families
		target.raw = filterRawExposition(body, opts.filter)
		doc.Targets = append(doc.Targets, target)
	}
	return doc
}

// clientsetMetricsScraper is the production scrape path: the API server's pod
// proxy subresource, which needs no port-forward.
func clientsetMetricsScraper(kube kubernetes.Interface) metricsScraper {
	return func(ctx context.Context, namespace, pod, port, path string) ([]byte, error) {
		wrapper := kube.CoreV1().Pods(namespace).ProxyGet("http", pod, port, path, nil)
		if wrapper == nil {
			return nil, fmt.Errorf("pod proxy is unavailable for %s/%s", namespace, pod)
		}
		body, err := wrapper.DoRaw(ctx)
		if err != nil {
			return nil, fmt.Errorf("proxy GET %s:%s%s: %w", pod, port, path, err)
		}
		return body, nil
	}
}

// filterRawExposition keeps the exposition lines belonging to metrics that pass
// the filter, so -o raw honors --filter and still parses as valid input to
// downstream Prometheus tooling.
func filterRawExposition(body []byte, filter string) []byte {
	if filter == "" {
		return body
	}
	var out bytes.Buffer
	out.Grow(len(body) / 4)
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var name string
		if trimmed[0] == '#' {
			n, _, _, ok := parseComment(trimmed)
			if !ok {
				continue
			}
			name = n
		} else {
			idx := strings.IndexAny(trimmed, "{ \t")
			if idx < 0 {
				continue
			}
			name = trimmed[:idx]
		}
		if matchesMetricFilter(name, filter) {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// renderMetrics writes the scrape in the requested format.
func renderMetrics(out io.Writer, output string, doc *metricsDocument) error {
	switch output {
	case "json":
		writer := cli.NewOutputWriter("json")
		writer.Writer = out
		return writer.WriteObject(doc)
	case "raw":
		for _, t := range doc.Targets {
			fmt.Fprintf(out, "# source: %s %s/%s on %s\n", t.Component, t.Namespace, t.Pod, t.Node)
			if t.Error != "" {
				fmt.Fprintf(out, "# error: %s\n", t.Error)
				continue
			}
			if _, err := out.Write(t.raw); err != nil {
				return err
			}
		}
		return nil
	default:
		return renderMetricsTable(out, doc)
	}
}

func renderMetricsTable(out io.Writer, doc *metricsDocument) error {
	writer := cli.NewOutputWriter("table")
	writer.Writer = out

	for i, t := range doc.Targets {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "=== %s %s/%s on %s ===\n", t.Component, t.Namespace, t.Pod, t.Node)
		if t.Error != "" {
			writer.PrintError(t.Error)
			continue
		}
		if len(t.Families) == 0 {
			writer.PrintInfo(fmt.Sprintf("no metrics matched filter %q on this pod", doc.Filter))
			continue
		}
		table := cli.NewTableData("METRIC", "TYPE", "LABELS", "VALUE")
		for _, f := range t.Families {
			for _, s := range f.Samples {
				table.AddRow(
					s.Name,
					orNone(f.Type),
					orNone(s.LabelString()),
					formatMetricValue(s.Value),
				)
			}
		}
		if err := table.Render(writer); err != nil {
			return err
		}
		fmt.Fprintf(out, "%d metric families, %d series\n", len(t.Families), countSamples(t.Families))
	}
	return nil
}

func countSamples(families []promFamily) int {
	n := 0
	for _, f := range families {
		n += len(f.Samples)
	}
	return n
}

// metricHighlight is a single named number pulled out of a scrape for the
// debug bundle.
type metricHighlight struct {
	Metric string  `json:"metric"`
	Labels string  `json:"labels,omitempty"`
	Value  float64 `json:"value"`
	Source string  `json:"source"`
}

// highlightMetrics is the list of series the debug bundle surfaces: the ones
// that say whether Pahlevan is actually doing its job.
var highlightMetrics = []string{
	"pahlevan_containers_tracked",
	"pahlevan_containers_learning",
	"pahlevan_containers_enforced",
	"pahlevan_policies_active",
	"pahlevan_policies_learning",
	"pahlevan_policies_enforcing",
	"pahlevan_policies_failed",
	"pahlevan_blocked_syscalls_total",
	"pahlevan_blocked_connections_total",
	"pahlevan_blocked_file_access_total",
	"pahlevan_policy_violations_total",
	"pahlevan_enforcement_actions_total",
	"pahlevan_rollback_actions_total",
	"pahlevan_self_healing_actions_total",
	"pahlevan_export_dropped_total",
	"pahlevan_health_check_score",
}

// extractHighlights pulls the highlight series out of a parsed scrape.
func extractHighlights(families []promFamily, source string) []metricHighlight {
	wanted := make(map[string]struct{}, len(highlightMetrics))
	for _, m := range highlightMetrics {
		wanted[m] = struct{}{}
	}
	var out []metricHighlight
	for _, f := range families {
		for _, s := range f.Samples {
			if _, ok := wanted[s.Name]; !ok {
				continue
			}
			out = append(out, metricHighlight{
				Metric: s.Name,
				Labels: s.LabelString(),
				Value:  s.Value,
				Source: source,
			})
		}
	}
	return out
}
