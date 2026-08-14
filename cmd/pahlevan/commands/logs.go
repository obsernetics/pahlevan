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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// maxLogLine bounds a single log line so a component emitting an unterminated
// stream cannot make the CLI allocate without limit.
const maxLogLine = 1 << 20

// podLogFetcher opens a log stream for one container. It exists so the command
// body can be driven with an injected reader in tests without a live API
// server; the default implementation goes through client-go.
type podLogFetcher func(ctx context.Context, namespace, pod, container string, opts *corev1.PodLogOptions) (io.ReadCloser, error)

// logsOptions holds the parsed flags of `pahlevan logs`.
type logsOptions struct {
	namespace  string
	component  string
	node       string
	container  string
	follow     bool
	tail       int64
	since      string
	previous   bool
	timestamps bool
	prefix     string

	// fetch is overridden in tests; nil means "use the clientset".
	fetch podLogFetcher
}

// NewLogsCommand creates the logs command
func NewLogsCommand() *cobra.Command {
	opts := &logsOptions{
		component: componentAll,
		tail:      200,
		prefix:    "auto",
	}

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Fetch or follow logs from the Pahlevan components",
		Long: `Fetch or follow the logs of the Pahlevan node agents and operator.

The agent runs as a DaemonSet on every node and the operator as a Deployment,
so a cluster normally has several log streams. This command discovers the pods
by their app.kubernetes.io/name label, reads them through the API server (no
port-forward or node access needed) and multiplexes them into one stream. When
more than one pod is read, every line is prefixed with the component, pod and
node it came from, so the interleaved output stays attributable.

Use --node to follow the agent on one specific node, which is usually what you
want when investigating a single workload.`,
		Example: `  # Last 200 lines from every Pahlevan pod
  pahlevan logs

  # Follow just the operator
  pahlevan logs --component operator --follow

  # The agent on one node, last 10 minutes
  pahlevan logs --component agent --node worker-2 --since 10m

  # The previous container after a crash loop
  pahlevan logs --component agent --node worker-2 --previous`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, kube, _, _, ready := GetClients()
			if !ready || kube == nil {
				return errClientsNotReady()
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if opts.follow {
				var stop context.CancelFunc
				ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
				defer stop()
			}
			return runLogs(ctx, kube, opts, cmd.OutOrStdout())
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.namespace, "namespace", "n", "", "Namespace the components run in (default: autodetect, "+defaultComponentNamespace+" in a standard install)")
	flags.StringVar(&opts.component, "component", opts.component, "Which component to read (agent, operator, all)")
	flags.StringVar(&opts.node, "node", "", "Only read the agent pod running on this node")
	flags.StringVarP(&opts.container, "container", "c", "", "Container to read (defaults to the component container)")
	flags.BoolVarP(&opts.follow, "follow", "f", false, "Stream new lines as they are written")
	flags.Int64Var(&opts.tail, "tail", opts.tail, "Number of lines to show from the end of each log (-1 for the whole log)")
	flags.StringVar(&opts.since, "since", "", "Only return logs newer than this relative duration, for example 10m or 2h")
	flags.BoolVar(&opts.previous, "previous", false, "Read the previous terminated container instead of the running one")
	flags.BoolVar(&opts.timestamps, "timestamps", false, "Include the RFC3339 timestamp the kubelet recorded for each line")
	flags.StringVar(&opts.prefix, "prefix", opts.prefix, "Per-line source prefix (auto, always, never); auto prefixes only when several pods are read")

	return cmd
}

// validateLogsOptions checks the flag combination before any API call, so a
// typo fails immediately instead of after a cluster round trip.
func validateLogsOptions(opts *logsOptions) (*corev1.PodLogOptions, error) {
	if _, err := componentAppNames(opts.component); err != nil {
		return nil, err
	}
	switch opts.prefix {
	case "auto", "always", "never":
	default:
		return nil, fmt.Errorf("invalid --prefix %q: expected one of auto, always, never", opts.prefix)
	}
	if opts.previous && opts.follow {
		return nil, fmt.Errorf("--previous cannot be combined with --follow: a terminated container produces no new lines")
	}

	logOpts := &corev1.PodLogOptions{
		Follow:     opts.follow,
		Previous:   opts.previous,
		Timestamps: opts.timestamps,
	}
	if opts.tail >= 0 {
		tail := opts.tail
		logOpts.TailLines = &tail
	}
	if opts.since != "" {
		d, err := time.ParseDuration(opts.since)
		if err != nil {
			return nil, fmt.Errorf("invalid --since %q: expected a duration such as 30s, 10m or 2h: %w", opts.since, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("invalid --since %q: expected a positive duration", opts.since)
		}
		seconds := int64(d.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		logOpts.SinceSeconds = &seconds
	}
	return logOpts, nil
}

// runLogs is the testable body of the logs command.
func runLogs(ctx context.Context, kube kubernetes.Interface, opts *logsOptions, out io.Writer) error {
	logOpts, err := validateLogsOptions(opts)
	if err != nil {
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

	withPrefix := opts.prefix == "always" || (opts.prefix == "auto" && len(pods) > 1)
	fetch := opts.fetch
	if fetch == nil {
		fetch = clientsetLogFetcher(kube)
	}

	if !opts.follow {
		return streamLogsSequentially(ctx, pods, opts, logOpts, fetch, out, withPrefix)
	}
	return streamLogsConcurrently(ctx, pods, opts, logOpts, fetch, out, withPrefix)
}

// clientsetLogFetcher is the production log source: the pods/log subresource
// via the API server.
func clientsetLogFetcher(kube kubernetes.Interface) podLogFetcher {
	return func(ctx context.Context, namespace, pod, container string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
		o := *opts
		o.Container = container
		return kube.CoreV1().Pods(namespace).GetLogs(pod, &o).Stream(ctx)
	}
}

// logSourceLabel is the per-line prefix identifying where a line came from.
func logSourceLabel(p componentPod) string {
	return fmt.Sprintf("[%s/%s@%s]", p.Component, p.Pod.Name, p.Node())
}

// containerFor picks the container to read for a pod: the explicit --container
// when given, otherwise the pod's first container.
func containerFor(p componentPod, override string) string {
	if override != "" {
		return override
	}
	return p.Container()
}

// streamLogsSequentially reads each pod's log to completion in turn. This is
// the non-follow path, where ordering per pod is more useful than interleaving.
func streamLogsSequentially(
	ctx context.Context,
	pods []componentPod,
	opts *logsOptions,
	logOpts *corev1.PodLogOptions,
	fetch podLogFetcher,
	out io.Writer,
	withPrefix bool,
) error {
	var failures []string
	wrote := false
	for _, p := range pods {
		rc, err := fetch(ctx, p.Pod.Namespace, p.Pod.Name, containerFor(p, opts.container), logOpts)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", logSourceLabel(p), err))
			continue
		}
		if !withPrefix && len(pods) > 1 {
			fmt.Fprintf(out, "==== %s ====\n", logSourceLabel(p))
		}
		prefix := ""
		if withPrefix {
			prefix = logSourceLabel(p) + " "
		}
		n, copyErr := copyPrefixed(out, rc, prefix)
		_ = rc.Close()
		wrote = wrote || n > 0
		if copyErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", logSourceLabel(p), copyErr))
		}
	}

	if len(failures) == len(pods) {
		return fmt.Errorf("could not read logs from any Pahlevan pod:\n  %s", strings.Join(failures, "\n  "))
	}
	for _, f := range failures {
		fmt.Fprintf(out, "warning: %s\n", f)
	}
	if !wrote {
		fmt.Fprintf(out, "(no log lines matched: %d pod(s) read, try --tail=-1 or a longer --since)\n", len(pods))
	}
	return nil
}

// streamLogsConcurrently follows every selected pod at once, funnelling the
// lines through a single writer so they never interleave mid-line.
func streamLogsConcurrently(
	ctx context.Context,
	pods []componentPod,
	opts *logsOptions,
	logOpts *corev1.PodLogOptions,
	fetch podLogFetcher,
	out io.Writer,
	withPrefix bool,
) error {
	type line struct {
		prefix string
		text   string
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lines := make(chan line, 256)
	errs := make(chan string, len(pods))

	var wg sync.WaitGroup
	for _, p := range pods {
		p := p
		prefix := ""
		if withPrefix {
			prefix = logSourceLabel(p) + " "
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := fetch(ctx, p.Pod.Namespace, p.Pod.Name, containerFor(p, opts.container), logOpts)
			if err != nil {
				errs <- fmt.Sprintf("%s: %v", logSourceLabel(p), err)
				return
			}
			defer func() { _ = rc.Close() }()

			scanner := bufio.NewScanner(rc)
			scanner.Buffer(make([]byte, 0, 64*1024), maxLogLine)
			for scanner.Scan() {
				select {
				case lines <- line{prefix: prefix, text: scanner.Text()}:
				case <-ctx.Done():
					return
				}
			}
			if err := scanner.Err(); err != nil && ctx.Err() == nil {
				errs <- fmt.Sprintf("%s: %v", logSourceLabel(p), err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(lines)
		close(errs)
		close(done)
	}()

	for l := range lines {
		if _, err := fmt.Fprintf(out, "%s%s\n", l.prefix, l.text); err != nil {
			cancel()
			<-done
			return fmt.Errorf("write log line: %w", err)
		}
	}
	<-done

	var failures []string
	for e := range errs {
		failures = append(failures, e)
	}
	if len(failures) == len(pods) && len(failures) > 0 && ctx.Err() == nil {
		return fmt.Errorf("could not follow logs from any Pahlevan pod:\n  %s", strings.Join(failures, "\n  "))
	}
	for _, f := range failures {
		fmt.Fprintf(out, "warning: %s\n", f)
	}
	return nil
}

// copyPrefixed copies r to w, prefixing each line. It returns the number of
// lines written. Without a prefix the copy is a straight io.Copy so large logs
// are not re-scanned line by line for nothing.
func copyPrefixed(w io.Writer, r io.Reader, prefix string) (int, error) {
	if prefix == "" {
		n, err := io.Copy(w, r)
		if n > 0 {
			return 1, err
		}
		return 0, err
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLine)
	count := 0
	for scanner.Scan() {
		if _, err := fmt.Fprintf(w, "%s%s\n", prefix, scanner.Text()); err != nil {
			return count, err
		}
		count++
	}
	return count, scanner.Err()
}

// formatRestarts renders a restart count, calling out the ones that matter.
func formatRestarts(n int32) string {
	if n == 0 {
		return "0"
	}
	return strconv.FormatInt(int64(n), 10)
}
