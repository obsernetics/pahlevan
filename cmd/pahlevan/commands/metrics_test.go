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
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// staticScraper returns canned exposition text for every pod.
func staticScraper(text string) metricsScraper {
	return func(context.Context, string, string, string, string) ([]byte, error) {
		return []byte(text), nil
	}
}

// recordingScraper captures the arguments each scrape was made with.
type recordingScraper struct {
	mu    sync.Mutex
	calls []struct{ namespace, pod, port, path string }
	body  string
	err   error
}

func (r *recordingScraper) scrape(_ context.Context, namespace, pod, port, path string) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, struct{ namespace, pod, port, path string }{namespace, pod, port, path})
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.body), nil
}

// staticResponseWrapper satisfies rest.ResponseWrapper for the proxy reactor.
type staticResponseWrapper struct {
	body string
	err  error
}

func (s staticResponseWrapper) DoRaw(context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.body), nil
}

func (s staticResponseWrapper) Stream(context.Context) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return io.NopCloser(strings.NewReader(s.body)), nil
}

func TestNewMetricsCommand_Flags(t *testing.T) {
	cmd := NewMetricsCommand()
	if cmd.Use != "metrics" {
		t.Errorf("Use = %q", cmd.Use)
	}
	for _, f := range []string{"namespace", "component", "node", "filter", "output", "port", "path", "watch", "interval"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("metrics missing flag %q", f)
		}
	}
	if got := cmd.Flags().Lookup("filter").DefValue; got != defaultMetricFilter {
		t.Errorf("filter default = %q, want %q", got, defaultMetricFilter)
	}
	if got := cmd.Flags().Lookup("port").DefValue; got != defaultMetricsPort {
		t.Errorf("port default = %q", got)
	}
	if strings.Contains(cmd.Long, "to be implemented") {
		t.Error("help text still advertises an unimplemented command")
	}
}

func TestMetricsCommand_ClientsNotReady(t *testing.T) {
	clearClients(t)
	_, err := runCommand(t, NewMetricsCommand())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateMetricsOptions(t *testing.T) {
	base := func() *metricsOptions {
		return &metricsOptions{component: componentAll, output: "table", port: defaultMetricsPort, path: "/metrics", interval: time.Second}
	}
	tests := []struct {
		name    string
		mutate  func(*metricsOptions)
		wantErr string
	}{
		{name: "defaults are valid", mutate: func(*metricsOptions) {}},
		{name: "bad component", mutate: func(o *metricsOptions) { o.component = "sidecar" }, wantErr: "invalid --component"},
		{name: "bad output", mutate: func(o *metricsOptions) { o.output = "yaml" }, wantErr: "invalid --output"},
		{name: "empty port", mutate: func(o *metricsOptions) { o.port = "" }, wantErr: "invalid --port"},
		{name: "empty path", mutate: func(o *metricsOptions) { o.path = "" }, wantErr: "invalid --path"},
		{name: "zero interval with watch", mutate: func(o *metricsOptions) { o.watch = true; o.interval = 0 }, wantErr: "invalid --interval"},
		{name: "zero interval without watch is fine", mutate: func(o *metricsOptions) { o.interval = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := base()
			tt.mutate(opts)
			err := validateMetricsOptions(opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunMetrics_TableOutput(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &metricsOptions{
		component: componentAll,
		filter:    defaultMetricFilter,
		output:    "table",
		port:      defaultMetricsPort,
		path:      "/metrics",
		scrape:    staticScraper(sampleExposition),
	}
	var buf bytes.Buffer
	if err := runMetrics(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runMetrics: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"=== agent pahlevan-system/pahlevan-agent-aaa on node-a ===",
		"=== operator pahlevan-system/pahlevan-operator-1 on node-b ===",
		"METRIC\tTYPE\tLABELS\tVALUE",
		"pahlevan_blocked_syscalls_total",
		`{container="web",syscall="ptrace"}`,
		"counter",
		"metric families",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// The default filter must hide the Go collector metrics.
	if strings.Contains(out, "go_goroutines") {
		t.Errorf("default filter leaked non-pahlevan metrics:\n%s", out)
	}
}

func TestRunMetrics_FilterVariants(t *testing.T) {
	kube := twoPodCluster(t)
	tests := []struct {
		name       string
		filter     string
		wantSubstr string
		notWant    string
	}{
		{name: "substring", filter: "blocked", wantSubstr: "pahlevan_blocked_syscalls_total", notWant: "pahlevan_containers_tracked"},
		{name: "empty shows everything", filter: "", wantSubstr: "go_goroutines"},
		{name: "no match", filter: "nothing_here", wantSubstr: "no metrics matched filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &metricsOptions{
				component: componentAgent, filter: tt.filter, output: "table",
				port: defaultMetricsPort, path: "/metrics", scrape: staticScraper(sampleExposition),
			}
			var buf bytes.Buffer
			if err := runMetrics(context.Background(), kube, opts, &buf); err != nil {
				t.Fatalf("runMetrics: %v", err)
			}
			out := buf.String()
			if !strings.Contains(out, tt.wantSubstr) {
				t.Errorf("output missing %q:\n%s", tt.wantSubstr, out)
			}
			if tt.notWant != "" && strings.Contains(out, tt.notWant) {
				t.Errorf("output should not contain %q:\n%s", tt.notWant, out)
			}
		})
	}
}

func TestRunMetrics_JSONOutput(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &metricsOptions{
		component: componentAgent, filter: defaultMetricFilter, output: "json",
		port: defaultMetricsPort, path: "/metrics", scrape: staticScraper(sampleExposition),
	}
	var buf bytes.Buffer
	if err := runMetrics(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runMetrics: %v", err)
	}
	var doc metricsDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(doc.Targets) != 1 {
		t.Fatalf("targets = %d", len(doc.Targets))
	}
	target := doc.Targets[0]
	if target.Component != componentAgent || target.Node != "node-a" {
		t.Errorf("target = %+v", target)
	}
	if len(target.Families) != 3 {
		t.Errorf("families = %d, want 3 pahlevan families", len(target.Families))
	}
	if doc.Filter != defaultMetricFilter {
		t.Errorf("filter = %q", doc.Filter)
	}
}

func TestRunMetrics_RawOutput(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &metricsOptions{
		component: componentAgent, filter: defaultMetricFilter, output: "raw",
		port: defaultMetricsPort, path: "/metrics", scrape: staticScraper(sampleExposition),
	}
	var buf bytes.Buffer
	if err := runMetrics(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runMetrics: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# source: agent pahlevan-system/pahlevan-agent-aaa on node-a") {
		t.Errorf("source header missing:\n%s", out)
	}
	if !strings.Contains(out, "# HELP pahlevan_blocked_syscalls_total") {
		t.Errorf("raw exposition missing:\n%s", out)
	}
	if strings.Contains(out, "go_goroutines") {
		t.Errorf("raw output should honour the filter:\n%s", out)
	}
	// The filtered raw output must still be parseable.
	if _, err := parsePrometheusText(strings.NewReader(strings.ReplaceAll(out, "# source:", "#source:"))); err != nil {
		t.Errorf("filtered raw output no longer parses: %v", err)
	}
}

func TestRunMetrics_ScrapeArguments(t *testing.T) {
	kube := twoPodCluster(t)
	rec := &recordingScraper{body: sampleExposition}
	opts := &metricsOptions{
		component: componentOperator, filter: defaultMetricFilter, output: "table",
		port: "9090", path: "/custom-metrics", scrape: rec.scrape,
	}
	if err := runMetrics(context.Background(), kube, opts, io.Discard); err != nil {
		t.Fatalf("runMetrics: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("calls = %+v", rec.calls)
	}
	c := rec.calls[0]
	if c.pod != "pahlevan-operator-1" || c.port != "9090" || c.path != "/custom-metrics" || c.namespace != "pahlevan-system" {
		t.Errorf("call = %+v", c)
	}
}

func TestRunMetrics_AllScrapesFail(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &metricsOptions{
		component: componentAll, filter: defaultMetricFilter, output: "table",
		port: defaultMetricsPort, path: "/metrics",
		scrape: func(context.Context, string, string, string, string) ([]byte, error) {
			return nil, errors.New("proxy forbidden")
		},
	}
	var buf bytes.Buffer
	err := runMetrics(context.Background(), kube, opts, &buf)
	if err == nil || !strings.Contains(err.Error(), "could not scrape metrics from any") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(buf.String(), "proxy forbidden") {
		t.Errorf("per-target error should still be printed:\n%s", buf.String())
	}
}

func TestRunMetrics_UnparseablePayloadIsReported(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &metricsOptions{
		component: componentAgent, filter: defaultMetricFilter, output: "table",
		port: defaultMetricsPort, path: "/metrics",
		scrape: staticScraper("this is not prometheus text\n"),
	}
	var buf bytes.Buffer
	err := runMetrics(context.Background(), kube, opts, &buf)
	if err == nil {
		t.Fatal("expected an error when nothing could be scraped")
	}
	if !strings.Contains(buf.String(), "parse metrics") {
		t.Errorf("parse error not surfaced:\n%s", buf.String())
	}
}

func TestRunMetrics_NoPodsIsActionable(t *testing.T) {
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
	opts := &metricsOptions{component: componentAll, filter: defaultMetricFilter, output: "table", port: defaultMetricsPort, path: "/metrics"}
	err := runMetrics(context.Background(), kc, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no Pahlevan") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunMetrics_WatchLoopsAndStops(t *testing.T) {
	kube := twoPodCluster(t)
	var scrapes int64
	ctx, cancel := context.WithCancel(context.Background())
	opts := &metricsOptions{
		component: componentAgent, filter: defaultMetricFilter, output: "table",
		port: defaultMetricsPort, path: "/metrics", watch: true, interval: time.Millisecond,
		scrape: func(context.Context, string, string, string, string) ([]byte, error) {
			if atomic.AddInt64(&scrapes, 1) >= 3 {
				cancel()
			}
			return []byte(sampleExposition), nil
		},
	}
	var buf bytes.Buffer
	if err := runMetrics(ctx, kube, opts, &buf); err != nil {
		t.Fatalf("runMetrics: %v", err)
	}
	if atomic.LoadInt64(&scrapes) < 3 {
		t.Errorf("watch scraped %d times, want at least 3", scrapes)
	}
	if !strings.Contains(buf.String(), "ctrl-c to stop") {
		t.Errorf("watch banner missing:\n%s", buf.String()[:200])
	}
}

func TestRunMetrics_ValidationRunsBeforeAPICalls(t *testing.T) {
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
	opts := &metricsOptions{component: componentAll, output: "xml", port: defaultMetricsPort, path: "/metrics"}
	err := runMetrics(context.Background(), kc, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "invalid --output") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientsetMetricsScraper(t *testing.T) {
	t.Run("proxy reactor supplies the body", func(t *testing.T) {
		_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
		kc.AddProxyReactor("pods", func(k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
			return true, staticResponseWrapper{body: sampleExposition}, nil
		})
		body, err := clientsetMetricsScraper(kc)(context.Background(), "pahlevan-system", "pod-1", "8080", "/metrics")
		if err != nil {
			t.Fatalf("scrape: %v", err)
		}
		if !strings.Contains(string(body), "pahlevan_blocked_syscalls_total") {
			t.Errorf("body = %q", string(body))
		}
	})

	t.Run("proxy error is wrapped", func(t *testing.T) {
		_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
		kc.AddProxyReactor("pods", func(k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
			return true, staticResponseWrapper{err: errors.New("connection refused")}, nil
		})
		_, err := clientsetMetricsScraper(kc)(context.Background(), "pahlevan-system", "pod-1", "8080", "/metrics")
		if err == nil || !strings.Contains(err.Error(), "proxy GET pod-1:8080/metrics") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("missing proxy support is reported", func(t *testing.T) {
		// With no proxy reactor registered the fake returns a nil wrapper.
		_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
		_, err := clientsetMetricsScraper(kc)(context.Background(), "pahlevan-system", "pod-1", "8080", "/metrics")
		if err == nil || !strings.Contains(err.Error(), "pod proxy is unavailable") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMetricsCommand_EndToEndViaProxy(t *testing.T) {
	core := twoPodCluster(t)
	_ = core
	_, kc, _, _, _ := GetClients()
	fakeClientset := kc.(interface {
		AddProxyReactor(string, k8stesting.ProxyReactionFunc)
	})
	fakeClientset.AddProxyReactor("pods", func(k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
		return true, staticResponseWrapper{body: sampleExposition}, nil
	})

	out, err := runCommand(t, NewMetricsCommand(), "-n", "pahlevan-system", "--component", "agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "pahlevan_containers_tracked") {
		t.Errorf("output = %s", out)
	}
}

func TestAllTargetsFailed(t *testing.T) {
	if !allTargetsFailed(&metricsDocument{}) {
		t.Error("an empty document counts as a total failure")
	}
	if !allTargetsFailed(&metricsDocument{Targets: []podMetrics{{Error: "x"}}}) {
		t.Error("all-error document should report failure")
	}
	if allTargetsFailed(&metricsDocument{Targets: []podMetrics{{Error: "x"}, {}}}) {
		t.Error("a partial failure is not a total failure")
	}
}

func TestFilterRawExposition(t *testing.T) {
	t.Run("empty filter passes through", func(t *testing.T) {
		out := filterRawExposition([]byte(sampleExposition), "")
		if string(out) != sampleExposition {
			t.Error("body should be untouched")
		}
	})
	t.Run("filter keeps help, type and series", func(t *testing.T) {
		out := string(filterRawExposition([]byte(sampleExposition), "pahlevan_containers_tracked"))
		if !strings.Contains(out, "# HELP pahlevan_containers_tracked") ||
			!strings.Contains(out, "# TYPE pahlevan_containers_tracked") ||
			!strings.Contains(out, "pahlevan_containers_tracked 42") {
			t.Errorf("out = %q", out)
		}
		if strings.Contains(out, "go_goroutines") {
			t.Errorf("unmatched metric leaked: %q", out)
		}
	})
	t.Run("unrecognised lines are dropped", func(t *testing.T) {
		out := string(filterRawExposition([]byte("# a bare comment\ngarbage\n\npahlevan_x 1\n"), "pahlevan_"))
		if out != "pahlevan_x 1\n" {
			t.Errorf("out = %q", out)
		}
	})
}

func TestCountSamples(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := countSamples(families); got != 8 {
		t.Errorf("countSamples = %d, want 8", got)
	}
	if countSamples(nil) != 0 {
		t.Error("nil families should count zero")
	}
}

func TestExtractHighlights(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	highlights := extractHighlights(families, "agent/pod-1")
	names := map[string]bool{}
	for _, h := range highlights {
		names[h.Metric] = true
		if h.Source != "agent/pod-1" {
			t.Errorf("source = %q", h.Source)
		}
	}
	if !names["pahlevan_containers_tracked"] || !names["pahlevan_blocked_syscalls_total"] {
		t.Errorf("highlights = %+v", highlights)
	}
	if names["pahlevan_syscall_processing_latency_seconds_sum"] {
		t.Error("non-highlight series should be excluded")
	}
	if len(extractHighlights(nil, "x")) != 0 {
		t.Error("nil families should yield no highlights")
	}
}

func BenchmarkScrapeAll(b *testing.B) {
	payload := []byte(benchExposition())
	pods := []componentPod{
		{Component: componentAgent, Pod: *agentPod("agent-1", "pahlevan-system", "node-a")},
		{Component: componentOperator, Pod: *operatorPod("operator-1", "pahlevan-system", "node-b")},
	}
	opts := &metricsOptions{filter: defaultMetricFilter}
	scrape := func(context.Context, string, string, string, string) ([]byte, error) { return payload, nil }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doc := scrapeAll(context.Background(), pods, opts, scrape)
		if len(doc.Targets) != 2 {
			b.Fatalf("targets = %d", len(doc.Targets))
		}
	}
}

func BenchmarkRenderMetricsTable(b *testing.B) {
	payload := []byte(benchExposition())
	pods := []componentPod{{Component: componentAgent, Pod: *agentPod("agent-1", "pahlevan-system", "node-a")}}
	doc := scrapeAll(context.Background(), pods, &metricsOptions{filter: defaultMetricFilter},
		func(context.Context, string, string, string, string) ([]byte, error) { return payload, nil })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := renderMetricsTable(io.Discard, doc); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

func BenchmarkFilterRawExposition(b *testing.B) {
	payload := []byte(benchExposition())
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(filterRawExposition(payload, defaultMetricFilter)) == 0 {
			b.Fatal("filter dropped everything")
		}
	}
}

func TestRenderMetrics_RawReportsTargetErrors(t *testing.T) {
	doc := &metricsDocument{
		ScrapedAt: "now",
		Filter:    defaultMetricFilter,
		Targets: []podMetrics{
			{Component: componentAgent, Namespace: "ns", Pod: "p1", Node: "n1", Error: "proxy refused"},
		},
	}
	var buf bytes.Buffer
	if err := renderMetrics(&buf, "raw", doc); err != nil {
		t.Fatalf("renderMetrics: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# error: proxy refused") {
		t.Errorf("error not rendered in raw output:\n%s", out)
	}
}

func TestRenderMetrics_RawWriteFailure(t *testing.T) {
	doc := &metricsDocument{Targets: []podMetrics{{Component: componentAgent, raw: []byte("x\n")}}}
	if err := renderMetrics(failingWriter{}, "raw", doc); err == nil {
		t.Fatal("expected the write error to propagate")
	}
}

func TestMetricsCommand_WatchThroughRunE(t *testing.T) {
	twoPodCluster(t)
	_, kc, _, _, _ := GetClients()
	kc.(interface {
		AddProxyReactor(string, k8stesting.ProxyReactionFunc)
	}).AddProxyReactor("pods", func(k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
		return true, staticResponseWrapper{body: sampleExposition}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := NewMetricsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"-n", "pahlevan-system", "--component", "agent", "--watch", "--interval", "1ms"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("watch through RunE: %v", err)
	}
	if !strings.Contains(buf.String(), "ctrl-c to stop") {
		t.Errorf("watch banner missing:\n%s", buf.String())
	}
}
