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
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

// staticLogFetcher returns canned log text per pod name.
func staticLogFetcher(byPod map[string]string) podLogFetcher {
	return func(_ context.Context, _, pod, _ string, _ *corev1.PodLogOptions) (io.ReadCloser, error) {
		text, ok := byPod[pod]
		if !ok {
			return nil, fmt.Errorf("no logs for %s", pod)
		}
		return io.NopCloser(strings.NewReader(text)), nil
	}
}

// recordingLogFetcher captures the options each call was made with.
type recordingLogFetcher struct {
	mu    sync.Mutex
	calls []struct {
		namespace, pod, container string
		opts                      corev1.PodLogOptions
	}
	text string
	err  error
}

func (r *recordingLogFetcher) fetch(_ context.Context, namespace, pod, container string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
	r.mu.Lock()
	r.calls = append(r.calls, struct {
		namespace, pod, container string
		opts                      corev1.PodLogOptions
	}{namespace, pod, container, *opts})
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return io.NopCloser(strings.NewReader(r.text)), nil
}

// errReadCloser fails partway through a read, exercising the copy error path.
type errReadCloser struct {
	read bool
}

func (e *errReadCloser) Read(p []byte) (int, error) {
	if !e.read {
		e.read = true
		n := copy(p, "first line\n")
		return n, nil
	}
	return 0, errors.New("stream reset by peer")
}

func (e *errReadCloser) Close() error { return nil }

func twoPodCluster(t *testing.T) kubernetes.Interface {
	t.Helper()
	core := []runtime.Object{
		agentPod("pahlevan-agent-aaa", "pahlevan-system", "node-a"),
		operatorPod("pahlevan-operator-1", "pahlevan-system", "node-b"),
	}
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", core)
	return kc
}

func TestNewLogsCommand_Flags(t *testing.T) {
	cmd := NewLogsCommand()
	if cmd.Use != "logs" {
		t.Errorf("Use = %q", cmd.Use)
	}
	for _, f := range []string{"namespace", "component", "node", "follow", "tail", "since", "previous", "container", "timestamps", "prefix"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("logs missing flag %q", f)
		}
	}
	if cmd.Flags().ShorthandLookup("f") == nil {
		t.Error("logs missing -f shorthand")
	}
	if strings.Contains(cmd.Long, "to be implemented") {
		t.Error("help text still advertises an unimplemented command")
	}
	if got := cmd.Flags().Lookup("component").DefValue; got != componentAll {
		t.Errorf("component default = %q", got)
	}
}

func TestLogsCommand_ClientsNotReady(t *testing.T) {
	clearClients(t)
	_, err := runCommand(t, NewLogsCommand())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateLogsOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    logsOptions
		wantErr string
		check   func(t *testing.T, o *corev1.PodLogOptions)
	}{
		{
			name: "defaults",
			opts: logsOptions{component: componentAll, prefix: "auto", tail: 200},
			check: func(t *testing.T, o *corev1.PodLogOptions) {
				if o.TailLines == nil || *o.TailLines != 200 {
					t.Errorf("tail = %v", o.TailLines)
				}
				if o.SinceSeconds != nil {
					t.Errorf("since should be unset: %v", *o.SinceSeconds)
				}
			},
		},
		{
			name: "negative tail means the whole log",
			opts: logsOptions{component: componentAll, prefix: "auto", tail: -1},
			check: func(t *testing.T, o *corev1.PodLogOptions) {
				if o.TailLines != nil {
					t.Errorf("tail should be unset, got %d", *o.TailLines)
				}
			},
		},
		{
			name: "since duration",
			opts: logsOptions{component: componentAll, prefix: "auto", tail: 10, since: "90s"},
			check: func(t *testing.T, o *corev1.PodLogOptions) {
				if o.SinceSeconds == nil || *o.SinceSeconds != 90 {
					t.Errorf("since = %v", o.SinceSeconds)
				}
			},
		},
		{
			name: "sub-second since rounds up to one second",
			opts: logsOptions{component: componentAll, prefix: "auto", since: "500ms"},
			check: func(t *testing.T, o *corev1.PodLogOptions) {
				if o.SinceSeconds == nil || *o.SinceSeconds != 1 {
					t.Errorf("since = %v", o.SinceSeconds)
				}
			},
		},
		{
			name: "previous and timestamps propagate",
			opts: logsOptions{component: componentAgent, prefix: "never", previous: true, timestamps: true},
			check: func(t *testing.T, o *corev1.PodLogOptions) {
				if !o.Previous || !o.Timestamps {
					t.Errorf("opts = %+v", o)
				}
			},
		},
		{name: "bad component", opts: logsOptions{component: "sidecar", prefix: "auto"}, wantErr: "invalid --component"},
		{name: "bad prefix", opts: logsOptions{component: componentAll, prefix: "sometimes"}, wantErr: "invalid --prefix"},
		{name: "previous with follow", opts: logsOptions{component: componentAll, prefix: "auto", previous: true, follow: true}, wantErr: "--previous cannot be combined"},
		{name: "bad since", opts: logsOptions{component: componentAll, prefix: "auto", since: "yesterday"}, wantErr: "invalid --since"},
		{name: "negative since", opts: logsOptions{component: componentAll, prefix: "auto", since: "-5m"}, wantErr: "positive duration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			got, err := validateLogsOptions(&opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestRunLogs_MultiplexesWithPrefix(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		tail:      100,
		fetch: staticLogFetcher(map[string]string{
			"pahlevan-agent-aaa":  "agent line 1\nagent line 2\n",
			"pahlevan-operator-1": "operator line 1\n",
		}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"[agent/pahlevan-agent-aaa@node-a] agent line 1",
		"[agent/pahlevan-agent-aaa@node-a] agent line 2",
		"[operator/pahlevan-operator-1@node-b] operator line 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunLogs_SinglePodHasNoPrefix(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentOperator,
		prefix:    "auto",
		fetch:     staticLogFetcher(map[string]string{"pahlevan-operator-1": "solo line\n"}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if buf.String() != "solo line\n" {
		t.Errorf("output = %q", buf.String())
	}
}

func TestRunLogs_PrefixAlwaysAndNever(t *testing.T) {
	kube := twoPodCluster(t)
	logs := map[string]string{
		"pahlevan-agent-aaa":  "a\n",
		"pahlevan-operator-1": "b\n",
	}

	t.Run("always prefixes a single pod", func(t *testing.T) {
		var buf bytes.Buffer
		opts := &logsOptions{component: componentAgent, prefix: "always", fetch: staticLogFetcher(logs)}
		if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
			t.Fatalf("runLogs: %v", err)
		}
		if !strings.HasPrefix(buf.String(), "[agent/pahlevan-agent-aaa@node-a] ") {
			t.Errorf("output = %q", buf.String())
		}
	})

	t.Run("never falls back to a section header", func(t *testing.T) {
		var buf bytes.Buffer
		opts := &logsOptions{component: componentAll, prefix: "never", fetch: staticLogFetcher(logs)}
		if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
			t.Fatalf("runLogs: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "==== [agent/pahlevan-agent-aaa@node-a] ====") {
			t.Errorf("section header missing:\n%s", out)
		}
		if strings.Contains(out, "] a") {
			t.Errorf("lines should not be prefixed:\n%s", out)
		}
	})
}

func TestRunLogs_NodeFilterSelectsOneAgent(t *testing.T) {
	core := []runtime.Object{
		agentPod("agent-a", "pahlevan-system", "node-a"),
		agentPod("agent-b", "pahlevan-system", "node-b"),
	}
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", core)

	rec := &recordingLogFetcher{text: "line\n"}
	opts := &logsOptions{component: componentAgent, node: "node-b", prefix: "auto", tail: 5, fetch: rec.fetch}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kc, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].pod != "agent-b" {
		t.Fatalf("calls = %+v", rec.calls)
	}
	if rec.calls[0].container != "agent" {
		t.Errorf("container = %q", rec.calls[0].container)
	}
	if rec.calls[0].opts.TailLines == nil || *rec.calls[0].opts.TailLines != 5 {
		t.Errorf("tail not propagated: %+v", rec.calls[0].opts)
	}
}

func TestRunLogs_ContainerOverride(t *testing.T) {
	kube := twoPodCluster(t)
	rec := &recordingLogFetcher{text: "x\n"}
	opts := &logsOptions{component: componentAgent, container: "debug", prefix: "auto", fetch: rec.fetch}
	if err := runLogs(context.Background(), kube, opts, io.Discard); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if rec.calls[0].container != "debug" {
		t.Errorf("container = %q", rec.calls[0].container)
	}
}

func TestRunLogs_NoPodsIsActionable(t *testing.T) {
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
	opts := &logsOptions{component: componentAll, prefix: "auto"}
	err := runLogs(context.Background(), kc, opts, io.Discard)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"no Pahlevan", "DaemonSet", "--namespace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

func TestRunLogs_AllFetchesFail(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		fetch: func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
			return nil, errors.New("forbidden")
		},
	}
	err := runLogs(context.Background(), kube, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "could not read logs from any") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("underlying cause missing: %v", err)
	}
}

func TestRunLogs_PartialFailureWarnsAndContinues(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		fetch:     staticLogFetcher(map[string]string{"pahlevan-agent-aaa": "agent line\n"}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("a partial failure must not fail the command: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "agent line") {
		t.Errorf("successful stream missing:\n%s", out)
	}
	if !strings.Contains(out, "warning: [operator/pahlevan-operator-1@node-b]") {
		t.Errorf("warning missing:\n%s", out)
	}
}

func TestRunLogs_EmptyLogsExplained(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		fetch: staticLogFetcher(map[string]string{
			"pahlevan-agent-aaa":  "",
			"pahlevan-operator-1": "",
		}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if !strings.Contains(buf.String(), "no log lines matched") {
		t.Errorf("empty result should be explained:\n%s", buf.String())
	}
}

func TestRunLogs_ReadErrorIsWarned(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAgent,
		prefix:    "always",
		fetch: func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
			return &errReadCloser{}, nil
		},
	}
	var buf bytes.Buffer
	err := runLogs(context.Background(), kube, opts, &buf)
	// A single pod that fails mid-stream is a total failure for that selection.
	if err == nil || !strings.Contains(err.Error(), "stream reset by peer") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogs_FollowMultiplexes(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		follow:    true,
		fetch: staticLogFetcher(map[string]string{
			"pahlevan-agent-aaa":  "agent a\nagent b\n",
			"pahlevan-operator-1": "operator a\n",
		}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"[agent/pahlevan-agent-aaa@node-a] agent a",
		"[agent/pahlevan-agent-aaa@node-a] agent b",
		"[operator/pahlevan-operator-1@node-b] operator a",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("follow output missing %q:\n%s", want, out)
		}
	}
	// Every line must be whole: no interleaving mid-line.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "[") {
			t.Errorf("line lost its prefix (interleaved write?): %q", line)
		}
	}
}

func TestRunLogs_FollowAllFail(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		follow:    true,
		fetch: func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
			return nil, errors.New("connection refused")
		},
	}
	err := runLogs(context.Background(), kube, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "could not follow logs from any") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogs_FollowPartialFailureWarns(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		follow:    true,
		fetch:     staticLogFetcher(map[string]string{"pahlevan-agent-aaa": "only agent\n"}),
	}
	var buf bytes.Buffer
	if err := runLogs(context.Background(), kube, opts, &buf); err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if !strings.Contains(buf.String(), "warning:") {
		t.Errorf("warning missing:\n%s", buf.String())
	}
}

func TestRunLogs_FollowStopsOnCancelledContext(t *testing.T) {
	kube := twoPodCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		follow:    true,
		fetch:     staticLogFetcher(map[string]string{"pahlevan-agent-aaa": "x\n", "pahlevan-operator-1": "y\n"}),
	}
	if err := runLogs(ctx, kube, opts, io.Discard); err != nil {
		t.Fatalf("a canceled follow should exit cleanly: %v", err)
	}
}

// failingWriter rejects every write, exercising the follow writer error path.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunLogs_FollowWriteErrorPropagates(t *testing.T) {
	kube := twoPodCluster(t)
	opts := &logsOptions{
		component: componentAll,
		prefix:    "auto",
		follow:    true,
		fetch:     staticLogFetcher(map[string]string{"pahlevan-agent-aaa": "x\n", "pahlevan-operator-1": "y\n"}),
	}
	err := runLogs(context.Background(), kube, opts, failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "write log line") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogs_ValidationRunsBeforeAPICalls(t *testing.T) {
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
	opts := &logsOptions{component: "bogus", prefix: "auto"}
	err := runLogs(context.Background(), kc, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "invalid --component") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientsetLogFetcher_UsesFakeClientset(t *testing.T) {
	kube := twoPodCluster(t)
	fetch := clientsetLogFetcher(kube)
	rc, err := fetch(context.Background(), "pahlevan-system", "pahlevan-agent-aaa", "agent", &corev1.PodLogOptions{})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "fake logs" {
		t.Errorf("data = %q", string(data))
	}
}

func TestLogsCommand_EndToEndWithFakeClientset(t *testing.T) {
	twoPodCluster(t)
	out, err := runCommand(t, NewLogsCommand(), "--component", "operator", "-n", "pahlevan-system")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "fake logs") {
		t.Errorf("output = %q", out)
	}
}

func TestCopyPrefixed(t *testing.T) {
	t.Run("no prefix copies verbatim", func(t *testing.T) {
		var buf bytes.Buffer
		n, err := copyPrefixed(&buf, strings.NewReader("a\nb"), "")
		if err != nil {
			t.Fatalf("copyPrefixed: %v", err)
		}
		if n != 1 || buf.String() != "a\nb" {
			t.Errorf("n = %d, out = %q", n, buf.String())
		}
	})
	t.Run("empty input", func(t *testing.T) {
		var buf bytes.Buffer
		n, err := copyPrefixed(&buf, strings.NewReader(""), "")
		if err != nil || n != 0 {
			t.Errorf("n = %d, err = %v", n, err)
		}
	})
	t.Run("prefix per line", func(t *testing.T) {
		var buf bytes.Buffer
		n, err := copyPrefixed(&buf, strings.NewReader("a\nb\n"), "P ")
		if err != nil {
			t.Fatalf("copyPrefixed: %v", err)
		}
		if n != 2 || buf.String() != "P a\nP b\n" {
			t.Errorf("n = %d, out = %q", n, buf.String())
		}
	})
	t.Run("write failure surfaces", func(t *testing.T) {
		_, err := copyPrefixed(failingWriter{}, strings.NewReader("a\n"), "P ")
		if err == nil {
			t.Fatal("expected a write error")
		}
	})
}

func TestLogSourceLabelAndContainerFor(t *testing.T) {
	p := componentPod{Component: componentAgent, Pod: *agentPod("a1", "ns", "n1")}
	if got := logSourceLabel(p); got != "[agent/a1@n1]" {
		t.Errorf("label = %q", got)
	}
	if got := containerFor(p, ""); got != "agent" {
		t.Errorf("container = %q", got)
	}
	if got := containerFor(p, "override"); got != "override" {
		t.Errorf("container = %q", got)
	}
}

func TestFormatRestarts(t *testing.T) {
	if got := formatRestarts(0); got != "0" {
		t.Errorf("got %q", got)
	}
	if got := formatRestarts(7); got != "7" {
		t.Errorf("got %q", got)
	}
}

func BenchmarkCopyPrefixed(b *testing.B) {
	var payload strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&payload, "2025-08-14T10:00:00Z INFO reconciling container profile id=%d node=worker-1\n", i)
	}
	text := payload.String()
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := copyPrefixed(io.Discard, strings.NewReader(text), "[agent/pahlevan-agent-aaa@node-a] "); err != nil {
			b.Fatalf("copyPrefixed: %v", err)
		}
	}
}

func TestLogsCommand_FollowThroughRunE(t *testing.T) {
	twoPodCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := NewLogsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"-n", "pahlevan-system", "--component", "operator", "--follow"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("follow through RunE: %v", err)
	}
}

func TestLogsCommand_NilCommandContext(t *testing.T) {
	twoPodCluster(t)
	cmd := NewLogsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"-n", "pahlevan-system", "--component", "agent"})
	// Execute (not ExecuteContext) leaves the command context unset on older
	// cobra paths; the command must still run.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "fake logs") {
		t.Errorf("output = %q", buf.String())
	}
}
