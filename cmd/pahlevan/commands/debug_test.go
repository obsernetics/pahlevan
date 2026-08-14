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
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func testNode(name, kernel string, ready bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           kernel,
				OSImage:                 "Ubuntu 24.04 LTS",
				ContainerRuntimeVersion: "containerd://2.0.0",
				Architecture:            "amd64",
			},
		},
	}
}

func pahlevanEvent(name, namespace, kind, objName, reason, msg string, when time.Time) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: namespace},
		InvolvedObject: corev1.ObjectReference{Kind: kind, Name: objName, Namespace: namespace},
		Reason:         reason,
		Message:        msg,
		Type:           corev1.EventTypeWarning,
		Count:          1,
		LastTimestamp:  metav1.NewTime(when),
	}
}

// debugCluster seeds a small but complete cluster for the bundle.
func debugCluster(t *testing.T) (*debugOptions, []runtime.Object, []crclient.Object) {
	t.Helper()
	now := time.Now()
	core := []runtime.Object{
		agentPod("pahlevan-agent-aaa", "pahlevan-system", "node-a"),
		operatorPod("pahlevan-operator-1", "pahlevan-system", "node-a"),
		testNode("node-a", "6.8.0-40-generic", true),
		testNode("node-b", "5.4.0-90-generic", true),
		pahlevanEvent("e1", "prod", "PahlevanPolicy", "web-policy", "LearningComplete", "learning window elapsed", now.Add(-5*time.Minute)),
		pahlevanEvent("e2", "default", "Pod", "some-other-pod", "Started", "not related", now.Add(-time.Minute)),
	}
	crObjs := []crclient.Object{
		makeAttackSurface("web", "prod", int32Ptr(80), nil),
		makeContainerProfile("web-1", "prod", "web", "Enforcing", nil),
		&policyv1alpha1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "web-policy", Namespace: "prod"}},
	}
	opts := &debugOptions{
		namespace: "pahlevan-system",
		component: componentAll,
		output:    "table",
		events:    20,
		fetch: func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("INFO started agent\nINFO attached raw_tracepoint sys_enter\n")), nil
		},
		scrape: staticScraper(sampleExposition),
	}
	return opts, core, crObjs
}

func TestNewDebugCommand_Flags(t *testing.T) {
	cmd := NewDebugCommand()
	if cmd.Use != "debug" {
		t.Errorf("Use = %q", cmd.Use)
	}
	for _, f := range []string{"namespace", "component", "output", "file", "events", "skip-logs"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("debug missing flag %q", f)
		}
	}
	if strings.Contains(cmd.Long, "to be implemented") {
		t.Error("help text still advertises an unimplemented command")
	}
	if !strings.Contains(cmd.Long, "never reads Secrets") {
		t.Error("help should state the command does not read secrets")
	}
}

func TestDebugCommand_ClientsNotReady(t *testing.T) {
	clearClients(t)
	_, err := runCommand(t, NewDebugCommand())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDebug_Validation(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	tests := []struct {
		name    string
		mutate  func(*debugOptions)
		wantErr string
	}{
		{name: "bad component", mutate: func(o *debugOptions) { o.component = "sidecar" }, wantErr: "invalid --component"},
		{name: "bad output", mutate: func(o *debugOptions) { o.output = "raw" }, wantErr: "invalid --output"},
		{name: "negative events", mutate: func(o *debugOptions) { o.events = -1 }, wantErr: "invalid --events"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := *opts
			tt.mutate(&o)
			err := runDebug(context.Background(), fc, kc, &o, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunDebug_TableBundle(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Pahlevan Debug Bundle",
		"Component pods",
		"pahlevan-agent-aaa",
		"pahlevan-operator-1",
		"Nodes",
		"6.8.0-40-generic",
		"Custom resource definitions",
		"PahlevanPolicy",
		"ContainerProfile",
		"AttackSurface",
		"Recent Pahlevan events",
		"LearningComplete",
		"Metric highlights",
		"pahlevan_containers_tracked",
		"Secrets, ServiceAccount tokens",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bundle missing %q:\n%s", want, out)
		}
	}
	// node-a has a healthy agent on a 6.8 kernel with no attach failures.
	if !strings.Contains(out, lsmStateLikelyOn) {
		t.Errorf("expected a %q verdict:\n%s", lsmStateLikelyOn, out)
	}
	// node-b runs 5.4, which predates CONFIG_BPF_LSM.
	if !strings.Contains(out, lsmStateTooOld) {
		t.Errorf("expected a %q verdict:\n%s", lsmStateTooOld, out)
	}
	// An unrelated pod event must not be pulled in.
	if strings.Contains(out, "not related") {
		t.Errorf("unrelated event leaked into the bundle:\n%s", out)
	}
}

func TestRunDebug_JSONAndYAML(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	t.Run("json", func(t *testing.T) {
		o := *opts
		o.output = "json"
		var buf strings.Builder
		if err := runDebug(context.Background(), fc, kc, &o, &buf); err != nil {
			t.Fatalf("runDebug: %v", err)
		}
		var bundle debugBundle
		if err := json.Unmarshal([]byte(buf.String()), &bundle); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
		}
		if len(bundle.Components) != 2 {
			t.Errorf("components = %d", len(bundle.Components))
		}
		if len(bundle.Nodes) != 2 {
			t.Errorf("nodes = %d", len(bundle.Nodes))
		}
		crdCounts := map[string]int{}
		for _, c := range bundle.CRDs {
			if !c.Installed {
				t.Errorf("CRD %s reported as missing", c.Kind)
			}
			crdCounts[c.Kind] = c.Count
		}
		if crdCounts["AttackSurface"] != 1 || crdCounts["ContainerProfile"] != 1 || crdCounts["PahlevanPolicy"] != 1 {
			t.Errorf("crd counts = %+v", crdCounts)
		}
		if len(bundle.Events) != 1 || bundle.Events[0].Reason != "LearningComplete" {
			t.Errorf("events = %+v", bundle.Events)
		}
		if len(bundle.Metrics) == 0 {
			t.Error("metric highlights missing")
		}
		if len(bundle.Notes) == 0 {
			t.Error("notes missing")
		}
	})

	t.Run("yaml", func(t *testing.T) {
		o := *opts
		o.output = "yaml"
		var buf strings.Builder
		if err := runDebug(context.Background(), fc, kc, &o, &buf); err != nil {
			t.Fatalf("runDebug: %v", err)
		}
		var bundle debugBundle
		if err := yaml.Unmarshal([]byte(buf.String()), &bundle); err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
		if bundle.Scope != `namespace "pahlevan-system"` {
			t.Errorf("scope = %q", bundle.Scope)
		}
	})
}

func TestRunDebug_WritesFile(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	path := filepath.Join(t.TempDir(), "bundle.json")
	opts.output = "json"
	opts.file = path
	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	if !strings.Contains(buf.String(), "Debug bundle written to "+path) {
		t.Errorf("confirmation missing: %s", buf.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	var bundle debugBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
}

func TestRunDebug_FileErrorIsActionable(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)
	opts.file = filepath.Join(t.TempDir(), "no-such-dir", "bundle.txt")
	err := runDebug(context.Background(), fc, kc, opts, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot write report to") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDebug_LSMDisabledFromAgentLog(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	opts.fetch = func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(
			"INFO booting\n" +
				`ERROR lsm/file_open attach failed; file enforcement/observation disabled (enable with lsm=...,bpf) error="no such file"` + "\n")), nil
	}
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, lsmStateDisabled) {
		t.Errorf("expected a Disabled verdict:\n%s", out)
	}
	if !strings.Contains(out, "lsm/file_open attach failure") {
		t.Errorf("verdict should name the hook:\n%s", out)
	}
}

func TestRunDebug_SkipLogs(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	called := false
	opts.skipLogs = true
	opts.fetch = func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
		called = true
		return io.NopCloser(strings.NewReader("")), nil
	}
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	if called {
		t.Error("--skip-logs must not read any log")
	}
	if !strings.Contains(buf.String(), "log inspection skipped") {
		t.Errorf("skip reason missing:\n%s", buf.String())
	}
}

func TestRunDebug_NoComponentsWarns(t *testing.T) {
	opts := &debugOptions{
		namespace: "pahlevan-system",
		component: componentAll,
		output:    "json",
		events:    5,
		scrape:    staticScraper(sampleExposition),
	}
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", []runtime.Object{testNode("node-a", "6.8.0", true)})

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("a missing install must still produce a bundle: %v", err)
	}
	var bundle debugBundle
	if err := json.Unmarshal([]byte(buf.String()), &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(bundle.Warnings) == 0 || !strings.Contains(bundle.Warnings[0], "no Pahlevan") {
		t.Errorf("warnings = %v", bundle.Warnings)
	}
	if bundle.Nodes[0].BPFLSM != lsmStateUnknown {
		t.Errorf("a node with no agent should be Unknown, got %q", bundle.Nodes[0].BPFLSM)
	}
}

func TestRunDebug_DegradesWhenSubsystemsFail(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	opts.output = "json"
	opts.scrape = func(context.Context, string, string, string, string) ([]byte, error) {
		return nil, errors.New("proxy forbidden")
	}
	opts.fetch = func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
		return nil, errors.New("logs forbidden")
	}
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)
	kc.PrependReactor("list", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "events"}, "", errors.New("nope"))
	})

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("a degraded cluster must still produce a bundle: %v", err)
	}
	var bundle debugBundle
	if err := json.Unmarshal([]byte(buf.String()), &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	joined := strings.Join(bundle.Warnings, "|")
	for _, want := range []string{"failed to list events", "metrics scrape of", "proxy forbidden"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q: %v", want, bundle.Warnings)
		}
	}
	// The unreadable log must show up as an Unknown LSM verdict, not a crash.
	found := false
	for _, n := range bundle.Nodes {
		if n.Name == "node-a" {
			found = true
			if n.BPFLSM != lsmStateUnknown || !strings.Contains(n.BPFLSMDetail, "logs forbidden") {
				t.Errorf("node-a = %+v", n)
			}
		}
	}
	if !found {
		t.Error("node-a missing from the bundle")
	}
}

func TestRunDebug_NodeListFailureIsWarned(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	opts.output = "json"
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)
	kc.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nodes unavailable")
	})

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	if !strings.Contains(buf.String(), "failed to list nodes") {
		t.Errorf("warning missing:\n%s", buf.String())
	}
}

func TestRunDebug_ZeroEventsSkipsEventCollection(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	opts.output = "json"
	opts.events = 0
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	var buf strings.Builder
	if err := runDebug(context.Background(), fc, kc, opts, &buf); err != nil {
		t.Fatalf("runDebug: %v", err)
	}
	var bundle debugBundle
	if err := json.Unmarshal([]byte(buf.String()), &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(bundle.Events) != 0 {
		t.Errorf("events = %+v", bundle.Events)
	}
}

func TestCollectPahlevanEvents_LimitKeepsMostRecent(t *testing.T) {
	now := time.Now()
	core := []runtime.Object{
		pahlevanEvent("old", "prod", "PahlevanPolicy", "p", "Old", "old", now.Add(-3*time.Hour)),
		pahlevanEvent("mid", "prod", "ContainerProfile", "c", "Mid", "mid", now.Add(-2*time.Hour)),
		pahlevanEvent("new", "prod", "AttackSurface", "a", "New", "new", now.Add(-time.Minute)),
	}
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", core)

	events, warnings := collectPahlevanEvents(context.Background(), kc, "pahlevan-system", nil, 2)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if len(events) != 2 {
		t.Fatalf("events = %+v", events)
	}
	reasons := events[0].Reason + "," + events[1].Reason
	if reasons != "Mid,New" {
		t.Errorf("kept %s, want the two most recent", reasons)
	}
}

func TestEventIsPahlevanRelated(t *testing.T) {
	podNames := map[string]struct{}{"pahlevan-agent-x": {}}
	tests := []struct {
		name  string
		event corev1.Event
		ns    string
		want  bool
	}{
		{name: "custom resource kind", event: corev1.Event{InvolvedObject: corev1.ObjectReference{Kind: "AttackSurface", Name: "a"}}, want: true},
		{name: "component pod", event: corev1.Event{InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "pahlevan-agent-x"}}, want: true},
		{name: "component namespace", event: corev1.Event{ObjectMeta: metav1.ObjectMeta{Namespace: "pahlevan-system"}}, ns: "pahlevan-system", want: true},
		{name: "name contains pahlevan", event: corev1.Event{InvolvedObject: corev1.ObjectReference{Kind: "Deployment", Name: "Pahlevan-Operator"}}, want: true},
		{name: "source component", event: corev1.Event{Source: corev1.EventSource{Component: "pahlevan-controller"}}, want: true},
		{name: "unrelated", event: corev1.Event{ObjectMeta: metav1.ObjectMeta{Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "nginx"}}, ns: "pahlevan-system", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventIsPahlevanRelated(&tt.event, podNames, tt.ns); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLatestEventTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	series := &corev1.Event{Series: &corev1.EventSeries{LastObservedTime: metav1.NewMicroTime(now)}}
	if !latestEventTime(series).Equal(now) {
		t.Errorf("series time not used: %v", latestEventTime(series))
	}
	last := &corev1.Event{LastTimestamp: metav1.NewTime(now)}
	if !latestEventTime(last).Equal(now) {
		t.Errorf("last timestamp not used: %v", latestEventTime(last))
	}
	created := &corev1.Event{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(now)}}
	if !latestEventTime(created).Equal(now) {
		t.Errorf("creation timestamp fallback failed: %v", latestEventTime(created))
	}
}

func TestClassifyLSMLog(t *testing.T) {
	tests := []struct {
		name       string
		logText    string
		agentReady bool
		wantState  string
		wantDetail string
	}{
		{
			name:       "file_open attach failure",
			logText:    "INFO x\nlsm/file_open attach failed; file enforcement disabled\n",
			agentReady: true,
			wantState:  lsmStateDisabled,
			wantDetail: "lsm/file_open",
		},
		{
			name:       "socket_connect attach failure",
			logText:    "lsm/socket_connect attach failed; network observation disabled\n",
			agentReady: true,
			wantState:  lsmStateDisabled,
			wantDetail: "lsm/socket_connect",
		},
		{
			name:       "clean log on a ready agent",
			logText:    "INFO attached raw_tracepoint sys_enter\n",
			agentReady: true,
			wantState:  lsmStateLikelyOn,
		},
		{
			name:       "clean log on an unready agent",
			logText:    "INFO starting\n",
			agentReady: false,
			wantState:  lsmStateUnknown,
		},
		{
			name:       "unrelated attach failure is not an LSM verdict",
			logText:    "raw_tracepoint attach failed\n",
			agentReady: true,
			wantState:  lsmStateLikelyOn,
		},
		{
			name:       "empty log from an unready agent",
			logText:    "",
			agentReady: false,
			wantState:  lsmStateUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyLSMLog(tt.logText, tt.agentReady)
			if got.state != tt.wantState {
				t.Errorf("state = %q, want %q", got.state, tt.wantState)
			}
			if tt.wantDetail != "" && !strings.Contains(got.detail, tt.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", got.detail, tt.wantDetail)
			}
		})
	}
}

func TestKernelAtLeast(t *testing.T) {
	tests := []struct {
		version    string
		wantOK     bool
		wantParsed bool
	}{
		{version: "6.8.0-40-generic", wantOK: true, wantParsed: true},
		{version: "5.7.0", wantOK: true, wantParsed: true},
		{version: "5.6.19", wantOK: false, wantParsed: true},
		{version: "4.19.0", wantOK: false, wantParsed: true},
		{version: "5.15", wantOK: true, wantParsed: true},
		{version: "", wantParsed: false},
		{version: "unknown", wantParsed: false},
		{version: "6", wantParsed: false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			ok, parsed := kernelAtLeast(tt.version, minBPFLSMKernel)
			if parsed != tt.wantParsed || (parsed && ok != tt.wantOK) {
				t.Errorf("got (%v, %v), want (%v, %v)", ok, parsed, tt.wantOK, tt.wantParsed)
			}
		})
	}
}

func TestResolveLSMState(t *testing.T) {
	findings := map[string]lsmFinding{"node-a": {state: lsmStateDisabled, detail: "boom"}}
	tests := []struct {
		name     string
		node     nodeReport
		skipLogs bool
		want     string
	}{
		{name: "old kernel", node: nodeReport{Name: "n", KernelVersion: "5.4.0", AgentPod: "p"}, want: lsmStateTooOld},
		{name: "no agent", node: nodeReport{Name: "n", KernelVersion: "6.8.0"}, want: lsmStateUnknown},
		{name: "skip logs", node: nodeReport{Name: "n", KernelVersion: "6.8.0", AgentPod: "p"}, skipLogs: true, want: lsmStateUnknown},
		{name: "finding applies", node: nodeReport{Name: "node-a", KernelVersion: "6.8.0", AgentPod: "p"}, want: lsmStateDisabled},
		{name: "no finding", node: nodeReport{Name: "node-z", KernelVersion: "6.8.0", AgentPod: "p"}, want: lsmStateUnknown},
		{name: "unparseable kernel with agent", node: nodeReport{Name: "node-a", KernelVersion: "weird", AgentPod: "p"}, want: lsmStateDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, detail := resolveLSMState(tt.node, findings, tt.skipLogs)
			if state != tt.want {
				t.Errorf("state = %q, want %q", state, tt.want)
			}
			if detail == "" {
				t.Error("every verdict should carry an explanation")
			}
		})
	}
}

func TestCollectCRDReports_MissingCRD(t *testing.T) {
	// A scheme without the Pahlevan types makes List fail the way a cluster
	// without the CRDs installed does.
	fc, _ := installFakeClientsWithCore(t, "pahlevan-system", nil)
	reports := collectCRDReports(context.Background(), fc)
	if len(reports) != len(pahlevanKinds) {
		t.Fatalf("reports = %+v", reports)
	}
	for _, r := range reports {
		if !r.Installed || r.Count != 0 {
			t.Errorf("report = %+v", r)
		}
	}
}

func TestNewComponentPodReport(t *testing.T) {
	pod := agentPod("agent-1", "pahlevan-system", "node-a")
	pod.Status.ContainerStatuses[0].RestartCount = 4
	pod.Status.ContainerStatuses[0].Ready = false
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
	}
	report := newComponentPodReport(componentPod{Component: componentAgent, Pod: *pod})
	if report.Restarts != 4 || report.Ready != "0/1" || report.Reason != "CrashLoopBackOff" {
		t.Errorf("report = %+v", report)
	}
	if report.Age == "" {
		t.Error("age should be rendered")
	}
}

func TestPodProblemReason(t *testing.T) {
	tests := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{name: "healthy", pod: *agentPod("a", "ns", "n"), want: ""},
		{
			name: "pod level reason wins",
			pod:  corev1.Pod{Status: corev1.PodStatus{Reason: "Evicted"}},
			want: "Evicted",
		},
		{
			name: "waiting reason",
			pod: corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}},
			}}},
			want: "ImagePullBackOff",
		},
		{
			name: "terminated reason",
			pod: corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error"}}},
			}}},
			want: "Error",
		},
		{
			name: "last termination reason",
			pod: corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}},
			}}},
			want: "last exit: OOMKilled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podProblemReason(tt.pod); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNodeIsReady(t *testing.T) {
	if !nodeIsReady(*testNode("n", "6.8", true)) {
		t.Error("ready node reported as not ready")
	}
	if nodeIsReady(*testNode("n", "6.8", false)) {
		t.Error("unready node reported as ready")
	}
	if nodeIsReady(corev1.Node{}) {
		t.Error("a node with no conditions is not ready")
	}
}

func TestBoolLabel(t *testing.T) {
	if boolLabel(true) != "yes" || boolLabel(false) != "no" {
		t.Error("boolLabel wrong")
	}
}

func TestDebugCommand_EndToEnd(t *testing.T) {
	_, core, crObjs := debugCluster(t)
	installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)

	out, err := runCommand(t, NewDebugCommand(), "-n", "pahlevan-system", "--skip-logs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "Pahlevan Debug Bundle") {
		t.Errorf("output = %s", out)
	}
	// Without an injected scraper the fake clientset has no proxy reactor, so
	// the scrape must degrade to a warning rather than failing the command.
	if !strings.Contains(out, "pod proxy is unavailable") {
		t.Errorf("scrape failure should be warned about:\n%s", out)
	}
}

func BenchmarkCollectMetricHighlights(b *testing.B) {
	payload := []byte(benchExposition())
	pods := []componentPod{
		{Component: componentAgent, Pod: *agentPod("agent-1", "pahlevan-system", "node-a")},
		{Component: componentOperator, Pod: *operatorPod("operator-1", "pahlevan-system", "node-b")},
	}
	scrape := func(context.Context, string, string, string, string) ([]byte, error) { return payload, nil }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, warnings := collectMetricHighlights(context.Background(), pods, scrape); len(warnings) != 0 {
			b.Fatalf("warnings = %v", warnings)
		}
	}
}

func BenchmarkClassifyLSMLog(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		sb.WriteString("2025-08-14T10:00:00Z INFO reconcile complete container=abc node=worker-1\n")
	}
	sb.WriteString("lsm/file_open attach failed; file enforcement disabled\n")
	logText := sb.String()
	b.ReportAllocs()
	b.SetBytes(int64(len(logText)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if classifyLSMLog(logText, true).state != lsmStateDisabled {
			b.Fatal("unexpected verdict")
		}
	}
}

// erroringClient fails every List with a non-NoKindMatch error.
type erroringClient struct {
	crclient.Client
}

func (erroringClient) List(context.Context, crclient.ObjectList, ...crclient.ListOption) error {
	return errors.New("etcd unavailable")
}

func TestCollectCRDReports_ListErrorIsRecorded(t *testing.T) {
	reports := collectCRDReports(context.Background(), erroringClient{})
	for _, r := range reports {
		if r.Installed {
			t.Errorf("%s should not be reported as installed on an error", r.Kind)
		}
		if !strings.Contains(r.Error, "etcd unavailable") {
			t.Errorf("%s error = %q", r.Kind, r.Error)
		}
	}
}

func TestCollectMetricHighlights_UnparseablePayload(t *testing.T) {
	pods := []componentPod{{Component: componentAgent, Pod: *agentPod("agent-1", "pahlevan-system", "node-a")}}
	highlights, warnings := collectMetricHighlights(context.Background(), pods, staticScraper("not prometheus\n"))
	if len(highlights) != 0 {
		t.Errorf("highlights = %+v", highlights)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "unparseable") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestDetectBPFLSM_SkipsNonAgentAndUnscheduledPods(t *testing.T) {
	unscheduled := agentPod("agent-pending", "pahlevan-system", "")
	pods := []componentPod{
		{Component: componentOperator, Pod: *operatorPod("op-1", "pahlevan-system", "node-a")},
		{Component: componentAgent, Pod: *unscheduled},
	}
	calls := 0
	findings := detectBPFLSM(context.Background(), pods, func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader("")), nil
	})
	if calls != 0 {
		t.Errorf("fetched %d logs, want 0", calls)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %+v", findings)
	}
}

func TestDetectBPFLSM_ReadFailureIsUnknown(t *testing.T) {
	pods := []componentPod{{Component: componentAgent, Pod: *agentPod("agent-1", "pahlevan-system", "node-a")}}
	findings := detectBPFLSM(context.Background(), pods, func(context.Context, string, string, string, *corev1.PodLogOptions) (io.ReadCloser, error) {
		return io.NopCloser(iotest.ErrReader(errors.New("stream broke"))), nil
	})
	f := findings["node-a"]
	if f.state != lsmStateUnknown || !strings.Contains(f.detail, "stream broke") {
		t.Errorf("finding = %+v", f)
	}
}

func TestCollectDebugBundle_NilContext(t *testing.T) {
	opts, core, crObjs := debugCluster(t)
	opts.skipLogs = true
	fc, kc := installFakeClientsWithCore(t, "pahlevan-system", core, crObjs...)
	//nolint:staticcheck // a nil context is defended against on purpose
	bundle, err := collectDebugBundle(nil, fc, kc, opts)
	if err != nil {
		t.Fatalf("collectDebugBundle: %v", err)
	}
	if len(bundle.Components) != 2 {
		t.Errorf("components = %d", len(bundle.Components))
	}
}
