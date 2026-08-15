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
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// installFakeClientsWithCore wires the package-global CLI clients to in-memory
// fakes, seeding both the controller-runtime client (CRDs) and the client-go
// clientset (core/apps objects). It restores the globals on cleanup.
func installFakeClientsWithCore(t *testing.T, namespace string, coreObjs []runtime.Object, crObjs ...crclient.Object) (crclient.Client, *k8sfake.Clientset) {
	t.Helper()
	fc := fake.NewClientBuilder().
		WithScheme(cli.GetScheme()).
		WithObjects(crObjs...).
		WithStatusSubresource(&policyv1alpha1.PahlevanPolicy{}).
		Build()
	kc := k8sfake.NewClientset(coreObjs...)

	prevK8s, prevKube, prevNs, prevReady := k8sClient, kubeClient, globalNamespace, clientsReady
	k8sClient = fc
	kubeClient = kc
	globalNamespace = namespace
	clientsReady = true
	t.Cleanup(func() {
		k8sClient, kubeClient, globalNamespace, clientsReady = prevK8s, prevKube, prevNs, prevReady
	})
	return fc, kc
}

// clearClients simulates a CLI run where client initialization failed.
func clearClients(t *testing.T) {
	t.Helper()
	prevK8s, prevKube, prevNs, prevReady := k8sClient, kubeClient, globalNamespace, clientsReady
	k8sClient, kubeClient, clientsReady = nil, nil, false
	t.Cleanup(func() {
		k8sClient, kubeClient, globalNamespace, clientsReady = prevK8s, prevKube, prevNs, prevReady
	})
}

// agentPod builds a pahlevan-agent pod on the given node.
func agentPod(name, namespace, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         namespace,
			Labels:            map[string]string{componentLabelKey: agentAppName},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "agent", Image: "ghcr.io/obsernetics/pahlevan:v2"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "agent", Ready: true, RestartCount: 0},
			},
		},
	}
}

// operatorPod builds a pahlevan-operator pod.
func operatorPod(name, namespace, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         namespace,
			Labels:            map[string]string{componentLabelKey: operatorAppName},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-30 * time.Minute)),
		},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "operator", Image: "ghcr.io/obsernetics/pahlevan:v2"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "operator", Ready: true, RestartCount: 1},
			},
		},
	}
}

func TestComponentAppNames(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "", want: []string{agentAppName, operatorAppName}},
		{in: "all", want: []string{agentAppName, operatorAppName}},
		{in: "ALL", want: []string{agentAppName, operatorAppName}},
		{in: "agent", want: []string{agentAppName}},
		{in: " Agent ", want: []string{agentAppName}},
		{in: "pahlevan-agent", want: []string{agentAppName}},
		{in: "operator", want: []string{operatorAppName}},
		{in: "pahlevan-operator", want: []string{operatorAppName}},
		{in: "sidecar", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := componentAppNames(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), "agent, operator, all") {
					t.Errorf("error should list the valid values: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComponentForAppName(t *testing.T) {
	if got := componentForAppName(agentAppName); got != componentAgent {
		t.Errorf("agent = %q", got)
	}
	if got := componentForAppName(operatorAppName); got != componentOperator {
		t.Errorf("operator = %q", got)
	}
	if got := componentForAppName("other"); got != "other" {
		t.Errorf("passthrough = %q", got)
	}
}

func TestResolveComponentNamespace(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		global   string
		want     string
	}{
		{name: "explicit wins", explicit: "custom", global: "pahlevan-system", want: "custom"},
		{name: "explicit is trimmed", explicit: "  custom  ", global: "", want: "custom"},
		{name: "global used when meaningful", explicit: "", global: "pahlevan-system", want: "pahlevan-system"},
		{name: "default global means search everywhere", explicit: "", global: "default", want: ""},
		{name: "empty global means search everywhere", explicit: "", global: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installFakeClientsWithCore(t, tt.global, nil)
			if got := resolveComponentNamespace(tt.explicit); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindComponentPods(t *testing.T) {
	core := []runtime.Object{
		agentPod("pahlevan-agent-aaa", "pahlevan-system", "node-b"),
		agentPod("pahlevan-agent-bbb", "pahlevan-system", "node-a"),
		operatorPod("pahlevan-operator-1", "pahlevan-system", "node-a"),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default"}},
	}
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", core)

	tests := []struct {
		name      string
		namespace string
		component string
		node      string
		want      []string
		wantErr   bool
	}{
		{
			name:      "all components sorted",
			component: componentAll,
			want:      []string{"pahlevan-agent-aaa", "pahlevan-agent-bbb", "pahlevan-operator-1"},
		},
		{
			name:      "agent only",
			component: componentAgent,
			want:      []string{"pahlevan-agent-aaa", "pahlevan-agent-bbb"},
		},
		{
			name:      "operator only",
			component: componentOperator,
			want:      []string{"pahlevan-operator-1"},
		},
		{
			name:      "node filter",
			component: componentAgent,
			node:      "node-a",
			want:      []string{"pahlevan-agent-bbb"},
		},
		{
			name:      "node with no agent",
			component: componentAgent,
			node:      "node-z",
			want:      nil,
		},
		{
			name:      "namespace with nothing",
			namespace: "kube-system",
			component: componentAll,
			want:      nil,
		},
		{
			name:      "invalid component",
			component: "bogus",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pods, err := findComponentPods(context.Background(), kc, tt.namespace, tt.component, tt.node)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var names []string
			for _, p := range pods {
				names = append(names, p.Pod.Name)
			}
			if strings.Join(names, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %v, want %v", names, tt.want)
			}
		})
	}
}

func TestFindComponentPods_NilClientset(t *testing.T) {
	_, err := findComponentPods(context.Background(), nil, "", componentAll, "")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("err = %v", err)
	}
}

func TestFindComponentPods_ListError(t *testing.T) {
	_, kc := installFakeClientsWithCore(t, "pahlevan-system", nil)
	kc.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("nope"))
	})
	_, err := findComponentPods(context.Background(), kc, "pahlevan-system", componentAll, "")
	if err == nil || !strings.Contains(err.Error(), "failed to list") {
		t.Fatalf("err = %v", err)
	}
}

func TestComponentPodAccessors(t *testing.T) {
	pod := agentPod("agent-1", "pahlevan-system", "node-a")
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Name: "agent", Ready: true, RestartCount: 3},
		{Name: "sidecar", Ready: false, RestartCount: 1},
	}
	cp := componentPod{Component: componentAgent, Pod: *pod}

	if cp.Node() != "node-a" {
		t.Errorf("Node = %q", cp.Node())
	}
	if cp.Container() != "agent" {
		t.Errorf("Container = %q", cp.Container())
	}
	if cp.Restarts() != 4 {
		t.Errorf("Restarts = %d", cp.Restarts())
	}
	if cp.Ready() {
		t.Error("Ready should be false when a container is not ready")
	}
	if cp.ReadyString() != "1/2" {
		t.Errorf("ReadyString = %q", cp.ReadyString())
	}
	if cp.Image() != "ghcr.io/obsernetics/pahlevan:v2" {
		t.Errorf("Image = %q", cp.Image())
	}

	// A pod with no containers and no node must degrade gracefully.
	empty := componentPod{Pod: corev1.Pod{}}
	if empty.Node() != "<unscheduled>" {
		t.Errorf("Node = %q", empty.Node())
	}
	if empty.Container() != "" {
		t.Errorf("Container = %q", empty.Container())
	}
	if empty.Image() != "<unknown>" {
		t.Errorf("Image = %q", empty.Image())
	}
	if empty.Ready() {
		t.Error("a pod with no container statuses is not ready")
	}
	if empty.ReadyString() != "0/0" {
		t.Errorf("ReadyString = %q", empty.ReadyString())
	}

	allReady := componentPod{Pod: *agentPod("a", "ns", "n")}
	if !allReady.Ready() {
		t.Error("all-ready pod should report ready")
	}
}

func TestNoComponentPodsError(t *testing.T) {
	err := noComponentPodsError("pahlevan-system", componentAgent, "node-a")
	msg := err.Error()
	for _, want := range []string{"agent", `namespace "pahlevan-system"`, `node "node-a"`, "--namespace"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}

	msg = noComponentPodsError("", componentAll, "").Error()
	if !strings.Contains(msg, "any namespace") {
		t.Errorf("cluster-wide message = %s", msg)
	}
	if strings.Contains(msg, "on node") {
		t.Errorf("node clause leaked into message: %s", msg)
	}
}

func TestComponentDescription(t *testing.T) {
	if got := componentDescription(componentAgent); got != "agent" {
		t.Errorf("got %q", got)
	}
	if got := componentDescription(componentOperator); got != "operator" {
		t.Errorf("got %q", got)
	}
	if got := componentDescription(componentAll); got != "component" {
		t.Errorf("got %q", got)
	}
}

func TestValidateOutputFormat(t *testing.T) {
	if err := validateOutputFormat("json", "table", "json"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := validateOutputFormat("xml", "table", "json")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "table, json") {
		t.Errorf("error should list the valid formats: %v", err)
	}
}

func TestErrClientsNotReady(t *testing.T) {
	if !strings.Contains(errClientsNotReady().Error(), "kubeconfig") {
		t.Error("message should mention kubeconfig")
	}
}
