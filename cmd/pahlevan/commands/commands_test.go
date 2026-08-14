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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// installFakeClients wires the package-global CLI clients to in-memory fakes so
// command RunE paths can be driven without a live cluster. It restores the
// globals on test cleanup.
func installFakeClients(t *testing.T, objs ...crclient.Object) (crclient.Client, *k8sfake.Clientset) {
	t.Helper()
	scheme := cli.GetScheme()
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&policyv1alpha1.PahlevanPolicy{}).
		Build()
	kc := k8sfake.NewSimpleClientset()

	prevK8s, prevKube, prevNs, prevReady := k8sClient, kubeClient, globalNamespace, clientsReady
	k8sClient = fc
	kubeClient = kc
	globalNamespace = "default"
	clientsReady = true
	t.Cleanup(func() {
		k8sClient, kubeClient, globalNamespace, clientsReady = prevK8s, prevKube, prevNs, prevReady
	})
	return fc, kc
}

func samplePolicy(name, ns string) *policyv1alpha1.PahlevanPolicy {
	p, _ := createPolicyFromFlags("5m", "monitoring", "app=web", ns)
	p.Name = name
	p.Status.Phase = policyv1alpha1.PolicyPhaseLearning
	return p
}

// withSilencedStdout runs fn with os.Stdout redirected to the null device, so
// command output does not pollute test logs. Errors are still returned normally.
func withSilencedStdout(t *testing.T, fn func() error) error {
	t.Helper()
	orig := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fn()
	}
	os.Stdout = devnull
	defer func() {
		os.Stdout = orig
		_ = devnull.Close()
	}()
	return fn()
}

// --- Command construction / wiring ---------------------------------------

func TestNewPolicyCommand_Wiring(t *testing.T) {
	cmd := NewPolicyCommand()
	if cmd.Use != "policy" {
		t.Errorf("Use = %q", cmd.Use)
	}
	want := map[string]bool{"list": false, "get": false, "describe": false, "create": false, "delete": false, "update": false, "status": false}
	for _, c := range cmd.Commands() {
		want[c.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("policy subcommand %q not registered", name)
		}
	}
}

func TestPolicyListCommand_Flags(t *testing.T) {
	cmd := NewPolicyListCommand()
	for _, f := range []string{"all-namespaces", "selector", "output"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("list command missing flag %q", f)
		}
	}
	if len(cmd.Aliases) == 0 || cmd.Aliases[0] != "ls" {
		t.Errorf("list command should have alias 'ls', got %v", cmd.Aliases)
	}
}

func TestPolicyCreateCommand_Flags(t *testing.T) {
	cmd := NewPolicyCreateCommand()
	for _, f := range []string{"filename", "learning-time", "enforcement-mode", "selector", "dry-run"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("create command missing flag %q", f)
		}
	}
}

func TestPolicyUpdateCommand_Flags(t *testing.T) {
	cmd := NewPolicyUpdateCommand()
	for _, f := range []string{"learning-time", "enforcement-mode", "block-unknown", "auto-transition", "lifecycle-aware"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("update command missing flag %q", f)
		}
	}
}

func TestPolicyCommands_ArgValidation(t *testing.T) {
	// get/describe/delete/update/status require exactly one arg.
	for _, mk := range []func() interface{ Execute() error }{
		func() interface{ Execute() error } { c := NewPolicyGetCommand(); c.SetArgs(nil); return c },
		func() interface{ Execute() error } { c := NewPolicyDeleteCommand(); c.SetArgs(nil); return c },
	} {
		if err := mk().Execute(); err == nil {
			t.Error("expected error when required positional arg is missing")
		}
	}
}

// --- policy list ----------------------------------------------------------

func TestPolicyList_Run(t *testing.T) {
	installFakeClients(t, samplePolicy("p1", "default"), samplePolicy("p2", "default"))

	cmd := NewPolicyListCommand()
	cmd.SetArgs([]string{})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("list run error: %v", err)
	}

	// JSON output path.
	cmdJSON := NewPolicyListCommand()
	cmdJSON.SetArgs([]string{"-o", "json"})
	if err := withSilencedStdout(t, cmdJSON.Execute); err != nil {
		t.Fatalf("list -o json error: %v", err)
	}

	// all-namespaces + selector.
	cmdAll := NewPolicyListCommand()
	cmdAll.SetArgs([]string{"-A", "--selector", "app=web"})
	if err := withSilencedStdout(t, cmdAll.Execute); err != nil {
		t.Fatalf("list -A --selector error: %v", err)
	}
}

func TestPolicyList_InvalidSelector(t *testing.T) {
	installFakeClients(t)
	cmd := NewPolicyListCommand()
	cmd.SetArgs([]string{"--selector", "!!!bad!!!"})
	if err := withSilencedStdout(t, cmd.Execute); err == nil {
		t.Error("expected error for invalid selector")
	}
}

// --- policy get -----------------------------------------------------------

func TestPolicyGet_Run(t *testing.T) {
	installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyGetCommand()
	cmd.SetArgs([]string{"p1", "-o", "json"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("get run error: %v", err)
	}

	cmdMissing := NewPolicyGetCommand()
	cmdMissing.SetArgs([]string{"does-not-exist"})
	if err := withSilencedStdout(t, cmdMissing.Execute); err == nil {
		t.Error("expected error getting non-existent policy")
	}
}

// --- policy describe ------------------------------------------------------

func TestPolicyDescribe_Run(t *testing.T) {
	p := samplePolicy("p1", "default")
	// Give it some status detail to exercise the describe branches.
	rs := int32(50)
	p.Status.AttackSurface = &policyv1alpha1.AttackSurfaceStatus{
		ExposedSyscalls: []string{"read"},
		ExposedPorts:    []int32{80},
		WritableFiles:   []string{"/tmp"},
		Capabilities:    []string{"CAP_NET_ADMIN"},
		RiskScore:       &rs,
	}
	p.Status.Conditions = []policyv1alpha1.PolicyCondition{{
		Type:               policyv1alpha1.PolicyConditionReady,
		Status:             policyv1alpha1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "Ok",
		Message:            "all good",
	}}
	installFakeClients(t, p)

	cmd := NewPolicyDescribeCommand()
	cmd.SetArgs([]string{"p1"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("describe run error: %v", err)
	}

	cmdMissing := NewPolicyDescribeCommand()
	cmdMissing.SetArgs([]string{"nope"})
	if err := withSilencedStdout(t, cmdMissing.Execute); err == nil {
		t.Error("expected error describing non-existent policy")
	}
}

// --- policy create --------------------------------------------------------

func TestPolicyCreate_FromFlags(t *testing.T) {
	fc, _ := installFakeClients(t)
	cmd := NewPolicyCreateCommand()
	cmd.SetArgs([]string{"--selector", "app=demo", "--enforcement-mode", "blocking", "--learning-time", "2m"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("create run error: %v", err)
	}
	list := &policyv1alpha1.PahlevanPolicyList{}
	if err := fc.List(context.Background(), list, crclient.InNamespace("default")); err != nil {
		t.Fatalf("list after create: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 created policy, got %d", len(list.Items))
	}
	got := list.Items[0]
	if got.Spec.EnforcementConfig.Mode != policyv1alpha1.EnforcementModeBlocking {
		t.Errorf("created mode = %q, want Blocking", got.Spec.EnforcementConfig.Mode)
	}
	if !got.Spec.EnforcementConfig.BlockUnknown {
		t.Error("blocking mode should set BlockUnknown")
	}
	if got.Spec.Selector.MatchLabels["app"] != "demo" {
		t.Errorf("selector = %v", got.Spec.Selector.MatchLabels)
	}
}

func TestPolicyCreate_DryRunDoesNotPersist(t *testing.T) {
	fc, _ := installFakeClients(t)
	cmd := NewPolicyCreateCommand()
	cmd.SetArgs([]string{"--selector", "app=demo", "--dry-run"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("dry-run create error: %v", err)
	}
	list := &policyv1alpha1.PahlevanPolicyList{}
	if err := fc.List(context.Background(), list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("dry-run must not persist, found %d policies", len(list.Items))
	}
}

func TestPolicyCreate_InvalidMode(t *testing.T) {
	installFakeClients(t)
	cmd := NewPolicyCreateCommand()
	cmd.SetArgs([]string{"--selector", "app=demo", "--enforcement-mode", "bogus"})
	if err := withSilencedStdout(t, cmd.Execute); err == nil {
		t.Error("expected error for invalid enforcement mode")
	}
}

func TestPolicyCreate_FromFile(t *testing.T) {
	fc, _ := installFakeClients(t)
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	content := `apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: file-policy
  namespace: default
spec:
  selector:
    matchLabels:
      app: fromfile
  enforcementConfig:
    mode: Monitoring
`
	if err := os.WriteFile(yamlPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewPolicyCreateCommand()
	cmd.SetArgs([]string{"-f", yamlPath})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("create from file error: %v", err)
	}
	got := &policyv1alpha1.PahlevanPolicy{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "file-policy", Namespace: "default"}, got); err != nil {
		t.Fatalf("policy from file not persisted: %v", err)
	}
}

// --- policy delete / update / status --------------------------------------

func TestPolicyDelete_Run(t *testing.T) {
	fc, _ := installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyDeleteCommand()
	cmd.SetArgs([]string{"p1"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("delete run error: %v", err)
	}
	got := &policyv1alpha1.PahlevanPolicy{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "p1", Namespace: "default"}, got); err == nil {
		t.Error("policy should be deleted")
	}

	cmdMissing := NewPolicyDeleteCommand()
	cmdMissing.SetArgs([]string{"nope"})
	if err := withSilencedStdout(t, cmdMissing.Execute); err == nil {
		t.Error("expected error deleting non-existent policy")
	}
}

func TestPolicyUpdate_Run(t *testing.T) {
	fc, _ := installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyUpdateCommand()
	cmd.SetArgs([]string{"p1", "--enforcement-mode", "blocking", "--learning-time", "10m", "--block-unknown", "--auto-transition", "--lifecycle-aware"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("update run error: %v", err)
	}
	got := &policyv1alpha1.PahlevanPolicy{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "p1", Namespace: "default"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.EnforcementConfig.Mode != policyv1alpha1.EnforcementModeBlocking {
		t.Errorf("mode after update = %q, want Blocking", got.Spec.EnforcementConfig.Mode)
	}
	if got.Spec.LearningConfig.Duration == nil || got.Spec.LearningConfig.Duration.Duration != 10*time.Minute {
		t.Errorf("duration after update = %v", got.Spec.LearningConfig.Duration)
	}
}

func TestPolicyUpdate_NoChanges(t *testing.T) {
	installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyUpdateCommand()
	cmd.SetArgs([]string{"p1"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("update with no changes should be a no-op, got: %v", err)
	}
}

func TestPolicyUpdate_InvalidMode(t *testing.T) {
	installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyUpdateCommand()
	cmd.SetArgs([]string{"p1", "--enforcement-mode", "bogus"})
	if err := withSilencedStdout(t, cmd.Execute); err == nil {
		t.Error("expected error for invalid enforcement mode on update")
	}
}

func TestPolicyStatus_Run(t *testing.T) {
	installFakeClients(t, samplePolicy("p1", "default"))
	cmd := NewPolicyStatusCommand()
	cmd.SetArgs([]string{"p1"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("status run error: %v", err)
	}
	if cmd.Flags().Lookup("watch") == nil {
		t.Error("status command should have --watch flag")
	}
}

// --- createPolicyFromFile direct ------------------------------------------

func TestCreatePolicyFromFile_JSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "policy.json")
	content := `{"apiVersion":"policy.pahlevan.io/v1alpha1","kind":"PahlevanPolicy","metadata":{"name":"json-policy"},"spec":{"selector":{"matchLabels":{"app":"x"}}}}`
	if err := os.WriteFile(jsonPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := createPolicyFromFile(jsonPath)
	if err != nil {
		t.Fatalf("createPolicyFromFile json: %v", err)
	}
	if p.Name != "json-policy" {
		t.Errorf("name = %q", p.Name)
	}
	if p.Namespace != "default" {
		t.Errorf("namespace should default to 'default', got %q", p.Namespace)
	}
	if p.Spec.EnforcementConfig.Mode != policyv1alpha1.EnforcementModeMonitoring {
		t.Errorf("mode should default to Monitoring, got %q", p.Spec.EnforcementConfig.Mode)
	}
	if p.Spec.LearningConfig.Duration == nil {
		t.Error("duration should be defaulted")
	}
}

func TestCreatePolicyFromFile_Errors(t *testing.T) {
	if _, err := createPolicyFromFile("/nonexistent/file.yaml"); err == nil {
		t.Error("expected error for missing file")
	}

	dir := t.TempDir()
	// Missing name.
	noName := filepath.Join(dir, "noname.yaml")
	_ = os.WriteFile(noName, []byte("spec:\n  selector:\n    matchLabels:\n      app: x\n"), 0o644)
	if _, err := createPolicyFromFile(noName); err == nil {
		t.Error("expected error for policy without name")
	}

	// Missing selector.
	noSel := filepath.Join(dir, "nosel.yaml")
	_ = os.WriteFile(noSel, []byte("metadata:\n  name: x\n"), 0o644)
	if _, err := createPolicyFromFile(noSel); err == nil {
		t.Error("expected error for policy without selector")
	}

	// Invalid JSON.
	badJSON := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(badJSON, []byte("{not json"), 0o644)
	if _, err := createPolicyFromFile(badJSON); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- formatting helpers ---------------------------------------------------

func TestFormatHelpers(t *testing.T) {
	if formatLabels(nil) != "<none>" {
		t.Error("formatLabels(nil) should be <none>")
	}
	if formatLabels(map[string]string{"a": "b"}) != "a=b" {
		t.Error("formatLabels single")
	}
	if formatAnnotations(nil) != "<none>" {
		t.Error("formatAnnotations(nil) should be <none>")
	}
	if formatAnnotations(map[string]string{"a": "b", "c": "d"}) != "2 annotations" {
		t.Error("formatAnnotations count")
	}
	if formatRiskScore(nil) != "<none>" {
		t.Error("formatRiskScore(nil)")
	}
	score := int32(7)
	if formatRiskScore(&score) != "7" {
		t.Error("formatRiskScore")
	}
	if formatPorts(nil) != "<none>" {
		t.Error("formatPorts(nil)")
	}
	if formatPorts([]int32{80, 443}) == "<none>" {
		t.Error("formatPorts non-empty")
	}
	p := samplePolicy("x", "ns")
	if formatProgress(p) != "N/A" || formatViolations(p) != "N/A" {
		t.Error("formatProgress/formatViolations should be N/A")
	}
}

func TestParseDuration(t *testing.T) {
	d, err := parseDuration("90s")
	if err != nil || d.Duration != 90*time.Second {
		t.Errorf("parseDuration(90s) = %v, %v", d, err)
	}
	if _, err := parseDuration(""); err == nil {
		t.Error("empty duration should error")
	}
	if _, err := parseDuration("notaduration"); err == nil {
		t.Error("invalid duration should error")
	}
}

func TestParseSelector_Empty(t *testing.T) {
	m, err := parseSelector("")
	if err != nil {
		t.Fatalf("empty selector error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("empty selector should yield empty map, got %v", m)
	}
}

func TestEventTime(t *testing.T) {
	base := time.Unix(1700000000, 0)
	// LastTimestamp preferred.
	e := &corev1.Event{
		LastTimestamp: metav1.NewTime(base),
		EventTime:     metav1.NewMicroTime(base.Add(time.Hour)),
		ObjectMeta:    metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(base.Add(2 * time.Hour))},
	}
	if !eventTime(e).Equal(base) {
		t.Errorf("eventTime should prefer LastTimestamp, got %v", eventTime(e))
	}
	// Fall back to EventTime.
	e2 := &corev1.Event{
		EventTime:  metav1.NewMicroTime(base.Add(time.Hour)),
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(base.Add(2 * time.Hour))},
	}
	if !eventTime(e2).Equal(base.Add(time.Hour)) {
		t.Errorf("eventTime should fall back to EventTime, got %v", eventTime(e2))
	}
	// Fall back to CreationTimestamp.
	e3 := &corev1.Event{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(base.Add(2 * time.Hour))}}
	if !eventTime(e3).Equal(base.Add(2 * time.Hour)) {
		t.Errorf("eventTime should fall back to CreationTimestamp, got %v", eventTime(e3))
	}
}

// --- status command -------------------------------------------------------

func TestStatusCommand_NotReady(t *testing.T) {
	prevReady := clientsReady
	prevK8s := k8sClient
	clientsReady = false
	k8sClient = nil
	t.Cleanup(func() { clientsReady = prevReady; k8sClient = prevK8s })

	cmd := NewStatusCommand()
	cmd.SetArgs([]string{})
	if err := withSilencedStdout(t, cmd.Execute); err == nil {
		t.Error("status should error when clients are not initialized")
	}
}

func TestStatusCommand_Run(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pahlevan-operator",
			Namespace: "pahlevan-system",
			Labels:    map[string]string{"app.kubernetes.io/name": "pahlevan-operator"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "op", Image: "pahlevan:latest"}}},
			},
		},
		Status: appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: 1},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pahlevan-agent",
			Namespace: "pahlevan-system",
			Labels:    map[string]string{"app.kubernetes.io/name": "pahlevan-agent"},
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "pahlevan-agent:latest"}}},
			},
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3, NumberAvailable: 3},
	}
	installFakeClients(t, dep, ds, samplePolicy("p1", "default"))

	cmd := NewStatusCommand()
	cmd.SetArgs([]string{})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("status run error: %v", err)
	}
}

func TestStatusCommand_WithAdmissionResources(t *testing.T) {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pahlevan-validating-webhook"},
	}
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pahlevan-mutating-webhook"},
	}
	vap := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pahlevan-policy-check"},
	}
	vapBound := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "pahlevan-binding"},
		Spec:       admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "pahlevan-policy-check"},
	}
	installFakeClients(t, vwc, mwc, vap, vapBound, samplePolicy("p1", "default"))

	cmd := NewStatusCommand()
	cmd.SetArgs([]string{})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("status with admission resources error: %v", err)
	}
}

func TestPolicyDescribe_WithEvents(t *testing.T) {
	_, kc := installFakeClients(t, samplePolicy("p1", "default"))
	// Seed a real Kubernetes event for the policy's involved object.
	_, err := kc.CoreV1().Events("default").Create(context.Background(), &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "p1.evt", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "PahlevanPolicy",
			Name:      "p1",
			Namespace: "default",
		},
		Reason:        "Learned",
		Message:       "learning complete",
		Type:          "Normal",
		LastTimestamp: metav1.Now(),
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}

	cmd := NewPolicyDescribeCommand()
	cmd.SetArgs([]string{"p1"})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("describe with events error: %v", err)
	}
}

func TestStatus_ImageHelpers(t *testing.T) {
	d := appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "img:1"}}}}}}
	if getContainerImage(d) != "img:1" {
		t.Error("getContainerImage")
	}
	if getContainerImage(appsv1.Deployment{}) != "<unknown>" {
		t.Error("getContainerImage empty")
	}
	ds := appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "img:2"}}}}}}
	if getDaemonSetContainerImage(ds) != "img:2" {
		t.Error("getDaemonSetContainerImage")
	}
	if getDaemonSetContainerImage(appsv1.DaemonSet{}) != "<unknown>" {
		t.Error("getDaemonSetContainerImage empty")
	}
}

func TestFilterPahlevanNames(t *testing.T) {
	got := filterPahlevanNames([]string{"pahlevan-webhook", "other", "PAHLEVAN-x", "kube-system"})
	if len(got) != 2 {
		t.Errorf("filterPahlevanNames = %v, want 2 entries", got)
	}
}

func TestIsNoKindMatch(t *testing.T) {
	if isNoKindMatch(nil) {
		t.Error("nil error is not a no-kind-match")
	}
	for _, msg := range []string{"no matches for kind", "no kind is registered", "the server could not find the requested resource"} {
		if !isNoKindMatch(errString(msg)) {
			t.Errorf("expected isNoKindMatch true for %q", msg)
		}
	}
	if isNoKindMatch(errString("some other error")) {
		t.Error("unrelated error should not match")
	}
}

func TestCheckPahlevanPolicyCRD(t *testing.T) {
	installFakeClients(t)
	ok, err := checkPahlevanPolicyCRD(k8sClient)
	if err != nil {
		t.Fatalf("checkPahlevanPolicyCRD error: %v", err)
	}
	if !ok {
		t.Error("CRD should be considered installed when list succeeds")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// --- version / completion / stub commands ---------------------------------

func TestVersionCommand(t *testing.T) {
	cmd := NewVersionCommand("v9.9.9", "2026-01-01", "abc123")
	cmd.SetArgs([]string{})
	if err := withSilencedStdout(t, cmd.Execute); err != nil {
		t.Fatalf("version run error: %v", err)
	}

	cmdJSON := NewVersionCommand("v9.9.9", "2026-01-01", "abc123")
	cmdJSON.SetArgs([]string{"-o", "json"})
	if err := withSilencedStdout(t, cmdJSON.Execute); err != nil {
		t.Fatalf("version -o json error: %v", err)
	}

	cmdYAML := NewVersionCommand("v9.9.9", "2026-01-01", "abc123")
	cmdYAML.SetArgs([]string{"-o", "yaml"})
	if err := withSilencedStdout(t, cmdYAML.Execute); err != nil {
		t.Fatalf("version -o yaml error: %v", err)
	}
}

func TestCompletionCommand(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		cmd := NewCompletionCommand()
		// Completion generators need a root command context.
		root := NewVersionCommand("v", "d", "c") // any command works as a stand-in root
		root.Use = "pahlevan"
		root.AddCommand(cmd)
		root.SetArgs([]string{"completion", shell})
		if err := withSilencedStdout(t, root.Execute); err != nil {
			t.Errorf("completion %s error: %v", shell, err)
		}
	}
}

// TestNoStubCommandsRemain guards the regression this package was built to fix:
// every command that once printed "to be implemented" now either does real work
// or fails loudly because it cannot reach a cluster. Silently succeeding while
// doing nothing is the behaviour under test.
func TestNoStubCommandsRemain(t *testing.T) {
	clearClients(t)

	commands := map[string]*cobra.Command{
		"attack-surface analyze": NewAttackSurfaceAnalyzeCommand(),
		"attack-surface report":  NewAttackSurfaceReportCommand(),
		"logs":                   NewLogsCommand(),
		"metrics":                NewMetricsCommand(),
		"debug":                  NewDebugCommand(),
	}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			out, err := runCommand(t, cmd)
			if err == nil {
				t.Fatalf("%s succeeded without a cluster; a command that cannot do its job must say so", name)
			}
			if !strings.Contains(err.Error(), "not initialized") {
				t.Errorf("error should explain the missing cluster connection: %v", err)
			}
			if strings.Contains(out, "to be implemented") {
				t.Errorf("%s still prints a stub message: %s", name, out)
			}
		})
	}

	// The help text must not advertise unimplemented behaviour either.
	all := []*cobra.Command{
		NewAttackSurfaceCommand(), NewAttackSurfaceAnalyzeCommand(), NewAttackSurfaceReportCommand(),
		NewLogsCommand(), NewMetricsCommand(), NewDebugCommand(),
	}
	for _, cmd := range all {
		if strings.Contains(cmd.Long, "to be implemented") || strings.Contains(cmd.Short, "to be implemented") {
			t.Errorf("%s help still says 'to be implemented'", cmd.Name())
		}
	}

	if n := len(NewAttackSurfaceCommand().Commands()); n != 2 {
		t.Errorf("attack-surface should have 2 subcommands, got %d", n)
	}
}
