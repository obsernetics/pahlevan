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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func int32Ptr(v int32) *int32 { return &v }

// makeAttackSurface builds an AttackSurface with an explicit risk score.
func makeAttackSurface(name, namespace string, risk *int32, mutate func(*policyv1alpha1.AttackSurface)) *policyv1alpha1.AttackSurface {
	now := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	as := &policyv1alpha1.AttackSurface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyv1alpha1.AttackSurfaceSpec{
			PolicyRef: name + "-policy",
			Namespace: namespace,
			Workload: &policyv1alpha1.WorkloadReference{
				APIVersion: "apps/v1", Kind: "Deployment", Name: name, Namespace: namespace,
			},
		},
		Status: policyv1alpha1.AttackSurfaceStatus{
			ExposedSyscalls: []string{"openat", "ptrace", "read"},
			ExposedPorts:    []int32{8443, 80},
			WritableFiles:   []string{"/var/run", "/tmp"},
			Capabilities:    []string{"CAP_NET_RAW", "CAP_SYS_ADMIN"},
			RiskScore:       risk,
			LastAnalysis:    &now,
		},
	}
	if mutate != nil {
		mutate(as)
	}
	return as
}

func makeContainerProfile(name, namespace, workload, phase string, mutate func(*policyv1alpha1.ContainerProfile)) *policyv1alpha1.ContainerProfile {
	cp := &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyv1alpha1.ContainerProfileSpec{
			PolicyRef: workload + "-policy",
			Namespace: namespace,
			PodName:   name,
			Node:      "node-a",
			Workload: &policyv1alpha1.WorkloadReference{
				APIVersion: "apps/v1", Kind: "Deployment", Name: workload, Namespace: namespace,
			},
		},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:        phase,
			SyscallCount: 40,
			FileCount:    12,
			NetworkCount: 3,
		},
	}
	if mutate != nil {
		mutate(cp)
	}
	return cp
}

// runCommand executes a cobra command with the given args, capturing stdout.
func runCommand(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// --- wiring and flags -----------------------------------------------------

func TestNewAttackSurfaceCommand_Wiring(t *testing.T) {
	cmd := NewAttackSurfaceCommand()
	if cmd.Use != "attack-surface" {
		t.Errorf("Use = %q", cmd.Use)
	}
	found := map[string]bool{}
	for _, c := range cmd.Commands() {
		found[c.Name()] = true
	}
	for _, want := range []string{"analyze", "report"} {
		if !found[want] {
			t.Errorf("subcommand %q not registered", want)
		}
	}
	if strings.Contains(cmd.Long, "to be implemented") {
		t.Error("help text still advertises an unimplemented command")
	}
}

func TestAttackSurfaceAnalyzeCommand_Flags(t *testing.T) {
	cmd := NewAttackSurfaceAnalyzeCommand()
	for _, f := range []string{"namespace", "all-namespaces", "output", "min-risk"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("analyze missing flag %q", f)
		}
	}
	if cmd.Flags().ShorthandLookup("n") == nil {
		t.Error("analyze missing -n shorthand")
	}
	if cmd.Flags().ShorthandLookup("A") == nil {
		t.Error("analyze missing -A shorthand")
	}
	if cmd.Flags().ShorthandLookup("o") == nil {
		t.Error("analyze missing -o shorthand")
	}
}

func TestAttackSurfaceReportCommand_Flags(t *testing.T) {
	cmd := NewAttackSurfaceReportCommand()
	for _, f := range []string{"namespace", "all-namespaces", "output", "file", "top"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("report missing flag %q", f)
		}
	}
}

func TestAttackSurfaceCommands_FlagValidation(t *testing.T) {
	installFakeClientsWithCore(t, "default", nil)

	tests := []struct {
		name    string
		cmd     func() *cobra.Command
		args    []string
		wantErr string
	}{
		{name: "analyze bad output", cmd: NewAttackSurfaceAnalyzeCommand, args: []string{"-o", "xml"}, wantErr: "invalid --output"},
		{name: "analyze negative min-risk", cmd: NewAttackSurfaceAnalyzeCommand, args: []string{"--min-risk", "-1"}, wantErr: "invalid --min-risk"},
		{name: "analyze min-risk above 100", cmd: NewAttackSurfaceAnalyzeCommand, args: []string{"--min-risk", "101"}, wantErr: "invalid --min-risk"},
		{name: "report bad output", cmd: NewAttackSurfaceReportCommand, args: []string{"-o", "pdf"}, wantErr: "invalid --output"},
		{name: "report zero top", cmd: NewAttackSurfaceReportCommand, args: []string{"--top", "0"}, wantErr: "invalid --top"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runCommand(t, tt.cmd(), tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestAttackSurfaceCommands_ClientsNotReady(t *testing.T) {
	clearClients(t)
	for name, newCmd := range map[string]func() *cobra.Command{
		"analyze": NewAttackSurfaceAnalyzeCommand,
		"report":  NewAttackSurfaceReportCommand,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runCommand(t, newCmd())
			if err == nil || !strings.Contains(err.Error(), "not initialized") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// --- analyze --------------------------------------------------------------

func TestAttackSurfaceAnalyze_HappyPathTable(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(85), nil),
		makeAttackSurface("cache", "prod", int32Ptr(20), nil),
		makeContainerProfile("web-abc", "prod", "web", "Enforcing", nil),
	)

	out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"NAMESPACE", "web", "cache", "85", "Critical", "Enforcing", "2 of 2 attack surface(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Riskiest first.
	if strings.Index(out, "web") > strings.Index(out, "cache") {
		t.Errorf("output is not sorted by descending risk:\n%s", out)
	}
}

func TestAttackSurfaceAnalyze_WideIncludesDetail(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(85), nil),
		makeContainerProfile("web-abc", "prod", "web", "Learning", func(cp *policyv1alpha1.ContainerProfile) {
			cp.Status.RollbackCount = 2
			cp.Status.DenialCount = 9
		}),
	)
	out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod", "-o", "wide")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"Exposed ports:", "8443", "Risky capabilities:", "CAP_SYS_ADMIN", "Risky syscalls:", "ptrace", "Learned baseline:", "2 rollback(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("wide output missing %q:\n%s", want, out)
		}
	}
}

func TestAttackSurfaceAnalyze_AllNamespaces(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(85), nil),
		makeAttackSurface("api", "staging", int32Ptr(40), nil),
	)
	out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "staging") || !strings.Contains(out, "prod") {
		t.Errorf("all-namespaces output missing a namespace:\n%s", out)
	}
	if !strings.Contains(out, "all namespaces") {
		t.Errorf("scope not reported:\n%s", out)
	}
}

func TestAttackSurfaceAnalyze_MinRiskFilter(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(85), nil),
		makeAttackSurface("cache", "prod", int32Ptr(20), nil),
	)

	out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod", "--min-risk", "50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "cache") {
		t.Errorf("low-risk workload should be filtered out:\n%s", out)
	}
	if !strings.Contains(out, "1 of 2") {
		t.Errorf("filtered count not reported:\n%s", out)
	}

	out, err = runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod", "--min-risk", "99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "none scored at or above") {
		t.Errorf("threshold message missing:\n%s", out)
	}
}

func TestAttackSurfaceAnalyze_EmptyExplainsWhy(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil)

	out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"No AttackSurface resources exist", "operator computes these", "pahlevan status"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty-result message missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "NAMESPACE\tNAME") {
		t.Errorf("an empty table should not be printed with no context:\n%s", out)
	}
}

func TestAttackSurfaceAnalyze_JSONAndYAML(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(85), nil),
		makeContainerProfile("web-abc", "prod", "web", "Enforcing", nil),
	)

	t.Run("json", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod", "-o", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var doc attackSurfaceAnalysis
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v\n%s", err, out)
		}
		if doc.Total != 1 || doc.Shown != 1 {
			t.Errorf("totals = %+v", doc)
		}
		e := doc.Exposures[0]
		if e.Name != "web" || e.RiskScore != 85 || e.RiskLevel != "Critical" {
			t.Errorf("exposure = %+v", e)
		}
		if e.Workload != "Deployment/web" {
			t.Errorf("workload = %q", e.Workload)
		}
		if e.Baseline == nil || e.Baseline.Enforcing != 1 {
			t.Errorf("baseline = %+v", e.Baseline)
		}
		if len(e.RiskySyscalls) != 1 || e.RiskySyscalls[0] != "ptrace" {
			t.Errorf("risky syscalls = %v", e.RiskySyscalls)
		}
	})

	t.Run("yaml", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "prod", "-o", "yaml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var doc attackSurfaceAnalysis
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("output is not valid YAML: %v\n%s", err, out)
		}
		if doc.Shown != 1 {
			t.Errorf("shown = %d", doc.Shown)
		}
	})

	t.Run("json carries the empty explanation", func(t *testing.T) {
		installFakeClientsWithCore(t, "empty-ns", nil)
		out, err := runCommand(t, NewAttackSurfaceAnalyzeCommand(), "-n", "empty-ns", "-o", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var doc attackSurfaceAnalysis
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if !strings.Contains(doc.Message, "No AttackSurface resources exist") {
			t.Errorf("message = %q", doc.Message)
		}
		if doc.Exposures == nil {
			t.Error("exposures should serialize as an empty list, not null")
		}
	})
}

// --- scoring and correlation ----------------------------------------------

func TestSurfaceRiskScore(t *testing.T) {
	tests := []struct {
		name        string
		status      policyv1alpha1.AttackSurfaceStatus
		wantScore   int32
		wantDerived bool
	}{
		{
			name:      "explicit score is used verbatim",
			status:    policyv1alpha1.AttackSurfaceStatus{RiskScore: int32Ptr(42)},
			wantScore: 42,
		},
		{
			name:      "explicit score is clamped high",
			status:    policyv1alpha1.AttackSurfaceStatus{RiskScore: int32Ptr(500)},
			wantScore: 100,
		},
		{
			name:      "explicit score is clamped low",
			status:    policyv1alpha1.AttackSurfaceStatus{RiskScore: int32Ptr(-5)},
			wantScore: 0,
		},
		{
			name:        "empty surface derives zero",
			status:      policyv1alpha1.AttackSurfaceStatus{},
			wantScore:   0,
			wantDerived: true,
		},
		{
			name: "capabilities dominate the derived score",
			status: policyv1alpha1.AttackSurfaceStatus{
				Capabilities: []string{"CAP_SYS_ADMIN", "sys_module"},
			},
			wantScore:   24,
			wantDerived: true,
		},
		{
			name: "risky syscalls, ports and paths contribute",
			status: policyv1alpha1.AttackSurfaceStatus{
				ExposedSyscalls: []string{"ptrace", "read"},
				ExposedPorts:    []int32{80, 443},
				WritableFiles:   []string{"/tmp"},
			},
			wantScore:   8,
			wantDerived: true,
		},
		{
			name: "derived score saturates at 100",
			status: policyv1alpha1.AttackSurfaceStatus{
				Capabilities: []string{"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_PTRACE",
					"CAP_BPF", "CAP_SYS_BOOT", "CAP_NET_ADMIN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID",
					"CAP_DAC_READ_SEARCH", "CAP_NET_RAW", "CAP_MKNOD", "CAP_SYS_CHROOT", "CAP_PERFMON"},
				ExposedSyscalls: []string{"ptrace", "mount", "bpf"},
			},
			wantScore:   100,
			wantDerived: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, derived := surfaceRiskScore(&tt.status)
			if score != tt.wantScore || derived != tt.wantDerived {
				t.Errorf("got (%d, %v), want (%d, %v)", score, derived, tt.wantScore, tt.wantDerived)
			}
		})
	}
}

func TestRiskLevel(t *testing.T) {
	tests := map[int32]string{0: "Minimal", 1: "Low", 29: "Low", 30: "Medium", 59: "Medium", 60: "High", 79: "High", 80: "Critical", 100: "Critical"}
	for score, want := range tests {
		if got := riskLevel(score); got != want {
			t.Errorf("riskLevel(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestNormalizeCapability(t *testing.T) {
	tests := map[string]string{
		"sys_admin":     "CAP_SYS_ADMIN",
		"CAP_SYS_ADMIN": "CAP_SYS_ADMIN",
		//nolint:gocritic // the surrounding whitespace is the case under test
		" net_raw ": "CAP_NET_RAW",
		"":          "",
	}
	for in, want := range tests {
		if got := normalizeCapability(in); got != want {
			t.Errorf("normalizeCapability(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterRiskyCapabilitiesAndSyscalls(t *testing.T) {
	caps := filterRiskyCapabilities([]string{"CAP_CHOWN", "CAP_SYS_ADMIN", "net_raw"})
	if strings.Join(caps, ",") != "CAP_SYS_ADMIN,net_raw" {
		t.Errorf("caps = %v", caps)
	}
	syscalls := filterRiskySyscalls([]string{"read", "PTRACE", "openat", "bpf"})
	if strings.Join(syscalls, ",") != "PTRACE,bpf" {
		t.Errorf("syscalls = %v", syscalls)
	}
	if filterRiskyCapabilities(nil) != nil || filterRiskySyscalls(nil) != nil {
		t.Error("nil input should give nil output")
	}
}

func TestIndexBaselines_CorrelatesByWorkloadAndPolicy(t *testing.T) {
	profiles := []policyv1alpha1.ContainerProfile{
		*makeContainerProfile("web-1", "prod", "web", "Learning", nil),
		*makeContainerProfile("web-2", "prod", "web", "Enforcing", func(cp *policyv1alpha1.ContainerProfile) {
			cp.Status.RollbackCount = 1
			cp.Status.DenialCount = 4
		}),
		// A profile that only knows its policy reference.
		{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "prod"},
			Spec:       policyv1alpha1.ContainerProfileSpec{PolicyRef: "solo-policy"},
			Status:     policyv1alpha1.ContainerProfileStatus{Phase: "Enforcing", SyscallCount: 5},
		},
	}
	index := indexBaselines(profiles)

	web := index[baselineKey{namespace: "prod", workload: "web"}]
	if web == nil {
		t.Fatal("web baseline not indexed")
	}
	if web.Containers != 2 || web.Learning != 1 || web.Enforcing != 1 {
		t.Errorf("web = %+v", web)
	}
	if web.LearnedSyscall != 80 || web.Rollbacks != 1 || web.Denials != 4 {
		t.Errorf("web counts = %+v", web)
	}
	if web.Phase() != "Mixed" {
		t.Errorf("phase = %q", web.Phase())
	}

	// The orphan falls back to the object namespace and the policy ref.
	if index[baselineKey{namespace: "prod", workload: "solo-policy"}] == nil {
		t.Error("policy-ref-only profile not indexed")
	}
}

func TestBaselineSummaryPhase(t *testing.T) {
	var nilSummary *baselineSummary
	tests := []struct {
		name string
		b    *baselineSummary
		want string
	}{
		{name: "nil", b: nilSummary, want: "Unknown"},
		{name: "no containers", b: &baselineSummary{}, want: "Unknown"},
		{name: "enforcing", b: &baselineSummary{Containers: 1, Enforcing: 1}, want: "Enforcing"},
		{name: "learning", b: &baselineSummary{Containers: 1, Learning: 1}, want: "Learning"},
		{name: "mixed", b: &baselineSummary{Containers: 2, Learning: 1, Enforcing: 1}, want: "Mixed"},
		{name: "other phase", b: &baselineSummary{Containers: 1}, want: "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.b.Phase(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSurfaceExposure_FallsBackToObjectNamespace(t *testing.T) {
	as := makeAttackSurface("web", "prod", int32Ptr(10), func(a *policyv1alpha1.AttackSurface) {
		a.Spec.Namespace = ""
		a.Spec.Workload = nil
	})
	e := newSurfaceExposure(as, nil)
	if e.Namespace != "prod" {
		t.Errorf("namespace = %q", e.Namespace)
	}
	if e.Workload != "" {
		t.Errorf("workload = %q", e.Workload)
	}
	if e.LastAnalysis == "" {
		t.Error("last analysis should be rendered")
	}
}

func TestWorkloadLabel(t *testing.T) {
	tests := []struct {
		ref  *policyv1alpha1.WorkloadReference
		want string
	}{
		{ref: nil, want: ""},
		{ref: &policyv1alpha1.WorkloadReference{}, want: ""},
		{ref: &policyv1alpha1.WorkloadReference{Name: "web"}, want: "web"},
		{ref: &policyv1alpha1.WorkloadReference{Kind: "Deployment", Name: "web"}, want: "Deployment/web"},
	}
	for _, tt := range tests {
		if got := workloadLabel(tt.ref); got != tt.want {
			t.Errorf("workloadLabel(%+v) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestSortExposures_StableOnTies(t *testing.T) {
	exposures := []surfaceExposure{
		{Namespace: "b", Name: "z", RiskScore: 10},
		{Namespace: "a", Name: "b", RiskScore: 10},
		{Namespace: "a", Name: "a", RiskScore: 10},
		{Namespace: "c", Name: "c", RiskScore: 90},
	}
	sortExposures(exposures)
	got := make([]string, 0, len(exposures))
	for _, e := range exposures {
		got = append(got, e.Namespace+"/"+e.Name)
	}
	want := "c/c,a/a,a/b,b/z"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

// --- report ---------------------------------------------------------------

func reportFixture(t *testing.T) (surfaces []policyv1alpha1.AttackSurface, profiles []policyv1alpha1.ContainerProfile, policies []policyv1alpha1.PahlevanPolicy) {
	t.Helper()
	surfaces = []policyv1alpha1.AttackSurface{
		*makeAttackSurface("web", "prod", int32Ptr(90), nil),
		*makeAttackSurface("api", "prod", int32Ptr(65), func(a *policyv1alpha1.AttackSurface) {
			a.Status.ExposedPorts = []int32{8443}
			a.Status.Capabilities = []string{"CAP_SYS_ADMIN"}
			a.Status.WritableFiles = []string{"/tmp"}
			a.Status.ExposedSyscalls = []string{"ptrace", "mount"}
		}),
		*makeAttackSurface("cache", "staging", int32Ptr(10), nil),
	}
	rollback := metav1.NewTime(time.Now().Add(-time.Hour))
	profiles = []policyv1alpha1.ContainerProfile{
		*makeContainerProfile("web-1", "prod", "web", "Enforcing", nil),
		*makeContainerProfile("api-1", "prod", "api", "Learning", func(cp *policyv1alpha1.ContainerProfile) {
			cp.Status.RollbackCount = 2
			cp.Status.DenialCount = 11
			cp.Status.LastRollbackTime = &rollback
			cp.Status.LastRollbackReason = "denial rate exceeded threshold"
		}),
		*makeContainerProfile("cache-1", "staging", "cache", "Initializing", nil),
	}
	policies = []policyv1alpha1.PahlevanPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "prod"}, Status: policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseEnforcing}},
		{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "prod"}, Status: policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseLearning}},
		{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: "staging"}},
	}
	return
}

func TestAggregateAttackSurfaceReport(t *testing.T) {
	surfaces, profiles, policies := reportFixture(t)
	report := aggregateAttackSurfaceReport(surfaces, profiles, policies, "", 10)

	if report.Totals.AttackSurfaces != 3 || report.Totals.Namespaces != 2 {
		t.Errorf("totals = %+v", report.Totals)
	}
	if report.Totals.Policies != 3 || report.Totals.ContainerProfiles != 3 {
		t.Errorf("totals = %+v", report.Totals)
	}
	if report.Totals.MaxRisk != 90 {
		t.Errorf("max risk = %d", report.Totals.MaxRisk)
	}
	if report.Totals.HighRisk != 2 {
		t.Errorf("high risk = %d, want 2 (90 and 65)", report.Totals.HighRisk)
	}
	// (90 + 65 + 10) / 3 = 55.0
	if report.Totals.AverageRisk != 55 {
		t.Errorf("average risk = %v", report.Totals.AverageRisk)
	}
	if report.TopWorkloads[0].Name != "web" {
		t.Errorf("top workload = %q", report.TopWorkloads[0].Name)
	}

	// Aggregates: 8443 is exposed by all three, 80 by two.
	if len(report.ExposedPorts) == 0 || report.ExposedPorts[0].Port != 8443 || report.ExposedPorts[0].Workloads != 3 {
		t.Errorf("exposed ports = %+v", report.ExposedPorts)
	}
	if report.Capabilities[0].Name != "CAP_SYS_ADMIN" || report.Capabilities[0].Workloads != 3 {
		t.Errorf("capabilities = %+v", report.Capabilities)
	}
	if report.WritablePaths[0].Name != "/tmp" || report.WritablePaths[0].Workloads != 3 {
		t.Errorf("writable paths = %+v", report.WritablePaths)
	}
	if len(report.RiskySyscalls) != 2 {
		t.Errorf("risky syscalls = %+v", report.RiskySyscalls)
	}

	e := report.Enforcement
	if e.ProfilesTotal != 3 || e.ProfilesLearning != 1 || e.ProfilesEnforcing != 1 || e.ProfilesOther != 1 {
		t.Errorf("posture = %+v", e)
	}
	if e.Rollbacks != 2 || e.Denials != 11 || e.ProfilesRolledBk != 1 {
		t.Errorf("self healing = %+v", e)
	}
	if e.LastRollback == "" || e.LastRollbackWhy != "denial rate exceeded threshold" {
		t.Errorf("last rollback = %+v", e)
	}
	if e.PoliciesByPhase["Enforcing"] != 1 || e.PoliciesByPhase["Learning"] != 1 || e.PoliciesByPhase["Unknown"] != 1 {
		t.Errorf("policies by phase = %+v", e.PoliciesByPhase)
	}
	if got := e.EnforcingRatio(); got < 0.33 || got > 0.34 {
		t.Errorf("enforcing ratio = %v", got)
	}
}

func TestAggregateAttackSurfaceReport_TopTruncates(t *testing.T) {
	surfaces, profiles, policies := reportFixture(t)
	report := aggregateAttackSurfaceReport(surfaces, profiles, policies, "prod", 1)
	if len(report.TopWorkloads) != 1 || report.TopWorkloads[0].Name != "web" {
		t.Errorf("top = %+v", report.TopWorkloads)
	}
	if report.Scope != `namespace "prod"` {
		t.Errorf("scope = %q", report.Scope)
	}
}

func TestAggregateAttackSurfaceReport_Empty(t *testing.T) {
	report := aggregateAttackSurfaceReport(nil, nil, nil, "prod", 10)
	if report.Totals.AttackSurfaces != 0 || report.Totals.AverageRisk != 0 {
		t.Errorf("totals = %+v", report.Totals)
	}
	if !strings.Contains(report.Message, "No AttackSurface resources exist") {
		t.Errorf("message = %q", report.Message)
	}
	if report.Enforcement.EnforcingRatio() != 0 {
		t.Error("ratio of an empty cluster should be zero")
	}
	if report.Enforcement.PoliciesByPhase != nil {
		t.Error("empty phase map should be nil so it is omitted")
	}
}

func TestAttackSurfaceReport_OutputFormats(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(90), nil),
		makeContainerProfile("web-1", "prod", "web", "Enforcing", nil),
		&policyv1alpha1.PahlevanPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "web-policy", Namespace: "prod"},
			Status:     policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseEnforcing},
		},
	)

	t.Run("table", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, want := range []string{"Pahlevan Attack Surface Report", "Cluster totals", "Riskiest workloads",
			"Most exposed ports", "Most common capabilities", "Enforcement posture", "Enforcing ratio"} {
			if !strings.Contains(out, want) {
				t.Errorf("table report missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("markdown", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "-o", "markdown")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, want := range []string{"# Pahlevan attack surface report", "## Cluster totals", "| Metric | Value |",
			"## Riskiest workloads", "## Enforcement posture", "### Policies by phase"} {
			if !strings.Contains(out, want) {
				t.Errorf("markdown report missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "-o", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var report attackSurfaceReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out)
		}
		if report.Totals.AttackSurfaces != 1 {
			t.Errorf("totals = %+v", report.Totals)
		}
	})

	t.Run("yaml", func(t *testing.T) {
		out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "-o", "yaml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var report attackSurfaceReport
		if err := yaml.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("invalid YAML: %v\n%s", err, out)
		}
		if report.Scope != "all namespaces" {
			t.Errorf("scope = %q", report.Scope)
		}
	})
}

func TestAttackSurfaceReport_EmptyMarkdownAndTable(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil)
	for _, format := range []string{"table", "markdown"} {
		t.Run(format, func(t *testing.T) {
			out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "-o", format)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(out, "No AttackSurface resources exist") {
				t.Errorf("empty report should explain why:\n%s", out)
			}
		})
	}
}

func TestAttackSurfaceReport_WritesFile(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil, makeAttackSurface("web", "prod", int32Ptr(90), nil))

	path := filepath.Join(t.TempDir(), "surface.md")
	out, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "-o", "markdown", "--file", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "written to "+path) {
		t.Errorf("confirmation missing:\n%s", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	if !strings.HasPrefix(string(data), "# Pahlevan attack surface report") {
		t.Errorf("file content = %q", string(data)[:min(80, len(data))])
	}
}

func TestAttackSurfaceReport_FileErrorIsActionable(t *testing.T) {
	installFakeClientsWithCore(t, "prod", nil, makeAttackSurface("web", "prod", int32Ptr(90), nil))
	path := filepath.Join(t.TempDir(), "missing-dir", "surface.md")
	_, err := runCommand(t, NewAttackSurfaceReportCommand(), "-A", "--file", path)
	if err == nil || !strings.Contains(err.Error(), "cannot write report to") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteReportFile_WriteFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory cannot be overwritten with a regular file.
	if err := writeReportFile(dir, []byte("x")); err == nil {
		t.Fatal("expected an error writing over a directory")
	}
}

func TestTopCountHelpers(t *testing.T) {
	names := topNameCounts(map[string]int{"a": 1, "b": 3, "c": 3, "d": 2}, 3)
	if len(names) != 3 || names[0].Name != "b" || names[1].Name != "c" || names[2].Name != "d" {
		t.Errorf("names = %+v", names)
	}
	if topNameCounts(nil, 3) != nil {
		t.Error("empty map should give nil")
	}

	ports := topPortCounts(map[int32]int{80: 1, 443: 5, 8080: 5}, 2)
	if len(ports) != 2 || ports[0].Port != 443 || ports[1].Port != 8080 {
		t.Errorf("ports = %+v", ports)
	}
	if topPortCounts(nil, 3) != nil {
		t.Error("empty map should give nil")
	}
}

func TestDedupeHelpers(t *testing.T) {
	if got := dedupeStrings([]string{"a", "b", "a"}); strings.Join(got, ",") != "a,b" {
		t.Errorf("dedupeStrings = %v", got)
	}
	if got := dedupeStrings([]string{"a"}); len(got) != 1 {
		t.Errorf("single element should pass through: %v", got)
	}
	if got := dedupePorts([]int32{80, 80, 443}); len(got) != 2 {
		t.Errorf("dedupePorts = %v", got)
	}
	if got := dedupePorts([]int32{80}); len(got) != 1 {
		t.Errorf("single element should pass through: %v", got)
	}
	// Dedupe must not clobber the caller's slice.
	in := []string{"a", "b", "a"}
	_ = dedupeStrings(in)
	if in[1] != "b" {
		t.Errorf("input mutated: %v", in)
	}
}

func TestRoundTo(t *testing.T) {
	if got := roundTo(1.2345, 1); got != 1.2 {
		t.Errorf("got %v", got)
	}
	if got := roundTo(1.25, 1); got != 1.3 {
		t.Errorf("got %v", got)
	}
	if got := roundTo(7, 0); got != 7 {
		t.Errorf("got %v", got)
	}
}

func TestAttackSurfaceFormatHelpers(t *testing.T) {
	if got := formatPortsFull(nil); got != "<none>" {
		t.Errorf("got %q", got)
	}
	if got := formatPortsFull([]int32{1, 2, 3, 4}); got != "1, 2, 3, 4" {
		t.Errorf("got %q", got)
	}
	if got := orNone(""); got != "<none>" {
		t.Errorf("got %q", got)
	}
	if got := orNone("x"); got != "x" {
		t.Errorf("got %q", got)
	}
	if got := mdList(nil); got != "-" {
		t.Errorf("got %q", got)
	}
	if got := mdList([]string{"a", "b"}); got != "a<br>b" {
		t.Errorf("got %q", got)
	}
	if got := riskCell(surfaceExposure{RiskScore: 5, RiskDerived: true}); got != "5*" {
		t.Errorf("derived score should be marked: %q", got)
	}
	if got := riskCell(surfaceExposure{RiskScore: 5}); got != "5" {
		t.Errorf("got %q", got)
	}
	if got := formatCapCell(surfaceExposure{Capabilities: []string{"a", "b"}}); got != "2" {
		t.Errorf("got %q", got)
	}
	if got := formatCapCell(surfaceExposure{Capabilities: []string{"a", "b"}, RiskyCapability: []string{"a"}}); got != "2 (1 risky)" {
		t.Errorf("got %q", got)
	}
	if got := formatSyscallCell(surfaceExposure{ExposedSyscalls: []string{"a"}}); got != "1" {
		t.Errorf("got %q", got)
	}
	if got := formatSyscallCell(surfaceExposure{ExposedSyscalls: []string{"a"}, RiskySyscalls: []string{"a"}}); got != "1 (1 risky)" {
		t.Errorf("got %q", got)
	}
	if got := sortedKeys(map[string]int{"b": 1, "a": 1}); strings.Join(got, ",") != "a,b" {
		t.Errorf("got %v", got)
	}
	if sortedCopy(nil) != nil || sortedPorts(nil) != nil {
		t.Error("nil input should give nil output")
	}
}

func TestScopeLabel(t *testing.T) {
	if got := scopeLabel(""); got != "all namespaces" {
		t.Errorf("got %q", got)
	}
	if got := scopeLabel("prod"); got != `namespace "prod"` {
		t.Errorf("got %q", got)
	}
}

// --- benchmarks -----------------------------------------------------------

func benchReportFixture(workloads int) ([]policyv1alpha1.AttackSurface, []policyv1alpha1.ContainerProfile, []policyv1alpha1.PahlevanPolicy) {
	surfaces := make([]policyv1alpha1.AttackSurface, 0, workloads)
	profiles := make([]policyv1alpha1.ContainerProfile, 0, workloads*3)
	policies := make([]policyv1alpha1.PahlevanPolicy, 0, workloads)

	caps := []string{"CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_CHOWN", "CAP_SETUID", "CAP_BPF"}
	syscalls := []string{"openat", "read", "write", "ptrace", "mount", "bpf", "close", "futex"}

	for i := 0; i < workloads; i++ {
		ns := fmt.Sprintf("ns-%d", i%12)
		name := fmt.Sprintf("workload-%d", i)
		as := makeAttackSurface(name, ns, int32Ptr(int32(i%101)), func(a *policyv1alpha1.AttackSurface) {
			a.Status.ExposedPorts = []int32{int32(8000 + i%50), 443, 80}
			a.Status.Capabilities = caps[:1+i%len(caps)]
			a.Status.ExposedSyscalls = syscalls[:1+i%len(syscalls)]
			a.Status.WritableFiles = []string{"/tmp", fmt.Sprintf("/var/lib/app-%d", i%20), "/run"}
		})
		surfaces = append(surfaces, *as)
		for c := 0; c < 3; c++ {
			phase := "Learning"
			if i%2 == 0 {
				phase = "Enforcing"
			}
			profiles = append(profiles, *makeContainerProfile(fmt.Sprintf("%s-%d", name, c), ns, name, phase, nil))
		}
		policies = append(policies, policyv1alpha1.PahlevanPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-policy", Namespace: ns},
			Status:     policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseEnforcing},
		})
	}
	return surfaces, profiles, policies
}

func BenchmarkAggregateAttackSurfaceReport(b *testing.B) {
	surfaces, profiles, policies := benchReportFixture(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := aggregateAttackSurfaceReport(surfaces, profiles, policies, "", 10)
		if report.Totals.AttackSurfaces != 500 {
			b.Fatalf("unexpected totals: %+v", report.Totals)
		}
	}
}

func BenchmarkIndexBaselines(b *testing.B) {
	_, profiles, _ := benchReportFixture(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(indexBaselines(profiles)) == 0 {
			b.Fatal("no baselines indexed")
		}
	}
}

func BenchmarkRenderAttackSurfaceReportMarkdown(b *testing.B) {
	surfaces, profiles, policies := benchReportFixture(500)
	report := aggregateAttackSurfaceReport(surfaces, profiles, policies, "", 25)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeReportMarkdown(&buf, report); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

// Ensure the analyze aggregation path itself is exercised under load.
func BenchmarkBuildAttackSurfaceAnalysis(b *testing.B) {
	surfaces, profiles, _ := benchReportFixture(200)
	baselines := indexBaselines(profiles)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exposures := make([]surfaceExposure, 0, len(surfaces))
		for j := range surfaces {
			exposures = append(exposures, newSurfaceExposure(&surfaces[j], baselines))
		}
		sortExposures(exposures)
	}
}

// --- missing CRD paths ----------------------------------------------------

// clientWithoutPahlevanCRDs returns a controller-runtime client whose scheme
// omits the Pahlevan types, which is how a cluster without the CRDs installed
// behaves: List fails with a kind-not-registered error.
func clientWithoutPahlevanCRDs(t *testing.T) crclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func TestAttackSurface_MissingCRDIsExplained(t *testing.T) {
	c := clientWithoutPahlevanCRDs(t)

	t.Run("analyze", func(t *testing.T) {
		_, err := buildAttackSurfaceAnalysis(context.Background(), c, "prod", 0)
		if err == nil || !strings.Contains(err.Error(), "AttackSurface CRD is not installed") {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), "install.yaml") {
			t.Errorf("error should say how to fix it: %v", err)
		}
	})

	t.Run("report", func(t *testing.T) {
		_, err := buildAttackSurfaceReport(context.Background(), c, "prod", 10)
		if err == nil || !strings.Contains(err.Error(), "AttackSurface CRD is not installed") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestBuildAttackSurfaceReport_NilContext(t *testing.T) {
	fc, _ := installFakeClientsWithCore(t, "prod", nil,
		makeAttackSurface("web", "prod", int32Ptr(50), nil),
		makeContainerProfile("web-1", "prod", "web", "Enforcing", nil),
		&policyv1alpha1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"}},
	)
	//nolint:staticcheck // a nil context is defended against on purpose
	report, err := buildAttackSurfaceReport(nil, fc, "prod", 5)
	if err != nil {
		t.Fatalf("buildAttackSurfaceReport: %v", err)
	}
	if report.Totals.AttackSurfaces != 1 || report.Totals.ContainerProfiles != 1 || report.Totals.Policies != 1 {
		t.Errorf("totals = %+v", report.Totals)
	}
}

func TestBuildAttackSurfaceAnalysis_NilContext(t *testing.T) {
	fc, _ := installFakeClientsWithCore(t, "prod", nil, makeAttackSurface("web", "prod", int32Ptr(50), nil))
	//nolint:staticcheck // a nil context is defended against on purpose
	analysis, err := buildAttackSurfaceAnalysis(nil, fc, "prod", 0)
	if err != nil {
		t.Fatalf("buildAttackSurfaceAnalysis: %v", err)
	}
	if analysis.Shown != 1 {
		t.Errorf("shown = %d", analysis.Shown)
	}
}

func TestProfileKeys(t *testing.T) {
	// Namespace falls back to the object namespace, and duplicate keys collapse.
	p := &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "fallback-ns"},
		Spec: policyv1alpha1.ContainerProfileSpec{
			PolicyRef: "same",
			Workload:  &policyv1alpha1.WorkloadReference{Name: "same"},
		},
	}
	keys := profileKeys(p)
	if len(keys) != 1 || keys[0].namespace != "fallback-ns" || keys[0].workload != "same" {
		t.Errorf("keys = %+v", keys)
	}

	// A profile with neither reference produces no keys.
	if got := profileKeys(&policyv1alpha1.ContainerProfile{}); len(got) != 0 {
		t.Errorf("keys = %+v", got)
	}
}
