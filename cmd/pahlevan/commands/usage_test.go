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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testCmd(use string) *cobra.Command {
	root := &cobra.Command{Use: "pahlevan"}
	c := &cobra.Command{Use: use, Run: func(*cobra.Command, []string) {}}
	root.AddCommand(c)
	return c
}

func TestNamedArgsNamesWhatIsMissing(t *testing.T) {
	c := testCmd("get <policy-name>")
	err := NamedArgs("policy-name")(c, nil)
	if err == nil {
		t.Fatal("a missing argument must be an error")
	}
	if !strings.Contains(err.Error(), "<policy-name>") {
		t.Errorf("error should name the argument: %v", err)
	}
	if !strings.Contains(err.Error(), "Usage: pahlevan get <policy-name>") {
		t.Errorf("error should carry the one-line usage: %v", err)
	}
	// The number cobra would have printed is exactly what is not useful here.
	if strings.Contains(err.Error(), "accepts 1 arg(s)") {
		t.Errorf("error fell back to cobra's counting message: %v", err)
	}
}

func TestNamedArgsAcceptsTheRightCount(t *testing.T) {
	c := testCmd("get <policy-name>")
	if err := NamedArgs("policy-name")(c, []string{"web"}); err != nil {
		t.Errorf("one argument should be accepted: %v", err)
	}
}

func TestNamedArgsRejectsExtraArguments(t *testing.T) {
	c := testCmd("get <policy-name>")
	err := NamedArgs("policy-name")(c, []string{"web", "extra"})
	if err == nil {
		t.Fatal("an extra argument must be an error")
	}
	// A second name typed by habit ("policy get a b") is usually a forgotten
	// flag, so the message has to show which word was not expected.
	if !strings.Contains(err.Error(), `"extra"`) {
		t.Errorf("error should quote the unexpected argument: %v", err)
	}
	if !strings.Contains(err.Error(), "one argument") {
		t.Errorf("error should say how many arguments are taken: %v", err)
	}
}

func TestNamedArgsListsSeveralMissingArguments(t *testing.T) {
	c := testCmd("move <from> <to>")
	err := NamedArgs("from", "to")(c, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "<from> and <to>") {
		t.Errorf("both names should be listed: %v", err)
	}

	err = NamedArgs("a", "b", "c")(c, nil)
	if err == nil || !strings.Contains(err.Error(), "<a>, <b> and <c>") {
		t.Errorf("three names should be listed in series: %v", err)
	}

	// The count in the "too many" message follows the number of names.
	err = NamedArgs("from", "to")(c, []string{"a", "b", "c"})
	if err == nil || !strings.Contains(err.Error(), "2 arguments") {
		t.Errorf("error should say how many arguments are taken: %v", err)
	}

	// Already-bracketed names must not end up double-bracketed.
	err = NamedArgs("<from>")(c, nil)
	if err == nil || strings.Contains(err.Error(), "<<from>>") {
		t.Errorf("names should be bracketed once: %v", err)
	}
}

func TestOneOfArgsNamesTheValidValues(t *testing.T) {
	c := testCmd("completion [bash|zsh]")

	err := OneOfArgs("shell", "bash", "zsh")(c, nil)
	if err == nil || !strings.Contains(err.Error(), "<shell>") {
		t.Errorf("a missing shell should name the argument: %v", err)
	}

	err = OneOfArgs("shell", "bash", "zsh")(c, []string{"tcsh"})
	if err == nil {
		t.Fatal("an unsupported shell must be an error")
	}
	if !strings.Contains(err.Error(), "bash, zsh") {
		t.Errorf("error should list the accepted values: %v", err)
	}
	if !strings.Contains(err.Error(), "Usage:") {
		t.Errorf("error should carry the usage line: %v", err)
	}

	if err := OneOfArgs("shell", "bash", "zsh")(c, []string{"zsh"}); err != nil {
		t.Errorf("a valid value should be accepted: %v", err)
	}
}

// TestClusterErrorsTellTheUserWhatToDo covers both halves of the missing
// cluster message: the machine-readable marker other tests rely on, and the
// three things a stuck user needs - a flag, an environment variable, and a
// command that works anyway.
func TestClusterErrorsTellTheUserWhatToDo(t *testing.T) {
	msg := errClientsNotReady().Error()
	if !strings.Contains(msg, "not initialized") {
		t.Errorf("the marker other commands assert on is gone: %v", msg)
	}
	for _, want := range []string{"--kubeconfig", "KUBECONFIG", "kubectl config current-context", "version"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing-cluster error should mention %q, got:\n%s", want, msg)
		}
	}
	if !strings.Contains(ClusterHint(), "policy explain") {
		t.Errorf("the hint should name the offline commands: %s", ClusterHint())
	}
}

// TestWatchAndFollowAreInterchangeable pins the alias down. The primary
// spelling stays what it was - that is the backward-compatibility half - and
// the other word resolves to the same flag instead of "unknown flag".
func TestWatchAndFollowAreInterchangeable(t *testing.T) {
	logs := NewLogsCommand()
	if err := logs.Flags().Parse([]string{"--watch"}); err != nil {
		t.Fatalf("logs should accept --watch as --follow: %v", err)
	}
	if f := logs.Flags().Lookup("follow"); f == nil || f.Value.String() != "true" {
		t.Errorf("--watch did not set --follow on logs: %v", f)
	}
	if logs.Flags().Lookup("watch") == nil {
		t.Error("looking up the alias should resolve to the real flag")
	}

	events := NewEventsCommand()
	if err := events.Flags().Parse([]string{"--watch"}); err != nil {
		t.Fatalf("events should accept --watch as --follow: %v", err)
	}

	metrics := NewMetricsCommand()
	if err := metrics.Flags().Parse([]string{"--follow"}); err != nil {
		t.Fatalf("metrics should accept --follow as --watch: %v", err)
	}
	if f := metrics.Flags().Lookup("watch"); f == nil || f.Value.String() != "true" {
		t.Errorf("--follow did not set --watch on metrics: %v", f)
	}

	status := NewPolicyStatusCommand()
	if err := status.Flags().Parse([]string{"--follow"}); err != nil {
		t.Fatalf("policy status should accept --follow as --watch: %v", err)
	}

	// The shorthands are deliberately not aliased, and each command keeps its
	// own: breaking -f on logs to make room for a -w would be the opposite of
	// backward compatible.
	if logs.Flags().ShorthandLookup("f") == nil {
		t.Error("logs must keep -f")
	}
	if metrics.Flags().ShorthandLookup("w") == nil {
		t.Error("metrics must keep -w")
	}
}

// TestStatusRefusesAFormatItCannotProduce: status inherits the root's
// --output and renders a report. Printing a table to someone who asked for
// JSON means their jq pipeline fails somewhere else entirely.
func TestStatusRefusesAFormatItCannotProduce(t *testing.T) {
	installFakeClients(t)

	root := &cobra.Command{Use: "pahlevan"}
	root.PersistentFlags().StringP("output", "o", "table", "Output format")
	status := NewStatusCommand()
	root.AddCommand(status)
	root.SetArgs([]string{"status", "-o", "json"})
	root.SetOut(&strings.Builder{})

	err := root.Execute()
	if err == nil {
		t.Fatal("status should refuse a format it cannot produce")
	}
	if !strings.Contains(err.Error(), "pahlevan debug -o json") {
		t.Errorf("the error should name the command that does produce JSON: %v", err)
	}
}

func BenchmarkNamedArgs(b *testing.B) {
	c := testCmd("get <policy-name>")
	args := cobra.PositionalArgs(NamedArgs("policy-name"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = args(c, []string{"web"})
	}
}

func BenchmarkNamedArgsError(b *testing.B) {
	c := testCmd("get <policy-name>")
	args := cobra.PositionalArgs(NamedArgs("policy-name"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = args(c, nil)
	}
}

// TestInitializeClientsReadsTheNamedFile pins the difference between a path
// and a context name. --kubeconfig used to be handed to a function whose
// argument is a context, so naming a file either failed with `context
// "/path/to/file" does not exist` or, when a context of that name existed,
// silently used a different cluster than the one asked for.
func TestInitializeClientsReadsTheNamedFile(t *testing.T) {
	prevK8s, prevKube, prevCfg, prevNs, prevReady := k8sClient, kubeClient, restConfig, globalNamespace, clientsReady
	t.Cleanup(func() {
		k8sClient, kubeClient, restConfig, globalNamespace, clientsReady = prevK8s, prevKube, prevCfg, prevNs, prevReady
	})
	t.Setenv("KUBECONFIG", "/nonexistent/pahlevan-test-kubeconfig")
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), "kubeconfig.yaml")
	const kubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: demo
  cluster: {server: https://127.0.0.1:65001}
contexts:
- name: demo
  context: {cluster: demo, user: demo}
- name: other
  context: {cluster: demo, user: demo}
current-context: demo
users:
- name: demo
  user: {token: abc}
`
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatalf("writing the test kubeconfig: %v", err)
	}

	if err := InitializeClients(path, "", "demo-ns", false); err != nil {
		t.Fatalf("a kubeconfig path should be read as a file: %v", err)
	}
	_, _, cfg, ns, ready := GetClients()
	if !ready || cfg == nil {
		t.Fatal("clients should be ready after loading a valid kubeconfig")
	}
	if cfg.Host != "https://127.0.0.1:65001" {
		t.Errorf("loaded the wrong cluster: %s", cfg.Host)
	}
	if ns != "demo-ns" {
		t.Errorf("namespace = %q, want demo-ns", ns)
	}

	// A context that the file does not define must fail rather than quietly
	// fall back to the current one.
	if err := InitializeClients(path, "missing", "", false); err == nil {
		t.Error("an unknown --context should be an error")
	}
	if err := InitializeClients(path, "other", "", false); err != nil {
		t.Errorf("a context the file defines should be selectable: %v", err)
	}
}
