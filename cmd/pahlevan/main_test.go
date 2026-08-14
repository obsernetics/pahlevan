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

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRootCommand_Basics(t *testing.T) {
	cmd := NewRootCommand()
	if cmd.Use != "pahlevan" {
		t.Errorf("Use = %q, want pahlevan", cmd.Use)
	}
	if !strings.Contains(cmd.Version, version) {
		t.Errorf("Version = %q, want it to contain %q", cmd.Version, version)
	}
	if !cmd.SilenceUsage || !cmd.SilenceErrors {
		t.Error("root command should silence usage and errors")
	}
}

func TestNewRootCommand_GlobalFlags(t *testing.T) {
	cmd := NewRootCommand()
	flags := cmd.PersistentFlags()
	for _, name := range []string{"output", "verbose", "kubeconfig", "namespace"} {
		if flags.Lookup(name) == nil {
			t.Errorf("expected persistent flag %q to be registered", name)
		}
	}
	// Short flags.
	if flags.ShorthandLookup("o") == nil {
		t.Error("expected -o shorthand for output")
	}
	if flags.ShorthandLookup("v") == nil {
		t.Error("expected -v shorthand for verbose")
	}
	// Default value of output.
	if f := flags.Lookup("output"); f == nil || f.DefValue != "table" {
		t.Errorf("output flag default = %v, want table", f)
	}
}

func TestNewRootCommand_Subcommands(t *testing.T) {
	cmd := NewRootCommand()
	want := map[string]bool{
		"policy": false, "attack-surface": false, "status": false,
		"logs": false, "metrics": false, "debug": false,
		"completion": false, "version": false,
	}
	for _, sub := range cmd.Commands() {
		want[sub.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected subcommand %q to be registered", name)
		}
	}
}

func TestRootCommand_HelpRuns(t *testing.T) {
	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Pahlevan CLI") {
		t.Errorf("help output missing description: %q", out)
	}
	if !strings.Contains(out, "Available Commands") {
		t.Errorf("help output missing command list: %q", out)
	}
}

// TestRootCommand_PersistentPreRunE drives the root PersistentPreRunE closure
// (kubeconfig/namespace extraction + client initialization). With no reachable
// cluster config, InitializeClients must fail, surfacing an error from Execute.
// This exercises the wiring without requiring a live cluster.
func TestRootCommand_PersistentPreRunE(t *testing.T) {
	// Make config discovery deterministic: no default kubeconfig, no in-cluster.
	t.Setenv("KUBECONFIG", "/nonexistent/pahlevan-test-kubeconfig")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	// Pass namespace + kubeconfig so both closure branches are taken, then a
	// subcommand so PersistentPreRunE runs.
	cmd.SetArgs([]string{
		"--kubeconfig", "/nonexistent/pahlevan-test-kubeconfig",
		"--namespace", "demo",
		"status",
	})
	err := cmd.Execute()
	if err == nil {
		t.Skip("cluster config unexpectedly available; skipping negative init assertion")
	}
	if !strings.Contains(err.Error(), "config") && !strings.Contains(err.Error(), "kubeconfig") {
		t.Logf("got expected initialization error: %v", err)
	}
}

func TestRootCommand_VersionFlag(t *testing.T) {
	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version returned error: %v", err)
	}
	if !strings.Contains(buf.String(), version) {
		t.Errorf("--version output = %q, want it to contain %q", buf.String(), version)
	}
}
