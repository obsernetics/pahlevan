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
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// These tests are about the shape of the command surface rather than what any
// one command does. They walk the tree, so a command added next year is held
// to the same rules without anybody remembering to add a test for it.

// walk visits every command in the tree, skipping the ones cobra generates.
//
// The generated help command carries no Example and no group of its own; it is
// cobra's, not ours, and holding it to our rules would only teach the next
// person to weaken the rules.
func walk(root *cobra.Command, visit func(*cobra.Command)) {
	var rec func(*cobra.Command)
	rec = func(c *cobra.Command) {
		if strings.HasPrefix(c.Name(), "__") || c.Name() == "help" {
			return
		}
		visit(c)
		for _, sub := range c.Commands() {
			rec(sub)
		}
	}
	rec(root)
}

// --- bare invocation ------------------------------------------------------

// TestBareInvocationWithoutATerminalPrintsHelp is the rule that keeps
// `pahlevan | head` and `pahlevan > file` working. A bytes.Buffer is not an
// *os.File, so the decision function sees no terminal - the same answer a pipe
// produces - and the tool must print help and succeed.
func TestBareInvocationWithoutATerminalPrintsHelp(t *testing.T) {
	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("bare invocation returned an error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "pahlevan [command]") {
		t.Errorf("bare invocation should print help, got:\n%s", out)
	}
	// Nothing may be drawn: an escape sequence in a pipe is the failure this
	// test exists to catch.
	if strings.Contains(out, "\x1b[") {
		t.Errorf("bare invocation wrote terminal escape sequences into a non-terminal writer:\n%q", out)
	}
}

// TestOpensConsoleOnlyForABareTerminalInvocation drives the decision function
// directly, because deciding this correctly matters more than being able to
// spawn a pseudo-terminal in CI.
func TestOpensConsoleOnlyForABareTerminalInvocation(t *testing.T) {
	// A terminal is only ever claimed for an *os.File that really is one.
	// os.Stdout under `go test` is a pipe, so this is the honest negative.
	cmd := NewRootCommand()
	cmd.SetOut(&bytes.Buffer{})
	if opensConsole(cmd, nil) {
		t.Error("a non-file writer must never select the console")
	}

	cmd = NewRootCommand()
	cmd.SetOut(os.Stdout)
	// Whatever os.Stdout is under the test runner, adding a flag or an
	// argument must take the console off the table either way. ParseFlags is
	// how cobra itself populates the set before RunE, so NFlag sees what it
	// would see in a real invocation.
	if err := cmd.ParseFlags([]string{"--verbose"}); err != nil {
		t.Fatalf("parsing a flag: %v", err)
	}
	if opensConsole(cmd, nil) {
		t.Error("a flag with no command is a half-typed command line, not a request to draw")
	}
	if opensConsole(cmd, []string{"something"}) {
		t.Error("positional arguments must not select the console")
	}
}

// TestBareInvocationNeedsNoCluster guards the regression that would make the
// whole feature useless on a laptop: the root's PersistentPreRunE must not try
// to build Kubernetes clients for an invocation that only prints help or draws
// an event view.
func TestBareInvocationNeedsNoCluster(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/pahlevan-test-kubeconfig")
	t.Setenv("HOME", t.TempDir())

	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bare invocation must not need a cluster, got: %v", err)
	}
}

// --- help text ------------------------------------------------------------

func TestEveryCommandHasAShort(t *testing.T) {
	walk(NewRootCommand(), func(c *cobra.Command) {
		if strings.TrimSpace(c.Short) == "" {
			t.Errorf("%q has no Short, so it is a blank line in its parent's help", c.CommandPath())
		}
	})
}

// TestEveryRunnableCommandHasAnExample holds the line that one unexplained
// command breaks. A command a user can actually run takes arguments or flags,
// and cobra prints Example right under the usage line - the one place a reader
// looks to find out what a real invocation looks like.
func TestEveryRunnableCommandHasAnExample(t *testing.T) {
	walk(NewRootCommand(), func(c *cobra.Command) {
		if !c.Runnable() && !c.HasSubCommands() {
			return
		}
		if strings.TrimSpace(c.Example) == "" {
			t.Errorf("%q has no Example; add one and run it before committing it", c.CommandPath())
		}
		// An example that does not name the command it illustrates is a
		// copy-paste from somewhere else.
		if !strings.Contains(c.Example, c.CommandPath()) {
			t.Errorf("%q's Example never invokes %q:\n%s", c.CommandPath(), c.CommandPath(), c.Example)
		}
	})
}

// --- grouping -------------------------------------------------------------

// TestEveryCommandIsInARegisteredGroup catches the failure that ships quietly:
// cobra panics at execute time on a GroupID its parent never registered, and a
// command with no GroupID at all is filed under a stray "Additional Commands"
// heading instead of where it belongs.
func TestEveryCommandIsInARegisteredGroup(t *testing.T) {
	root := NewRootCommand()
	// The generated help command gets its group from SetHelpCommandGroupID,
	// which only takes effect once the command exists.
	root.InitDefaultHelpCmd()

	for _, sub := range root.Commands() {
		if sub.GroupID == "" {
			t.Errorf("%q has no GroupID: it would be listed under \"Additional Commands\"", sub.CommandPath())
			continue
		}
		if !root.ContainsGroup(sub.GroupID) {
			t.Errorf("%q is in group %q, which the root never registered (cobra panics on this)",
				sub.CommandPath(), sub.GroupID)
		}
	}
	if !root.AllChildCommandsHaveGroup() {
		t.Error("help would print an \"Additional Commands\" section")
	}
}

func TestHelpListsTheGroups(t *testing.T) {
	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help returned an error: %v", err)
	}
	out := buf.String()
	for _, title := range []string{
		"Watch a running deployment:",
		"Inspect policies and workloads:",
		"Other commands:",
	} {
		if !strings.Contains(out, title) {
			t.Errorf("help is missing the group %q:\n%s", title, out)
		}
	}
	if strings.Contains(out, "Additional Commands:") {
		t.Errorf("help has an ungrouped leftover section:\n%s", out)
	}
}

// --- failure messages -----------------------------------------------------

// TestMissingArgumentNamesTheArgumentAndTheUsage covers the message a user
// gets on their first attempt. "accepts 1 arg(s), received 0" names neither
// the argument nor the command.
func TestMissingArgumentNamesTheArgumentAndTheUsage(t *testing.T) {
	cases := []struct {
		args      []string
		wantArg   string
		wantUsage string
	}{
		{[]string{"policy", "get"}, "<policy-name>", "pahlevan policy get <policy-name>"},
		{[]string{"policy", "describe"}, "<policy-name>", "pahlevan policy describe <policy-name>"},
		{[]string{"policy", "delete"}, "<policy-name>", "pahlevan policy delete <policy-name>"},
		{[]string{"policy", "update"}, "<policy-name>", "pahlevan policy update <policy-name>"},
		{[]string{"policy", "status"}, "<policy-name>", "pahlevan policy status <policy-name>"},
		{[]string{"profile", "get"}, "<container-profile>", "pahlevan profile get <container-profile>"},
		{[]string{"profile", "patch"}, "<container-profile>", "pahlevan profile patch <container-profile>"},
		{[]string{"completion"}, "<shell>", "pahlevan completion"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd := NewRootCommand()
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("%v with no argument should fail", tc.args)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantArg) {
				t.Errorf("error should name the missing argument %s, got: %v", tc.wantArg, msg)
			}
			if !strings.Contains(msg, tc.wantUsage) {
				t.Errorf("error should show the usage line %q, got: %v", tc.wantUsage, msg)
			}
		})
	}
}

// TestMissingKubeconfigSaysWhatToDo is the first failure a new user hits.
// client-go's own "invalid configuration: no configuration has been provided"
// reads as a broken binary; the replacement has to name a flag, an environment
// variable and something that still works without a cluster.
func TestMissingKubeconfigSaysWhatToDo(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/pahlevan-test-kubeconfig")
	t.Setenv("HOME", t.TempDir())

	cmd := NewRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	err := cmd.Execute()
	if err == nil {
		t.Skip("a cluster config was discoverable in this environment")
	}
	msg := err.Error()
	for _, want := range []string{"--kubeconfig", "KUBECONFIG", "version"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the missing-cluster error should mention %q, got:\n%s", want, msg)
		}
	}
}

// TestOfflineCommandsRunWithoutACluster is the other half of that message: it
// promises commands that work anyway, so they had better work.
func TestOfflineCommandsRunWithoutACluster(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/pahlevan-test-kubeconfig")
	t.Setenv("HOME", t.TempDir())

	for _, args := range [][]string{
		{"version"},
		{"coverage"},
		{"completion", "bash"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := NewRootCommand()
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("%v needs no cluster but failed: %v", args, err)
			}
			if buf.Len() == 0 {
				t.Errorf("%v produced no output", args)
			}
		})
	}
}

// TestBareInvocationOnATerminalOpensTheConsole is the positive case. Without
// it every test above would pass on a runRoot that printed help and never
// drew anything at all, which is the feature silently not existing.
func TestBareInvocationOnATerminalOpensTheConsole(t *testing.T) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	// The fallback signals are checked before the terminal test, so they have
	// to be neutral for this case to mean anything.
	t.Setenv("CI", "")
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")

	cmd := NewRootCommand()
	cmd.SetOut(ptmx)

	if !opensConsole(cmd, nil) {
		t.Fatal("a bare invocation on a real terminal must select the console")
	}

	// Stand in for the ui command: running the real one would take over the
	// pty and wait for a keystroke.
	opened := false
	console := &cobra.Command{
		Use:  "ui",
		RunE: func(*cobra.Command, []string) error { opened = true; return nil },
	}
	if err := runRoot(cmd, nil, console); err != nil {
		t.Fatalf("runRoot returned an error: %v", err)
	}
	if !opened {
		t.Error("runRoot printed help instead of opening the console")
	}
}
