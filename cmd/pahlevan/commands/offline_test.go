package commands

import (
	"os"
	"regexp"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfflineMarksAndDetects(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	assert.False(t, IsOffline(cmd))
	assert.Same(t, cmd, Offline(cmd), "Offline returns the command so it composes inline")
	assert.True(t, IsOffline(cmd))
}

// A subcommand of an offline group inherits it. Repeating the annotation on
// every child is how one gets forgotten.
func TestOfflineIsInherited(t *testing.T) {
	parent := Offline(&cobra.Command{Use: "parent"})
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)

	assert.True(t, IsOffline(child))
}

// An online command under an online parent must stay online, or the root would
// skip building clients for something that needs them and the failure would
// surface as a nil dereference rather than a clear error.
func TestOnlineCommandsAreNotOffline(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)

	assert.False(t, IsOffline(child))
	assert.False(t, IsOffline(parent))
}

// The commands that must work on a laptop with no kubeconfig. `version` is the
// first thing anyone runs against a new binary, and it used to fail with
// "no configuration has been provided" - which reads as a broken tool.
func TestCommandsThatMustWorkWithoutACluster(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"version":        Offline(NewVersionCommand("v0", "d", "c")),
		"completion":     Offline(NewCompletionCommand()),
		"events":         NewEventsCommand(),
		"policy explain": newPolicyExplainCommand(),
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsOffline(cmd),
				"%s reads a file or prints a constant; it must not need a kubeconfig", name)
		})
	}
}

// The version variables are set by -ldflags in the Dockerfile. They were named
// main.commit and main.date there while the code declares gitCommit and
// buildDate, so neither was ever injected and every shipped binary reported
// "unknown" for both - which is exactly what you need during an incident and
// cannot get.
func TestDockerfileInjectsTheVariablesTheCodeDeclares(t *testing.T) {
	dockerfile, err := os.ReadFile("../../../Dockerfile")
	if err != nil {
		t.Skipf("Dockerfile not present: %v", err)
	}
	mainGo, err := os.ReadFile("../main.go")
	require.NoError(t, err)

	// Every -X main.NAME= in the Dockerfile must name a variable main.go
	// declares, or the value goes nowhere.
	injected := regexp.MustCompile(`-X main\.([A-Za-z_][A-Za-z0-9_]*)=`).
		FindAllStringSubmatch(string(dockerfile), -1)
	require.NotEmpty(t, injected, "the Dockerfile should inject build metadata")

	seen := map[string]bool{}
	for _, m := range injected {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		declared := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=`).
			Match(mainGo)
		assert.True(t, declared,
			"the Dockerfile injects main.%s, which cmd/pahlevan/main.go does not declare - "+
				"the value is silently discarded", name)
	}

	// And the three that matter must all be injected.
	for _, want := range []string{"version", "gitCommit", "buildDate"} {
		assert.True(t, seen[want], "the Dockerfile must inject main.%s", want)
	}
}

// A binary built from a working tree has no release identity. Claiming a
// version number is worse than admitting it does not have one, because the
// number will be wrong the moment the real version moves.
func TestVersionDefaultsToDev(t *testing.T) {
	mainGo, err := os.ReadFile("../main.go")
	require.NoError(t, err)
	assert.Regexp(t, `(?m)^\s*version\s*=\s*"dev"`, string(mainGo),
		`the un-injected default must be "dev", not a version number that will go stale`)
}
