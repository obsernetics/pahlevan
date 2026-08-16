package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The generated half of docs/api-reference.md must match what the generator
// produces from the current types.
//
// The file this replaced was hand-written and described an API that had never
// existed: `learning:` instead of `learningConfig:`, `enforcement:` instead of
// `enforcementConfig:`, and whole subsystems - maxSamples, confidence,
// aggressive, emergencyMode, syscall argument filters - the CRD has never had.
// A Kubernetes API server prunes an unknown field in a custom resource rather
// than rejecting it, so anybody who copied from it got a policy that applied
// cleanly and did a fraction of what they asked for.
//
// Regenerating it once would have fixed that for a while. This is what keeps
// it fixed.
func TestGeneratedSectionMatchesTheTypes(t *testing.T) {
	const root = "../.."
	if _, err := os.Stat(root + "/" + typesFile); err != nil {
		t.Skipf("not running in the repository: %v", err)
	}

	out, err := exec.Command("go", "run", ".", root).Output()
	require.NoError(t, err, "the generator must run cleanly")

	committed, err := os.ReadFile(root + "/docs/api-reference.md")
	require.NoError(t, err)

	// Only the generated prefix is compared: the file also carries hand-written
	// sections for the metrics, the event stream and the CLI, which describe
	// surfaces outside the CRD and have no types to generate from.
	const boundary = "## Metrics, events and the CLI"
	got := string(committed)
	if i := strings.Index(got, boundary); i >= 0 {
		// Trim back to the end of the generated output, which ends with a
		// blank line; the appended section adds its own leading newline.
		got = strings.TrimSuffix(got[:i], "\n")
	}

	if got != string(out) {
		t.Errorf("docs/api-reference.md is stale.\n\n"+
			"Regenerate the CRD section with:\n\n"+
			"    go run ./hack/apidocs > /tmp/api.md\n\n"+
			"generated %d bytes, committed %d bytes",
			len(out), len(got))
	}
}

// The generator must not silently produce an empty document if the parse fails
// or the root type list goes stale.
func TestGeneratorProducesTheCoreTypes(t *testing.T) {
	const root = "../.."
	if _, err := os.Stat(root + "/" + typesFile); err != nil {
		t.Skip("not running in the repository")
	}
	out, err := exec.Command("go", "run", ".", root).Output()
	require.NoError(t, err)
	text := string(out)

	for _, want := range []string{
		"## PahlevanPolicySpec", "## EnforcementConfig", "## ProcessFilter",
		"`learningConfig`", "`enforcementConfig`", "`processFilter`",
	} {
		assert.Contains(t, text, want)
	}

	// And it must not reintroduce the fiction.
	for _, never := range []string{"maxSamples", "emergencyMode", "aggressive"} {
		assert.NotContains(t, text, never,
			"%q is not a field the CRD has", never)
	}
}

// A field the agent does not act on must be labeled, not merely listed. A
// reader who finds one in a cluster and is not told is exactly the person this
// document exists for.
func TestInertFieldsAreLabelled(t *testing.T) {
	const root = "../.."
	if _, err := os.Stat(root + "/" + typesFile); err != nil {
		t.Skip("not running in the repository")
	}
	out, err := exec.Command("go", "run", ".", root).Output()
	require.NoError(t, err)

	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range []string{"`windowSize`", "`lifecycleAware`", "`requireSignature`"} {
			if strings.HasPrefix(line, "| "+f) {
				assert.Contains(t, line, "**Inert**", "%s must be marked inert", f)
			}
		}
	}
}
