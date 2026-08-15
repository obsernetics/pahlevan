package v1alpha1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// install.yaml is what the release publishes and what the quickstart tells
// people to `kubectl apply -f`. It is generated from deploy/base and config/crd
// by scripts/gen-install.sh, and nothing regenerates it automatically.
//
// So it drifts, silently, and the drift is invisible in review: the diff shows
// a change to deploy/base and nothing else, and the reviewer has no reason to
// wonder whether the all-in-one manifest still matches. It had drifted when
// this test was written - the agent had gained a downward-API environment
// variable that the published manifest did not set, so an OpenTelemetry
// resource attribute would have been empty for everyone installing the released
// way and correct for everyone installing from source.

const repoRoot = "../../../.."

// The generated manifest must match what the generator produces right now.
func TestInstallManifestIsUpToDate(t *testing.T) {
	script := filepath.Join(repoRoot, "scripts", "gen-install.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("generator not present: %v", err)
	}

	// No cmd.Dir: the script cds to the repo root itself from $0, and setting
	// a working directory would make bash resolve the relative script path
	// against it rather than against ours.
	want, err := exec.Command("bash", script).Output() // #nosec G204 -- a fixed path in-tree
	require.NoError(t, err, "scripts/gen-install.sh must run cleanly")

	got, err := os.ReadFile(filepath.Join(repoRoot, "install.yaml"))
	require.NoError(t, err)

	if !bytes.Equal(got, want) {
		t.Errorf("install.yaml is stale: regenerate it with\n\n"+
			"    ./scripts/gen-install.sh > install.yaml\n\n"+
			"generated %d bytes, committed %d bytes", len(want), len(got))
	}
}

// Whatever the generator does, the result has to be applicable: every document
// parses, and the set of kinds is the one a working install needs.
func TestInstallManifestIsApplicable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "install.yaml"))
	require.NoError(t, err)

	kinds := map[string]int{}
	for i, doc := range splitYAML(data) {
		if len(strings.TrimSpace(string(doc))) == 0 {
			continue
		}
		var obj map[string]interface{}
		require.NoError(t, yaml.Unmarshal(doc, &obj), "install.yaml doc %d", i)
		if len(obj) == 0 {
			continue
		}
		kind, _ := obj["kind"].(string)
		require.NotEmpty(t, kind, "install.yaml doc %d has no kind", i)
		require.NotEmpty(t, obj["apiVersion"], "install.yaml doc %d has no apiVersion", i)
		kinds[kind]++
	}

	// An install missing any of these does not work, and each has failed
	// before: a missing CRD makes every policy unappliable, and a missing
	// ClusterRole makes the agent crashloop on its first List.
	for kind, atLeast := range map[string]int{
		"Namespace":                1,
		"CustomResourceDefinition": 3,
		"ServiceAccount":           2,
		"ClusterRole":              2,
		"ClusterRoleBinding":       2,
		"DaemonSet":                1,
		"Deployment":               1,
	} {
		assert.GreaterOrEqual(t, kinds[kind], atLeast,
			"install.yaml has %d %s, want at least %d", kinds[kind], kind, atLeast)
	}
}

// The agent's OpenTelemetry resource is assembled from the downward API. If the
// published manifest does not project these, the attributes Grafana joins on
// are empty and every cross-signal query silently returns nothing - which looks
// exactly like no data rather than like a misconfiguration.
func TestInstallManifestProjectsTheDownwardAPI(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "install.yaml"))
	require.NoError(t, err)

	var agent map[string]interface{}
	for _, doc := range splitYAML(data) {
		var obj map[string]interface{}
		if yaml.Unmarshal(doc, &obj) != nil {
			continue
		}
		if kind, _ := obj["kind"].(string); kind == "DaemonSet" {
			agent = obj
			break
		}
	}
	require.NotNil(t, agent, "install.yaml has no agent DaemonSet")

	text := string(data)
	for _, name := range []string{
		"PAHLEVAN_NODE_NAME",
		"PAHLEVAN_POD_NAME",
		"PAHLEVAN_POD_NAMESPACE",
	} {
		assert.Contains(t, text, name,
			"the agent must receive %s from the downward API", name)
	}
}
