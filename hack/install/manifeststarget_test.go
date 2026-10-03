package install

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestChartShipsEveryCRDTheControllersWatch already fails when the chart's CRD
// copies drift from config/crd. This guards the other half: that the command
// which regenerates them produces a consistent tree.
//
// Without it, `make manifests` updates config/crd and leaves the chart copy
// behind, so the generator itself puts the tree into the state the other guard
// then reports. The person who ran the documented command sees a red test and
// no reason to think they caused it.
func TestTheManifestsTargetSyncsTheChartCRDs(t *testing.T) {
	// `make -n` expands the recipe without running controller-gen, so this does
	// not need the tool installed. It is also the only way to assert what the
	// target *would* do: reading the Makefile text would miss a variable.
	cmd := exec.Command("make", "-n", "manifests")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n manifests: %v: %s", err, out)
	}
	recipe := string(out)

	if !strings.Contains(recipe, "config/crd") {
		t.Fatalf("the manifests target does not mention config/crd, so this guard is reading the wrong target:\n%s", recipe)
	}
	if !strings.Contains(recipe, "charts/pahlevan-operator/crds") {
		t.Errorf("`make manifests` regenerates config/crd but does not update charts/pahlevan-operator/crds. "+
			"Helm never templates crds/, so the chart ships its own copy, and leaving it behind means `helm install` "+
			"creates a stale schema: the API server prunes fields it does not describe, so a policy applies cleanly "+
			"and does nothing. Recipe was:\n%s", recipe)
	}
}

// TestTheChartCRDDirectoryIsNotEmpty is a cheap sanity check that the two
// guards above are looking at a directory that exists. A rename would otherwise
// make both vacuously pass.
func TestTheChartCRDDirectoryIsNotEmpty(t *testing.T) {
	matches, err := filepath.Glob(repoPath("charts/pahlevan-operator/crds/*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("charts/pahlevan-operator/crds holds no CRDs, so a Helm install creates none of the types the controllers watch")
	}
}
