package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GitHub decides which release wears the "Latest" badge by publish time, not by
// version. Two tags pushed close together finish their builds in whatever order
// the runners allocate, so the older version can win.
//
// It did. v3.5.1 and v3.6.0 were tagged a minute apart; v3.5.1 published 32
// seconds later and /releases/latest served v3.5.1 for hours, while the tag
// list, the changelog, install.yaml and the website all said v3.6.0. Nothing
// was failing: every existing check was satisfied, because a tag did exist for
// the declared version. The badge is the surface most people actually click.

func checkScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(repoPath("scripts/check-release-tagged.sh"))
	if err != nil {
		t.Fatalf("reading scripts/check-release-tagged.sh: %v", err)
	}
	return string(b)
}

// TestTheReleaseCheckAlsoVerifiesWhichReleaseIsLatest guards the check itself.
func TestTheReleaseCheckAlsoVerifiesWhichReleaseIsLatest(t *testing.T) {
	s := checkScript(t)

	if !strings.Contains(s, "releases/latest") {
		t.Error("scripts/check-release-tagged.sh does not look at which release GitHub serves as latest. " +
			"A tag existing is not enough: GitHub picks Latest by publish time, so a release whose build " +
			"finished later wins even when its version is older, and everyone clicking Latest gets the wrong one")
	}
	if !strings.Contains(s, "make_latest") {
		t.Error("the check does not tell the reader how to fix a wrong Latest badge; the fix is not obvious " +
			"because it is an API call, not a git operation")
	}
	// The check must not break a local run, where there is no gh and no token.
	if !strings.Contains(s, "command -v gh") {
		t.Error("the latest-release check is not guarded on gh being available, so running the script locally " +
			"would fail on a machine without the GitHub CLI")
	}
}

// TestTheReleaseCheckStillPassesOffline is the other half: the script has to
// remain usable with no network and no gh, because it is also a local command.
func TestTheReleaseCheckStillPassesOffline(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", "-n", repoPath("scripts/check-release-tagged.sh"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/check-release-tagged.sh is not valid bash: %v: %s", err, out)
	}

	// Run it without --remote against this checkout. It reads local tags only
	// and must not reach for gh.
	cmd = exec.Command("bash", "scripts/check-release-tagged.sh")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "is NOT tagged") {
		t.Fatalf("a local run failed for an unexpected reason: %v: %s", err, text)
	}
	if strings.Contains(text, "latest release") {
		t.Error("a local run without --remote consulted the GitHub API; the script is also a local command " +
			"and must not need a token")
	}
}

// TestTheWorkflowRunsTheCheckWithRemote keeps the scheduled guard wired to the
// network form, which is the only form that can see the latest-release badge.
func TestTheWorkflowRunsTheCheckWithRemote(t *testing.T) {
	b, err := os.ReadFile(repoPath(filepath.Join(".github/workflows", "release-tagged.yml")))
	if err != nil {
		t.Fatalf("reading the workflow: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "check-release-tagged.sh --remote") {
		t.Error("the release-tagged workflow no longer runs the check with --remote, so it trusts the " +
			"runner's checkout for tags and cannot see which release is latest")
	}
	if !strings.Contains(s, "GH_TOKEN") {
		t.Error("the workflow does not provide GH_TOKEN, which the latest-release check needs")
	}
}

func BenchmarkReleaseCheckScan(b *testing.B) {
	raw, err := os.ReadFile(repoPath("scripts/check-release-tagged.sh"))
	if err != nil {
		b.Fatal(err)
	}
	s := string(raw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !strings.Contains(s, "releases/latest") || !strings.Contains(s, "make_latest") {
			b.Fatal("a guard input stopped matching")
		}
	}
}
