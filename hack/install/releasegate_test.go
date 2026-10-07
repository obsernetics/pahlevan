package install

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// v3.6.1 published a signed release, with an image, an SBOM and provenance,
// while `test` and `test-race` were both red. Nothing was broken in the release
// machinery: the release job simply did not depend on the tests, so it could
// not see them fail.
//
// The condition is spelled out in the workflow rather than left to the default,
// because the default is wrong in both directions. A plain `needs` entry skips
// the dependent job when the dependency is skipped, and the test jobs are
// skipped for a change that touches no code; a skipped release is then
// indistinguishable from a successful one. So the tests must not have failed,
// and a skipped test is tolerated.

func releaseJob(t *testing.T) map[string]interface{} {
	t.Helper()
	raw := []byte(workflowText(t, "ci.yml"))
	var wf struct {
		Jobs map[string]map[string]interface{} `json:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parsing ci.yml: %v", err)
	}
	j, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("ci.yml has no release job")
	}
	return j
}

func TestTheReleaseDependsOnTheTests(t *testing.T) {
	j := releaseJob(t)

	needs := map[string]bool{}
	switch v := j["needs"].(type) {
	case []interface{}:
		for _, n := range v {
			needs[n.(string)] = true
		}
	case string:
		needs[v] = true
	}

	for _, want := range []string{"test", "test-race"} {
		if !needs[want] {
			t.Errorf("the release job does not list %q in needs, so it cannot see that job fail. "+
				"v3.6.1 shipped a signed release with both test jobs red for exactly this reason", want)
		}
	}
	for _, want := range []string{"build", "push-image"} {
		if !needs[want] {
			t.Errorf("the release job no longer needs %q, which it depends on for the artifacts it publishes", want)
		}
	}
}

// TestTheReleaseGateToleratesSkippedTests is the other direction. Making the
// release depend on the tests without this would turn every docs-only tag into
// a silently skipped release.
func TestTheReleaseGateToleratesSkippedTests(t *testing.T) {
	j := releaseJob(t)
	cond, _ := j["if"].(string)
	if cond == "" {
		t.Fatal("the release job has no if condition")
	}
	flat := strings.Join(strings.Fields(cond), " ")

	if !strings.Contains(flat, "!cancelled()") {
		t.Error("the condition does not use !cancelled(). Without a status function, a skipped test job skips " +
			"the release instead of allowing it, and the tests are skipped for a change that touches no code")
	}
	for _, want := range []string{
		"needs.test.result != 'failure'",
		"needs.test-race.result != 'failure'",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the condition is missing %q, so a failing test would not block the release", want)
		}
	}
	// A positive equality check would be the easy mistake: it reads as stricter
	// and is actually broken, because it rejects a skipped test too.
	for _, wrong := range []string{
		"needs.test.result == 'success'",
		"needs.test-race.result == 'success'",
	} {
		if strings.Contains(flat, wrong) {
			t.Errorf("the condition requires %q. That blocks a release whose tests were skipped, which is "+
				"every tag on a change that touches no code", wrong)
		}
	}
	if !strings.Contains(flat, "startsWith(github.ref, 'refs/tags/v')") {
		t.Error("the condition no longer restricts the release to version tags")
	}
	if !strings.Contains(flat, "needs.build.result == 'success'") ||
		!strings.Contains(flat, "needs.push-image.result == 'success'") {
		t.Error("with !cancelled() in the condition, build and push-image must be checked explicitly or a " +
			"release would publish after they failed")
	}
}

func BenchmarkReleaseGateGuards(b *testing.B) {
	var wf struct {
		Jobs map[string]map[string]interface{} `json:"jobs"`
	}
	raw, err := os.ReadFile(repoPath(".github/workflows/ci.yml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			b.Fatal(err)
		}
	}
}
