package install

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The version main declares is now tagged by a workflow rather than by hand.
// Six releases reached main without a tag before this existed, so the pieces
// that make it work are worth holding in place.
//
// The non-obvious one: a tag pushed with GITHUB_TOKEN does not trigger a
// workflow run, because GitHub suppresses that to stop a workflow setting
// itself off forever. So creating the tag is not sufficient. If the dispatch
// were dropped, the tag would exist with no release behind it, which satisfies
// scripts/check-release-tagged.sh while still shipping nothing installable: a
// quieter version of the bug this replaces.

func workflowYAML(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(repoPath(".github/workflows/" + name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var out map[string]interface{}
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return out
}

func workflowText(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(repoPath(".github/workflows/" + name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(raw)
}

func TestTheReleaseTagWorkflowCreatesTheTagAndStartsTheRelease(t *testing.T) {
	s := workflowText(t, "release-tag.yml")

	if !strings.Contains(s, "git push origin") {
		t.Error("release-tag.yml does not push a tag, so the version main declares is still tagged by hand")
	}
	if !strings.Contains(s, "gh workflow run ci.yml") {
		t.Error("release-tag.yml creates a tag but never dispatches the release run. A tag pushed with " +
			"GITHUB_TOKEN does not trigger a workflow, so the tag would exist with no release, no image and no " +
			"signature behind it, while the tagged check passes")
	}
	if !strings.Contains(s, "--ref") {
		t.Error("the dispatch does not name a ref, so the release run would not see a tag and the release job " +
			"would be skipped")
	}

	wf := workflowYAML(t, "release-tag.yml")
	perms, _ := wf["permissions"].(map[string]interface{})
	if perms["contents"] != "write" {
		t.Errorf("release-tag.yml needs contents: write to create a tag ref, has %v", perms["contents"])
	}
	if perms["actions"] != "write" {
		t.Errorf("release-tag.yml needs actions: write to dispatch the release run, has %v", perms["actions"])
	}
}

// TestCIIsDispatchableOnATag is the other half of the pair: the dispatch is
// rejected unless ci.yml accepts one.
func TestCIIsDispatchableOnATag(t *testing.T) {
	wf := workflowYAML(t, "ci.yml")
	// "on" is parsed as the boolean true by YAML 1.1 readers, so accept both.
	triggers, ok := wf["on"].(map[string]interface{})
	if !ok {
		triggers, ok = wf["true"].(map[string]interface{})
	}
	if !ok {
		t.Fatal("could not read ci.yml's trigger block")
	}
	if _, has := triggers["workflow_dispatch"]; !has {
		t.Error("ci.yml has no workflow_dispatch trigger, so release-tag.yml cannot start a release and every " +
			"automated tag would land with nothing behind it")
	}
}

// TestTheTagLandsOnTheCommitThatSetTheVersion guards against tagging whatever
// main points at now. v3.6.0 was tagged at a merge commit that carried commits
// made after the release, because the tag was placed on main's tip.
func TestTheTagLandsOnTheCommitThatSetTheVersion(t *testing.T) {
	s := workflowText(t, "release-tag.yml")
	if !strings.Contains(s, `-S "VERSION?=`) {
		t.Error("release-tag.yml does not look up the commit that introduced the version, so the tag lands on " +
			"main's tip and the release silently acquires whatever landed after it")
	}
	if !strings.Contains(s, "fetch-depth: 0") {
		t.Error("release-tag.yml needs the full history to find the commit that set the version")
	}
	if !strings.Contains(s, "fetch-tags: true") {
		t.Error("release-tag.yml needs tags fetched, or it cannot tell whether the version is already tagged " +
			"and would try to create a tag that exists")
	}
}

// TestTheReleaseVerifiesItsOwnSignature is the safety net for the dispatch
// route. The certificate identity cosign checks is the workflow ref, and this
// release job is now reachable both by a tag push and by a dispatch on a tag.
func TestTheReleaseVerifiesItsOwnSignature(t *testing.T) {
	wf := workflowYAML(t, "ci.yml")
	jobs, _ := wf["jobs"].(map[string]interface{})
	rel, ok := jobs["release"].(map[string]interface{})
	if !ok {
		t.Fatal("ci.yml has no release job")
	}
	steps, _ := rel["steps"].([]interface{})

	var verifies bool
	for _, raw := range steps {
		st, _ := raw.(map[string]interface{})
		run, _ := st["run"].(string)
		if strings.Contains(run, "cosign verify") {
			verifies = true
		}
	}
	if !verifies {
		t.Error("the release job does not verify the signature it just published. The certificate identity is " +
			"the workflow ref, and this job can be reached by a tag push or by a dispatch on a tag; if those " +
			"differ, every documented `cosign verify` fails against an automated release while the pipeline " +
			"stays green. The only proof a signature is usable is verifying it")
	}
}

// TestTheReleaseTagWorkflowSyncsTheSiteAfterTagging guards the gap that shipped
// v3.6.1: pagesync and sitegen hold back the real version in docs/packages.md
// and the changelog page until the tag exists, which is correct right up until
// this job creates one - and then the site is stale until something re-runs
// them. v3.6.1 needed a second, hand-written PR to fix it. This job has to do
// that itself, in the same run, with a signed-off commit or the DCO check
// would reject it.
func TestTheReleaseTagWorkflowSyncsTheSiteAfterTagging(t *testing.T) {
	s := workflowText(t, "release-tag.yml")

	if !strings.Contains(s, "hack/pagesync -write") {
		t.Error("release-tag.yml does not re-run pagesync after tagging, so docs/packages.md stays on the " +
			"previous version until someone notices and fixes it by hand")
	}
	if !strings.Contains(s, "hack/sitegen -write") {
		t.Error("release-tag.yml does not re-run sitegen after tagging, so the changelog page's Current badge " +
			"stays on the previous version until someone notices and fixes it by hand")
	}
	if !strings.Contains(s, "Signed-off-by: github-actions[bot]") {
		t.Error("the site-sync commit this job pushes carries no DCO sign-off, so the dco.yml check would reject " +
			"it the one time there is actually a diff to push")
	}
	if !strings.Contains(s, "git push origin HEAD:main") {
		t.Error("release-tag.yml generates the site sync but never pushes it to main")
	}

	// The sync has to happen before the dispatch, or the Go toolchain needed
	// to run the generators would race the release build for the same runner
	// minute without buying anything: the dispatched run checks out the
	// immutable tag, which the sync commit landing on main afterward cannot
	// change.
	if i, j := strings.Index(s, "hack/sitegen -write"), strings.Index(s, "gh workflow run ci.yml"); i < 0 || j < 0 || i > j {
		t.Error("the site sync must run before the release dispatch, not after")
	}
}

// TestTheTaggedCheckRemainsTheBackstop keeps the scheduled guard in place.
// Automation that fails silently is worse than none, so the thing that notices
// has to outlive the thing that acts.
func TestTheTaggedCheckRemainsTheBackstop(t *testing.T) {
	s := workflowText(t, "release-tagged.yml")
	if !strings.Contains(s, "check-release-tagged.sh") {
		t.Error("the scheduled tagged check is gone. It is the only thing that notices when the tagging " +
			"workflow is skipped, fails, or its dispatch does not take")
	}
	if !strings.Contains(s, "schedule") {
		t.Error("the tagged check no longer runs on a schedule, so nothing notices an untagged release on its own")
	}
}

func BenchmarkReleaseTagGuards(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/workflows/release-tag.yml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out map[string]interface{}
		if err := yaml.Unmarshal(raw, &out); err != nil {
			b.Fatal(err)
		}
	}
}
