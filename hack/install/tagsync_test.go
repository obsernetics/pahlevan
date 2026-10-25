package install

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The release flow has an ordering constraint that is easy to get wrong and
// whose failure is invisible until a release silently does not happen.
//
// pagesync and sitegen derive the advertised version from the newest TAG, so
// they cannot write the real version until the tag exists. The tagging job
// therefore creates the tag first and syncs the site afterwards. But the sync
// is a new commit, and the tag still points at the commit before it, so a
// release run dispatched on that tag sees a tree whose site advertises the
// previous version. The version-sync guards fail, and the release gate then
// correctly refuses to publish over a red suite.
//
// That is what happened: v3.6.2 and v3.6.3 both ended up tagged with no
// release, no image and nothing installable, while CHANGELOG.md and the
// website named them as shipped, and /releases/latest still served v3.6.1
// three weeks later. Every individual piece behaved correctly; the order was
// wrong.

func tagJobSyncStep(t *testing.T) string {
	t.Helper()
	raw := []byte(workflowText(t, "release-tag.yml"))
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `json:"name"`
				Run  string `json:"run"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parsing release-tag.yml: %v", err)
	}
	job, ok := wf.Jobs["tag"]
	if !ok {
		t.Fatal("release-tag.yml has no tag job")
	}
	for _, s := range job.Steps {
		if strings.Contains(s.Run, "pagesync") || strings.Contains(s.Run, "sitegen") {
			return s.Run
		}
	}
	t.Fatal("no step in the tag job runs the site generators, so the site is never synced to the new tag")
	return ""
}

// TestTheTagEndsUpOnTheSyncedSite is the guard for the ordering.
func TestTheTagEndsUpOnTheSyncedSite(t *testing.T) {
	run := tagJobSyncStep(t)

	if !strings.Contains(run, "HEAD:main") {
		t.Error("the sync step does not push the regenerated site to main, so the site stays stale after a release")
	}

	moved := strings.Contains(run, "tag -f") || strings.Contains(run, "--force origin \"refs/tags/")
	if !moved {
		t.Error("the sync step does not re-point the tag at the commit it just created. The tag then names the " +
			"commit BEFORE the site was synced, so the release run dispatched on it sees a stale site, the " +
			"version-sync guards fail, and the release gate refuses to publish. v3.6.2 and v3.6.3 were both " +
			"left tagged with no release that way")
	}

	// Order matters: the tag has to move after the sync commit exists.
	if moved {
		iMain := strings.Index(run, "HEAD:main")
		iTag := strings.Index(run, "tag -f")
		if iTag >= 0 && iMain >= 0 && iTag < iMain {
			t.Error("the tag is re-pointed before the sync commit is pushed, so it lands on the wrong commit")
		}
	}
}

// TestTheReleaseIsStillDispatchedOnTheTag keeps the other half intact: the
// release job gates on a tag ref, so dispatching on a branch would skip it.
func TestTheReleaseIsStillDispatchedOnTheTag(t *testing.T) {
	raw := workflowText(t, "release-tag.yml")

	if !strings.Contains(raw, "gh workflow run ci.yml") {
		t.Error("the tagging job no longer dispatches the release run. A tag pushed with GITHUB_TOKEN does not " +
			"trigger a workflow, so without the dispatch the tag exists with nothing behind it")
	}
	if !strings.Contains(raw, `--ref "${VERSION}"`) {
		t.Error("the dispatch no longer names the tag as its ref. The release job gates on refs/tags/v, so " +
			"dispatching on a branch would skip it and publish nothing")
	}
}

func BenchmarkTagSyncGuards(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/workflows/release-tag.yml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wf struct {
			Jobs map[string]interface{} `json:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			b.Fatal(err)
		}
	}
}
