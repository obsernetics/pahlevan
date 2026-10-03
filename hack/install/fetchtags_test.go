package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The site generators derive the version they advertise from git tags, so a job
// that runs them needs a checkout that fetched tags. actions/checkout does not
// fetch tags by default, and a shallow clone has none.
//
// Without this guard the failure is a new job added months from now that runs
// `sitegen -check` on a tagless checkout and fails with something that looks
// like a generator bug.

type workflowFile struct {
	Jobs map[string]struct {
		Steps []struct {
			Uses string                 `json:"uses"`
			Run  string                 `json:"run"`
			With map[string]interface{} `json:"with"`
		} `json:"steps"`
	} `json:"jobs"`
}

// generatorCommands are the invocations that need tags.
var generatorCommands = []string{"hack/pagesync", "hack/sitegen", "hack/release"}

func TestJobsThatBuildTheSiteFetchTags(t *testing.T) {
	dir := repoPath(".github/workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yml" && filepath.Ext(e.Name()) != ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a fixed in-tree directory
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}

		for jobName, job := range wf.Jobs {
			runsGenerator := false
			for _, s := range job.Steps {
				for _, c := range generatorCommands {
					// `go test ./hack/...` reaches the generators' own tests,
					// which build the real site, so it needs tags too.
					if strings.Contains(s.Run, c) || strings.Contains(s.Run, "./hack/...") {
						runsGenerator = true
					}
				}
			}
			if !runsGenerator {
				continue
			}
			checked++

			for _, s := range job.Steps {
				if !strings.Contains(s.Uses, "actions/checkout") {
					continue
				}
				if s.With == nil || s.With["fetch-tags"] != true {
					t.Errorf("%s: job %q runs a site generator but its actions/checkout does not set `fetch-tags: true`. "+
						"The advertised version comes from tags, so on a tagless checkout the generator fails rather than "+
						"guessing, and the failure will read like a generator bug", e.Name(), jobName)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("found no job running a site generator, so this guard is checking nothing; " +
			"the step names or commands it looks for must have changed")
	}
}
