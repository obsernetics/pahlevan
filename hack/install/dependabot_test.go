package install

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// Dependabot cannot be asked whether a config entry is doing anything. An
// ecosystem pointed at a directory holding no manifest it understands does not
// warn: the scheduled job just fails, every time, forever.
//
// This repo had `package-ecosystem: "bundler"` on `/charts` under a comment
// reading "Helm charts". Dependabot has no Helm ecosystem, so somebody reached
// for the nearest name. There is no Gemfile anywhere in the tree, so that job
// failed on its monthly schedule and updated nothing, and the only visible
// symptom was one more red run among the red runs.

// dependabotConfig is the subset of the schema these guards read.
type dependabotConfig struct {
	Version int `json:"version"`
	Updates []struct {
		Ecosystem string `json:"package-ecosystem"`
		Directory string `json:"directory"`
	} `json:"updates"`
}

// manifestsByEcosystem lists, per ecosystem, the filenames whose presence means
// the ecosystem has something to do. Globs are matched with filepath.Match
// against the entries of the configured directory.
//
// Only ecosystems this repo could plausibly grow are listed. An ecosystem that
// is absent from this map fails the known-ecosystem check instead, which is the
// behaviour we want for a typo: "helm" should fail loudly rather than be
// treated as satisfiable.
var manifestsByEcosystem = map[string][]string{
	"gomod":        {"go.mod"},
	"docker":       {"Dockerfile", "Dockerfile.*", "*.Dockerfile", "docker-compose.yml", "docker-compose.yaml"},
	"bundler":      {"Gemfile"},
	"npm":          {"package.json"},
	"pip":          {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"},
	"cargo":        {"Cargo.toml"},
	"composer":     {"composer.json"},
	"maven":        {"pom.xml"},
	"gradle":       {"build.gradle", "build.gradle.kts"},
	"nuget":        {"*.csproj", "*.fsproj", "packages.config"},
	"terraform":    {"*.tf"},
	"gitsubmodule": {".gitmodules"},
	// github-actions is special: the manifests are the workflow files, and
	// Dependabot requires the directory to be "/" regardless of where they sit.
	"github-actions": nil,
}

func loadDependabot(t *testing.T) dependabotConfig {
	t.Helper()
	b, err := os.ReadFile(repoPath(".github/dependabot.yml"))
	if err != nil {
		t.Fatalf("reading .github/dependabot.yml: %v", err)
	}
	var cfg dependabotConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parsing .github/dependabot.yml: %v", err)
	}
	if len(cfg.Updates) == 0 {
		t.Fatal(".github/dependabot.yml declares no updates, so nothing is kept current")
	}
	return cfg
}

// TestEveryDependabotEcosystemIsOneDependabotKnows catches a name invented to
// stand in for an ecosystem Dependabot does not support.
func TestEveryDependabotEcosystemIsOneDependabotKnows(t *testing.T) {
	for _, u := range loadDependabot(t).Updates {
		if _, ok := manifestsByEcosystem[u.Ecosystem]; !ok {
			t.Errorf("dependabot.yml declares package-ecosystem %q on %q, which is not an ecosystem Dependabot supports. "+
				"If it stands in for something Dependabot cannot do, such as Helm chart dependencies, the entry cannot work and "+
				"should be removed rather than aimed at the closest-sounding name", u.Ecosystem, u.Directory)
		}
	}
}

// TestEveryDependabotEntryHasAManifestToUpdate is the guard that would have
// caught the bundler entry: it asserts the configured directory actually holds
// a manifest the ecosystem reads.
func TestEveryDependabotEntryHasAManifestToUpdate(t *testing.T) {
	for _, u := range loadDependabot(t).Updates {
		globs, known := manifestsByEcosystem[u.Ecosystem]
		if !known {
			continue // reported by the known-ecosystem guard
		}

		if u.Ecosystem == "github-actions" {
			if u.Directory != "/" {
				t.Errorf("dependabot.yml points github-actions at %q; Dependabot only scans workflows when the directory is \"/\"", u.Directory)
				continue
			}
			entries, err := os.ReadDir(repoPath(".github/workflows"))
			if err != nil || len(entries) == 0 {
				t.Errorf("dependabot.yml configures github-actions but .github/workflows holds no workflows to update (%v)", err)
			}
			continue
		}

		dir := repoPath(filepath.Clean("/" + u.Directory))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("dependabot.yml points %s at %q, which does not exist: %v", u.Ecosystem, u.Directory, err)
			continue
		}

		var found string
		for _, e := range entries {
			for _, g := range globs {
				if ok, _ := filepath.Match(g, e.Name()); ok {
					found = e.Name()
					break
				}
			}
			if found != "" {
				break
			}
		}
		if found == "" {
			t.Errorf("dependabot.yml points %s at %q, but that directory holds none of %v. "+
				"Dependabot does not warn about this: the scheduled job just fails every time and updates nothing",
				u.Ecosystem, u.Directory, globs)
		}
	}
}

// TestDependabotCoversTheRepoLanguages is the other direction: a manifest this
// repo does have should be kept current by something.
func TestDependabotCoversTheRepoLanguages(t *testing.T) {
	cfg := loadDependabot(t)
	covered := map[string]bool{}
	for _, u := range cfg.Updates {
		covered[u.Ecosystem] = true
	}

	for _, tc := range []struct{ file, ecosystem string }{
		{"go.mod", "gomod"},
		{"Dockerfile", "docker"},
	} {
		if _, err := os.Stat(repoPath(tc.file)); err != nil {
			continue // not present, nothing to cover
		}
		if !covered[tc.ecosystem] {
			t.Errorf("the repo has %s but dependabot.yml has no %q entry, so those dependencies are never updated", tc.file, tc.ecosystem)
		}
	}
}

func BenchmarkDependabotGuards(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/dependabot.yml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cfg dependabotConfig
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			b.Fatal(err)
		}
		for _, u := range cfg.Updates {
			if _, ok := manifestsByEcosystem[u.Ecosystem]; !ok {
				b.Fatalf("unknown ecosystem %q", u.Ecosystem)
			}
		}
	}
}
