package install

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The image job had no condition on it, so every pull request built
// linux/amd64 and linux/arm64 and pushed the result to the registry. Two
// separate problems wearing one cause:
//
// Ten pr-N image tags were published to GHCR from code nobody had reviewed. A
// registry tag is a thing other people can pull.
//
// And arm64 is built under QEMU emulation, which made this the slowest job in
// the pipeline at about five minutes. The `ci` gate waits for it, so every
// pull request paid for an emulated cross-build and a registry push it did not
// need. Measured mean wall clock before this change was 7m45s.

type buildPushStep struct {
	Uses string            `json:"uses"`
	With map[string]string `json:"with"`
}

func imageBuildStep(t *testing.T) buildPushStep {
	t.Helper()
	raw, err := os.ReadFile(repoPath(".github/workflows/ci.yml"))
	if err != nil {
		t.Fatalf("reading ci.yml: %v", err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []buildPushStep `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parsing ci.yml: %v", err)
	}
	job, ok := wf.Jobs["push-image"]
	if !ok {
		t.Fatal("ci.yml has no push-image job, so this guard is checking nothing")
	}
	for _, s := range job.Steps {
		if strings.Contains(s.Uses, "docker/build-push-action") {
			return s
		}
	}
	t.Fatal("the push-image job no longer uses docker/build-push-action")
	return buildPushStep{}
}

// TestAPullRequestDoesNotPublishAnImage is the security half.
func TestAPullRequestDoesNotPublishAnImage(t *testing.T) {
	s := imageBuildStep(t)
	push := s.With["push"]

	if push == "true" {
		t.Error("the image job pushes unconditionally, so every pull request publishes an image to the registry " +
			"built from code that has not been reviewed. Gate it on github.event_name != 'pull_request'")
	}
	if !strings.Contains(push, "pull_request") {
		t.Errorf("push is %q, which does not distinguish a pull request from a push to main or a tag", push)
	}
}

// TestAPullRequestDoesNotEmulateArm64 is the speed half. Cross-compilation for
// arm64 is already proven on every pull request by the cross-compile job, so
// emulating the architecture to build a container nobody will pull buys nothing.
func TestAPullRequestDoesNotEmulateArm64(t *testing.T) {
	s := imageBuildStep(t)
	platforms := s.With["platforms"]

	if platforms == "linux/amd64,linux/arm64" {
		t.Error("the image job builds arm64 unconditionally. On a pull request that runs under QEMU emulation and " +
			"is the slowest job in the pipeline, and the `ci` gate waits for it. Build the host architecture only " +
			"for a pull request")
	}
	if !strings.Contains(platforms, "pull_request") {
		t.Errorf("platforms is %q, which does not distinguish a pull request", platforms)
	}
	// The release path must still produce both, or the published image stops
	// being multi-architecture, which is a silent regression for arm64 users.
	if !strings.Contains(platforms, "linux/arm64") {
		t.Error("arm64 is gone entirely; the released image must still be multi-architecture")
	}
}

// TestNoImageTagIsMintedForAPullRequest keeps the tag list honest: a pr-N tag
// only exists to be pushed, so leaving it configured invites the push back.
func TestNoImageTagIsMintedForAPullRequest(t *testing.T) {
	raw, err := os.ReadFile(repoPath(".github/workflows/ci.yml"))
	if err != nil {
		t.Fatalf("reading ci.yml: %v", err)
	}
	if strings.Contains(string(raw), "event=pr") {
		t.Error("ci.yml still mints a pr-N image tag. Nothing publishes it now, so it is either dead " +
			"configuration or a push waiting to be reintroduced")
	}
}

func BenchmarkImagePushGuards(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/workflows/ci.yml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wf struct {
			Jobs map[string]struct {
				Steps []buildPushStep `json:"steps"`
			} `json:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			b.Fatal(err)
		}
	}
}
