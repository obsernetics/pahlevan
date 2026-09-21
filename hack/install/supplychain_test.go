// Supply-chain guards for the release.
//
// The image and install.yaml are signed keyless with cosign, shipped with an
// SPDX SBOM, and attested with build provenance, so that somebody pulling
// ghcr.io/obsernetics/pahlevan can tell an artifact built by this repository
// from one pushed by whoever obtained a registry token. The agent runs
// privileged on every node with CAP_BPF, so that distinction is the whole
// security story of the install path.
//
// None of it is self-checking. A release workflow that silently loses its
// signing step is indistinguishable, from the outside, from one that never
// had it: the run is green, the image is published, and the only symptom is
// that `cosign verify` starts failing for people who are not watching this
// repository. The same is true of a dropped `id-token: write`, which turns
// keyless signing into an opaque OIDC error at the end of a release.
//
// So these tests assert the steps and the permissions exist, and that the
// verification identity printed in docs/packages.md still names the workflow
// file that actually does the signing - a documented identity that points at
// the wrong file fails verification for every reader while CI stays green.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// signingWorkflow is the workflow that signs. It is also half of the Fulcio
// certificate identity documented in docs/packages.md, which is why moving
// the signing steps to another file is a documentation-breaking change and
// not a refactor.
const signingWorkflow = ".github/workflows/ci.yml"

// oidcIssuer is GitHub's Actions OIDC issuer, the other flag every documented
// cosign invocation passes.
const oidcIssuer = "https://token.actions.githubusercontent.com"

type ciStep struct {
	Name string                 `json:"name"`
	Uses string                 `json:"uses"`
	Run  string                 `json:"run"`
	With map[string]interface{} `json:"with"`
}

type ciJob struct {
	Permissions map[string]string `json:"permissions"`
	Steps       []ciStep          `json:"steps"`
}

type ciWorkflow struct {
	Jobs map[string]ciJob `json:"jobs"`
}

func loadCIWorkflow(t testing.TB) ciWorkflow {
	t.Helper()
	b, err := os.ReadFile(repoPath(signingWorkflow))
	if err != nil {
		t.Fatalf("reading %s: %v", signingWorkflow, err)
	}
	var w ciWorkflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("parsing %s: %v", signingWorkflow, err)
	}
	return w
}

func job(t *testing.T, w ciWorkflow, name string) ciJob {
	t.Helper()
	j, ok := w.Jobs[name]
	if !ok {
		t.Fatalf("%s has no %q job; the release pipeline was restructured and these guards no longer cover it",
			signingWorkflow, name)
	}
	return j
}

// requirePermissions fails naming the scope and what breaks without it,
// because the runtime symptom is a Fulcio or attestations-API error hundreds
// of lines into a release log.
func requirePermissions(t *testing.T, j ciJob, name string, want map[string]string) {
	t.Helper()
	for scope, level := range want {
		if got := j.Permissions[scope]; got != level {
			t.Errorf("job %q grants %s: %q, want %q", name, scope, got, level)
		}
	}
}

// hasRun reports whether any step's shell contains the fragment. Matching on
// the command rather than the step name means renaming a step is free and
// deleting the command is not.
func hasRun(j ciJob, fragment string) bool {
	for _, s := range j.Steps {
		if strings.Contains(s.Run, fragment) {
			return true
		}
	}
	return false
}

// findUses returns the first step using the given action, matched on the
// part before the version so that a version bump does not fail the guard.
func findUses(j ciJob, action string) (ciStep, bool) {
	for _, s := range j.Steps {
		if name, _, _ := strings.Cut(s.Uses, "@"); name == action {
			return s, true
		}
	}
	return ciStep{}, false
}

func requireUses(t *testing.T, j ciJob, name, action, why string) ciStep {
	t.Helper()
	s, ok := findUses(j, action)
	if !ok {
		t.Errorf("job %q no longer uses %s: %s", name, action, why)
	}
	return s
}

func TestTheImageIsSignedAndAttested(t *testing.T) {
	w := loadCIWorkflow(t)
	const name = "push-image"
	j := job(t, w, name)

	requirePermissions(t, j, name, map[string]string{
		// Without this the registry push itself fails.
		"packages": "write",
		// Without this cosign cannot mint a Fulcio certificate and keyless
		// signing fails at the end of a release, after the image is public.
		"id-token": "write",
		// Without this actions/attest-build-provenance cannot record the
		// attestation.
		"attestations": "write",
	})

	requireUses(t, j, name, "sigstore/cosign-installer",
		"nothing installs cosign, so no signing step can run")

	if !hasRun(j, "cosign sign ") {
		t.Error("no step runs `cosign sign`; the published image carries no signature " +
			"and the `cosign verify` command in docs/packages.md fails for everyone")
	}
	if !hasRun(j, "cosign attest ") {
		t.Error("no step runs `cosign attest`; the SBOM is not attached to the image, " +
			"so anyone holding only a digest cannot obtain it")
	}

	sbom := requireUses(t, j, name, "anchore/sbom-action",
		"no SBOM is generated for the image")
	if got := fmt.Sprint(sbom.With["format"]); got != "spdx-json" {
		t.Errorf("the SBOM format is %q, want spdx-json; docs/packages.md documents "+
			"`cosign verify-attestation --type spdxjson`, which only matches SPDX", got)
	}

	prov := requireUses(t, j, name, "actions/attest-build-provenance",
		"the image gets no build provenance, so nothing records which commit and run produced it")
	if fmt.Sprint(prov.With["push-to-registry"]) != "true" {
		t.Error("image provenance is not pushed to the registry, so it cannot be " +
			"verified from a digest alone")
	}
	// Signing a tag would let anyone who can push to the registry move that
	// tag onto an unsigned image while the old signature keeps verifying.
	if !strings.Contains(fmt.Sprint(prov.With["subject-digest"]), "steps.build.outputs.digest") {
		t.Error("provenance is not bound to the digest the build step produced")
	}
}

func TestTheReleaseAssetsAreSignedAndAttested(t *testing.T) {
	w := loadCIWorkflow(t)
	const name = "release"
	j := job(t, w, name)

	requirePermissions(t, j, name, map[string]string{
		"contents":     "write",
		"id-token":     "write",
		"attestations": "write",
	})

	requireUses(t, j, name, "sigstore/cosign-installer",
		"nothing installs cosign, so the release assets cannot be signed")

	if !hasRun(j, "sha256sum install.yaml") {
		t.Error("nothing checksums install.yaml; the manifest people pipe into " +
			"`kubectl apply` with cluster-admin RBAC would be unverifiable")
	}
	if !hasRun(j, "cosign sign-blob") {
		t.Error("no step runs `cosign sign-blob`; SHA256SUMS is unsigned, so the " +
			"checksums only prove the download was not corrupted, not where it came from")
	}

	prov := requireUses(t, j, name, "actions/attest-build-provenance",
		"the release assets get no build provenance")
	if !strings.Contains(fmt.Sprint(prov.With["subject-path"]), "install.yaml") {
		t.Error("install.yaml is not a subject of the release provenance attestation")
	}

	rel, ok := findUses(j, "softprops/action-gh-release")
	if !ok {
		t.Fatal("the release job no longer publishes a GitHub release")
	}
	files := fmt.Sprint(rel.With["files"])
	for _, want := range []string{
		"install.yaml",
		"sbom.spdx.json",
		"SHA256SUMS",
		"SHA256SUMS.cosign.bundle",
	} {
		if !strings.Contains(files, want) {
			t.Errorf("the release does not attach %s, so docs/packages.md sends readers "+
				"to a download URL that 404s", want)
		}
	}
}

// Keyless is the point. A cosign private key in repository secrets is in the
// same compromise class as the registry token this signing is meant to
// defend against, and its signatures never expire, so a "simplification" that
// reintroduces one must fail here rather than quietly ship.
func TestSigningStaysKeyless(t *testing.T) {
	w := loadCIWorkflow(t)
	for _, name := range []string{"push-image", "release"} {
		for _, s := range job(t, w, name).Steps {
			if !strings.Contains(s.Run, "cosign ") {
				continue
			}
			for _, banned := range []string{"--key", "COSIGN_PRIVATE_KEY", "cosign.key"} {
				if strings.Contains(s.Run, banned) {
					t.Errorf("job %q step %q signs with %s; keyless signing via the "+
						"workflow's OIDC identity is what makes the signature unforgeable "+
						"by a stolen secret", name, s.Name, banned)
				}
			}
		}
	}
}

// The documented certificate identity is not a description of the pipeline -
// it is an exact string cosign compares against the Fulcio certificate. If
// the signing steps move to another workflow file, every `cosign verify` in
// docs/packages.md fails with an identity mismatch while CI stays green, so
// the doc and the file that signs are checked against each other here.
func TestTheDocumentedIdentityNamesTheWorkflowThatSigns(t *testing.T) {
	entries, err := os.ReadDir(repoPath(".github/workflows"))
	if err != nil {
		t.Fatalf("reading the workflow directory: %v", err)
	}
	var signers []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		rel := filepath.Join(".github/workflows", e.Name())
		b, err := os.ReadFile(repoPath(rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if strings.Contains(string(b), "cosign sign") {
			signers = append(signers, rel)
		}
	}
	if len(signers) != 1 || signers[0] != signingWorkflow {
		t.Fatalf("cosign signing lives in %v, but docs/packages.md documents an identity "+
			"built from %s; verification would fail for every reader", signers, signingWorkflow)
	}

	b, err := os.ReadFile(repoPath("docs/packages.md"))
	if err != nil {
		t.Fatalf("reading docs/packages.md: %v", err)
	}
	doc := string(b)

	wantIdentity := "https://github.com/obsernetics/pahlevan/" + signingWorkflow + "@refs/tags/"
	if !strings.Contains(doc, wantIdentity) {
		t.Errorf("docs/packages.md does not document the certificate identity %q", wantIdentity)
	}
	if !strings.Contains(doc, oidcIssuer) {
		t.Errorf("docs/packages.md does not document the OIDC issuer %q; `cosign verify` "+
			"requires both flags and refuses to run with only one", oidcIssuer)
	}
	for _, cmd := range []string{
		"cosign verify ",
		"cosign verify-attestation --type spdxjson",
		"cosign verify-blob",
		"--certificate-identity",
		"--certificate-oidc-issuer",
	} {
		if !strings.Contains(doc, cmd) {
			t.Errorf("docs/packages.md no longer shows %q, so a reader has no working "+
				"way to check what they are about to run privileged on every node", cmd)
		}
	}
}

func BenchmarkParseCIWorkflow(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadCIWorkflow(b)
	}
}
