# Packages and Releases

Pahlevan publishes three artifacts per release: a container image, a Helm chart,
and a single-file Kubernetes manifest. Release notes live in
[`CHANGELOG.md`](../CHANGELOG.md) and on the
[GitHub releases page](https://github.com/obsernetics/pahlevan/releases).

## Container image

The image is published to the GitHub Container Registry:

```
ghcr.io/obsernetics/pahlevan
```

| Tag | Meaning |
|---|---|
| `latest` | Most recent build of the default branch |
| `<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->` | Immutable release tag (recommended for production) |
| `main` | Rolling tag for the default branch |
| `main-<sha>` | Per-commit build of the default branch, useful for bisecting |

```bash
docker pull ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->
```

One image ships all three binaries:

- `pahlevan-agent` - the privileged DaemonSet that loads and attaches the eBPF
  programs and enforces locally in the kernel.
- `pahlevan-operator` - the leader-elected Deployment that drives policy
  lifecycle, aggregates status, and owns admission.
- `pahlevan` - the CLI.

The runtime layer is **distroless**: no shell, no package manager, and no
userland beyond the binaries themselves.

### Verifying the image

```bash
docker pull ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->

# Inspect the manifest, digest, architecture, and labels
docker inspect ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->

# Digest only (pin this in air-gapped or regulated environments)
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->

# Confirm the entrypoints exist without a shell in the image
docker run --rm --entrypoint /pahlevan-operator ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync--> --help
```

Pin by digest rather than by tag when you need a byte-for-byte reproducible
deployment:

```yaml
image: ghcr.io/obsernetics/pahlevan@sha256:<digest>
```

## Helm chart

The chart is served from the project's GitHub Pages site.

```bash
helm repo add pahlevan https://obsernetics.github.io/pahlevan/charts
helm repo update
helm install pahlevan pahlevan/pahlevan-operator \
  -n pahlevan-system --create-namespace
```

Useful overrides:

```bash
helm install pahlevan pahlevan/pahlevan-operator \
  -n pahlevan-system --create-namespace \
  --set image.repository=ghcr.io/obsernetics/pahlevan \
  --set image.tag=<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->
```

Show the resolved values and the available versions:

```bash
helm search repo pahlevan --versions
helm show values pahlevan/pahlevan-operator
```

Uninstall:

```bash
helm uninstall pahlevan -n pahlevan-system
```

CRDs are not removed by `helm uninstall`. Delete them explicitly if you want a
clean slate:

```bash
kubectl delete crd pahlevanpolicies.policy.pahlevan.io \
  containerprofiles.policy.pahlevan.io \
  attacksurfaces.policy.pahlevan.io
```

## Raw manifest

For clusters without Helm, each release attaches a rendered `install.yaml`
containing the CRDs, RBAC, the operator Deployment, and the agent DaemonSet:

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

Pin to a specific release instead of `latest`:

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/download/<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->/install.yaml
```

Review before applying:

```bash
curl -sSL https://github.com/obsernetics/pahlevan/releases/download/<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->/install.yaml | less
```

## Verifying the supply chain

The agent runs privileged on every node with `CAP_BPF`, and `install.yaml` is
applied with cluster-admin-shaped permissions. Neither should be trusted
because it happens to sit at a `ghcr.io` or `github.com` URL: anyone who
obtains a registry or repository token can put something there. Every release
is therefore signed, shipped with an SBOM, and accompanied by build
provenance.

Signing is **keyless**. There is no Pahlevan public key to fetch and no
long-lived private key in repository secrets - a key like that would be as
useful to an attacker as the token it is supposed to defend against, and its
signatures would never expire. Instead the release workflow exchanges a
short-lived GitHub OIDC token for a Sigstore certificate valid for ten
minutes, and that certificate records which workflow in which repository
produced the artifact. So verification asks about identity, not possession:
*was this built by this repository's release workflow?*

Install [cosign](https://github.com/sigstore/cosign) v3.0.6 or newer - that is
the version the release workflow signs with - and set the two values that
every command below shares:

```bash
VERSION=<!--pahlevan:sync version-->v3.5.0<!--/pahlevan:sync-->
IDENTITY="https://github.com/obsernetics/pahlevan/.github/workflows/ci.yml@refs/tags/${VERSION}"
ISSUER="https://token.actions.githubusercontent.com"
```

`IDENTITY` is the workflow file that does the signing, at the exact tag being
released. It is not a name somebody chose; it is what GitHub puts in the
certificate, and cosign fails the verification if the artifact was signed by
any other workflow, any other repository, or any other tag.

### Image signature

```bash
cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/obsernetics/pahlevan:${VERSION}
```

The image is signed by digest, so this also works - and is the better habit -
against a digest pin:

```bash
cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/obsernetics/pahlevan@sha256:<digest>
```

A successful run prints the verified payload. A tag that was moved onto an
image nobody signed fails with `no signatures found`, and an artifact signed
by a different workflow fails with a certificate identity mismatch.

### SBOM

The SBOM is SPDX 2.3 JSON, attached to the image as a Sigstore attestation and
also attached to the GitHub release as `sbom.spdx.json`.

Verify and read the copy attached to the image:

```bash
cosign verify-attestation --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/obsernetics/pahlevan:${VERSION} \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.spdx.json
```

It describes the `linux/amd64` image. The published image is a multi-platform
index, and the SBOM is generated from the variant the release runner resolves,
so an `arm64` deployment should treat it as the package inventory of the same
source build rather than a byte-level statement about the image it pulls.

### Build provenance

Provenance is a SLSA statement generated and signed by GitHub from the release
run's own metadata: which commit, which workflow, which run built the artifact.
It is pushed to the registry alongside the image and recorded for the release
assets.

```bash
gh attestation verify \
  oci://ghcr.io/obsernetics/pahlevan:${VERSION} \
  --repo obsernetics/pahlevan
```

`gh attestation` needs GitHub CLI v2.49 or newer.

### Release assets

Each release carries `SHA256SUMS` covering `install.yaml` and
`sbom.spdx.json`, plus `SHA256SUMS.cosign.bundle`, the keyless signature over
that checksum file. Verifying the signature and then the checksums covers
every asset with one identity check:

```bash
base="https://github.com/obsernetics/pahlevan/releases/download/${VERSION}"
curl -sSLO "${base}/install.yaml"
curl -sSLO "${base}/sbom.spdx.json"
curl -sSLO "${base}/SHA256SUMS"
curl -sSLO "${base}/SHA256SUMS.cosign.bundle"

cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  SHA256SUMS

sha256sum -c SHA256SUMS
```

Only apply the manifest once both commands have passed:

```bash
kubectl apply -f install.yaml
```

Provenance for `install.yaml` can be checked the same way as the image's:

```bash
gh attestation verify install.yaml --repo obsernetics/pahlevan
```

Signatures, SBOMs and provenance are produced by the release workflow, so they
exist for releases published after it gained those steps. Tags older than that
have no signature to verify, and `cosign verify` will say so rather than pass
quietly.

## After installing

Verify both workloads are up, then apply a policy:

```bash
kubectl -n pahlevan-system get pods
kubectl get crd | grep pahlevan.io
```

See [`quick-start.md`](quick-start.md) for the first `PahlevanPolicy`, and
[`system-requirements.md`](system-requirements.md) plus [`lsm-support.md`](lsm-support.md)
for the kernel prerequisites of in-kernel enforcement.
