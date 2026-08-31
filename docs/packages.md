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
| `<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->` | Immutable release tag (recommended for production) |
| `main` | Rolling tag for the default branch |
| `main-<sha>` | Per-commit build of the default branch, useful for bisecting |

```bash
docker pull ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->
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
docker pull ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->

# Inspect the manifest, digest, architecture, and labels
docker inspect ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->

# Digest only (pin this in air-gapped or regulated environments)
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->

# Confirm the entrypoints exist without a shell in the image
docker run --rm --entrypoint /pahlevan-operator ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync--> --help
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
  --set image.tag=<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->
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
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/download/<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->/install.yaml
```

Review before applying:

```bash
curl -sSL https://github.com/obsernetics/pahlevan/releases/download/<!--pahlevan:sync version-->v3.0.0<!--/pahlevan:sync-->/install.yaml | less
```

## After installing

Verify both workloads are up, then apply a policy:

```bash
kubectl -n pahlevan-system get pods
kubectl get crd | grep pahlevan.io
```

See [`quick-start.md`](quick-start.md) for the first `PahlevanPolicy`, and
[`system-requirements.md`](system-requirements.md) plus [`lsm-support.md`](lsm-support.md)
for the kernel prerequisites of in-kernel enforcement.
