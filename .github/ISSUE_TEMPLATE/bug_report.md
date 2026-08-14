---
name: Bug report
about: Something does not work the way it should
title: ''
labels: bug
assignees: ''
---

<!--
Found a security vulnerability? Do not file it here. See SECURITY.md and use
GitHub private security advisories instead.
-->

## What happened

<!-- Include the actual error, log line, or denial. -->

## What you expected

## How to reproduce

<!-- Manifests plus commands. A minimal PahlevanPolicy that shows the problem is ideal. -->

1.
2.
3.

## Environment

| | |
|---|---|
| Pahlevan version or image tag | |
| Kubernetes version | |
| Kubernetes distribution | |
| Container runtime | |
| Kernel (`uname -r`) | |
| Architecture | |
| Active LSMs (`cat /sys/kernel/security/lsm`) | |
| Enforcement mode (`Off` / `Monitoring` / `Blocking`) | |
| Installed via | Helm / install.yaml / kustomize / from source |

## Logs

<details>
<summary>Agent logs</summary>

```text
kubectl -n pahlevan-system logs ds/pahlevan-agent
```

</details>

<details>
<summary>Operator logs</summary>

```text
kubectl -n pahlevan-system logs deploy/pahlevan-operator
```

</details>

<details>
<summary>Policy status</summary>

```text
kubectl get pahlevanpolicy <name> -o yaml
```

</details>

## Anything else

<!-- Is it consistent or intermittent? Did it start after an upgrade? Was the
workload restarted after the agent came up? -->
