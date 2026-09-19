# Policy reference

A policy says which workloads Pahlevan governs, and what the kernel does with
an operation that falls outside what it learned.

## Headings and emphasis

### A third-level heading

Text with **bold**, *italic*, `inline code`, and a [link to another doc](architecture.md),
a [link with a fragment](quick-start.md#installation), an [external link](https://example.org/x),
a [link to a repository file](../CHANGELOG.md), and a [link to a file with no page](../Makefile).

## A fenced code block

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
spec:
  selector:
    matchLabels:
      app: web
```

```
no language on this fence
```

## A table

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `selector` | `LabelSelector` | yes | Which workloads the policy governs |
| `mode` | string | no | `monitor` or `enforce` |

## Lists

- A bullet with `code` in it
- A bullet with a [link](troubleshooting.md)
  1. A nested ordered item
  2. Another one

> A block quote, for an aside.

---

The end.
