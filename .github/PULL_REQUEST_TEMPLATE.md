<!--
Thanks for the contribution. Keep this short; delete anything that does not apply.
Security vulnerability? Do not open a PR. See SECURITY.md.
-->

## What and why

<!-- What this changes, and the problem it solves. Link the issue: Fixes #123 -->

## How it was verified

<!-- Commands you ran and what you saw. "make test passes" is fine for most changes. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`), per [CONTRIBUTING.md](../CONTRIBUTING.md#developer-certificate-of-origin)
- [ ] `make test lint` passes locally
- [ ] New behavior has tests, or this needs none (say why)
- [ ] Docs updated, and `CHANGELOG.md` under `[Unreleased]` if user visible
- [ ] No em dashes or en dashes anywhere in the diff

## eBPF and enforcement

<!-- Delete this whole section if you did not touch bpf/, pkg/ebpf/, or enforcement behavior. -->

- [ ] Ran `make vm-test` in the VM (`hack/vm/up.sh`) and it passed
- [ ] Regenerated bindings with `make ebpf-build` and committed the objects
- [ ] Map layouts or event structs changed: the Go decoders were updated to match
- [ ] This changes what gets denied at runtime, and the changelog entry says so

<!-- Paste the relevant vm-test output or summarize it: -->
