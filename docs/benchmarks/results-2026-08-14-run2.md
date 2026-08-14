# Pahlevan vs Falco vs Tetragon - measured runtime-security benchmark (run 2)

> **These numbers are real and measured**, produced by `test/benchmark/run.sh`
> inside the kernel-isolated VM (`hack/vm/`). Where something could not be
> measured, or a tool could not be deployed as shipped, it is stated explicitly.
> Nothing here is tuned to favour any tool, and the sections that make Pahlevan
> look bad are as load-bearing as the ones that do not.

> **Filename note:** this run happened on the same UTC date as the earlier one,
> so it is filed as `results-2026-08-14-run2.md` rather than overwriting
> `results-2026-08-14.md`, which is the record of that first run and is left
> untouched.

## What changed since the first run

The first run (`results-2026-08-14.md`) covered 4 scenarios and found only the
`file_open` LSM hook wired. Since then the tree gained network egress enforcement
(`lsm/socket_connect`, IPv4 and IPv6), process exec enforcement
(`lsm/bprm_check_security`), capability monitoring and enforcement
(`lsm/capable`), a large BPF map right-sizing, and a JSON-lines/webhook event
export. The scenario suite grew from 4 to 26 attack scenarios plus 3 benign
controls, and this run adds 3 builtin-only **mechanism probes** and a **no-tool
control run**.

The harness also changed in one important way. Previously every scenario was a
separate `kubectl exec`; under Pahlevan enforcement the `runc exec` setup is
itself denied, so that harness could only ever record "exec was denied" and could
say nothing about which mechanism stopped what. Scenarios now run from a
**resident bash runner started inside the target pod during the learning window**,
which drives everything with builtins only. All three tools are driven the same
way. See `test/benchmark/README.md`.

<!--RESULTS-->
