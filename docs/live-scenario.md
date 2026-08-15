# What Pahlevan does to a real workload

Every claim in this project's documentation is about kernel behavior, which is
easy to assert and hard to check. This page is the check: a harness that runs a
real web application under Pahlevan's data plane for an hour, learns its
behavior, switches enforcement on, and then attacks it. The result is recorded
rather than described, and the harness is in the repository so you can disagree
with it by running it.

```
go run ./hack/demo/scenario -learn 50m -out report.md
```

Root, on a kernel with the BPF LSM active. That means a VM — `make vm-up`
provisions one, and loading these programs on a developer's own machine is
exactly what the project's tooling is arranged to prevent.

## What it does

A static file server runs inside one cgroup under continuous HTTP traffic. The
cgroup is the unit Pahlevan governs; in a cluster it comes from the container
runtime, and here it is created directly, because the point is to exercise the
data plane rather than the Kubernetes plumbing above it.

For the learning window, every syscall, file open, connection, exec and
capability check the workload makes is recorded. Then all four hooks switch to
enforcing, and nine scenarios run against the workload. Each is a real
`execve`, `connect` or `open` inside the governed cgroup. None of them consult
Pahlevan's state to decide the outcome — the result recorded is whatever the
kernel did.

## The two mistakes the harness made first

Both are worth writing down, because they are the two easiest ways to misread
what this tool enforces, and the first smoke run made both.

**The controls were denied along with the attacks.** The harness was issuing its
"is the application still working" request with `curl`, from inside the governed
cgroup. `curl` is a binary the web server never ran, so the exec was refused —
correctly. But Pahlevan governs what the workload does, not what is done to it.
A request arriving from a browser is not the container executing anything. The
controls now come from outside the cgroup, which is where requests come from.

**Every attack collapsed into the same exec denial.** The reverse shell was
`nc`, the credential theft was `cat`, the escape attempt was `mount` — and once
exec enforcement is on, none of those binaries can start at all. Every scenario
was refused at the same hook, before the interesting one was ever reached, and
the run said nothing about whether the file, network and capability hooks work.

That is not a flaw in the tool; it is the tool working. But it is also not what
a real attacker does. Once exec enforcement is on, a new binary cannot be
introduced, so the attacker reaches for the interpreter that is already in the
image and already learned. The scenarios now go through `python3`, which the
application is written in: the exec is permitted, and the file, network and
capability hooks are what refuse the action. Three exec-denial scenarios remain,
so both halves are shown.

## The scenarios

| # | Scenario | Hook that decides | Expected |
|---|---|---|---|
| 1 | A legitimate request, from outside the cgroup | none | allowed |
| 2 | Reverse shell through `python3` | `lsm/socket_connect` | denied |
| 3 | Read `/etc/shadow` through `python3` | `lsm/file_open` | denied |
| 4 | Append to `/etc/passwd` via a shell redirect | `lsm/file_open` (write) | denied |
| 5 | `mount(2)` via `ctypes` | `lsm/capable` | denied |
| 6 | Run a binary dropped into `/tmp` | `lsm/bprm_check_security` | denied |
| 7 | Run a miner under a plausible name | `lsm/bprm_check_security` | denied |
| 8 | Spawn a shell | `lsm/bprm_check_security` | denied |
| 9 | The application after all of the above | none | allowed |

Scenario 4 is the one worth dwelling on. It is a shell redirect, so no new
process is involved at all, and the write path is what is refused. A workload
that read `/etc/passwd` at startup does not thereby get to write it, because
reads and writes are separate entries in the allow-set. That distinction was a
real defect once: keying the allow-set on the path alone meant learning a
startup read of `/etc/passwd` also permitted an attacker to rewrite it.

Scenario 7 exists because the question comes up. Renaming a binary changes
nothing: the allow-set keys on the resolved path, not on a signature or a name
list, so there is no name that makes an unlearned binary permitted.

## Reading the report

The report the harness writes has two halves.

The first is the learned baseline: every binary, file, destination and
capability the workload used. **Nobody wrote it.** That is the whole argument
for this approach, and it is also where its limits are visible — a baseline is
a summary of one observation window, and anything the workload does rarely will
not be in it. That is what `enforcementConfig.exceptions` and self-healing are
for, and why the database example in `examples/policies/` uses an hour-long
window and still names its backup paths explicitly.

The second is what happened when each scenario ran, including the exact error
the shell reported and how many in-kernel denials the event stream recorded
while it did. A scenario whose result does not match its expectation is marked
**MISMATCH**, so a regression in enforcement shows up as a word rather than as
something you have to notice.
