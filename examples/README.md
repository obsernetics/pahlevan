# Policy examples

Every file here is validated against the CRD by a test
(`pkg/apis/policy/v1alpha1/examples_test.go`), so what is written in them is
what the API actually accepts.

That test exists because it found something. Before it was written, every
example in this directory used fields the CRD does not have —
`learning:` instead of `learningConfig:`, `enforcement:` instead of
`enforcementConfig:`, plus around twenty-five invented keys like
`fileEnforcement`, `attackSurface` and `compliance`. The Kubernetes API server
does not reject an unknown field in a CRD spec; it prunes it. So every one of
those examples applied cleanly and then did a fraction of what it said. The
examples have been rewritten against the real schema, and the test now fails
the build if that happens again.

## Start here

**[`quickstart/simple-policy.yaml`](quickstart/simple-policy.yaml)** — the
smallest policy that does something real. Four fields: what to govern, how long
to watch, what to do about the rest, and what to do when that turns out to be
wrong.

## By workload

| File | Workload | Mode | The interesting part |
|---|---|---|---|
| [`policies/web-application.yaml`](policies/web-application.yaml) | Frontends, HTTP APIs | Blocking | The easy case. A web app reaches steady state in minutes, so a short window converges and anything outside it is genuinely anomalous. |
| [`policies/database.yaml`](policies/database.yaml) | PostgreSQL, MySQL | Monitoring → manual | The hard case. A database's *rare* operations are its most important ones — backup, WAL archival, recovery — and a window that only saw queries produces a baseline that blocks the 02:00 backup. |
| [`policies/microservices.yaml`](policies/microservices.yaml) | Service mesh workloads | Blocking | Egress is where the value is. File and exec behavior is trivial; a service reaching a fourth peer when it has only ever had three is the signal. Separate policy for the sidecar, which has nothing behaviorally in common with the app. |
| [`policies/batch-jobs.yaml`](policies/batch-jobs.yaml) | Jobs, CronJobs | Two-phase | Breaks the learn-then-enforce assumption: the job exits before the window closes. Resolved by accumulating a profile across runs, then enforcing from process start. |
| [`policies/ci-runner.yaml`](policies/ci-runner.yaml) | Build agents | Monitoring | The counter-example. A workload whose purpose is to run arbitrary code cannot be enforced, and saying so is more useful than pretending otherwise. Enforcement moves to the sidecars instead. |
| [`policies/process-filter.yaml`](policies/process-filter.yaml) | Interpreted workloads | Blocking | Constrains *who* may exec rather than *what* may be exec'd — the axis that matters once the interpreter in the image is itself learned. |

## By topic

| File | What it covers |
|---|---|
| [`security/self-healing-demo.yaml`](security/self-healing-demo.yaml) | What happens when the learned baseline is wrong. Includes a workload that deliberately trips the rollback so you can watch it. |
| [`advanced/production-policy.yaml`](advanced/production-policy.yaml) | A three-stage rollout: observe, alert, enforce. The alert stage is byte-identical to the enforce stage except for one field, so what you test is what you ship. |
| [`advanced/comprehensive-security-policy.yaml`](advanced/comprehensive-security-policy.yaml) | Every field the CRD has, with what each one does. A reference, not something to apply. |
| [`observability/attack-surface-monitoring.yaml`](observability/attack-surface-monitoring.yaml) | The attack surface is what a container *could* do, not what it has done. Enforcement narrows the second and not the first. |
| [`observability/lgtm-stack.yaml`](observability/lgtm-stack.yaml) | Loki, Grafana, Tempo and Mimir wired to one OpenTelemetry collector, with the correlation that makes a denial spike clickable through to the events behind it. |

## The three decisions

Almost every field is a detail. These three are not.

**Monitoring or Blocking.** Monitoring records what *would* have been denied,
using the same counters Blocking increments. That number is the cost of turning
enforcement on, measured before you pay it. There is no reason to guess.

**How long to learn.** The window has to be long enough to contain the
workload's rare operations, not just its common ones. The question to ask is not
"how long until the profile stops growing" but "what does this workload do
hourly, nightly, or during an incident, and would this window have seen it".

**Self-healing on or off.** With it on, a baseline that turns out to be wrong
returns the container to learning instead of leaving it broken. It only examines
the interval right after the transition — the interval in which a breakage is
attributable to enforcement — so a container that runs fine for an hour and then
gets denied is not un-enforced. That bound is deliberate: without it, an attacker
could disable enforcement by making noise.

## Applying them

```bash
# Install the operator and CRDs first.
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Then a policy.
kubectl apply -f examples/quickstart/simple-policy.yaml

# Watch it learn.
kubectl get containerprofiles -w

# See what it decided, and any part of the policy it could not represent.
kubectl describe pahlevanpolicy simple-app-policy
```

That last command is worth the habit. Anything in a policy that the data plane
cannot enforce — an ingress rule, a CIDR too wide to enumerate, a capability
name that does not exist — is reported on the status as a warning rather than
being silently dropped. A policy with warnings is doing less than it says.
