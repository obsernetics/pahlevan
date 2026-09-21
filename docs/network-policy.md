# Generating a NetworkPolicy from what was observed

`pahlevan netpol` turns a learned network baseline into a
`networking.k8s.io/v1` NetworkPolicy you can review and apply.

Everything else in the CLI reports. This is the one command whose output you
put into a cluster, so the rest of this page is mostly about the ways that can
be wrong and what the command does about each of them.

```bash
# Review what the baseline supports, in the current namespace
pahlevan netpol

# Every namespace
pahlevan netpol --all-namespaces

# What applying this would change, against the policies already there
pahlevan netpol --diff

# The manifests alone, once you have read the review
pahlevan netpol -o yaml | kubectl apply -f -
```

The command applies nothing, ever. There is no `--apply` flag. The default
output is the review rather than the manifests, because the manifests are the
part somebody pipes into `kubectl` and the argument of this page is that they
should not be piped anywhere unread.

## What applying one does

A NetworkPolicy is allow-only. The moment one selects a pod, every connection
in a named direction that no rule permits is dropped: connections that were
working a second earlier, connections from clients that were quiet during the
learning window, and connections nobody observed because they happen less often
than the window is long.

That is not a gradual tightening. It is a cut down to a list derived from one
window, and it takes effect on the pods the policy selects the instant the
object is created.

## The three ways a generated policy lies, and what happens instead

### An address that resolves to nothing

A learned baseline is a list of addresses. A NetworkPolicy is a list of label
selectors. An address the cluster cannot name has no selector, so it becomes an
`ipBlock` with a single-host CIDR, and the review says the rule is a literal
address that is wrong the day that address is reassigned.

It never becomes a `namespaceSelector` inferred from a subnet. A subnet is not
an identity.

A node address gets the same treatment for a different reason: NetworkPolicy
has no node selector, so a node can only ever be an address.

A Service address becomes a selector over the pods behind the Service, because
a NetworkPolicy cannot name a Service at all. The review says how many pods
that is.

### A selector that would be wider than the evidence

This is the one that matters.

Every label set derived from a group of pods selects at least those pods. The
question is what else it selects. In a namespace where `app=api` is on the API
deployment, on its debug deployment and on last quarter's canary, a rule built
from watching the first one permits traffic to all three. Nobody watched the
other two.

So the rule is: a label set may be written into a policy only if, applied to
the namespace as it actually is, it selects exactly the pods it was derived
from and nothing else. When it does not, no policy is generated for that
workload and the review names the pods that made it unsafe:

```text
prod/Deployment/api
-------------------
  policy          none
  observed        12 learned destination(s), 0 written into rules

    blocked: a podSelector on app=api would also select prod/debug-7d9f4,
    which were never observed
```

Fixing that is a change to the workloads, not to this command: give the two
deployments labels that tell them apart, and regenerate.

Labels a controller rewrites are dropped before the check, because a policy
naming `pod-template-hash` matches the pods it was generated from and nothing
after the next rollout, and a policy that selects zero pods enforces nothing.
When dropping one is what made the selector unsafe, the review says so.

### A baseline that is shorter than the workload's cycle

A baseline only contains what happened during the learning window. A policy
generated from it denies anything rarer than that window is long.

For a workload owned by a CronJob, `pahlevan netpol` walks the pod's owner
chain to the schedule and runs the pair through the same logic the operator
uses to decide how long to learn for. A monthly job learned over an hour gets:

```text
    warn: this workload fires on a 720h0m0s cycle and the learning window is
    capped at 168h0m0s, so the baseline cannot contain a whole period. A policy
    generated from it denies whatever that period does
```

Every workload, cycle or not, gets the shorter version of the same caveat with
its own window in it.

## Ingress is derived, not observed

The agents record a connection at the end that made it, so the learned baseline
is egress. An ingress rule here is therefore a derivation: workload A was
observed connecting to workload B's pods on port 8080, so B's policy permits
ingress from A on 8080.

That is sound as far as it goes and it is not the whole truth about B. Any
client of B that Pahlevan did not observe, including clients outside the
cluster, is not in the rule and would be denied. The review says this once per
derived rule. `--direction egress` leaves ingress out entirely.

## Other things the review tells you

- **DNS.** Name resolution happens before the connection the baseline
  recorded, so a baseline that captured the connection and not the lookup
  produces a policy that permits the destination and denies finding it. A
  generated egress policy with no flow to port 53 in it says so.
- **Replicas.** A selector names a workload, not a pod, because a replica is
  not an identity a policy can name. When the baseline came from fewer pods
  than the workload has, the review says how many will be enforced on evidence
  that is not theirs.
- **A workload that made no outbound connection at all.** That produces a
  policy permitting none, which is an honest reading of the baseline and a
  strong control. It is marked as such rather than emitted quietly.
- **Destinations that did not make it.** When part of a baseline could not be
  written down, the count is in the review. When none of it could, no policy is
  generated at all: a policy narrower than the evidence is how this command
  would take a workload down.

## Reviewing before applying

`--diff` compares each generated policy against the one already in the cluster
under the same name and prints what would be replaced. A generated policy that
displaces rules a person reasoned about is invisible in the YAML, which says
only what the new policy is:

```bash
pahlevan netpol --diff
```

```text
Against the NetworkPolicies already in the cluster:

~ prod/pahlevan-deployment-web already exists and would be replaced:
      ...
    -       app: something-else
    +       app: web
```

## Requirements

- A CNI that enforces NetworkPolicy. Creating the object in a cluster whose CNI
  ignores it changes nothing, which is its own kind of surprise.
- Kubernetes 1.21 or newer, because peers are written with a
  `namespaceSelector` on `kubernetes.io/metadata.name`, the label the API
  server sets on every namespace from that release.
- Containers that have reached a learned baseline. `pahlevan profile list -A`
  says whether any have.

## Flags

| Flag | Does |
|---|---|
| `-n`, `--namespace` | Namespace to read baselines from |
| `-A`, `--all-namespaces` | Read every namespace |
| `-o`, `--output` | `report` (default), `yaml` for the manifests alone, `json` for the review as data |
| `--direction` | `both` (default), `egress`, `ingress` |
| `--diff` | Show what applying this would change against what is in the cluster |
| `--name-prefix` | Prefix for generated policy names, `pahlevan-` by default |

Nothing in Pahlevan reconciles a generated policy. It is a starting point
handed to whoever owns the namespace, and once applied it is theirs.
