# Governance

## Status: young and maintainer-led

Pahlevan is a young project. As of this document it has **one maintainer**
([MAINTAINERS.md](MAINTAINERS.md)), a handful of contributors, and no public
production adopters ([ADOPTERS.md](ADOPTERS.md)).

We are writing this down rather than inventing a steering committee, a technical
oversight board, and a set of special interest groups that do not exist. A
governance document describing bodies with no members is worse than no document
at all, because it misleads people about who actually decides things. What
follows is the process the project genuinely runs on, plus the concrete
conditions under which it grows into something more distributed.

The intent is that this document is replaced by a more distributed model as soon
as there are enough active maintainers to justify one. The trigger for that
rewrite is stated in [Evolving this document](#evolving-this-document).

## Roles

### Contributor

Anyone who opens an issue, comments on one, improves documentation, or sends a
pull request. No prior approval and no formal status is required. Contributors
must sign off their commits under the DCO and follow the
[Code of Conduct](CODE_OF_CONDUCT.md). See [CONTRIBUTING.md](CONTRIBUTING.md).

### Reviewer

A contributor with a demonstrated track record in some part of the codebase.
Reviewers can be requested on pull requests and their review carries weight, but
they do not have merge rights. Reviewers are listed in
[MAINTAINERS.md](MAINTAINERS.md).

### Maintainer

A reviewer who has been granted write access. Maintainers can approve and merge
pull requests, cut releases, and administer the repository. Maintainers are
responsible for the health of the project as a whole, not only for their own
changes.

Maintainer responsibilities:

- Review pull requests in reasonable time, or say plainly that they cannot.
- Keep CI green and keep the release process working.
- Uphold the Code of Conduct in project spaces.
- Say no to changes that do not fit the project, with a reason.
- Disclose conflicts of interest, including employer interest in a change.

## How decisions are made

### The default: lazy consensus

Most changes are decided by lazy consensus. A pull request that has been open,
has green CI, and has no unresolved objection can be merged by any maintainer
after approval. Silence is agreement. This is deliberate: for a project this
small, requiring active agreement from multiple people would simply stop work.

### Substantial changes

Changes that alter the security model, the CRD API surface, the enforcement
semantics, the supported kernel or Kubernetes floor, or add a dependency with a
non-permissive license should start as an **issue** describing the problem before
code is written. This gives anyone affected a place to object before effort is
spent. Maintainers may ask for an issue on any pull request they consider
substantial.

Specifically, the following require an issue and explicit maintainer approval,
never lazy consensus:

- Anything that changes what the agent is allowed to do on the node, including
  its capability set or host mounts.
- Anything that changes the default enforcement behavior of an existing policy.
- Breaking changes to `policy.pahlevan.io/v1alpha1`.
- Removing or relicensing existing functionality.

### Voting

When consensus cannot be reached, maintainers decide by simple majority of
active maintainers, with the caveat that today a "majority" is one person. Votes
happen in public on the relevant issue or pull request, so the reasoning is on
the record. A tie fails, meaning the change does not land.

This mechanism is written down now so that it exists the moment there is more
than one maintainer, rather than being improvised during the first real
disagreement.

### Releases

Releases follow [semantic versioning](https://semver.org/spec/v2.0.0.html) and
are recorded in [CHANGELOG.md](CHANGELOG.md). Any maintainer may cut a release.
Because Pahlevan enforces policy in the kernel, a release that changes
enforcement behavior must say so explicitly in the changelog, at the top of the
entry, even when the change is a bug fix.

## Becoming a reviewer

Open an issue titled `Request: reviewer` (or ask an existing maintainer to
nominate you). There is no fixed contribution count, but in practice we look
for:

- Several merged, non-trivial pull requests, with tests.
- Review comments on other people's pull requests that caught something real.
- Familiarity with at least one area: the eBPF programs and the loader, the
  controllers and CRDs, or the build, packaging, and test harness.
- Sustained engagement over more than a few weeks, so that we are adding a
  colleague rather than a one-off.

An existing maintainer approves the request in public. Reviewers are added to
[MAINTAINERS.md](MAINTAINERS.md) by pull request.

## Becoming a maintainer

Maintainers are drawn from reviewers. In addition to the reviewer bar, we look
for:

- Judgment on changes outside the candidate's own area, demonstrated in review.
- Willingness to do unglamorous work: triage, CI repair, release chores,
  answering user questions.
- Understanding of the project's security posture. The agent is privileged by
  necessity; a maintainer must appreciate what that means before they can
  approve changes to it.

Nomination is by an existing maintainer, in a public issue, and requires
approval from a majority of existing maintainers with no maintainer objecting.
The nominee must accept. The change is then made by a pull request to
[MAINTAINERS.md](MAINTAINERS.md) that grants write access.

While the project has a single maintainer, that maintainer will actively look
for candidates rather than waiting to be asked. Concentrating all merge rights
in one person is a real risk to the project, and reducing it is a priority.

## Stepping down and removal for inactivity

### Stepping down

A maintainer may step down at any time by opening a pull request moving
themselves to the emeritus list. No justification is required. Emeritus
maintainers keep the credit and lose the access.

### Inactivity

A maintainer is considered inactive after **six months** with no meaningful
activity: no merged pull requests, no substantive reviews, no release or triage
work, and no participation in maintainer decisions.

The process is:

1. Any maintainer, or any contributor, may open an issue noting the inactivity.
2. The inactive maintainer is contacted directly at the address they have on
   file and given **30 days** to respond.
3. If they respond and wish to stay, they stay. Life happens, and an explicit
   "I am still here but slow" is enough.
4. If there is no response after 30 days, the remaining maintainers move them to
   emeritus by pull request and revoke write access.

Removal for inactivity is administrative and carries no stigma. Returning is
easy: an emeritus maintainer can be restored by a single maintainer approval,
without repeating the nomination process.

### Removal for cause

A maintainer may be removed for a serious or repeated Code of Conduct violation,
for abusing repository access, or for acting against the interests of the
project. This requires a majority vote of the other maintainers. Code of Conduct
matters concerning a maintainer are referred to the CNCF Code of Conduct
Committee (`conduct@cncf.io`) rather than decided by the project.

## Handling disagreement

Disagreement is expected and is not a failure state. The escalation path is:

1. **Discuss on the pull request or issue.** Most disagreements are actually
   missing context, and they end when someone explains the constraint the other
   person did not know about.
2. **Write it down.** If the discussion goes past a few rounds, whoever is
   proposing the change writes a short summary of the options and the trade-offs
   in the issue. Requiring the argument to be stated in full resolves a
   surprising number of them.
3. **Escalate to maintainers.** Any participant may ask maintainers to decide.
   Maintainers must give a reason for the decision in public.
4. **Vote.** If maintainers themselves disagree, the vote described above
   applies.

Some ground rules:

- A maintainer must not merge their own change over an unresolved objection from
  another maintainer or reviewer.
- Objections should be specific and, where possible, actionable. "I do not like
  this" should be turned into what would make it acceptable, or withdrawn.
- Once a decision is made it is final for that change. Reopening the same
  argument requires new information.
- Disagreement about technical direction is never a Code of Conduct matter. How
  people treat each other while disagreeing can be.

## Security decisions

Vulnerability handling is deliberately not consensus-driven. Reports are handled
privately by maintainers under the process in [SECURITY.md](SECURITY.md), and a
fix may be developed and merged without prior public discussion. The rationale
and the fix are made public at disclosure time.

## Evolving this document

This document is expected to change as the project grows. It is amended by pull
request under the same rules as any other substantial change: an issue first,
then maintainer approval.

Concretely, when Pahlevan reaches **three active maintainers from at least two
different employers**, the maintainers commit to revisiting this document and
replacing the single-maintainer defaults with a genuinely distributed model,
including a documented process for maintainer votes with quorum and a clear
statement of any vendor-neutrality commitments required by the project's
foundation status.
