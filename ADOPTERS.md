# Adopters

## Current status: no public production adopters

Pahlevan has **no known public production adopters**. The project's first
release under its current architecture (`v2.0.0`) is recent, the CRD API is
`v1alpha1`, and the honest summary of where it stands is: evaluated and tested,
including a measured overhead benchmark in a kernel-isolated
VM ([`docs/benchmarks/`](docs/benchmarks)), but not yet
running someone's production cluster as far as the maintainers are aware.

This file exists so there is a real place to record adoption as it happens. It
will not be padded with logos, "users" who once starred the repository, or
companies that have not agreed to be listed. If you are looking at Pahlevan for
a CNCF Sandbox evaluation, treat the emptiness of this table as the accurate
signal it is.

## Adopters

| Organization | Contact | Status | Environment | Notes |
|---|---|---|---|---|
| _(none yet)_ | | | | |

`Status` values we use:

- **Evaluating** - running Pahlevan in a lab, dev cluster, or proof of concept.
- **Testing** - running in a staging or pre-production cluster with real
  workloads, typically in `Monitoring` mode.
- **Production** - running in production, usually with at least one policy in
  `Blocking` mode.

## Adding yourself

We would genuinely like to hear from you, at any of the three statuses above.
Early evaluators are the most useful feedback the project can get right now, and
listing an evaluation costs you nothing and helps the project enormously.

Open a pull request adding a row to the table with:

- **Organization** - the name you want shown, optionally linked to your site.
- **Contact** - a GitHub handle or an email you are happy to have in a public
  file. Optional, but it lets maintainers reach you before a change that might
  affect you.
- **Status** - one of the values above.
- **Environment** - roughly what you run it on. Kubernetes distribution, kernel
  version, and architecture are the useful details.
- **Notes** - anything you want to share: what you use it for, which
  enforcement mode, scale, or what stopped you going further.

You must be authorized to list your organization. Please sign off the commit
(`git commit -s`) like any other contribution; see
[CONTRIBUTING.md](CONTRIBUTING.md).

If you would rather not be listed publicly but are willing to tell the
maintainers privately, email `team@obsernetics.com`. We will not add you to this
file without your explicit consent, and we will not use your name in
presentations or proposals without asking first.

## Case studies

None yet. If you have run Pahlevan against real workloads, a short write-up of
what the learned baselines looked like, what enforcement broke, and what you had
to tune would be more valuable to this project than almost any code
contribution. Open an issue and we will help you shape it.
