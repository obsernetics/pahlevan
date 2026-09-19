#!/usr/bin/env bash
#
# Fail if the version main declares has never been tagged.
#
# The scheduled maintenance agent runs as the GitHub App, which cannot create
# tag refs. So it merges a release PR, the tag never appears, and there is no
# tag, no release and no image - while CHANGELOG.md and the website both
# announce the version as the current release. Nothing distinguishes that from
# a release that worked.
#
# It has happened three times: v3.1.0 sat untagged for five days, and v3.3.1
# and v3.3.3 were each announced while nothing could install them. Rewriting
# the agent's prompt did not stop it, twice, which is the argument for checking
# rather than reminding.
#
# Usage: scripts/check-release-tagged.sh [--remote]
#   --remote  ask the origin for tags instead of trusting the local clone,
#             which is what CI wants and what a stale checkout gets wrong.
set -euo pipefail
cd "$(dirname "$0")/.."

use_remote=0
[ "${1:-}" = "--remote" ] && use_remote=1

version="$(sed -n 's/^VERSION?=\(v[0-9][^ \t]*\).*/\1/p' Makefile | head -1)"
if [ -z "${version}" ]; then
  echo "check-release-tagged: no VERSION?= line in the Makefile" >&2
  exit 2
fi

if [ "${use_remote}" = "1" ]; then
  tags="$(git ls-remote --tags origin 2>/dev/null | sed 's|.*refs/tags/||' | sed 's|\^{}$||')"
else
  tags="$(git tag -l)"
fi

if printf '%s\n' "${tags}" | grep -qx -- "${version}"; then
  echo "check-release-tagged: ${version} is tagged"
  exit 0
fi

cat >&2 <<EOF
check-release-tagged: ${version} is NOT tagged.

main's Makefile declares ${version}, and CHANGELOG.md and the website say so
too, but no such tag exists. That means no GitHub release, no image, and
nothing anyone can install - while every surface claims otherwise.

The usual cause is a release merged by an automation that cannot create tag
refs. Fix it by pushing the tag with a credential that can:

    git checkout main && git pull
    git tag -a ${version} -m ${version}
    git push origin ${version}
EOF
exit 1
