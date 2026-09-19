#!/usr/bin/env bash
#
# Fails unless every job in the `needs` context succeeded or was skipped.
#
# This is the body of the single "CI" status check that branch protection
# requires. It exists because the aggregate job has to run with `if: always()`
# in order to report at all when a dependency failed - and `if: always()` also
# means the job's own steps run and, by default, pass. A required check that
# goes green while a dependency was red is worse than having no check, so the
# gate has to inspect the results itself.
#
# Input: NEEDS, the JSON of the `needs` context, i.e. ${{ toJSON(needs) }}.
#
# "skipped" counts as a pass: a documentation-only change legitimately skips
# every compile and test job, and the pipeline must still be mergeable.
set -uo pipefail

if [ -z "${NEEDS:-}" ]; then
  echo "::error::NEEDS is empty - the gate was wired up without \${{ toJSON(needs) }}."
  exit 1
fi

if ! printf '%s' "${NEEDS}" | jq -e . >/dev/null 2>&1; then
  echo "::error::NEEDS is not valid JSON: ${NEEDS}"
  exit 1
fi

count="$(printf '%s' "${NEEDS}" | jq -r 'length')"
if [ "${count}" -eq 0 ]; then
  # A gate with no dependencies is a green light that checks nothing, which is
  # exactly the failure mode this script is here to prevent.
  echo "::error::the gate has no dependencies - it would pass no matter what broke."
  exit 1
fi

status=0
while IFS=$'\t' read -r result job; do
  case "${result}" in
    success|skipped)
      printf '  %-10s %s\n' "${result}" "${job}"
      ;;
    *)
      printf '  %-10s %s\n' "${result}" "${job}"
      echo "::error::job '${job}' finished with result '${result}'."
      status=1
      ;;
  esac
done < <(printf '%s' "${NEEDS}" | jq -r 'to_entries[] | "\(.value.result)\t\(.key)"')

if [ "${status}" -ne 0 ]; then
  echo "CI is red: at least one required job did not succeed."
  exit 1
fi

echo "All ${count} required jobs succeeded or were skipped."
