#!/usr/bin/env bash
#
# Proves the CI gate actually fails when a dependency fails.
#
# Run from anywhere:  bash .github/actions/require-success/selftest.sh
# The `lint` job runs it on every CI run, so the gate cannot silently rot into
# a check that is always green.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="${here}/require-success.sh"

pass=0
fail=0

# expect <wanted-exit-code> <description> <needs-json>
expect() {
  local want="$1" desc="$2" json="$3" out got
  out="$(NEEDS="${json}" bash "${script}" 2>&1)"
  got=$?
  if [ "${got}" -eq "${want}" ]; then
    printf 'ok    %s (exit %s)\n' "${desc}" "${got}"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s: wanted exit %s, got %s\n' "${desc}" "${want}" "${got}"
    printf '%s\n' "${out}" | sed 's/^/        /'
    fail=$((fail + 1))
  fi
}

expect 0 'everything succeeded' \
  '{"build":{"result":"success"},"test":{"result":"success"}}'

expect 1 'one dependency failed' \
  '{"build":{"result":"success"},"test":{"result":"failure"}}'

expect 1 'one dependency was cancelled' \
  '{"build":{"result":"success"},"test":{"result":"cancelled"}}'

expect 1 'every dependency failed' \
  '{"build":{"result":"failure"},"test":{"result":"failure"}}'

expect 0 'a docs-only change skips the compile jobs' \
  '{"changes":{"result":"success"},"build":{"result":"skipped"},"test":{"result":"skipped"}}'

expect 0 'everything skipped' \
  '{"build":{"result":"skipped"},"test":{"result":"skipped"}}'

expect 1 'the gate has no dependencies at all' '{}'

expect 1 'the needs context was not passed through' ''

expect 1 'the needs context is not JSON' 'build=success'

# The real pipeline's job list, with the slowest job red. This is the case the
# gate exists for: `if: always()` means the gate job itself still runs.
expect 1 'the race job failed while the rest were green' \
  '{"changes":{"result":"success"},"build":{"result":"success"},"test":{"result":"success"},"test-race":{"result":"failure"},"lint":{"result":"success"},"cross-compile":{"result":"success"},"push-image":{"result":"success"}}'

# action.yml must actually invoke the script these cases exercise. Without
# this, someone could inline a different (and untested) copy of the logic and
# every case above would keep passing against dead code.
if grep -q 'require-success.sh' "${here}/action.yml"; then
  printf 'ok    action.yml runs require-success.sh\n'
  pass=$((pass + 1))
else
  printf 'FAIL  action.yml does not run require-success.sh\n'
  fail=$((fail + 1))
fi

printf '\n%s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
