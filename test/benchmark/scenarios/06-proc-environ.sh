#!/usr/bin/env sh
# Tactic: Credential Access (TA0006)
# Technique: Unsecured Credentials - Credentials In Files (T1552)
# Attack: read /proc/self/environ to harvest secrets injected as env vars.
# A normal nginx worker never reads its own process environment this way.
# Marker: outcome=allowed if the read succeeded, blocked if prevented.
set -u
TAG="06-proc-environ"
KIND="attack"
rc=0
cat /proc/self/environ >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
