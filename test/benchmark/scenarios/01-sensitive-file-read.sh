#!/usr/bin/env sh
# Tactic: Credential Access (TA0006)
# Technique: OS Credential Dumping - /etc/passwd and /etc/shadow (T1003.008)
# Attack: read a sensitive credential file the workload never touched in
# baseline. nginx never reads /etc/shadow.
# Expected: Pahlevan (enforce) DENIES the open in-kernel (EPERM); Falco ALERTS
#           (read sensitive file untrusted); Tetragon depends on policy.
# Marker: outcome=allowed if the read succeeded, blocked if prevented.
set -u
TAG="01-sensitive-file-read"
KIND="attack"
rc=0
cat /etc/shadow >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
