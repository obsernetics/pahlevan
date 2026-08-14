#!/usr/bin/env sh
# Tactic: Credential Access (TA0006)
# Technique: Unsecured Credentials - Credentials In Files (T1552.001)
# Attack: read the mounted Kubernetes service-account token. A plain nginx
# workload never reads its own SA token; an attacker uses it to talk to the API.
# Marker: prints "BENCH_RESULT ..." with outcome=allowed if the read succeeded,
#         outcome=blocked if it was prevented (EPERM).
set -u
TAG="05-serviceaccount-token"
KIND="attack"
TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
rc=0
cat "$TOKEN" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
