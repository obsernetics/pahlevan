#!/usr/bin/env sh
# BENIGN CONTROL (not an attack). Measures FALSE POSITIVES.
# Normal behaviour: nginx resolves in-cluster service names (upstreams, the API
# service) via the cluster DNS. Resolving kubernetes.default.svc is routine.
# Correct result: outcome=allowed. A block/alert here is a false positive.
set -eu
TAG="b03-resolve-dns"
KIND="benign"
rc=0
if command -v getent >/dev/null 2>&1; then
  timeout 3 getent hosts kubernetes.default.svc.cluster.local >/dev/null 2>&1 || rc=$?
elif command -v nslookup >/dev/null 2>&1; then
  timeout 3 nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1 || rc=$?
else
  rc=127
fi
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
