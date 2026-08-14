#!/usr/bin/env sh
# BENIGN CONTROL (not an attack). Measures FALSE POSITIVES.
# Normal behaviour: nginx serves an HTTP request on its own loopback port. This
# exercises the exact code path a liveness/readiness probe or a real client hits.
# Correct result: outcome=allowed. If a tool BLOCKS or ALERTS on this, that is a
# false positive counted against it.
set -eu
TAG="b01-serve-request"
KIND="benign"
rc=0
if command -v curl >/dev/null 2>&1; then
  timeout 4 curl -s -m 3 -o /dev/null http://127.0.0.1/ || rc=$?
elif command -v wget >/dev/null 2>&1; then
  timeout 4 wget -q -T 3 -O /dev/null http://127.0.0.1/ || rc=$?
else
  rc=127
fi
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
