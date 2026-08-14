#!/usr/bin/env sh
# Tactic: Execution (TA0002) / Impact (TA0040)
# Technique: Resource Hijacking (T1496); User Execution shape (T1204)
# Attack: run a binary from a suspicious path never in the baseline (miner shape).
# nginx never execs a binary out of /tmp.
# Marker: outcome=allowed if it ran, blocked if exec was prevented.
set -u
TAG="03-crypto-miner-exec"
KIND="attack"
DROP="/tmp/xmrig"
rc=0
cp /bin/sleep "$DROP" 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then
  "$DROP" 1 2>/dev/null || rc=$?
fi
rm -f "$DROP" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
