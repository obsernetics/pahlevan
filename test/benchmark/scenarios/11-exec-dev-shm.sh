#!/usr/bin/env sh
# Tactic: Execution (TA0002)
# Technique: Command and Scripting Interpreter (T1059)
# Attack: drop a binary into /dev/shm (a tmpfs, world-writable, often overlooked)
# and execute it. nginx never execs from /dev/shm.
# Marker: outcome=allowed if it ran, blocked if exec was prevented.
set -u
TAG="11-exec-dev-shm"
KIND="attack"
DROP="/dev/shm/.payload"
rc=0
cp /bin/true "$DROP" 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then
  "$DROP" 2>/dev/null || rc=$?
fi
rm -f "$DROP" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
