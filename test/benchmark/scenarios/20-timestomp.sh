#!/usr/bin/env sh
# Tactic: Defense Evasion (TA0005)
# Technique: Indicator Removal - Timestomp (T1070.006)
# Attack: backdate a dropped file's timestamps to blend in with system files.
# nginx never rewrites file timestamps.
# Marker: outcome=allowed if the timestamp was changed, blocked if prevented.
set -u
TAG="20-timestomp"
KIND="attack"
DROP="/tmp/.ts"
rc=0
: > "$DROP" 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then
  touch -t 200001010000.00 "$DROP" 2>/dev/null || rc=$?
fi
if [ "$rc" -eq 0 ]; then
  # Also try to copy a reference file's timestamp onto our drop.
  touch -r /etc/hostname "$DROP" 2>/dev/null || true
fi
rm -f "$DROP" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
