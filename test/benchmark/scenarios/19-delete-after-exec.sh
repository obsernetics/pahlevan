#!/usr/bin/env sh
# Tactic: Defense Evasion (TA0005)
# Technique: Indicator Removal - File Deletion (T1070.004)
# Attack: drop a payload, run it, then delete it to remove evidence (self-clean).
# nginx does not drop-run-delete executables from /tmp.
# Marker: outcome=allowed if the drop/exec/delete cycle completed, blocked if
#         any step was prevented.
set -u
TAG="19-delete-after-exec"
KIND="attack"
DROP="/tmp/.stage"
rc=0
cp /bin/true "$DROP" 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then "$DROP" 2>/dev/null || rc=$?; fi
if [ "$rc" -eq 0 ]; then rm -f "$DROP" 2>/dev/null || rc=$?; fi
rm -f "$DROP" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
