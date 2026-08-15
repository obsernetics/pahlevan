#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004) - container escape signal
# Technique: Escape to Host (T1611)
# Attack: try to write kernel-influencing pseudo-files (core_pattern is a known
# escape primitive) under /proc/sys and /sys. nginx never writes to these.
# Marker: outcome=allowed if any write succeeded, blocked/attempted otherwise.
#         Note: these paths are usually read-only in a container regardless of
#         Pahlevan, so a failure alone is not proof of enforcement; the write
#         attempt on the path is the signal.
set -u
TAG="24-write-sys-procsys"
KIND="attack"
ok=1
{ echo '|/tmp/.esc' > /proc/sys/kernel/core_pattern; } 2>/dev/null && ok=0
{ echo 0 > /proc/sys/kernel/kptr_restrict; } 2>/dev/null && ok=0
{ echo 1 > /sys/kernel/mm/transparent_hugepage/enabled; } 2>/dev/null && ok=0
if [ "$ok" -eq 0 ]; then OUT="allowed"; else OUT="attempted"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$ok"
