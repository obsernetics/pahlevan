#!/usr/bin/env sh
# Tactic: Defense Evasion (TA0005)
# Technique: Indicator Removal - Clear Command History (T1070.003)
# Attack: neutralise shell history (point HISTFILE at /dev/null, delete the
# history file). nginx has no interactive shell history to tamper with.
# Marker: outcome=allowed if the history file was removed/redirected, blocked
#         if prevented.
set -u
TAG="18-disable-history"
KIND="attack"
ok=1
export HISTFILE=/dev/null
unset HISTFILE 2>/dev/null || true
{ : > "$HOME/.bash_history"; } 2>/dev/null && ok=0
{ rm -f "$HOME/.bash_history"; } 2>/dev/null && ok=0
{ ln -sf /dev/null "$HOME/.bash_history"; } 2>/dev/null && ok=0
rm -f "$HOME/.bash_history" 2>/dev/null || true
if [ "$ok" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$ok"
