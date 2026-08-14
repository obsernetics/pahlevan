#!/usr/bin/env sh
# MECHANISM PROBE (not one of the 26 attack scenarios).
# Reads /etc/shadow with the shell's read builtin instead of `cat`, so the only
# kernel decision involved is the file_open on /etc/shadow itself. Scenario 01
# does the same thing through `cat`, where the binary's own open is denied first
# and the sensitive file is never reached; this probe separates the two.
set -u
TAG="p03-read-shadow-builtin"
KIND="probe"
rc=0
read -r _line < /etc/shadow 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
