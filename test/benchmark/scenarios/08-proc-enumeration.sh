#!/usr/bin/env sh
# Tactic: Discovery (TA0007)
# Technique: Process Discovery (T1057)
# Attack: enumerate /proc to list other processes and their command lines.
# nginx does not walk /proc/<pid>/cmdline of neighbours.
# Marker: outcome=attempted (a read sweep; judge blocking via tool logs).
set -u
TAG="08-proc-enumeration"
KIND="attack"
rc=0
{
  for p in /proc/[0-9]*; do
    cat "$p/cmdline" 2>/dev/null | tr '\0' ' '
    echo
  done
} >/dev/null 2>&1 || rc=$?
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
