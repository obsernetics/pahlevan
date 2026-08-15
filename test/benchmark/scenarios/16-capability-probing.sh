#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004) / Discovery (TA0007)
# Technique id omitted (capability enumeration does not map cleanly to a single
# ATT&CK technique; treated as recon for later escalation).
# Attack: read the process capability sets and probe for a permissive posture
# (e.g. CAP_SYS_ADMIN) that would enable escape. nginx never inspects caps.
# Marker: outcome=attempted (a read/probe; judge blocking via tool logs).
set -u
TAG="16-capability-probing"
KIND="attack"
rc=0
{
  grep -i '^Cap' /proc/self/status 2>/dev/null
  cat /proc/1/status 2>/dev/null | grep -i '^Cap' 2>/dev/null
  if command -v capsh >/dev/null 2>&1; then capsh --print 2>/dev/null; fi
} >/dev/null 2>&1 || rc=$?
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
