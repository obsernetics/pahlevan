#!/usr/bin/env sh
# Tactic: Exfiltration (TA0010) / Command and Control (TA0011)
# Technique: Exfiltration Over C2 Channel shape (T1041); Application Layer
#            Protocol - Web (T1071.001)
# Attack: connect out to a destination not seen during baseline (C2/exfil shape).
# Uses 198.51.100.10 (TEST-NET-2, unroutable) so nothing real is contacted.
# Marker: outcome=attempted (unroutable destination fails regardless of
#         enforcement; judge blocking via tool logs).
set -u
TAG="04-unexpected-egress"
KIND="attack"
URL="http://198.51.100.10/"
rc=0
if command -v curl >/dev/null 2>&1; then
  timeout 4 curl -s -m 3 -o /dev/null "$URL" >/dev/null 2>&1 || rc=$?
elif command -v wget >/dev/null 2>&1; then
  timeout 4 wget -q -T 3 -O /dev/null "$URL" >/dev/null 2>&1 || rc=$?
else
  rc=127
fi
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
