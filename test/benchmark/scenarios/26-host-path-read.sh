#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004) - container escape signal
# Technique: Escape to Host (T1611)
# Attack: read host filesystem paths that appear only when the host root is
# bind-mounted into the container (a common misconfiguration). nginx never
# reads /host or /rootfs.
# Marker: outcome=attempted (these paths are normally absent, so an error is not
#         proof of enforcement; the open attempt on the path is the signal).
set -u
TAG="26-host-path-read"
KIND="attack"
rc=0
for p in /host/etc/shadow /host/etc/passwd /rootfs/etc/shadow /host/proc/1/environ; do
  cat "$p" >/dev/null 2>&1 || true
done
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
