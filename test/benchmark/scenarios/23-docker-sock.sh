#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004) - container escape signal
# Technique: Escape to Host (T1611); Deploy Container (T1610)
# Attack: look for and touch a mounted container runtime socket (docker.sock /
# containerd.sock), the classic path to breaking out to the host. nginx never
# references a runtime socket.
# Marker: outcome=attempted (the socket is normally absent, so an error is not
#         proof of enforcement; the open attempt on the path is the signal).
set -u
TAG="23-docker-sock"
KIND="attack"
rc=0
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock; do
  ls -l "$s" 2>/dev/null || true
  if [ -S "$s" ]; then
    if command -v curl >/dev/null 2>&1; then
      timeout 3 curl -s --unix-socket "$s" http://localhost/version >/dev/null 2>&1 || true
    fi
  fi
done
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
