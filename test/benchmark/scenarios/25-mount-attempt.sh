#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004) - container escape signal
# Technique: Escape to Host (T1611)
# Attack: exec the mount binary to attach a new filesystem (a step in many
# breakout chains). nginx never runs mount.
# Marker: outcome=attempted (mount needs CAP_SYS_ADMIN and fails in a normal
#         container regardless of Pahlevan; the exec of mount and the mount
#         syscall are the signals to judge from tool logs).
set -u
TAG="25-mount-attempt"
KIND="attack"
rc=0
if command -v mount >/dev/null 2>&1; then
  mkdir -p /tmp/.mnt 2>/dev/null || true
  timeout 3 mount -t tmpfs none /tmp/.mnt >/dev/null 2>&1 || rc=$?
  umount /tmp/.mnt >/dev/null 2>&1 || true
  rmdir /tmp/.mnt 2>/dev/null || true
  OUT="attempted"
else
  OUT="skipped"
fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
