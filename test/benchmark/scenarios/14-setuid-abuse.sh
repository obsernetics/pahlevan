#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004)
# Technique: Abuse Elevation Control Mechanism - Setuid and Setgid (T1548.001)
# Attack: enumerate existing setuid binaries and try to create a new setuid-root
# binary. nginx never chmods a copied binary to setuid.
# Marker: outcome=allowed if the setuid bit was set, blocked if prevented.
set -u
TAG="14-setuid-abuse"
KIND="attack"
DROP="/tmp/.suid"
rc=0
timeout 5 find / -perm -4000 -type f 2>/dev/null >/dev/null || true
cp /bin/true "$DROP" 2>/dev/null || rc=$?
if [ "$rc" -eq 0 ]; then
  chmod u+s "$DROP" 2>/dev/null || rc=$?
fi
if [ "$rc" -eq 0 ]; then
  case "$(ls -l "$DROP" 2>/dev/null)" in
    *rws*) rc=0 ;;
    *) rc=1 ;;
  esac
fi
rm -f "$DROP" 2>/dev/null || true
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
