#!/usr/bin/env sh
# Tactic: Persistence (TA0003)
# Technique: Server Software Component - Web Shell (T1505.003)
# Attack: plant a server-side script in a directory the web server serves. The
# file is remotely reachable the moment it lands, so the write is the whole
# intrusion: no exec follows until the attacker fetches the URL, which may be
# days later and from somewhere else. This is how the PTC Windchill
# exploitation (CVE-2026-12569) was found, by hex-named .jsp files appearing
# under the login directory.
# A .php written to /tmp would be staging; a .png written to a document root
# would be an upload. Only a script inside a served directory is this.
# Marker: outcome=allowed if a drop succeeded, blocked if every write was
#         prevented, skipped if the image has no document root to write into.
set -u
TAG="28-webshell-file-drop"
KIND="attack"
rc=0
ok=1
found=1
for DIR in /usr/share/nginx/html /var/www/html /srv/http; do
  [ -d "$DIR" ] || continue
  found=0
  for NAME in .pahlevan-bench.php pahlevan-bench.php.bak; do
    DROP="${DIR}/${NAME}"
    if { printf '%s\n' '<?php echo 1; ?>' >"$DROP"; } 2>/dev/null; then
      ok=0
    fi
    # Remove it whether or not the write landed, so the pod stays reusable and
    # no scenario leaves a reachable script behind.
    rm -f "$DROP" 2>/dev/null || true
  done
done
if [ "$found" -ne 0 ]; then
  OUT="skipped"
  rc=127
elif [ "$ok" -eq 0 ]; then
  OUT="allowed"
else
  OUT="blocked"
  rc=1
fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
