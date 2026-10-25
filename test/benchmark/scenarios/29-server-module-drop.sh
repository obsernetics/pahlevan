#!/usr/bin/env sh
# Tactic: Persistence (TA0003)
# Technique: Hijack Execution Flow (T1574)
# Attack: write a shared object into a directory the server loads modules from.
# A server that loads every .so it finds at startup, without a signature, an
# execute bit or a symbol check, turns a file write into code execution on the
# next restart. That is the last link of the Plex2Shell chain
# (CVE-2026-96656), and it is a file write rather than an exec, so nothing in
# the process-execution path sees it at all.
# Marker: outcome=allowed if the write succeeded, blocked if it was prevented,
#         skipped if the image has no module directory.
set -u
TAG="29-server-module-drop"
KIND="attack"
rc=0
ok=1
found=1
for DIR in /usr/lib/nginx/modules /etc/nginx/modules /usr/local/nginx/modules; do
  [ -d "$DIR" ] || continue
  found=0
  DROP="${DIR}/ngx_pahlevan_bench_module.so"
  if { printf '%s' 'not-a-real-object' >"$DROP"; } 2>/dev/null; then
    ok=0
  fi
  # Removed immediately: a half-written .so left in a module directory would
  # stop the server loading on its next restart.
  rm -f "$DROP" 2>/dev/null || true
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
