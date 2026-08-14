#!/usr/bin/env sh
# BENIGN CONTROL (not an attack). Measures FALSE POSITIVES.
# Normal behaviour: nginx reads its own configuration and served content, which
# it does on every start and reload. These are baselined paths.
# Correct result: outcome=allowed. A block/alert here is a false positive.
set -eu
TAG="b02-read-own-config"
KIND="benign"
rc=0
for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html; do
  if [ -f "$f" ]; then
    cat "$f" >/dev/null 2>&1 || rc=$?
  fi
done
if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
