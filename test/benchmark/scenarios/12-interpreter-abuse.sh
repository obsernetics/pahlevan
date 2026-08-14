#!/usr/bin/env sh
# Tactic: Execution (TA0002)
# Technique: Command and Scripting Interpreter - Python (T1059.006)
# Attack: run a scripting-interpreter one-liner (python or perl). The exec of an
# interpreter that is not part of the nginx baseline is the signal.
# Marker: outcome=allowed if the interpreter ran, blocked if prevented,
#         skipped if no interpreter is installed in the image.
set -u
TAG="12-interpreter-abuse"
KIND="attack"
rc=0
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import os,sys; sys.stdout.write(str(os.getuid()))' >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
elif command -v perl >/dev/null 2>&1; then
  perl -e 'print $>;' >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then OUT="allowed"; else OUT="blocked"; fi
else
  OUT="skipped"
fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
