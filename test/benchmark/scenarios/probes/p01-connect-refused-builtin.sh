#!/usr/bin/env sh
# MECHANISM PROBE (not one of the 26 attack scenarios).
# Opens a TCP connection using only the shell's /dev/tcp builtin, so no new
# binary is exec'd and no new file is opened. That is the only way to reach an
# LSM socket_connect decision while a path/exec allow-list is denying every
# helper binary first. Destination is loopback:9 (discard, closed), which fails
# instantly either way, so the exit code proves nothing: judge from whether the
# tool reports a network denial for 127.0.0.1:9 in the same window.
set -u
TAG="p01-connect-refused-builtin"
KIND="probe"
rc=0
(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null || rc=$?
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
