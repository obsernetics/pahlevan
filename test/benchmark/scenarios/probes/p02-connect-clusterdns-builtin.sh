#!/usr/bin/env sh
# MECHANISM PROBE (not one of the 26 attack scenarios).
# Same builtin-only TCP connect, but to a destination that exists and accepts:
# the cluster DNS service on TCP 53 (k3s default ClusterIP 10.43.0.10). An
# unenforced pod connects successfully; a pod whose egress allow-list never
# learned this destination should be refused in-kernel at socket_connect.
set -u
TAG="p02-connect-clusterdns-builtin"
KIND="probe"
rc=0
(exec 3<>/dev/tcp/10.43.0.10/53) 2>/dev/null || rc=$?
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
