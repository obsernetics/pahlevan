#!/usr/bin/env sh
# Tactic: Discovery (TA0007)
# Technique: Network Service Discovery (T1046)
# Attack: probe a handful of common service ports to map reachable hosts.
# nginx only listens; it does not scan the cluster network.
# Marker: outcome=attempted (connect probes; judge blocking via tool logs).
set -u
TAG="10-network-discovery"
KIND="attack"
rc=0
probe() {
  # $1 host, $2 port; uses bash /dev/tcp when available, else nc.
  if command -v bash >/dev/null 2>&1; then
    timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    timeout 2 nc -z "$1" "$2" >/dev/null 2>&1
  fi
}
for hp in "kubernetes.default.svc 443" "127.0.0.1 80" "10.0.0.1 22"; do
  # shellcheck disable=SC2086
  probe $hp || true
done
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
