#!/usr/bin/env sh
# Tactic: Discovery (TA0007)
# Technique: Container and Resource Discovery (T1613)
# Attack: use the mounted service-account token to query the Kubernetes API
# for pods in the namespace. A benign nginx never calls the API server.
# Marker: outcome=attempted (network path; classify via tool logs and the
#         API response, not by exit code alone).
set -u
TAG="09-k8s-api-query"
KIND="attack"
SA="/var/run/secrets/kubernetes.io/serviceaccount"
API="https://kubernetes.default.svc/api/v1/namespaces/bench/pods"
rc=0
if command -v curl >/dev/null 2>&1; then
  timeout 4 curl -s -m 3 --cacert "$SA/ca.crt" \
    -H "Authorization: Bearer $(cat "$SA/token" 2>/dev/null)" \
    "$API" >/dev/null 2>&1 || rc=$?
  OUT="attempted"
elif command -v wget >/dev/null 2>&1; then
  timeout 4 wget -q -T 3 --ca-certificate="$SA/ca.crt" \
    --header="Authorization: Bearer $(cat "$SA/token" 2>/dev/null)" \
    -O /dev/null "$API" >/dev/null 2>&1 || rc=$?
  OUT="attempted"
else
  OUT="skipped"
fi
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
