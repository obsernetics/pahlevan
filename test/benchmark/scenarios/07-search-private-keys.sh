#!/usr/bin/env sh
# Tactic: Credential Access (TA0006)
# Technique: Unsecured Credentials - Private Keys (T1552.004)
# Attack: sweep the filesystem for private key material. This opens a large
# number of files nginx never touches; that mass of file_open is the signal.
# Marker: outcome=attempted (a search cannot be cleanly classified as
#         blocked vs empty-result from inside the pod; judge via tool logs).
set -u
TAG="07-search-private-keys"
KIND="attack"
rc=0
{
  timeout 5 find / -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null
  timeout 5 grep -rlI 'BEGIN .*PRIVATE KEY' /etc /root /home /var 2>/dev/null
} >/dev/null 2>&1 || rc=$?
OUT="attempted"
printf 'BENCH_RESULT tag=%s kind=%s outcome=%s rc=%s\n' "$TAG" "$KIND" "$OUT" "$rc"
