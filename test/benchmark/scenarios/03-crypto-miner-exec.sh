#!/usr/bin/env sh
# Attack: run a binary from a suspicious path never in the baseline (miner shape).
set -e
cp /bin/sleep /tmp/xmrig 2>/dev/null || true
/tmp/xmrig 1 2>&1 || echo "MINER_EXEC_BLOCKED_OR_FAILED rc=$?"
