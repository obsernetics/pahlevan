#!/usr/bin/env sh
# Attack: read a sensitive credential file the workload never touched in baseline.
# Expected: Pahlevan (enforce) DENIES the open in-kernel (EPERM);
#           Falco ALERTS (Read sensitive file untrusted); Tetragon depends on policy.
set -e
cat /etc/shadow 2>&1 || echo "READ_BLOCKED_OR_FAILED rc=$?"
