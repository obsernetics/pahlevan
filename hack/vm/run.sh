#!/usr/bin/env bash
#
# run.sh '<command>' - Run a command inside the eBPF test VM.
#
# Streams stdout/stderr live and propagates the remote exit code. The command
# runs in a login shell so /etc/profile.d/go.sh (Go on PATH) is loaded.
#
# Example:
#   hack/vm/run.sh 'uname -r'
#   hack/vm/run.sh 'cd /home/pahlevan/pahlevan && sudo go test ./...'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

if [[ $# -eq 0 ]]; then
  err "usage: $0 '<command>'"
  exit 2
fi

if ! vm_is_running; then
  err "VM is not running. Start it with: hack/vm/up.sh"
  exit 1
fi

# -t only if we have a TTY, so piping/capturing works cleanly too.
TTY_OPT=()
[[ -t 1 ]] && TTY_OPT=(-t)

# Join all args into a single command string; run under a login bash so PATH
# (Go, /usr/local/bin) is set up.
exec ssh "${SSH_OPTS[@]}" "${TTY_OPT[@]}" "${SSH_USER}@${SSH_HOST}" \
  "bash -lc $(printf '%q' "$*")"
