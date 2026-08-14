#!/usr/bin/env bash
#
# cp.sh <local> <remote> - Copy a file (or dir with -r semantics) into the VM.
#
# <remote> is a path inside the VM, relative to the pahlevan user's home unless
# absolute. Examples:
#   hack/vm/cp.sh ./prog.o /tmp/prog.o
#   hack/vm/cp.sh -r ./hack/vm/smoke smoke

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

RECURSIVE=()
if [[ "${1:-}" == "-r" ]]; then
  RECURSIVE=(-r)
  shift
fi

if [[ $# -ne 2 ]]; then
  err "usage: $0 [-r] <local-path> <remote-path>"
  exit 2
fi

LOCAL="$1"
REMOTE="$2"

if ! vm_is_running; then
  err "VM is not running. Start it with: hack/vm/up.sh"
  exit 1
fi

exec scp "${SCP_OPTS[@]}" "${RECURSIVE[@]}" "${LOCAL}" "${SSH_USER}@${SSH_HOST}:${REMOTE}"
