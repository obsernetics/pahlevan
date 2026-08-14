#!/usr/bin/env bash
#
# down.sh - Shut the eBPF test VM down cleanly.
#
# Tries a graceful `sudo poweroff` over SSH, falls back to the QEMU monitor
# (system_powerdown), then to terminating the QEMU process. Pass --force to
# skip straight to killing the process.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if ! vm_is_running; then
  log "VM is not running."
  rm -f "${VM_PIDFILE}"
  exit 0
fi

PID="$(cat "${VM_PIDFILE}")"

if [[ "${FORCE}" -eq 0 ]]; then
  log "Requesting graceful shutdown over SSH..."
  vm_ssh "sudo poweroff" 2>/dev/null || true

  # Wait for QEMU to exit.
  for i in $(seq 1 30); do
    if ! vm_is_running; then
      log "VM powered off cleanly."
      rm -f "${VM_PIDFILE}"
      exit 0
    fi
    sleep 2
  done
  log "Graceful shutdown timed out; falling back to QEMU monitor..."
fi

# Fallback: ACPI powerdown via monitor socket.
if [[ -S "${QEMU_MONITOR}" ]] && command -v socat >/dev/null 2>&1; then
  echo "system_powerdown" | socat - "UNIX-CONNECT:${QEMU_MONITOR}" 2>/dev/null || true
  for i in $(seq 1 15); do
    vm_is_running || { log "VM powered off via monitor."; rm -f "${VM_PIDFILE}"; exit 0; }
    sleep 2
  done
fi

# Last resort: terminate the process.
log "Terminating QEMU process ${PID}..."
kill "${PID}" 2>/dev/null || true
for i in $(seq 1 10); do
  vm_is_running || { log "VM stopped."; rm -f "${VM_PIDFILE}"; exit 0; }
  sleep 1
done
kill -9 "${PID}" 2>/dev/null || true
rm -f "${VM_PIDFILE}"
log "VM force-stopped."
