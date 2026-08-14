#!/usr/bin/env bash
# Shared configuration + helpers for the pahlevan QEMU/KVM eBPF test VM.
#
# This harness exists so eBPF programs (load/attach/enforce) and Go eBPF tests
# run inside a VM that has its OWN kernel. eBPF is NEVER loaded on the host.
#
# All paths are absolute and derived from the repo root so the scripts are
# reproducible regardless of the caller's working directory.

set -euo pipefail

# --- Locations -------------------------------------------------------------
# Repo root = two levels up from this file (hack/vm/env.sh -> repo root).
VM_ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VM_ENV_DIR}/../.." && pwd)"

# Cache dir holds large artifacts (base image, VM disk, seed ISO, SSH keys).
# Override with PAHLEVAN_VM_CACHE if you want it elsewhere (e.g. scratchpad).
CACHE_DIR="${PAHLEVAN_VM_CACHE:-${REPO_ROOT}/.vmcache}"

# --- Image ---------------------------------------------------------------
UBUNTU_RELEASE="noble" # 24.04 LTS
CLOUD_IMG_NAME="${UBUNTU_RELEASE}-server-cloudimg-amd64.img"
CLOUD_IMG_URL="https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${CLOUD_IMG_NAME}"
BASE_IMG="${CACHE_DIR}/${CLOUD_IMG_NAME}"
DISK_IMG="${CACHE_DIR}/disk.qcow2"
SEED_ISO="${CACHE_DIR}/seed.iso"
DISK_SIZE="20G"

# --- SSH -----------------------------------------------------------------
# Default 2223 (2222 is a common default and may be taken by another local VM);
# override with PAHLEVAN_VM_SSH_PORT.
SSH_PORT="${PAHLEVAN_VM_SSH_PORT:-2223}"
SSH_USER="pahlevan"
SSH_KEY="${CACHE_DIR}/id_ed25519"
SSH_PUB="${SSH_KEY}.pub"
SSH_HOST="127.0.0.1"

# --- VM runtime ----------------------------------------------------------
VM_PIDFILE="${CACHE_DIR}/vm.pid"
VM_LOGFILE="${CACHE_DIR}/vm-serial.log"
VM_MEM="${PAHLEVAN_VM_MEM:-4096}"
VM_CPUS="${PAHLEVAN_VM_CPUS:-4}"
QEMU_MONITOR="${CACHE_DIR}/qemu-monitor.sock"

# Force the bpf LSM active in the guest via the kernel cmdline (set through
# GRUB by cloud-init). The host does NOT have bpf in its lsm list; the guest
# will, because we control the guest cmdline.
GUEST_LSM_LIST="capability,landlock,yama,apparmor,bpf"

# Marker file the guest touches once cloud-init provisioning finished.
PROVISION_MARKER="/var/lib/pahlevan-provisioned"

# --- SSH helpers ---------------------------------------------------------
# Common options shared by ssh and scp (no port here: ssh uses -p, scp uses -P).
SSH_COMMON_OPTS=(
  -i "${SSH_KEY}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o GlobalKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=5
)

# For ssh (lowercase -p for port).
SSH_OPTS=(-p "${SSH_PORT}" "${SSH_COMMON_OPTS[@]}")

# For scp (uppercase -P for port).
SCP_OPTS=(-P "${SSH_PORT}" "${SSH_COMMON_OPTS[@]}")

vm_ssh() {
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" "$@"
}

vm_scp() {
  scp "${SCP_OPTS[@]}" "$@"
}

# Is the VM process alive?
vm_is_running() {
  [[ -f "${VM_PIDFILE}" ]] || return 1
  local pid
  pid="$(cat "${VM_PIDFILE}" 2>/dev/null || true)"
  [[ -n "${pid}" ]] || return 1
  kill -0 "${pid}" 2>/dev/null
}

# Can we SSH in right now?
vm_ssh_ready() {
  vm_ssh -o ConnectTimeout=3 -o BatchMode=yes true 2>/dev/null
}

log() { printf '\033[1;34m[vm]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31m[vm]\033[0m %s\n' "$*" >&2; }
