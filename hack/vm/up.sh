#!/usr/bin/env bash
#
# up.sh - Bring up the pahlevan eBPF test VM (idempotent).
#
# Downloads an Ubuntu 24.04 cloud image once, builds a cloud-init seed with a
# generated SSH keypair + passwordless-sudo user, boots the VM headless under
# KVM with SSH forwarded to a localhost port, and provisions it with the eBPF
# toolchain (clang/llvm/libbpf/headers) and Go so eBPF programs can be compiled
# AND loaded INSIDE the VM.
#
# The guest kernel is forced to enable the *bpf* LSM via GRUB_CMDLINE_LINUX
# (lsm=...,bpf) so /sys/kernel/security/lsm inside the VM includes "bpf" - the
# host does not have it, but we control the guest cmdline.
#
# Re-running while the VM is already up is a no-op.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

GO_VERSION="1.25.13"

# --------------------------------------------------------------------------
# 0. Fast path: already running and reachable.
# --------------------------------------------------------------------------
if vm_is_running; then
  if vm_ssh_ready; then
    log "VM already running (pid $(cat "${VM_PIDFILE}")) and SSH is up on port ${SSH_PORT}. Nothing to do."
    exit 0
  fi
  log "VM process is alive but SSH is not ready yet; waiting..."
else
  mkdir -p "${CACHE_DIR}"

  # ----------------------------------------------------------------------
  # 1. Base cloud image (download once).
  # ----------------------------------------------------------------------
  if [[ ! -f "${BASE_IMG}" ]]; then
    log "Downloading Ubuntu ${UBUNTU_RELEASE} cloud image..."
    wget -q --show-progress -O "${BASE_IMG}.part" "${CLOUD_IMG_URL}"
    mv "${BASE_IMG}.part" "${BASE_IMG}"
  fi
  log "Base image: ${BASE_IMG}"

  # ----------------------------------------------------------------------
  # 2. SSH keypair (generate once).
  # ----------------------------------------------------------------------
  if [[ ! -f "${SSH_KEY}" ]]; then
    log "Generating SSH keypair..."
    ssh-keygen -t ed25519 -N "" -f "${SSH_KEY}" -C "pahlevan-vm" >/dev/null
  fi
  PUBKEY="$(cat "${SSH_PUB}")"

  # ----------------------------------------------------------------------
  # 3. VM disk: a qcow2 overlay on the base image, resized for the toolchain.
  #    Reused across cold restarts so the provisioned toolchain persists.
  #    Delete ${DISK_IMG} (or the whole cache dir) for a clean slate.
  # ----------------------------------------------------------------------
  if [[ -f "${DISK_IMG}" ]]; then
    log "Reusing existing VM disk: ${DISK_IMG}"
  else
    log "Creating VM disk (${DISK_SIZE})..."
    qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMG}" "${DISK_IMG}" >/dev/null
    qemu-img resize "${DISK_IMG}" "${DISK_SIZE}" >/dev/null
  fi

  # ----------------------------------------------------------------------
  # 4. cloud-init seed (user-data + meta-data).
  # ----------------------------------------------------------------------
  log "Building cloud-init seed..."
  USER_DATA="${CACHE_DIR}/user-data"
  META_DATA="${CACHE_DIR}/meta-data"

  cat >"${META_DATA}" <<EOF
instance-id: pahlevan-ebpf-vm
local-hostname: pahlevan-vm
EOF

  cat >"${USER_DATA}" <<EOF
#cloud-config
users:
  - name: ${SSH_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - ${PUBKEY}

# Password login as a fallback (SSH still uses the key).
chpasswd:
  expire: false
  list: |
    ${SSH_USER}:pahlevan

package_update: true
packages:
  - build-essential
  - clang
  - llvm
  - libbpf-dev
  - libelf-dev
  - zlib1g-dev
  - pkg-config
  - linux-headers-generic
  - linux-tools-common
  - linux-tools-generic
  - bpftool
  - git
  - curl

write_files:
  # Force the bpf LSM active in the guest kernel cmdline.
  - path: /etc/default/grub.d/99-pahlevan-bpf-lsm.cfg
    content: |
      GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} lsm=${GUEST_LSM_LIST}"
    permissions: '0644'

runcmd:
  # Install Go ${GO_VERSION} (apt Go is too old for this repo).
  - [ bash, -c, "curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -o /tmp/go.tgz" ]
  - [ bash, -c, "rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz" ]
  - [ bash, -c, "printf 'export PATH=\$PATH:/usr/local/go/bin:/root/go/bin:/home/${SSH_USER}/go/bin\\n' > /etc/profile.d/go.sh" ]
  - [ bash, -c, "ln -sf /usr/local/go/bin/go /usr/local/bin/go && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt" ]
  # Apply the bpf-LSM grub cmdline (takes effect after the reboot up.sh triggers).
  - [ bash, -c, "update-grub" ]
  # Signal provisioning complete.
  - [ bash, -c, "touch ${PROVISION_MARKER}" ]

final_message: "pahlevan eBPF VM cloud-init finished after \$UPTIME seconds"
EOF

  cloud-localds "${SEED_ISO}" "${USER_DATA}" "${META_DATA}"

  # ----------------------------------------------------------------------
  # 5. Boot the VM headless under KVM.
  # ----------------------------------------------------------------------
  log "Booting VM (headless, KVM, ${VM_CPUS} vCPU / ${VM_MEM}MB, SSH -> ${SSH_HOST}:${SSH_PORT})..."
  rm -f "${VM_LOGFILE}"
  qemu-system-x86_64 \
    -name pahlevan-ebpf-vm \
    -machine q35,accel=kvm \
    -cpu host \
    -smp "${VM_CPUS}" \
    -m "${VM_MEM}" \
    -display none \
    -serial "file:${VM_LOGFILE}" \
    -monitor "unix:${QEMU_MONITOR},server,nowait" \
    -drive "if=virtio,format=qcow2,file=${DISK_IMG}" \
    -drive "if=virtio,format=raw,file=${SEED_ISO}" \
    -netdev "user,id=net0,hostfwd=tcp:${SSH_HOST}:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -pidfile "${VM_PIDFILE}" \
    -daemonize

  log "QEMU started (pid $(cat "${VM_PIDFILE}")). Serial log: ${VM_LOGFILE}"
fi

# --------------------------------------------------------------------------
# 6. Wait for SSH.
# --------------------------------------------------------------------------
log "Waiting for SSH on ${SSH_HOST}:${SSH_PORT} (cloud image first boot can take a minute)..."
for i in $(seq 1 120); do
  if vm_ssh_ready; then
    log "SSH is up."
    break
  fi
  if ! vm_is_running; then
    err "QEMU process died. Serial log tail:"
    tail -n 40 "${VM_LOGFILE}" >&2 || true
    exit 1
  fi
  sleep 5
  [[ $i -eq 120 ]] && { err "Timed out waiting for SSH."; tail -n 40 "${VM_LOGFILE}" >&2 || true; exit 1; }
done

# --------------------------------------------------------------------------
# 7. Wait for cloud-init provisioning to finish (marker file).
# --------------------------------------------------------------------------
log "Waiting for cloud-init provisioning to finish (installs toolchain + Go)..."
for i in $(seq 1 120); do
  if vm_ssh "test -f ${PROVISION_MARKER}" 2>/dev/null; then
    log "Provisioning complete."
    break
  fi
  sleep 10
  [[ $i -eq 120 ]] && { err "Timed out waiting for provisioning marker."; vm_ssh "sudo cloud-init status --long" >&2 || true; exit 1; }
done

# --------------------------------------------------------------------------
# 8. Ensure the bpf LSM is active; reboot once to apply the GRUB cmdline.
# --------------------------------------------------------------------------
if vm_ssh "cat /sys/kernel/security/lsm" 2>/dev/null | grep -q bpf; then
  log "bpf LSM already active."
else
  log "bpf LSM not active yet; rebooting guest to apply kernel cmdline..."
  vm_ssh "sudo reboot" 2>/dev/null || true
  sleep 8
  for i in $(seq 1 60); do
    if vm_ssh_ready; then break; fi
    sleep 5
    [[ $i -eq 60 ]] && { err "Timed out waiting for SSH after reboot."; exit 1; }
  done
  if vm_ssh "cat /sys/kernel/security/lsm" 2>/dev/null | grep -q bpf; then
    log "bpf LSM active after reboot."
  else
    err "bpf LSM STILL not active. /sys/kernel/security/lsm =>"
    vm_ssh "cat /sys/kernel/security/lsm" >&2 || true
    err "Kernel cmdline =>"
    vm_ssh "cat /proc/cmdline" >&2 || true
    exit 1
  fi
fi

# --------------------------------------------------------------------------
# 9. Summary.
# --------------------------------------------------------------------------
log "VM is ready."
log "  kernel : $(vm_ssh 'uname -r' 2>/dev/null || echo '?')"
log "  lsm    : $(vm_ssh 'cat /sys/kernel/security/lsm' 2>/dev/null || echo '?')"
log "  ssh    : ssh -i ${SSH_KEY} -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST}"
log "Use: hack/vm/run.sh '<cmd>' | hack/vm/cp.sh <local> <remote> | hack/vm/down.sh"
