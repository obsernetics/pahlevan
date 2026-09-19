#!/usr/bin/env bash
#
# up.sh - Bring up the pahlevan eBPF test VM (idempotent).
#
# Downloads an Ubuntu 24.04 cloud image once, builds a cloud-init seed with a
# generated SSH keypair + passwordless-sudo user, boots the VM headless under
# KVM with SSH forwarded to a localhost port, and provisions it with bpftool
# and a Go toolchain so the committed eBPF objects are LOADED INSIDE the VM by
# a real kernel. The programs are compiled out-of-band by `make ebpf`, not
# here - see the package list below.
#
# The guest kernel is forced to enable the *bpf* LSM via GRUB_CMDLINE_LINUX
# (lsm=...,bpf) so /sys/kernel/security/lsm inside the VM includes "bpf" - the
# host does not have it, but we control the guest cmdline.
#
# Re-running while the VM is already up is a no-op.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

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

  # Packages the guest actually needs.
  #
  # The eBPF objects and their Go bindings are committed and loaded by
  # cilium/ebpf, which is pure Go: nothing in the guest compiles BPF C, so the
  # toolchain that used to be installed here - build-essential, clang, llvm,
  # libbpf-dev, libelf-dev, zlib1g-dev, pkg-config, linux-headers-generic and
  # linux-tools-{common,generic} - was several hundred megabytes of download
  # and unpack on every provision for code that is never run. Grepping the VM
  # suite for what it execs turns up bpftool, setpriv, sudo, ip and /bin/sh;
  # only bpftool is not already in the cloud image. Go arrives separately, as a
  # host-cached tarball (see below).
  #
  # Set PAHLEVAN_VM_EXTRA_PACKAGES="clang llvm libbpf-dev ..." to get the
  # compile toolchain back for a guest where you want to run `make ebpf`.
  GUEST_PACKAGES=(bpftool curl git)
  if [[ -n "${PAHLEVAN_VM_EXTRA_PACKAGES:-}" ]]; then
    read -r -a _extra_packages <<<"${PAHLEVAN_VM_EXTRA_PACKAGES}"
    GUEST_PACKAGES+=("${_extra_packages[@]}")
  fi
  PACKAGE_LINES="$(printf '  - %s\n' "${GUEST_PACKAGES[@]}")"

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
${PACKAGE_LINES}
write_files:
  # Force the bpf LSM active in the guest kernel cmdline.
  - path: /etc/default/grub.d/99-pahlevan-bpf-lsm.cfg
    content: |
      GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} lsm=${GUEST_LSM_LIST}"
    permissions: '0644'

runcmd:
  # PATH for the Go that up.sh unpacks from the host-cached tarball. Writing
  # the profile fragment needs no network, so it stays in cloud-init.
  - [ bash, -c, "printf 'export PATH=\$PATH:/usr/local/go/bin:/root/go/bin:/home/${SSH_USER}/go/bin\\n' > /etc/profile.d/go.sh" ]
  # Apply the bpf-LSM grub cmdline. It only takes effect on the next boot,
  # which power_state below starts the moment this returns.
  - [ bash, -c, "update-grub" ]
  # Signal provisioning complete.
  - [ bash, -c, "touch ${PROVISION_MARKER}" ]

# lsm= only takes effect on the next boot; rebooting from cloud-init itself
# saves up.sh an SSH round trip and a fixed sleep (see section 6 of up.sh).
power_state:
  mode: reboot
  condition: true
  message: "rebooting to activate lsm=${GUEST_LSM_LIST}"

final_message: "pahlevan eBPF VM cloud-init finished after \$UPTIME seconds"
EOF

  cloud-localds "${SEED_ISO}" "${USER_DATA}" "${META_DATA}"

  # ----------------------------------------------------------------------
  # 5. Boot the VM headless under KVM.
  # ----------------------------------------------------------------------
  if ! vm_kvm_ready; then
    err "/dev/kvm is not usable by this user, and these tests need a real"
    err "kernel rather than an emulated one: the whole point is that the BPF"
    err "verifier accepts the programs."
    err "  ls -l /dev/kvm => $(ls -l /dev/kvm 2>&1 || true)"
    err "On a CI runner, grant access with a udev rule:"
    err "  echo 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=kvm\"' | sudo tee /etc/udev/rules.d/99-kvm.rules"
    err "  sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm"
    exit 1
  fi
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
    -drive "if=virtio,format=qcow2,cache=${DISK_CACHE},file=${DISK_IMG}" \
    -drive "if=virtio,format=raw,file=${SEED_ISO}" \
    -netdev "user,id=net0,hostfwd=tcp:${SSH_HOST}:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -pidfile "${VM_PIDFILE}" \
    -daemonize

  log "QEMU started (pid $(cat "${VM_PIDFILE}")). Serial log: ${VM_LOGFILE}"

  # Fetch the Go tarball on the host, in the background, while the guest boots
  # and runs apt. Two reasons it is not a curl inside cloud-init any more: a
  # file in CACHE_DIR is something actions/cache can keep between CI runs and a
  # guest download never can, and doing it here overlaps the ~80MB with the
  # boot instead of adding it to the end of provisioning.
  GO_FETCH_PID=""
  if [[ ! -f "${GO_TARBALL}" ]]; then
    log "Fetching ${GO_TARBALL_NAME} on the host (background)..."
    ( curl -fsSL -o "${GO_TARBALL}.part" "${GO_TARBALL_URL}" && mv "${GO_TARBALL}.part" "${GO_TARBALL}" ) &
    GO_FETCH_PID=$!
  else
    log "Go tarball already cached: ${GO_TARBALL}"
  fi
fi

# --------------------------------------------------------------------------
# 6. Wait for the guest to be ready.
#
# Ready means two things at once: cloud-init finished, and the kernel it
# finished on has the bpf LSM. That used to be three waits - SSH every 5s,
# then the provisioning marker every 10s, then a manual `sudo reboot`, a flat
# 8s sleep and SSH again every 5s - which spent up to 23 seconds asleep past a
# guest that was already up, on top of the reboot itself. cloud-init now
# reboots itself (power_state above), so there is one condition, one SSH round
# trip per poll, and a 2s interval: the thing being waited on is a boot, and
# rounding a boot up to the next 10s multiple cost more than polling does.
# --------------------------------------------------------------------------
log "Waiting for the guest to provision and come up with lsm=${GUEST_LSM_LIST}..."
ready=0
deadline=$(( $(date +%s) + VM_READY_TIMEOUT ))
while [[ $(date +%s) -lt ${deadline} ]]; do
  if ! vm_is_running; then
    err "QEMU process died. Serial log tail:"
    tail -n 40 "${VM_LOGFILE}" >&2 || true
    exit 1
  fi
  # An unprovisioned guest, a guest mid-reboot and a guest still on its first
  # boot's kernel are all the same "not yet" from out here, so they are one
  # test rather than three states to sequence.
  if vm_ssh "test -f ${PROVISION_MARKER} && grep -q bpf /sys/kernel/security/lsm" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 2
done
if [[ ${ready} -ne 1 ]]; then
  err "Timed out after ${VM_READY_TIMEOUT}s waiting for a provisioned guest with the bpf LSM."
  err "cloud-init status, kernel cmdline and active LSMs, if the guest answers:"
  vm_ssh "sudo cloud-init status --long; cat /proc/cmdline; cat /sys/kernel/security/lsm" >&2 || true
  tail -n 40 "${VM_LOGFILE}" >&2 || true
  exit 1
fi
log "Provisioned, and the bpf LSM is active."

# --------------------------------------------------------------------------
# 7. Go toolchain, unpacked from the host tarball.
#
# The apt Go in noble is too old for this repo. cloud-init used to curl the
# upstream tarball inside the guest, which put the download on the critical
# path and made it impossible to cache in CI.
# --------------------------------------------------------------------------
if vm_ssh "/usr/local/go/bin/go version 2>/dev/null | grep -q 'go${GO_VERSION} '" 2>/dev/null; then
  log "Go ${GO_VERSION} already installed in the guest."
else
  if [[ -n "${GO_FETCH_PID:-}" ]]; then
    log "Waiting for the host Go download to finish..."
    wait "${GO_FETCH_PID}" || true
  fi
  if [[ ! -f "${GO_TARBALL}" ]]; then
    log "Fetching ${GO_TARBALL_NAME} on the host..."
    curl -fsSL -o "${GO_TARBALL}.part" "${GO_TARBALL_URL}"
    mv "${GO_TARBALL}.part" "${GO_TARBALL}"
  fi
  log "Installing Go ${GO_VERSION} in the guest..."
  vm_scp "${GO_TARBALL}" "${SSH_USER}@${SSH_HOST}:/tmp/go.tgz"
  vm_ssh "sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz && \
          sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go && \
          sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt"
  log "Guest Go: $(vm_ssh 'go version' 2>/dev/null || echo '?')"
fi

# --------------------------------------------------------------------------
# 8. Summary.
# --------------------------------------------------------------------------
log "VM is ready."
log "  kernel : $(vm_ssh 'uname -r' 2>/dev/null || echo '?')"
log "  lsm    : $(vm_ssh 'cat /sys/kernel/security/lsm' 2>/dev/null || echo '?')"
log "  ssh    : ssh -i ${SSH_KEY} -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST}"
log "Use: hack/vm/run.sh '<cmd>' | hack/vm/cp.sh <local> <remote> | hack/vm/down.sh"
