#!/usr/bin/env bash
#
# smoke/run.sh - End-to-end eBPF smoke test, executed INSIDE the VM.
#
# From the host, invoke it via the harness (which copies this dir into the VM):
#
#   hack/vm/up.sh
#   hack/vm/cp.sh -r hack/vm/smoke smoke
#   hack/vm/run.sh 'cd smoke && ./run.sh'
#
# Steps (all inside the guest, using the guest's own kernel + BTF):
#   1. Generate a CO-RE vmlinux.h from the guest's /sys/kernel/btf/vmlinux.
#   2. Compile smoke.bpf.c with clang -target bpf.
#   3. Build and run the Go loader, which loads the object, attaches a
#      tracepoint AND a BPF-LSM hook, and verifies both fire.
#
# The LSM attach only succeeds when the running kernel has the bpf LSM enabled,
# so a PASS proves the VM can load+attach+enforce eBPF including LSM.

set -euo pipefail

cd "$(dirname "$0")"

echo "== guest kernel =="
uname -r
echo "== lsm =="
cat /sys/kernel/security/lsm
echo

echo "== [1/3] generate vmlinux.h from guest BTF =="
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "ERROR: /sys/kernel/btf/vmlinux missing in guest" >&2
  exit 1
fi
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
echo "vmlinux.h: $(wc -l < bpf/vmlinux.h) lines"

echo "== [2/3] compile CO-RE BPF object =="
clang -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86 \
  -I bpf -c bpf/smoke.bpf.c -o smoke.bpf.o
ls -l smoke.bpf.o
echo "sections:"
llvm-objdump -h smoke.bpf.o 2>/dev/null | grep -E 'lsm|tracepoint|\.maps' || true

echo "== [3/3] build + run Go loader (requires root to attach) =="
export PATH="$PATH:/usr/local/go/bin"
export GOFLAGS=-mod=mod
go mod tidy
go build -o smoke-loader .

# Attaching programs needs privilege; run the loader as root.
sudo ./smoke-loader
