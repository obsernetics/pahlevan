#!/usr/bin/env python3
"""Generate the per-arch syscall name tables used to render seccomp profiles.

amd64 numbering comes from <asm/unistd_64.h>; arm64 uses the generic ABI in
<asm-generic/unistd.h>. Run via `make syscall-tables`.
"""
import re
import sys

ARCHES = {
    "amd64": ("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "x86_64"),
    "arm64": ("/usr/include/asm-generic/unistd.h", "arm64"),
}


def generate(arch, header, human):
    try:
        lines = open(header).read().splitlines()
    except OSError as e:
        print(f"skip {arch}: {e}", file=sys.stderr)
        return False
    seen = {}
    for line in lines:
        m = re.match(r"#define __NR_(\w+)\s+(\d+)$", line.strip())
        if m:
            seen.setdefault(int(m.group(2)), m.group(1))
    if not seen:
        print(f"skip {arch}: no syscalls parsed from {header}", file=sys.stderr)
        return False
    path = f"pkg/seccomp/syscalls_linux_{arch}.go"
    with open(path, "w") as f:
        f.write(f"//go:build linux && {arch}\n\npackage seccomp\n\n")
        f.write(f"// SyscallName maps a Linux {human} syscall number to its name, generated\n")
        f.write(f"// from <{header}>. Used to render seccomp profiles (which use names) from\n")
        f.write("// the numeric syscall set learned by the eBPF data plane.\n")
        f.write("// Regenerate with `make syscall-tables`.\n")
        f.write("var SyscallName = map[uint64]string{\n")
        for nr, name in sorted(seen.items()):
            f.write(f'\t{nr}: "{name}",\n')
        f.write("}\n")
    print(f"{arch}: {len(seen)} syscalls -> {path}")
    return True


if __name__ == "__main__":
    ok = [generate(a, h, human) for a, (h, human) in ARCHES.items()]
    sys.exit(0 if any(ok) else 1)
