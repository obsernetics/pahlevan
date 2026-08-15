#!/usr/bin/env python3
"""modes.py - report Pahlevan's per-cgroup enforcement mode from the BPF maps.

Runs inside the benchmark VM. Reads the four per-cgroup mode maps with
`bpftool -j map dump` and prints one line per entry:

    MODE <map> <cgroup-id> <0|1>

then a single summary line:

    ENFORCING <space separated map names>   (empty if nothing is enforcing)

bpftool renders keys and values either as decoded scalars (when BTF is present)
or as lists of hex byte strings, so both forms are handled.
"""

import json
import subprocess
import sys

MAPS = ["file_mode", "exec_mode", "network_mode", "cap_mode"]


def scalar(v):
    """Decode a bpftool key/value into an int, whichever form it took."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    if isinstance(v, list):
        total = 0
        for i, byte in enumerate(v):
            total |= int(byte, 0) << (8 * i)
        return total
    return None


def dump(name):
    try:
        out = subprocess.run(
            ["bpftool", "-j", "map", "dump", "name", name],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return []
    if out.returncode != 0 or not out.stdout.strip():
        return []
    try:
        entries = json.loads(out.stdout)
    except json.JSONDecodeError:
        return []
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        k = scalar(e.get("key"))
        v = scalar(e.get("value"))
        if k is None or v is None:
            continue
        rows.append((k, v))
    return rows


def main():
    want = set()
    for arg in sys.argv[1:]:
        for tok in arg.split(","):
            if tok.strip().isdigit():
                want.add(int(tok.strip()))
    enforcing = []
    for name in MAPS:
        on = False
        for k, v in dump(name):
            print("MODE %s %d %d" % (name, k, v))
            if v == 1 and (not want or k in want):
                on = True
        if on:
            enforcing.append(name)
    print("ENFORCING %s" % " ".join(enforcing))


if __name__ == "__main__":
    main()
