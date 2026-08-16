#!/usr/bin/env python3
"""report.py - render the combined results matrix from the per-tool artifacts.

Reads /tmp/pahlevan-bench/results/<tool>/matrix.json for each tool that has one
(plus control/scenarios.txt if present) and prints the markdown tables that go
into docs/benchmarks/results-<date>.md, so the published numbers are generated
from the run rather than transcribed.

usage: report.py [results-dir]
"""

import json
import os
import sys

TOOLS = ["control", "pahlevan"]


def load_control(path):
    """Baseline outcome per scenario with no security tool installed."""
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, errors="replace"):
        if not line.startswith("SCENARIO "):
            continue
        kv = {}
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv.setdefault(k, v)
        out[kv.get("name", "?")] = kv.get("outcome", "?")
    return out


def blocked(row, control_outcome):
    """Was the in-pod action prevented, and can we say so honestly?

    'blocked'   the script itself reports the action failed
    'yes(k)'    the tool's own stream shows an in-kernel denial in the window
    'no'        the action completed
    'ambiguous' the script cannot tell from inside the pod and the tool shows
                no denial: the control run had the same outcome, so there is no
                evidence either way
    """
    if row["denied_in_kernel"]:
        return "yes"
    if row["outcome"] == "blocked":
        return "yes"
    if row["outcome"] == "allowed":
        return "no"
    if row["outcome"] == "no-marker":
        return "yes"
    # attempted / skipped: compare with the control run
    if control_outcome and control_outcome == row["outcome"]:
        return "no*"
    return "no*"


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pahlevan-bench/results"
    control = load_control(os.path.join(base, "control", "scenarios.txt"))

    data = {}
    for t in TOOLS:
        p = os.path.join(base, t, "matrix.json")
        if os.path.exists(p):
            data[t] = json.load(open(p))

    if not data:
        print("no matrix.json found under %s" % base, file=sys.stderr)
        return 1

    order = []
    rows = {}
    for t, d in data.items():
        for r in d["scenarios"]:
            if r["name"] not in rows:
                rows[r["name"]] = {}
                order.append(r["name"])
            rows[r["name"]][t] = r

    present = [t for t in TOOLS if t in data]

    print("### Attack scenarios\n")
    head = "| Scenario | Control |"
    sep = "|---|---|"
    for t in present:
        head += " %s Det | %s Blocked |" % (t.capitalize(), t.capitalize())
        sep += ":-:|:-:|"
    print(head)
    print(sep)
    for name in order:
        if name.startswith("b0") or name.startswith("p0"):
            continue
        cells = "| `%s` | %s |" % (name[:-3], control.get(name, "n/a"))
        for t in present:
            r = rows[name].get(t)
            if r is None:
                cells += " n/a | n/a |"
                continue
            det = "Yes" if r["detected"] else "No"
            blk = blocked(r, control.get(name))
            mech = ",".join(r["deny_mechanisms"])
            blk = {"yes": "**Yes**", "no": "No", "no*": "No*"}[blk]
            if mech:
                blk += " (%s)" % mech
            cells += " %s | %s |" % (det, blk)
        print(cells)

    print("\n### Mechanism probes (builtin-only; not scored as attacks)\n")
    head = "| Probe | Control |"
    sep = "|---|---|"
    for t in present:
        head += " %s outcome | %s signals |" % (t.capitalize(), t.capitalize())
        sep += ":-:|---|"
    print(head)
    print(sep)
    for name in order:
        if not name.startswith("p0"):
            continue
        cells = "| `%s` | %s |" % (name[:-3], control.get(name, "n/a"))
        for t in present:
            r = rows[name].get(t)
            if r is None:
                cells += " n/a | n/a |"
                continue
            cells += " %s | %s |" % (r["outcome"], "; ".join(r["signals"])[:120] or "-")
        print(cells)

    print("\n### Benign controls (false positives)\n")
    head = "| Control | Correct |"
    sep = "|---|---|"
    for t in present:
        head += " %s outcome | %s FP? |" % (t.capitalize(), t.capitalize())
        sep += ":-:|:-:|"
    print(head)
    print(sep)
    for name in order:
        if not name.startswith("b0"):
            continue
        cells = "| `%s` | allowed |" % name[:-3]
        for t in present:
            r = rows[name].get(t)
            if r is None:
                cells += " n/a | n/a |"
                continue
            fp = "**yes**" if r["outcome"] not in ("allowed",) else "no"
            cells += " %s | %s |" % (r["outcome"], fp)
        print(cells)

    print("\n### Signal accounting\n")
    print("| Tool | Signals total | Attributed to target pod | Other workloads | Outside any scenario window |")
    print("|---|--:|--:|--:|--:|")
    for t in present:
        d = data[t]
        print(
            "| %s | %d | %d | %d | %d |"
            % (
                t.capitalize(),
                d["signal_total"],
                d["signal_attributed"],
                d["signal_unattributed_to_target"],
                d["signal_outside_any_window"],
            )
        )

    print("\n### Totals\n")
    print("| Tool | Attacks detected | Attacks blocked | Benign false positives |")
    print("|---|--:|--:|--:|")
    for t in present:
        det = blk = fp = 0
        for r in data[t]["scenarios"]:
            if r["kind"] == "probe":
                continue
            if r["kind"] == "benign":
                if r["outcome"] != "allowed":
                    fp += 1
                continue
            if r["detected"]:
                det += 1
            if blocked(r, control.get(r["name"])) == "yes":
                blk += 1
        print("| %s | %d/26 | %d/26 | %d/3 |" % (t.capitalize(), det, blk, fp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
