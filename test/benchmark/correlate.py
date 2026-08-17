#!/usr/bin/env python3
"""correlate.py - turn one tool's raw signal stream into a per-scenario matrix.

Input is (a) the SCENARIO lines the in-pod runner wrote, each carrying the
wall-clock window [t0, t1] in which that scenario ran, and (b) the tool's own
raw signal stream for the whole run. Every signal is bucketed into the scenario
whose window contains it (plus a settle margin, because userspace alerting is
asynchronous). Signals outside every window, or attributed to something other
than the target pod, are reported separately rather than silently counted.

Nothing here decides "blocked" for the tool: blocked comes from the scenario's
own marker (the in-pod action failed) and, for `attempted` scenarios where the
exit code is ambiguous, from whether the tool's own stream shows a denial.

usage:
  correlate.py --tool pahlevan --scenarios out.txt --signals events.jsonl \
               --pod target-xxxxx --cgroups 1234,5678 --out matrix.json
"""

import argparse
import json
import re
import sys
from datetime import datetime

SETTLE_SECONDS = 3.0


_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?"
    r"(Z|z|[+-]\d{2}:?\d{2})?$"
)


def parse_rfc3339(s):
    """Parse RFC3339 (with or without fractional seconds) into epoch seconds."""
    if not s:
        return None
    m = _RFC3339.match(s.strip())
    if not m:
        return None
    date, clock, frac, zone = m.groups()
    frac = ((frac or "") + "000000")[:6]
    if zone in (None, "", "Z", "z"):
        zone = "+00:00"
    elif ":" not in zone:
        zone = zone[:3] + ":" + zone[3:]
    try:
        return datetime.fromisoformat(
            "%sT%s.%s%s" % (date, clock, frac, zone)
        ).timestamp()
    except ValueError:
        return None


# ---------------------------------------------------------------- scenarios


def load_scenarios(path):
    rows = []
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw.startswith("SCENARIO "):
                if raw.startswith("RUNNER "):
                    rows.append({"runner": raw})
                continue
            kv = {}
            for tok in raw.split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    kv.setdefault(k, v)
            rows.append(
                {
                    "name": kv.get("name", "?"),
                    "kind": kv.get("kind", "?"),
                    "t0": float(kv.get("t0", "0")),
                    "t1": float(kv.get("t1", "0")),
                    "outcome": kv.get("outcome", "?"),
                    "rc": kv.get("rc", "?"),
                    "tag": kv.get("tag", "?"),
                }
            )
    return rows


# ------------------------------------------------------------------ signals


def signals_pahlevan(path, pod, cgroups):
    """Pahlevan's JSON-lines event export (pkg/export envelope)."""
    out = []
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw.startswith("{"):
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ts = parse_rfc3339(ev.get("timestamp"))
            if ts is None:
                continue
            k8s = ev.get("kubernetes") or {}
            attributed = False
            if pod and k8s.get("pod") == pod:
                attributed = True
            elif cgroups and ev.get("cgroupId") in cgroups:
                attributed = True
            etype = ev.get("type", "?")
            action = ev.get("action", "?")
            detail = ""
            if etype == "file" and ev.get("file"):
                detail = ev["file"].get("path", "")
            elif etype == "network" and ev.get("network"):
                n = ev["network"]
                detail = "%s:%s" % (
                    n.get("destinationIp", "?"),
                    n.get("destinationPort", "?"),
                )
            elif etype == "process" and ev.get("exec"):
                detail = ev["exec"].get("binary", "")
            elif etype == "capability" and ev.get("capability"):
                c = ev["capability"]
                detail = c.get("name") or str(c.get("capability", ""))
            elif etype == "syscall" and ev.get("syscall"):
                detail = ev["syscall"].get("name") or str(ev["syscall"].get("number", ""))
            out.append(
                {
                    "ts": ts,
                    "mech": etype,
                    "denied": action == "deny",
                    "label": "%s/%s%s" % (etype, action, (":" + detail) if detail else ""),
                    "attributed": attributed,
                    "raw": raw,
                }
            )
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True, choices=sorted(PARSERS))
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--signals", required=True)
    ap.add_argument("--pod", default="")
    ap.add_argument("--cgroups", default="")
    ap.add_argument("--settle", type=float, default=SETTLE_SECONDS)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cgroups = set()
    for tok in args.cgroups.split(","):
        tok = tok.strip()
        if tok.isdigit():
            cgroups.add(int(tok))

    scenarios = [r for r in load_scenarios(args.scenarios) if "name" in r]
    runner_lines = [r["runner"] for r in load_scenarios(args.scenarios) if "runner" in r]
    try:
        signals = PARSERS[args.tool](args.signals, args.pod, cgroups)
    except FileNotFoundError:
        print("SIGNALS FILE MISSING: %s" % args.signals, file=sys.stderr)
        signals = []
    signals.sort(key=lambda s: s["ts"])

    used = set()
    report = []
    for sc in scenarios:
        lo, hi = sc["t0"], sc["t1"] + args.settle
        hits = []
        for idx, sig in enumerate(signals):
            if lo <= sig["ts"] <= hi and sig["attributed"]:
                hits.append(sig)
                used.add(idx)
        labels = []
        for h in hits:
            if h["label"] not in labels:
                labels.append(h["label"])
        denials = [h for h in hits if h["denied"]]
        mechs = []
        for h in denials:
            if h["mech"] not in mechs:
                mechs.append(h["mech"])
        report.append(
            {
                "name": sc["name"],
                "kind": sc["kind"],
                "outcome": sc["outcome"],
                "rc": sc["rc"],
                "t0": sc["t0"],
                "t1": sc["t1"],
                "detected": bool(hits),
                "signal_count": len(hits),
                "signals": labels[:8],
                "denied_in_kernel": bool(denials),
                "deny_mechanisms": mechs,
            }
        )

    unmatched = [s for i, s in enumerate(signals) if i not in used]
    unattributed = [s for s in signals if not s["attributed"]]

    summary = {
        "tool": args.tool,
        "pod": args.pod,
        "cgroups": sorted(cgroups),
        "scenarios": report,
        "runner": runner_lines,
        "signal_total": len(signals),
        "signal_attributed": sum(1 for s in signals if s["attributed"]),
        "signal_unattributed_to_target": len(unattributed),
        "signal_outside_any_window": len(unmatched),
    }

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(summary, fh, indent=1)

    print("== %s ==" % args.tool)
    print(
        "signals: total=%d attributed-to-target=%d other-workloads=%d outside-windows=%d"
        % (
            summary["signal_total"],
            summary["signal_attributed"],
            summary["signal_unattributed_to_target"],
            summary["signal_outside_any_window"],
        )
    )
    hdr = "%-28s %-7s %-12s %-4s %-4s %-6s %s"
    print(hdr % ("scenario", "kind", "outcome", "rc", "det", "denyK", "signals"))
    for r in report:
        print(
            hdr
            % (
                r["name"][:28],
                r["kind"],
                r["outcome"],
                r["rc"],
                "yes" if r["detected"] else "no",
                ",".join(r["deny_mechanisms"]) if r["deny_mechanisms"] else "-",
                "; ".join(r["signals"])[:150],
            )
        )


if __name__ == "__main__":
    main()
