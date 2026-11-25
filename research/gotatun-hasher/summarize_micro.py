#!/usr/bin/env python3
"""Turn criterion's text output (one or more runs) into a ns/op table (#260, J1204).

Usage: python3 -I summarize_micro.py crit-rep1.txt [crit-rep2.txt ...]

Every benchmark walks 1,024 lookups per iteration (64 for incoming_runs), so ns/op is the
median iteration time divided by that. With two or more files the ns/op column is the median of the
runs and the last column is the spread between runs (max - min, as a percentage of the median):
the A/A floor of the measurement, from the same binary or from rebuilds of the same code.
"""
import re
import statistics
import sys

UNIT = {"ns": 1.0, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}


def parse(path):
    """Return {benchmark id: median iteration time in ns} from one criterion text log."""
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    pattern = re.compile(
        r"^(?P<name>[A-Za-z_][^\n]*?)[ \t]*(?:\n[ \t]*)?time:[ \t]+\[[\d.]+ \S+ (?P<mid>[\d.]+) (?P<unit>\S+) [\d.]+ \S+\]",
        re.M,
    )
    for m in pattern.finditer(text):
        name = m.group("name").strip()
        if name.startswith(("Benchmarking", "change")) or "/" not in name:
            continue
        out[name] = float(m.group("mid")) * UNIT[m.group("unit")]
    return out


def per_op(name):
    return 64 if name.startswith("incoming_runs") else 1024


def main(paths):
    runs = [parse(p) for p in paths]
    names = list(dict.fromkeys(n for r in runs for n in r))
    group = None
    for n in names:
        g = "/".join(n.split("/", 2)[:2])
        if g != group:
            group = g
            print(f"\n### {g}\n\n| candidate | ns/op | rel. to first row |" + (" run spread |" if len(runs) > 1 else ""))
            print("|---|---:|---:|" + ("---:|" if len(runs) > 1 else ""))
            base = None
        vals = [r[n] / per_op(n) for r in runs if n in r]
        v = statistics.median(vals)
        base = base or v
        gap = f" {100 * (max(vals) - min(vals)) / v:.1f}% |" if len(vals) > 1 else ""
        print(f"| {n.split('/', 2)[2]} | {v:.2f} | {v / base:.2f}x |{gap}")


if __name__ == "__main__":
    main(sys.argv[1:])
