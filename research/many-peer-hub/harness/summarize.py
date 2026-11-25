#!/usr/bin/env python3
"""Turn the per-run `rows-<peers>-<run>.csv` files into one pivot: step/metric by peer count.

usage: summarize.py DIR [DIR...] > pivot.md

Numeric values are the median over runs, with [min-max] when the runs differ; text values come
from the first run. Rows keep the order in which the driver wrote them.
"""
import csv, glob, statistics, sys

cells = {}  # (step, metric) -> {peers: [values]}
order = []
units = {}
runs = set()
for d in sys.argv[1:]:
    for path in sorted(glob.glob(f"{d}/rows-*.csv")):
        with open(path) as f:
            for r in csv.DictReader(f):
                key = (r["step"], r["metric"])
                if key not in cells:
                    cells[key] = {}
                    order.append(key)
                    units[key] = r["unit"]
                cells[key].setdefault(int(r["peers"]), []).append(r["value"])
                runs.add((path, r["run"]))
peers = sorted({p for c in cells.values() for p in c})


def fmt(values):
    nums = []
    for v in values:
        try:
            nums.append(float(v))
        except ValueError:
            return values[0]
    if not nums:
        return ""
    def num(x):
        return f"{x:.0f}" if abs(x) >= 100 else f"{x:.3g}"

    m = statistics.median(nums)
    if len(nums) > 1 and min(nums) != max(nums):
        return f"{num(m)} [{num(min(nums))}-{num(max(nums))}]"
    return num(m)


print(f"| step | metric | unit | " + " | ".join(f"N={p}" for p in peers) + " |")
print("|---|---|---|" + "---|" * len(peers))
for key in order:
    print(f"| {key[0]} | {key[1]} | {units[key]} | " + " | ".join(fmt(cells[key].get(p, [])) if p in cells[key] else "" for p in peers) + " |")
