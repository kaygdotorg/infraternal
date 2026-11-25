#!/usr/bin/env python3
"""Paired macro-bench deltas for #260 / J1204: baseline rows I against patched rows H.

Usage: python3 -I macro_pairs.py windows.csv  (the CSV `table.py` of the cross-VM kit writes)

Rows are named `<engine>.<n>` (I.1, H.1, ...). Within one hold the same cell (direction, congestion
control, flows) is measured for every row, in an order like I H H I. For each hold and cell:
the patched mean against the baseline mean, in per cent, for Gbit/s and for whole-machine CPU
seconds per Gbit (A and B together), and the A/A gap of each engine (its two rows against each
other). The table prints the median delta over holds and the largest A/A gap seen in that cell:
a delta no larger than the gap is not distinguishable from noise.
"""
import csv
import statistics
import sys
from collections import defaultdict


def main(path):
    cells = defaultdict(lambda: defaultdict(list))  # (dir, cc, flows) -> hold,engine -> [(gbit, cpu)]
    for r in csv.DictReader(open(path)):
        if r.get("ok") != "1" or not r.get("cpu_s_per_gbit"):
            continue
        cells[(r["dir"], r["cc"], r["flows"])][(r["hold"], r["row"].split(".")[0])].append(
            (float(r["gbit"]), float(r["cpu_s_per_gbit"]))
        )
    print("| cell | holds | Gbit/s I | Gbit/s H | Δ Gbit/s | CPU s/Gbit I | CPU s/Gbit H | Δ CPU/Gbit | A/A gap Gbit/s | A/A gap CPU |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cell in sorted(cells):
        per = cells[cell]
        holds = sorted({h for h, _ in per})
        dg, dc, gi, gh, ci, ch, gapg, gapc = [], [], [], [], [], [], [], []
        for h in holds:
            i, p = per.get((h, "I")), per.get((h, "H"))
            if not i or not p:
                continue
            mean = lambda xs, k: statistics.mean(x[k] for x in xs)
            gi.append(mean(i, 0)); gh.append(mean(p, 0)); ci.append(mean(i, 1)); ch.append(mean(p, 1))
            dg.append(100 * (gh[-1] - gi[-1]) / gi[-1]); dc.append(100 * (ch[-1] - ci[-1]) / ci[-1])
            for xs in (i, p):
                if len(xs) > 1:
                    gapg.append(100 * abs(xs[0][0] - xs[1][0]) / mean(xs, 0))
                    gapc.append(100 * abs(xs[0][1] - xs[1][1]) / mean(xs, 1))
        if not dg:
            continue
        med = statistics.median
        print(f"| {cell[0]} {cell[1]}{cell[2]} | {len(dg)} | {med(gi):.3f} | {med(gh):.3f} | {med(dg):+.1f}% | {med(ci):.3f} | {med(ch):.3f} | {med(dc):+.1f}% | {max(gapg, default=0):.1f}% | {max(gapc, default=0):.1f}% |")


if __name__ == "__main__":
    main(sys.argv[1])
