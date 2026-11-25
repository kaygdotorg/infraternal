#!/usr/bin/env python3
"""Paired macro-bench deltas for #260 / J1227: baseline B against S (symmetric flow hash),
R (host-route table) and Q (both).

Usage: python3 -I macro_pairs_j1227.py windows.csv  (the CSV `kit-macro-j1227/table.py` writes)

Rows are `<engine>.<n>` (B.1, S.1, ...). In one hold the same cell (direction, congestion control,
flows) is measured for every row, in a palindromic order such as B S R Q Q R S B, so each engine
has two rows (its own A/A pair) and a slow drift cancels. For each hold and cell the variant mean is
compared with the baseline mean (per cent) for Gbit/s and for whole-machine CPU seconds per Gbit
(A and B together). The table prints the median delta over holds and the largest A/A gap of the
variant AND of the baseline in that cell: a delta no larger than the gap is not distinguishable
from noise.
"""
import csv
import statistics
import sys
from collections import defaultdict


def main(path):
    cells = defaultdict(lambda: defaultdict(list))
    for r in csv.DictReader(open(path)):
        if r.get("ok") != "1" or not r.get("cpu_s_per_gbit"):
            continue
        cells[(r["dir"], r["cc"], r["flows"])][(r["hold"], r["row"].split(".")[0])].append(
            (float(r["gbit"]), float(r["cpu_s_per_gbit"]))
        )
    mean = lambda xs, k: statistics.mean(x[k] for x in xs)
    gap = lambda xs, k: 100 * abs(xs[0][k] - xs[1][k]) / mean(xs, k) if len(xs) > 1 else None
    print("| cell | variant | holds | Gbit/s B | Gbit/s variant | Δ Gbit/s | CPU s/Gbit B | CPU s/Gbit variant | Δ CPU/Gbit | A/A gap B (Gbit/s, CPU) | A/A gap variant (Gbit/s, CPU) |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|")
    for cell in sorted(cells):
        per = cells[cell]
        holds = sorted({h for h, _ in per})
        for v in ("S", "R", "Q"):
            dg, dc, gb, gv, cb, cv, gapb, gapv = [], [], [], [], [], [], [[], []], [[], []]
            for h in holds:
                b, p = per.get((h, "B")), per.get((h, v))
                if not b or not p:
                    continue
                gb.append(mean(b, 0)); gv.append(mean(p, 0)); cb.append(mean(b, 1)); cv.append(mean(p, 1))
                dg.append(100 * (gv[-1] - gb[-1]) / gb[-1]); dc.append(100 * (cv[-1] - cb[-1]) / cb[-1])
                for xs, acc in ((b, gapb), (p, gapv)):
                    for k in (0, 1):
                        g = gap(xs, k)
                        if g is not None:
                            acc[k].append(g)
            if not dg:
                continue
            med = statistics.median
            mx = lambda a: max(a, default=0)
            print(f"| {cell[0]} {cell[1]}{cell[2]} | {v} | {len(dg)} | {med(gb):.3f} | {med(gv):.3f} | {med(dg):+.1f}% | {med(cb):.3f} | {med(cv):.3f} | {med(dc):+.1f}% | {mx(gapb[0]):.1f}%, {mx(gapb[1]):.1f}% | {mx(gapv[0]):.1f}%, {mx(gapv[1]):.1f}% |")


if __name__ == "__main__":
    main(sys.argv[1])
