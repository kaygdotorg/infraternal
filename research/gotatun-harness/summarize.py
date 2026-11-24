#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Turn the output directory of run.sh into a markdown table.

Usage: summarize.py OUTDIR

Per cell (congestion control x flow count) and per arm it prints the median over
holds of throughput, loaded ping latency, CPU per Gbit, memory and idle wakeups,
and the paired difference to the first arm (each hold compared with itself, then
the median of those). A difference that is no larger than the A/A noise floor
of the same cell is marked "=": the harness cannot tell it from no difference.
Standard library only.
"""

import csv
import json
import re
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

METRICS = ("gbit", "p50", "p99", "lost", "cpu", "rss", "wake")


def percentile(xs, p):
    """Linear-interpolated percentile of a non-empty list, p in 0..100."""
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def read_run(raw, row):
    """Metrics of one run, or None when its iperf3 output is unusable."""
    try:
        end = json.loads((raw / f"{row['id']}.iperf.json").read_text())["end"][
            "sum_received"
        ]
    except (OSError, ValueError, KeyError):
        print(f"skipping {row['id']}: no iperf3 result", file=sys.stderr)
        return None
    gbit, bits = end["bits_per_second"] / 1e9, end["bytes"] * 8 / 1e9
    ping = (raw / f"{row['id']}.ping").read_text()
    rtts = [float(x) for x in re.findall(r"time=([\d.]+) ms", ping)]
    sent = re.search(r"(\d+) packets transmitted", ping)
    sent = int(sent.group(1)) if sent else len(rtts)
    m = {
        "gbit": gbit,
        "p50": percentile(rtts, 50) if rtts else None,
        "p99": percentile(rtts, 99) if rtts else None,
        "lost": 100 * (sent - len(rtts)) / sent if sent else None,
        "cpu": None,
        "rss": None,
        "wake": None,
    }
    if row["cpu_ms_a"] != "NA":  # the kernel arm has no per-process numbers
        m["cpu"] = (int(row["cpu_ms_a"]) + int(row["cpu_ms_b"])) / 1000 / bits
        m["rss"] = int(row["hwm_kb"]) / 1024
        m["wake"] = int(row["wakeups_per_s"])
    return m


def mean(vals):
    vals = [v for v in vals if v is not None]
    return st.mean(vals) if vals else None


def main(out):
    out = Path(out)
    # runs[(phase, cc, flows, arm, hold)] -> list of metric dicts
    runs, arms = defaultdict(list), []
    with open(out / "runs.csv", newline="") as f:
        for row in csv.DictReader(f):
            m = read_run(out / "raw", row)
            if m is None:
                continue
            if row["arm"] not in arms:
                arms.append(row["arm"])
            runs[
                (
                    row["phase"],
                    row["cc"],
                    int(row["flows"]),
                    row["arm"],
                    int(row["hold"]),
                )
            ].append(m)
    cells = sorted({(k[1], k[2]) for k in runs})

    def per_hold(phase, cell, arm, metric):
        """hold -> mean of that metric over the runs of the hold."""
        return {
            k[4]: mean([r[metric] for r in v])
            for k, v in runs.items()
            if k[:4] == (phase, *cell, arm) and mean([r[metric] for r in v]) is not None
        }

    floor = {}  # (cell, metric) -> largest relative gap between the two A runs of a hold
    for cell in cells:
        for metric in METRICS:
            gaps = []
            for k, v in runs.items():
                if (
                    k[:3] == ("aa", *cell)
                    and len(v) == 2
                    and None not in (v[0][metric], v[1][metric])
                ):
                    avg = (v[0][metric] + v[1][metric]) / 2
                    gaps.append(
                        100 * abs(v[0][metric] - v[1][metric]) / avg if avg else 0.0
                    )
            floor[(cell, metric)] = max(gaps) if gaps else None

    print((out / "machine.txt").read_text().rstrip().replace("\n", "  \n"))
    print("\n### A/A noise floor (largest gap between the two runs of one hold, %)\n")
    print("| cell | Gbit/s | p99 | CPU s/Gbit |\n|---|---|---|---|")
    for cell in cells:
        g = [floor[(cell, m)] for m in ("gbit", "p99", "cpu")]
        print(
            f"| {cell[0]} {cell[1]} flows | "
            + " | ".join("n/a" if x is None else f"{x:.1f}" for x in g)
            + " |"
        )

    print(
        "\n### Results (median over holds; delta = paired, against the first arm; `=` = within noise)\n"
    )
    print(
        "| cell | arm | Gbit/s (min-max) | Δ | p50 ms | p99 ms | Δ | CPU s/Gbit | Δ | RSS MiB | wakeups/s | lost % |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    base = arms[0]

    def med(vals, m, fmt="{:.2f}"):
        return fmt.format(st.median(vals[m].values())) if vals[m] else "n/a"

    def delta(vals, cell, arm, m):
        """Paired median difference of `arm` to the first arm, with the noise verdict."""
        if arm == base or not vals[m]:
            return ""
        ref = per_hold("abba", cell, base, m)
        d = [100 * (vals[m][h] - ref[h]) / ref[h] for h in vals[m] if ref.get(h)]
        if not d:
            return "n/a"
        fl = floor[(cell, m)]
        tag = " =" if fl is None or abs(st.median(d)) <= fl else ""
        return f"{st.median(d):+.1f}%{tag}" + ("" if fl is not None else "?")

    for cell in cells:
        for arm in arms:
            vals = {m: per_hold("abba", cell, arm, m) for m in METRICS}
            if not vals["gbit"]:
                continue

            g = vals["gbit"].values()
            print(
                f"| {cell[0]} {cell[1]} fl | {arm} | {st.median(g):.2f} ({min(g):.2f}-{max(g):.2f}) | {delta(vals, cell, arm, 'gbit')} "
                f"| {med(vals, 'p50')} | {med(vals, 'p99')} | {delta(vals, cell, arm, 'p99')} | {med(vals, 'cpu', '{:.3f}')} | {delta(vals, cell, arm, 'cpu')} "
                f"| {med(vals, 'rss', '{:.0f}')} | {med(vals, 'wake', '{:.0f}')} | {med(vals, 'lost', '{:.2f}')} |"
            )
    print(
        f"\nholds per cell: {len({k[4] for k in runs if k[0] == 'abba'})} paired (A B B A); "
        f"A/A holds: {len({k[4] for k in runs if k[0] == 'aa'})}. `?` = no A/A data, so no noise verdict."
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
