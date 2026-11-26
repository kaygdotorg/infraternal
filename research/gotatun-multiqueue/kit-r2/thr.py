#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1230 (#260): hottest engine threads per window, from snap.py's per-thread ticks.

    thr.py <window-dir-on-A> <window-dir-on-B>   prints cores per thread name (summed by name
    and the top 4 single threads) on each side over the 40 s steady window.
"""
import json
import sys
from collections import defaultdict


def side(d):
    b = json.load(open(d + "/before.json"))
    a = json.load(open(d + "/after.json"))
    secs = (a["mono_ns"] - b["mono_ns"]) / 1e9
    tck = a["clk_tck"]
    by_name = defaultdict(float)
    single = []
    for pid, e in a["engines"].items():
        e0 = b["engines"].get(pid, {})
        for tid, (name, ticks) in e.get("thr", {}).items():
            t0 = e0.get("thr", {}).get(tid, [name, ticks])[1]
            cores = (ticks - t0) / tck / secs
            by_name[name] += cores
            single.append((cores, name, tid))
    single.sort(reverse=True)
    names = " ".join(f"{n}={c:.2f}" for n, c in sorted(by_name.items(), key=lambda x: -x[1]))
    top = " ".join(f"{n}:{c:.2f}" for c, n, _ in single[:4])
    return f"total={sum(by_name.values()):.2f} [{names}] top: {top}"


for label, d in (("A", sys.argv[1]), ("B", sys.argv[2])):
    try:
        print(f"  {label}: {side(d)}")
    except (OSError, KeyError, ValueError) as err:
        print(f"  {label}: n/a ({err})")
