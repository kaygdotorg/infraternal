#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1199 (#260, #580) paired summary of table.py's CSVs, with A/A floors.

    summarize.py <windows.csv> <rows.csv> --base G [--holds e3,e4] > summary.md

Every hold runs the base engine twice (rows "<base>.1" and "<base>.2", first and last), so each
hold measures its own A/A gap. Per cell (direction, congestion control, flows) and metric:

- floor = the largest A/A gap over the holds, |b1 - b2| / mean(b1, b2);
- a row's delta = median over holds of (row - mean(b1, b2)) / mean(b1, b2), paired within a hold;
- a delta no larger than the floor is printed as "=" (no difference this fixture can see).

The absolute columns are medians over holds (min-max in brackets). A row is identified by its
engine letter; ".n" tags of one engine in a hold are averaged first.
"""
import csv
import statistics
import sys
from collections import defaultdict

METRICS = [("gbit", "Gbit/s", 1), ("rr_p50_ms", "rr p50 ms", -1), ("rr_p99_ms", "rr p99 ms", -1),
           ("rr_p999_ms", "rr p99.9 ms", -1), ("page_p99_ms", "1200B p99 ms", -1),
           ("cpu_s_per_gbit", "CPU s/Gbit (A+B)", -1), ("cpu_a_s_per_gbit", "CPU A s/Gbit", -1),
           ("cpu_b_s_per_gbit", "CPU B s/Gbit", -1)]
NAMES = {"G": "GotaTun e87fef91 (gotatun-cli, sender off)", "J": "GotaTun e87fef91 + GOTATUN_SIDE_SOCKET=1",
         "W": "wireguard-go", "K": "kernel WireGuard", "I": "infraternal mesh (dev 7c719e8a2)",
         "T": "Tailscale 1.104.4 + headscale 0.29.7", "N": "NetBird 0.82.0 (kernel WG) + combined server"}


def fnum(v):
    try:
        x = float(v)
        return x
    except (TypeError, ValueError):
        return None


def main():
    wpath, rpath = sys.argv[1], sys.argv[2]
    base = sys.argv[sys.argv.index("--base") + 1]
    holds = None
    if "--holds" in sys.argv:
        holds = sys.argv[sys.argv.index("--holds") + 1].split(",")
    W = [r for r in csv.DictReader(open(wpath)) if r["ok"] == "1" and (not holds or r["hold"] in holds)]
    R = [r for r in csv.DictReader(open(rpath)) if not holds or r["hold"] in holds]
    # data[hold][rowtag][cell][metric]
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    for r in W:
        cell = (r["dir"], r["cc"], int(r["flows"]))
        for m, _, _ in METRICS:
            data[r["hold"]][r["row"]][cell][m] = fnum(r[m])
    cells = sorted({(r["dir"], r["cc"], int(r["flows"])) for r in W})
    engines = []
    for r in W:
        e = r["row"].split(".")[0]
        if e not in engines:
            engines.append(e)
    engines.sort(key=lambda e: (e != base, "GJWKITN".find(e)))

    def eng_val(hold, e, cell, m):
        vals = [data[hold][t][cell].get(m) for t in data[hold] if t.split(".")[0] == e]
        vals = [v for v in vals if v is not None]
        return statistics.mean(vals) if vals else None

    print(f"Holds: {', '.join(sorted(data))}. Base: {NAMES.get(base, base)} (rows {base}.1 first and {base}.2 last in every hold).\n")
    print("A/A floor = the largest gap between the two base runs of one hold; a delta inside it is `=`.\n")
    for m, label, sign in METRICS:
        print(f"### {label}\n")
        head = "| cell | floor |" + "".join(f" {e} |" for e in engines)
        print(head)
        print("|---|---|" + "---|" * len(engines))
        for cell in cells:
            gaps = []
            for h in data:
                b1 = data[h].get(f"{base}.1", {}).get(cell, {}).get(m)
                b2 = data[h].get(f"{base}.2", {}).get(cell, {}).get(m)
                if b1 is not None and b2 is not None and (b1 + b2):
                    gaps.append(abs(b1 - b2) / ((b1 + b2) / 2))
            floor = max(gaps) if gaps else None
            line = f"| {cell[0][:3]} {cell[1]} {cell[2]} | {'%.1f%%' % (floor * 100) if floor is not None else '?'} |"
            for e in engines:
                vals, rels = [], []
                for h in data:
                    v = eng_val(h, e, cell, m)
                    if v is None:
                        continue
                    vals.append(v)
                    b = eng_val(h, base, cell, m)
                    if b and e != base:
                        rels.append((v - b) / b)
                if not vals:
                    line += " – |"
                    continue
                med = statistics.median(vals)
                fmt = (lambda x: f"{x:.2f}") if m == "gbit" or "cpu" in m else (lambda x: f"{x:.2f}")
                txt = fmt(med) + (f" ({fmt(min(vals))}–{fmt(max(vals))})" if len(vals) > 1 else "")
                if rels:
                    d = statistics.median(rels)
                    eq = floor is not None and abs(d) <= floor
                    txt += f" **{d * 100:+.0f}%**" + (" =" if eq else "")
                line += f" {txt} |"
            print(line)
        print()
    # Per-row (not per-window) metrics.
    print("### Idle, memory and setup (median over holds)\n")
    print("| row | second node start → first packet, s | idle wakeups/s before load | after load | RSS MiB before load (A+B+C) | after load | processes (VM:name=RSS/wakeups per s, after load) |")
    print("|---|---|---|---|---|---|---|")
    by = defaultdict(list)
    for r in R:
        e = r["row"].split(".")[0]
        if e in ("X",) or r["row"].endswith(".cap"):
            continue
        by[e].append(r)
    for e in engines:
        rs = by.get(e, [])
        if not rs:
            continue

        def med(key):
            v = [fnum(r.get(key)) for r in rs]
            v = [x for x in v if x is not None]
            return statistics.median(v) if v else None

        def rss(phase):
            v = []
            for r in rs:
                parts = [fnum(r.get(f"{phase}_rss_mib_{x}")) for x in "abc"]
                v.append(sum(p for p in parts if p is not None))
            return statistics.median(v) if v else None

        def f(x, d=1):
            return "–" if x is None else f"{x:.{d}f}"
        procs = rs[-1].get("post_procs", "")
        print(f"| {e}: {NAMES.get(e, e)} | {f(med('setup_second_s'), 3)} | {f(med('pre_wakeups_s'))} | {f(med('post_wakeups_s'))} | {f(rss('pre'))} | {f(rss('post'))} | {procs} |")
    print()
    xs = [r for r in R if r["row"] == "X"]
    if xs:
        ctx = [f"{x}: {statistics.median([fnum(r[f'pre_machine_ctxt_s_{x}']) for r in xs]):.0f}" for x in "abc"]
        print(f"No engine at all (row X, start of each hold), machine context switches/s: {', '.join(ctx)}. "
              "Kernel WireGuard has no process, so its idle cost shows only as machine context switches above this.\n")
        print("| row | machine ctxt/s A / B / C before load | after load |")
        print("|---|---|---|")
        for e in ["X"] + engines:
            rs = xs if e == "X" else by.get(e, [])
            if not rs:
                continue
            def mc(phase):
                out = []
                for x in "abc":
                    v = [fnum(r.get(f"{phase}_machine_ctxt_s_{x}")) for r in rs]
                    v = [y for y in v if y is not None]
                    out.append(f"{statistics.median(v):.0f}" if v else "–")
                return " / ".join(out)
            print(f"| {e} | {mc('pre')} | {mc('post') if e != 'X' else '–'} |")


if __name__ == "__main__":
    main()
