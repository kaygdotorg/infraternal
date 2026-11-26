#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1230 (#260, #580) turn the raw hold directories into two CSV files.

    table.py <raw-dir> <hold>... --windows OUT.csv --rows OUT.csv

windows CSV, one line per loaded window: Gbit/s (iperf3 receiver), the 64 B round-trip probe's
p50/p99/p99.9 and lost count, the 1,200 B probe's p99, and CPU per Gbit over the 40 s steady
window: whole machine busy time (user+nice+system+irq+softirq; idle, iowait and steal excluded)
on A, on B and both, plus the engine/product processes' own CPU (userspace rows only).

rows CSV, one line per row and hold: connection setup time (first node start to first packet,
and second node start to first packet), idle wakeups per second of the row's processes before
and after load (voluntary + involuntary switches summed over every non-kit process in the netns
on A, B and C; whole-machine context switches per second for comparison, which is the only
number kernel WireGuard has), and the RSS of every process the row runs before and after load.
"""
import csv
import re
import json
import math
import os
import sys

BUSY = (0, 1, 2, 5, 6)  # user nice system irq softirq; idle=3 iowait=4 steal=7 excluded


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def busy_s(before, after):
    """Machine busy seconds (steal excluded) and steal seconds between two snap.py snapshots."""
    b, a = before["stat"]["cpu"], after["stat"]["cpu"]
    tck = after["clk_tck"]
    busy = sum(a[i] - b[i] for i in BUSY) / tck
    steal = (a[7] - b[7]) / tck
    return busy, steal


def engine_s(before, after):
    """CPU seconds of the watched engine processes between two snapshots (0 for kernel rows)."""
    total = 0
    for pid, e in after["engines"].items():
        e0 = before["engines"].get(pid)
        if e0:
            total += (e["utime"] + e["stime"]) - (e0["utime"] + e0["stime"])
    return total / after["clk_tck"]


def windows(raw, hold):
    out = []
    base_a = os.path.join(raw, hold, "a", hold)
    base_b = os.path.join(raw, hold, "b", hold)
    if not os.path.isdir(base_a):
        return out
    for row in sorted(os.listdir(base_a)):
        rdir = os.path.join(base_a, row)
        if not os.path.isdir(rdir) or row == "X":
            continue
        for w in sorted(os.listdir(rdir)):
            wa = os.path.join(rdir, w)
            if not os.path.isdir(wa):
                continue
            wb = os.path.join(base_b, row, w)
            ip = load(os.path.join(wa, "iperf.json"))
            key = load(os.path.join(wa, "rr-key.json")) or {}
            page = load(os.path.join(wa, "rr-page.json")) or {}
            sa0, sa1 = load(os.path.join(wa, "before.json")), load(os.path.join(wa, "after.json"))
            sb0, sb1 = load(os.path.join(wb, "before.json")), load(os.path.join(wb, "after.json"))
            if not ip or "end" not in ip or not all((sa0, sa1, sb0, sb1)):
                out.append({"hold": hold, "row": row, "window": w, "ok": 0})
                continue
            gbit = ip["end"]["sum_received"]["bits_per_second"] / 1e9
            # J1230 two-tunnel row: the second tunnel's flows add to the first's.
            ip2 = load(os.path.join(wa, "iperf2.json"))
            if ip2 and "end" in ip2:
                gbit += ip2["end"]["sum_received"]["bits_per_second"] / 1e9
            # Bytes moved in the 40 s steady window, from the tunnel device counters on A.
            dev = sa1["tun"]
            moved = None
            if dev and dev in sa1["dev"] and dev in sa0["dev"]:
                d1, d0 = sa1["dev"][dev], sa0["dev"][dev]
                moved = max(d1["rx_bytes"] - d0["rx_bytes"], d1["tx_bytes"] - d0["tx_bytes"]) * 8 / 1e9
            secs = (sa1["mono_ns"] - sa0["mono_ns"]) / 1e9
            ba, sta = busy_s(sa0, sa1)
            bb, stb = busy_s(sb0, sb1)
            ea, eb = engine_s(sa0, sa1), engine_s(sb0, sb1)
            gb = moved if moved else gbit * secs
            # J1239 window names: <r|f>-<cc><flows>[r<rate Mbit/s>][-perf].
            m = re.match(r"([rf])-([a-z]+)(\d+)(?:r(\d+))?(-perf)?$", w)
            d, cc, flows = (m.group(1), m.group(2), m.group(3)) if m else (w[0], w, "")
            rate = m.group(4) if m and m.group(4) else ""
            out.append({
                "hold": hold, "row": row, "window": w, "ok": 1, "dir": "reverse" if d == "r" else "forward",
                "cc": cc, "flows": flows, "rate_mbit": rate,
                "perf": int(w.endswith("-perf")), "gbit": round(gbit, 3),
                "retr": ip["end"].get("sum_sent", {}).get("retransmits", 0)
                + ((ip2 or {}).get("end", {}).get("sum_sent", {}).get("retransmits", 0)),
                "rr_p50_ms": key.get("p50_ms"), "rr_p99_ms": key.get("p99_ms"), "rr_p999_ms": key.get("p999_ms"),
                "rr_lost": key.get("lost"), "rr_sent": key.get("sent"), "page_p99_ms": page.get("p99_ms"),
                "steady_gbit": round(gb / secs, 3),
                "cpu_a_cores": round(ba / secs, 3), "cpu_b_cores": round(bb / secs, 3),
                "steal_a_cores": round(sta / secs, 3), "steal_b_cores": round(stb / secs, 3),
                "cpu_s_per_gbit": round((ba + bb) / gb, 4) if gb else None,
                "cpu_a_s_per_gbit": round(ba / gb, 4) if gb else None,
                "cpu_b_s_per_gbit": round(bb / gb, 4) if gb else None,
                "engine_cores": round((ea + eb) / secs, 3),
                # J1230: receiver-side reordering evidence over the steady window (both ends).
                **{f"{k}_{side}": (s1.get("tcpext", {}).get(k, 0) - s0.get("tcpext", {}).get(k, 0))
                   for side, (s0, s1) in (("a", (sa0, sa1)), ("b", (sb0, sb1)))
                   for k in ("TCPOFOQueue", "TCPSACKReorder", "TCPTSReorder")},
            })
    return out


def proc_delta(s0, s1):
    """Per-process wakeups/s and RSS for the non-kit processes present in both snapshots."""
    by0 = {p["pid"]: p for p in s0["procs"] if not p.get("gone")}
    secs = (s1["mono_ns"] - s0["mono_ns"]) / 1e9
    res = []
    for p in s1["procs"]:
        if p.get("gone") or p.get("kit") or p["pid"] not in by0:
            continue
        q = by0[p["pid"]]
        res.append({"comm": p["comm"], "wakeups_s": (p["vol"] + p["invol"] - q["vol"] - q["invol"]) / secs,
                    "rss_kb": p.get("rss_kb", 0), "rss0_kb": q.get("rss_kb", 0), "threads": p["threads"],
                    "cpu_ms_s": ((p["utime"] + p["stime"]) - (q["utime"] + q["stime"])) * 1000 / s1["clk_tck"] / secs})
    ctxt = (s1["ctxt"] - s0["ctxt"]) / secs
    return res, ctxt


def rows(raw, hold):
    out = []
    ev = os.path.join(raw, hold)
    base = {v: os.path.join(raw, hold, v, hold) for v in "abc"}
    if not os.path.isdir(base["a"]):
        return out
    for row in sorted(os.listdir(base["a"])):
        if not os.path.isdir(os.path.join(base["a"], row)):
            continue
        rec = {"hold": hold, "row": row}
        stamps = os.path.join(ev, f"{row}.stamps")
        if os.path.exists(stamps):
            lines = open(stamps).read().splitlines()
            reach = float([l for l in lines if l.startswith("reach")][0].split()[1])
            node = []
            for l in lines[:2]:  # A, B: started.node first (glob order: ctl < node), keep the node one
                vals = [float(x) for x in l.split()]
                node.append(vals)
            # started.* files sort as started.ctl, started.node; A and B have only started.node.
            a_start, b_start = node[0][-1], node[1][-1]
            rec["setup_first_s"] = round(reach - min(a_start, b_start), 3)
            rec["setup_second_s"] = round(reach - max(a_start, b_start), 3)
        for phase, (i0, i1) in (("pre", ("idle0", "idle1")), ("post", ("idle2", "idle3"))):
            tot_w = 0
            mem = []
            for v in "abc":
                s0 = load(os.path.join(base[v], row, f"{i0}.json"))
                s1 = load(os.path.join(base[v], row, f"{i1}.json"))
                if not (s0 and s1):
                    continue
                procs, ctxt = proc_delta(s0, s1)
                rec[f"{phase}_machine_ctxt_s_{v}"] = round(ctxt, 1)
                for p in procs:
                    tot_w += p["wakeups_s"]
                    mem.append(f"{v}:{p['comm']}={p['rss0_kb'] // 1024}MiB/{round(p['wakeups_s'], 1)}w")
                rec[f"{phase}_rss_mib_{v}"] = round(sum(p["rss0_kb"] for p in procs) / 1024, 1)
            rec[f"{phase}_wakeups_s"] = round(tot_w, 1)
            rec[f"{phase}_procs"] = " ".join(mem)
        out.append(rec)
    return out


def main():
    args = sys.argv[1:]
    wout = args[args.index("--windows") + 1]
    rout = args[args.index("--rows") + 1]
    raw = args[0]
    holds = [a for a in args[1:] if not a.startswith("--") and a not in (wout, rout)]
    W, R = [], []
    for h in holds:
        W += windows(raw, h)
        R += rows(raw, h)
    for path, data in ((wout, W), (rout, R)):
        keys = []
        for d in data:
            for k in d:
                if k not in keys:
                    keys.append(k)
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(data)
    print(f"{len(W)} windows, {len(R)} rows")


if __name__ == "__main__":
    main()
