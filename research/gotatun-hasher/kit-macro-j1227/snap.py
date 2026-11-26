#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1227 (#260, from J1137/J1160) observer snapshot: one JSON object with everything a window needs.

Whole-machine CPU jiffies (/proc/stat, so kernel WireGuard's softirq and kworker time
counts), machine context switches, per-engine-process CPU, voluntary/involuntary
context switches summed over threads, RSS/PSS, the tunnel and underlay byte counters
inside the j94 netns. Engine pids and the tunnel name come from /root/j1227/run/watch.

    snap.py <out.json>
"""
import json
import os
import subprocess
import sys
import time


def proc_stat():
    out = {}
    with open("/proc/stat") as f:
        for line in f:
            p = line.split()
            if p[0] == "cpu":
                out["cpu"] = list(map(int, p[1:]))
            elif p[0] == "ctxt":
                out["ctxt"] = int(p[1])
            elif p[0] == "intr":
                out["intr"] = int(p[1])
    return out


def process(pid):
    """CPU ticks, thread context switches and memory of one engine process and its children."""
    pids = [pid]
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
        pids += [int(k) for k in kids]
    except OSError:
        pass
    total = {"utime": 0, "stime": 0, "vol": 0, "invol": 0, "threads": 0, "rss_kb": 0, "pss_kb": 0, "pids": pids}
    for p in pids:
        try:
            with open(f"/proc/{p}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            total["utime"] += int(fields[11])
            total["stime"] += int(fields[12])
            for task in os.listdir(f"/proc/{p}/task"):
                with open(f"/proc/{p}/task/{task}/status") as f:
                    for line in f:
                        if line.startswith("voluntary_ctxt_switches"):
                            total["vol"] += int(line.split()[1])
                        elif line.startswith("nonvoluntary_ctxt_switches"):
                            total["invol"] += int(line.split()[1])
                total["threads"] += 1
            with open(f"/proc/{p}/smaps_rollup") as f:
                for line in f:
                    if line.startswith("Rss:"):
                        total["rss_kb"] += int(line.split()[1])
                    elif line.startswith("Pss:"):
                        total["pss_kb"] += int(line.split()[1])
        except (OSError, IndexError, ValueError):
            pass
    return total


def ns_bytes(dev):
    out = {}
    for d in [dev, "j94v"]:
        if not d:
            continue
        r = subprocess.run(["ip", "netns", "exec", "j94", "sh", "-c",
                            f"cat /sys/class/net/{d}/statistics/rx_bytes /sys/class/net/{d}/statistics/tx_bytes "
                            f"/sys/class/net/{d}/statistics/rx_packets /sys/class/net/{d}/statistics/tx_packets "
                            f"/sys/class/net/{d}/statistics/rx_dropped /sys/class/net/{d}/statistics/tx_dropped"],
                           capture_output=True, text=True)
        v = r.stdout.split()
        if len(v) == 6:
            out[d] = dict(zip(["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped"], map(int, v)))
    return out


def main():
    watch = {"tun": None, "pids": []}
    try:
        text = open("/root/j1227/run/watch").read()
        head, _, pids = text.partition("pids=")
        watch["tun"] = head.split("tun=", 1)[1].split()[0] if "tun=" in head else None
        watch["pids"] = [int(p) for p in pids.split()]
    except (OSError, ValueError):
        pass
    pids = watch["pids"]
    snap = {
        "mono_ns": time.monotonic_ns(),
        "wall": time.time(),
        "stat": proc_stat(),
        "engines": {str(p): process(p) for p in pids},
        "dev": ns_bytes(watch.get("tun")),
        "tun": watch.get("tun"),
        "clk_tck": os.sysconf("SC_CLK_TCK"),
    }
    with open(sys.argv[1], "w") as f:
        json.dump(snap, f)


if __name__ == "__main__":
    main()
