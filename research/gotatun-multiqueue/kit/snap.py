#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1230 (#260, from J1137/J1160) observer snapshot: one JSON object with everything a window needs.

Whole-machine CPU jiffies (/proc/stat, so kernel WireGuard's softirq and kworker time
counts), machine context switches, per-engine-process CPU, voluntary/involuntary
context switches summed over threads, RSS/PSS, the tunnel and underlay byte counters
inside the j30 netns. Engine pids and the tunnel name come from /root/j1230/run/watch.

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
                # J1230: per-thread CPU ticks and name, so a saturated single thread shows.
                try:
                    with open(f"/proc/{p}/task/{task}/stat") as f:
                        head, tail = f.read().rsplit(")", 1)
                    tf = tail.split()
                    total.setdefault("thr", {})[task] = [head.split("(", 1)[1], int(tf[11]) + int(tf[12])]
                except (OSError, IndexError, ValueError):
                    pass
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
    """Byte/packet counters of the tunnel device(s) and the underlay link. A comma-separated
    `dev` (the two-tunnel row) also gets a summed entry under its full name."""
    out = {}
    devs = dev.split(",") if dev else []
    for d in devs + ["j30v"]:
        if not d:
            continue
        r = subprocess.run(["ip", "netns", "exec", "j30", "sh", "-c",
                            f"cat /sys/class/net/{d}/statistics/rx_bytes /sys/class/net/{d}/statistics/tx_bytes "
                            f"/sys/class/net/{d}/statistics/rx_packets /sys/class/net/{d}/statistics/tx_packets "
                            f"/sys/class/net/{d}/statistics/rx_dropped /sys/class/net/{d}/statistics/tx_dropped"],
                           capture_output=True, text=True)
        v = r.stdout.split()
        if len(v) == 6:
            out[d] = dict(zip(["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped"], map(int, v)))
    if len(devs) > 1 and all(d in out for d in devs):
        out[dev] = {k: sum(out[d][k] for d in devs) for k in out[devs[0]]}
    return out


def main():
    watch = {"tun": None, "pids": []}
    try:
        text = open("/root/j1230/run/watch").read()
        head, _, pids = text.partition("pids=")
        watch["tun"] = head.split("tun=", 1)[1].split()[0] if "tun=" in head else None
        watch["pids"] = [int(p) for p in pids.split()]
    except (OSError, ValueError):
        pass
    pids = watch["pids"]
    # J1230: the netns's TCP extension counters (reordering, out-of-order queueing, SACK
    # reorder), so a multi-queue candidate that reorders a flow shows up per window.
    tcpext = {}
    r = subprocess.run(["ip", "netns", "exec", "j30", "cat", "/proc/net/netstat"], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    for i in range(0, len(lines) - 1, 2):
        keys, vals = lines[i].split(), lines[i + 1].split()
        if keys and keys[0] == "TcpExt:":
            tcpext = {k: int(v) for k, v in zip(keys[1:], vals[1:]) if k in (
                "TCPOFOQueue", "TCPSACKReorder", "TCPTSReorder", "TCPRenoReorder", "TCPLostRetransmit",
                "TCPFastRetrans", "TCPSlowStartRetrans", "TCPDSACKRecv")}
    snap_extra = {"tcpext": tcpext}
    snap = {
        "mono_ns": time.monotonic_ns(),
        "wall": time.time(),
        "stat": proc_stat(),
        "engines": {str(p): process(p) for p in pids},
        "dev": ns_bytes(watch.get("tun")),
        "tun": watch.get("tun"),
        "clk_tck": os.sysconf("SC_CLK_TCK"),
        **snap_extra,
    }
    with open(sys.argv[1], "w") as f:
        json.dump(snap, f)


if __name__ == "__main__":
    main()
