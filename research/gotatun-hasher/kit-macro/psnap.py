#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1204 (#260) per-process snapshot of everything running in the fixture netns `j94`.

For each process: comm, argv[0], RSS/PSS (smaps_rollup), utime/stime ticks and the voluntary and
involuntary context switches summed over its threads. Two snapshots taken while no traffic flows
give each product process's idle wakeups per second; one taken after the load windows gives its
memory after load. The kit's own helpers (iperf3, the round-trip probe, the sleepers that hold
fifos open, the fixture driver) are kept but tagged `kit`, so the summary can leave them out.

    psnap.py <out.json>
"""
import json
import os
import subprocess
import sys
import time

KIT = {"iperf3", "sleep", "sh", "bash", "python3", "unshare", "ip"}


def proc(pid):
    """One process's memory, CPU ticks and context switches (all threads)."""
    out = {"pid": pid}
    try:
        out["comm"] = open(f"/proc/{pid}/comm").read().strip()
        argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        out["argv0"] = os.path.basename(argv[0].decode(errors="replace"))
        out["args"] = " ".join(a.decode(errors="replace") for a in argv[1:4])
        fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        out["utime"], out["stime"] = int(fields[11]), int(fields[12])
        vol = invol = threads = 0
        for task in os.listdir(f"/proc/{pid}/task"):
            for line in open(f"/proc/{pid}/task/{task}/status"):
                if line.startswith("voluntary_ctxt_switches"):
                    vol += int(line.split()[1])
                elif line.startswith("nonvoluntary_ctxt_switches"):
                    invol += int(line.split()[1])
            threads += 1
        out.update(vol=vol, invol=invol, threads=threads)
        for line in open(f"/proc/{pid}/smaps_rollup"):
            if line.startswith("Rss:"):
                out["rss_kb"] = int(line.split()[1])
            elif line.startswith("Pss:"):
                out["pss_kb"] = int(line.split()[1])
    except (OSError, IndexError, ValueError):
        out["gone"] = True
    out["kit"] = out.get("comm") in KIT or out.get("argv0") in KIT
    return out


def main():
    pids = subprocess.run(["ip", "netns", "pids", "j94"], capture_output=True, text=True).stdout.split()
    stat = open("/proc/stat").read().splitlines()
    cpu = [int(v) for v in stat[0].split()[1:]]
    ctxt = next(int(l.split()[1]) for l in stat if l.startswith("ctxt"))
    snap = {"mono_ns": time.monotonic_ns(), "wall": time.time(), "clk_tck": os.sysconf("SC_CLK_TCK"),
            "cpu": cpu, "ctxt": ctxt, "procs": [proc(int(p)) for p in pids]}
    with open(sys.argv[1], "w") as f:
        json.dump(snap, f)


if __name__ == "__main__":
    main()
