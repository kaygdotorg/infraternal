#!/usr/bin/env python3
# Role: summarize the tile-lane recorder's METRIC lines per scenario and lane, for before/after comparisons [#146 proposal C].
"""Summarize one recorder run: python3 stages.py <run-dir> <stderr-file>

Reads the product's opt-in METRIC lines written while record.swift ran with INFRATERNAL_DESKTOP_MEASURE=1:
`surface_delivery` (one per packet sent: capture stamp, dequeue and output times, lane) and `encode_ns` (one per encoded
frame: encoder time and bytes). Builds without the tile lane print no `lane=` field; their packets are all video.

For each scenario in manifest.json it prints, per lane: packets, capture -> sent latency p50/p95 in ms (from the frame's
capture stamp to the end of the packet write, on the Mac's one monotonic clock), bytes p50 and total, and for video the
encoder time p50. Sharp refreshes (`fresh=false`) re-send an older picture; their stamp age is not latency, so they are
counted but left out of the latency columns. Standard library only.
"""
import json
import os
import sys


def fields(line):
    """The key=value pairs of one METRIC line."""
    return dict(item.split("=", 1) for item in line.split()[2:] if "=" in item)


def pct(values, q):
    """The q-quantile of values (nearest rank), or 0 for none."""
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def main():
    run, log = sys.argv[1], sys.argv[2]
    manifest = json.load(open(os.path.join(run, "manifest.json")))
    encodes, deliveries = {}, []
    for line in open(log, errors="replace"):
        if line.startswith("METRIC encode_ns="):
            f = dict(item.split("=", 1) for item in line.split()[1:] if "=" in item)
            encodes.setdefault(int(f["capture_ns"]), []).append((int(f["encode_ns"]), int(f["bytes"])))
        elif line.startswith("METRIC surface_delivery"):
            deliveries.append(fields(line))
    result = {}
    for scenario in manifest["scenarios"]:
        first, last = int(scenario["first_ns"]), int(scenario["last_ns"])
        lanes = {}
        for d in deliveries:
            capture = int(d["capture_ns"])
            if not first <= capture <= last:
                continue
            lane = d.get("lane", "video")
            entry = lanes.setdefault(lane, {"packets": 0, "refreshes": 0, "latency": [], "bytes": [], "encode": []})
            entry["packets"] += 1
            if lane == "video":
                encoded = encodes.get(capture, [])
                if encoded:
                    entry["encode"].append(encoded[0][0] / 1e6)
                    entry["bytes"].append(int(d["bytes"]) if "bytes" in d else encoded[0][1])
            else:
                entry["bytes"].append(int(d["bytes"]))
            if d.get("fresh") == "false":
                entry["refreshes"] += 1
                continue
            entry["latency"].append((int(d["output_end_ns"]) - capture) / 1e6)
        result[scenario["name"]] = {
            lane: {
                "packets": e["packets"], "refreshes": e["refreshes"],
                "capture_to_sent_ms_p50": round(pct(e["latency"], 0.5), 3), "capture_to_sent_ms_p95": round(pct(e["latency"], 0.95), 3),
                "bytes_p50": pct(e["bytes"], 0.5), "bytes_total": sum(e["bytes"]),
                "encode_ms_p50": round(pct(e["encode"], 0.5), 3) if e["encode"] else None,
            }
            for lane, e in lanes.items()
        }
    print(json.dumps(result, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
