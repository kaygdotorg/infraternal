#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Turn the raw cell files of the mixed flood-plus-TCP measurement into tables (#260, J1249).

    summarize.py OUTDIR RAWDIR [RAWDIR...]

Writes `OUTDIR/cells.csv` (one row per cell, from every `*.json` cell file in the raw folders) and
`OUTDIR/tables.md` (per scenario and mode: median over the repeats, with the range). All rates are
averages over the measurement window, taken from counters on the hub's own clock.
"""
import csv
import json
import math
import pathlib
import statistics
import sys

MODES = ["default", "off", "cap4", "cap16", "cap64", "cap256"]
SCENARIOS = ["tcp", "mix90", "mix10", "flood90"]
#: Columns of the printed tables: (key, heading, digits).
COLUMNS = [
    ("flood_offered_gbit", "flood offered Gbit/s", 3), ("flood_wire_gbit", "flood at hub NIC Gbit/s", 3),
    ("udp_delivered_gbit", "UDP delivered Gbit/s", 3), ("udp_delivery_pct", "UDP delivery %", 1),
    ("tcp_goodput_gbit", "TCP goodput Gbit/s", 3), ("tcp_min_peer_mbit", "slowest TCP peer Mbit/s", 1),
    ("rtt_p50_ms", "TCP peers RTT p50 ms", 1), ("rtt_p99_ms", "TCP peers RTT p99 ms", 1),
    ("rtt_lost_pct", "probes lost %", 2), ("idle_p99_ms", "idle peer RTT p99 ms", 1),
    ("engine_cpu_pct", "engine CPU % of a core", 0), ("cpu_s_per_gbit", "engine CPU-s per delivered Gbit", 3),
    ("rcvbuf_errors_k", "socket-buffer drops (k)", 1), ("aqm_drop_pct", "AQM drop % of judged", 1),
    ("aqm_tcp_drop_pct", "AQM drop % of TCP judged", 2), ("sojourn_mean_ms", "mean sojourn ms", 1),
]


def at(lines, when, value):
    """A cumulative counter at the instant `when`, interpolated between the sink's lines."""
    before = max((line for line in lines if line["t"] <= when), key=lambda line: line["t"], default=None)
    after = min((line for line in lines if line["t"] > when), key=lambda line: line["t"], default=None)
    if before is None or after is None:
        raise ValueError("the sink's lines do not cover the window")
    share = (when - before["t"]) / (after["t"] - before["t"])
    return value(before) + share * (value(after) - value(before))


def rate(lines, start, stop, value):
    """A cumulative counter's average growth per second over the window."""
    return (at(lines, stop, value) - at(lines, start, value)) / (stop - start)


def percentile(values, q):
    """Nearest-rank percentile (lost probes are infinite)."""
    if not values:
        return math.nan
    ordered = sorted(values)
    return ordered[max(1, math.ceil(q * len(ordered))) - 1]


def probe_stats(probes, peers):
    """All round trips of the chosen peers, lost requests as infinity."""
    values = []
    for probe in probes:
        if probe["peer"] in peers:
            if "error" in probe:
                raise ValueError(f"probe {probe['peer']} failed: {probe['error']}")
            values += probe["rtts"] + [math.inf] * probe["lost"]
    return values


def aqm_delta(lines, start, stop):
    """The AQM counters' growth over the window, and the mean of the per-period sojourns."""
    rows = [dict(word.split("=", 1) for word in line.split()[1:]) for line in lines]
    inside = [row for row in rows if start <= float(row["t"]) <= stop]
    if len(inside) < 2:
        return None
    first, last = inside[0], inside[-1]
    out = {key: int(last[key]) - int(first[key]) for key in ("seen", "drops", "marks", "seen_tcp", "drops_tcp")}
    out["sojourn_mean_ms"] = statistics.mean(int(row["sojourn_mean_us"]) for row in inside[1:]) / 1000
    out["sojourn_max_ms"] = max(int(row["sojourn_max_us"]) for row in inside[1:]) / 1000
    return out


def row_of(cell):
    """Every number of one cell."""
    start, stop = cell["times"]["start"], cell["times"]["stop"]
    window = stop - start
    hub, stopped = cell["results"]["hub"], cell["hub_stop"]
    first, last = hub["first"], hub["last"]
    # The sampled instants can differ from the schedule by a few ms; counters use their own times.
    span = last["t"] - first["t"]

    def wire(name):
        """Gbit/s that reached the hub's link from one sender VM."""
        return (last["nft"][name][1] - first["nft"][name][1]) * 8 / span / 1e9

    row = {"scenario": cell["scenario"], "mode": cell["mode"], "rep": cell["rep"], "window_s": round(window, 1),
           "load_target_gbit": cell["load_gbit"], "engine_alive": stopped["engine_alive_at_stop"]}
    sends = cell["results"].get("flood", {}).get("send", [])
    offered = sum(send["sent"] * cell["payload"] * 8 / send["secs"] for send in sends) / 1e9
    row["flood_offered_gbit"] = offered
    row["flood_wire_gbit"] = wire("wire-flood")
    row["tcp_wire_gbit"] = wire("wire-tcp")
    udp = rate(stopped["udpsink"], start, stop, lambda line: line["bytes"]) * 8 / 1e9
    row["udp_delivered_gbit"] = udp
    row["udp_delivery_pct"] = 100 * udp / offered if offered else math.nan
    results = cell["results"].get("tcp")
    goodput = [rate(stopped["tcpsink"], start, stop, lambda line, ip=f"10.254.200.{i + 1}": line["bytes"].get(ip, 0))
               * 8 / 1e9 for i in range(10)] if cell["scenario"] != "flood90" else []
    tcp = sum(goodput)
    row["tcp_goodput_gbit"] = tcp
    row["tcp_min_peer_mbit"] = 1000 * min(goodput) if goodput else math.nan
    row["tcp_max_peer_mbit"] = 1000 * max(goodput) if goodput else math.nan
    bulk = probe_stats(results["probes"], range(10))
    idle = probe_stats(results["probes"], [10])
    row["rtt_p50_ms"], row["rtt_p99_ms"] = percentile(bulk, 0.5), percentile(bulk, 0.99)
    row["rtt_lost_pct"] = 100 * sum(map(math.isinf, bulk)) / len(bulk) if bulk else math.nan
    row["rtt_samples"] = len(bulk)
    row["idle_p50_ms"], row["idle_p99_ms"] = percentile(idle, 0.5), percentile(idle, 0.99)
    row["idle_lost_pct"] = 100 * sum(map(math.isinf, idle)) / len(idle)
    out_segs = results["last"]["tcp"]["OutSegs"] - results["first"]["tcp"]["OutSegs"]
    retrans = results["last"]["tcp"]["RetransSegs"] - results["first"]["tcp"]["RetransSegs"]
    row["tcp_retrans_pct"] = 100 * retrans / out_segs if out_segs else math.nan
    cpu = last["engine_cpu_s"] - first["engine_cpu_s"]
    row["engine_cpu_pct"] = 100 * cpu / span
    delivered = tcp + udp
    row["cpu_s_per_gbit"] = cpu / span / delivered if delivered else math.nan
    for name in ("cpu1", "cpu2"):
        row[f"hub_{name}_busy_pct"] = 100 * (last["cpus"][name]["busy"] - first["cpus"][name]["busy"]) / span
    row["hub_steal_s"] = sum(last["cpus"][c]["steal"] - first["cpus"][c]["steal"] for c in last["cpus"])
    row["rcvbuf_errors_k"] = (last["udp"]["RcvbufErrors"] - first["udp"]["RcvbufErrors"]) / 1000
    row["nic_rx_dropped"] = sum(last["eth0"][k] - first["eth0"][k]
                                for k in ("rx_dropped", "rx_missed_errors", "softnet_dropped"))
    row["recvq_p50_mb"] = statistics.median(hub["recvq"]) / 1e6
    row["recvq_max_mb"] = max(hub["recvq"]) / 1e6
    for role in ("tcp", "flood"):
        sample = cell["results"].get(role)
        if sample:
            seconds = sample["last"]["t"] - sample["first"]["t"]
            busy = {c: (sample["last"]["cpus"][c]["busy"] - sample["first"]["cpus"][c]["busy"]) / seconds
                    for c in sample["last"]["cpus"]}
            row[f"{role}_vm_busy_cpus"] = sum(busy.values())
            row[f"{role}_vm_busiest_cpu_pct"] = 100 * max(busy.values())
    aqm = aqm_delta(stopped["aqm"], start, stop)
    if aqm:
        row["aqm_drop_pct"] = 100 * aqm["drops"] / aqm["seen"] if aqm["seen"] else math.nan
        row["aqm_tcp_drop_pct"] = 100 * aqm["drops_tcp"] / aqm["seen_tcp"] if aqm["seen_tcp"] else math.nan
        row["aqm_marks"] = aqm["marks"]
        row["sojourn_mean_ms"], row["sojourn_max_ms"] = aqm["sojourn_mean_ms"], aqm["sojourn_max_ms"]
    return row


def spread(values, digits):
    """`median (min-max)` of the repeats, or a dash when there is nothing to report."""
    values = [v for v in values if v is not None and not math.isnan(v)]
    if not values:
        return "-"
    text = lambda v: "lost" if math.isinf(v) else f"{v:.{digits}f}"
    if len(values) == 1:
        return text(values[0])
    return f"{text(statistics.median(values))} ({text(min(values))}-{text(max(values))})"


def main():
    """Read the cells, write the CSV and the tables."""
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for raw in sys.argv[2:]:
        for path in sorted(pathlib.Path(raw).glob("[0-9]*.json")):
            row = row_of(json.loads(path.read_text()))
            row["file"] = f"{pathlib.Path(raw).name}/{path.name}"
            rows.append(row)
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with open(out / "cells.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: round(v, 4) if isinstance(v, float) else v for k, v in row.items()})
    text = []
    for scenario in SCENARIOS:
        for load in sorted({r["load_target_gbit"] for r in rows if r["scenario"] == scenario}):
            group = [r for r in rows if r["scenario"] == scenario and r["load_target_gbit"] == load]
            modes = [m for m in MODES if any(r["mode"] == m for r in group)]
            if not modes:
                continue
            text.append(f"### {scenario}" + (f", flood target {load} Gbit/s" if load else ""))
            counts = {m: sum(r["mode"] == m for r in group) for m in modes}
            text.append("| | " + " | ".join(f"{m} (n={counts[m]})" for m in modes) + " |")
            text.append("|---" * (len(modes) + 1) + "|")
            for key, heading, digits in COLUMNS:
                cells = [spread([r.get(key) for r in group if r["mode"] == m], digits) for m in modes]
                if any(c != "-" for c in cells):
                    text.append(f"| {heading} | " + " | ".join(cells) + " |")
            text.append("")
    (out / "tables.md").write_text("\n".join(text) + "\n")
    print("\n".join(text))


if __name__ == "__main__":
    main()
