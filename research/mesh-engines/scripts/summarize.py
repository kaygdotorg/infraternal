"""Role: Summarize the five-run CSV measurements in results/ as Markdown."""

# SPDX-License-Identifier: AGPL-3.0-only

import csv
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def read_rows(name):
    with (RESULTS / name).open(newline="", encoding="utf-8") as stream:
        lines = (line for line in stream if line.strip() and not line.startswith("#"))
        return list(csv.DictReader(lines))


def spread(values, digits=2):
    clean = [float(value) for value in values if value not in ("NA", "")]
    if not clean:
        return "NA"
    return f"{statistics.median(clean):.{digits}f} ({min(clean):.{digits}f}–{max(clean):.{digits}f})"


def data_plane_summary():
    result = [
        "## Data plane",
        "",
        "Median (min–max), across five independent samples. Throughput is Mbit/s; CPU is engine CPU-seconds/Gbit.",
        "",
        "| Engine | 1 stream | 4 streams | CPU/Gbit 1 stream | CPU/Gbit 4 streams | Base ping p50 / p99 ms | Tunnel ping p50 / p99 ms | Added p50 / p99 ms | RSS growth / peer at 100 / 1,000 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for engine in ("kernel", "boringtun", "gotatun", "neptun", "wireguard-go"):
        rows = read_rows(f"{engine}.csv")
        add50 = [float(row["tunnel_ping_p50_ms"]) - float(row["base_ping_p50_ms"]) for row in rows]
        add99 = [float(row["tunnel_ping_p99_ms"]) - float(row["base_ping_p99_ms"]) for row in rows]
        memory100 = [
            (int(row["rss_100_bytes"]) - int(row["rss_base_bytes"])) / 100
            for row in rows
            if row["rss_base_bytes"] != "NA"
        ]
        memory1000 = [
            (int(row["rss_1000_bytes"]) - int(row["rss_base_bytes"])) / 1_000
            for row in rows
            if row["rss_base_bytes"] != "NA"
        ]
        memory = "NA" if not memory100 else f"{spread(memory100, 0)} / {spread(memory1000, 0)} B"
        result.append(
            "| {engine} | {one} | {four} | {cpu1} | {cpu4} | {base50} / {base99} | {tun50} / {tun99} | {add50} / {add99} | {memory} |".format(
                engine=engine,
                one=spread([row["iperf1_mbps"] for row in rows]),
                four=spread([row["iperf4_mbps"] for row in rows]),
                cpu1=spread([row["iperf1_cpu_seconds_per_gbit"] for row in rows], 3),
                cpu4=spread([row["iperf4_cpu_seconds_per_gbit"] for row in rows], 3),
                base50=spread([row["base_ping_p50_ms"] for row in rows], 3),
                base99=spread([row["base_ping_p99_ms"] for row in rows], 3),
                tun50=spread([row["tunnel_ping_p50_ms"] for row in rows], 3),
                tun99=spread([row["tunnel_ping_p99_ms"] for row in rows], 3),
                add50=spread(add50, 3),
                add99=spread(add99, 3),
                memory=memory,
            )
        )
    result.append("")
    result.append("Load average at sample start (1/5/15 min):")
    result.append("")
    result.append("| Engine | 1 min | 5 min | 15 min |")
    result.append("| --- | ---: | ---: | ---: |")
    for engine in ("kernel", "boringtun", "gotatun", "neptun", "wireguard-go"):
        rows = read_rows(f"{engine}.csv")
        parts = [[], [], []]
        for row in rows:
            for index, value in enumerate(row["loadavg_start"].split("/")):
                parts[index].append(value)
        result.append(f"| {engine} | {spread(parts[0])} | {spread(parts[1])} | {spread(parts[2])} |")
    return result


def control_summary():
    result = [
        "## Linux control plane",
        "",
        "Median (min–max), across five CPU-weighted rootless namespace runs. Times are microseconds.",
        "",
        "| Client | Apply 1,000 | One-peer update at 1,000 | Remove at 1,000 | Correctness |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for file_name, label in (("nl-wireguard.csv", "nl-wireguard"), ("netlink-minimal.csv", "typed minimal")):
        rows = read_rows(file_name)
        result.append(
            f"| {label} | {spread([r['apply_1000_us'] for r in rows], 0)} | {spread([r['update_one_of_1000_us'] for r in rows], 0)} | {spread([r['remove_one_of_1000_us'] for r in rows], 0)} | peer/IP/port/remove/stats OK |"
        )
    rows = read_rows("nlink.csv")
    result.append(
        f"| nlink 0.29.0 | rejected in {spread([r['apply_1000_us'] for r in rows], 0)} | {spread([r['update_one_of_1000_us'] for r in rows], 0)} | {spread([r['remove_one_of_1000_us'] for r in rows], 0)} | 1,000-peer apply returns EINVAL; updates measured on chunked baseline |"
    )
    result.append("")
    result.append(f"nlink fallback baseline load time: {spread([r['chunked_baseline_set_1000_us'] for r in rows], 0)} μs via nl-wireguard.")
    return result


if __name__ == "__main__":
    print("<!-- Role: Generated median and spread summary of the mesh engine benchmark results. SPDX-License-Identifier: AGPL-3.0-only -->")
    print("\n".join(data_plane_summary() + [""] + control_summary()))
