#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-engine table for one lossy-profile scenario (#260).

Usage: lossy_table.py <scenario-root>/matrix.json (silent seconds are recomputed from each row's raw tcp-N-progress.tsv)
Medians over the windows that completed, with [min-max] for goodput. Failed or missing rows are
counted as reliability events, never averaged in. `inf` marks a loss-aware p99 whose rank falls
inside the lost probes (the pingstat keep rule), beside the finite received-only p99.
"""
import importlib.util
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

_spec = importlib.util.spec_from_file_location("progress", Path(__file__).with_name("progress.py"))
progress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(progress)


def tcp_progress(root, row, flows):
    """Recompute silent seconds and the longest stall from the row's raw sampler file."""
    tsv = root / str(row.get("window")) / str(row.get("row_tag")) / f"mesh-{row.get('implementation', '')}" / "matrix" / f"tcp-{flows}-progress.tsv"
    if not tsv.is_file():
        return None
    result = progress.summarize(progress.read_samples(tsv))
    return result if result.get("status") == "measured" else None


def med(values):
    return statistics.median(values) if values else None


def fmt(value, digits=1):
    return "n/a" if value is None else f"{value:.{digits}f}"


def main():
    data = json.load(open(sys.argv[1]))
    root = Path(sys.argv[1]).parent
    labels = {spec["id"]: spec.get("label", spec["id"]) for spec in data.get("engine_specs", [])}
    rows_by_engine = defaultdict(list)
    for row in data["rows"]:
        rows_by_engine[row["engine"]].append(row)
    print(f"scenario {data['scenario']['id']}: {data['scenario'].get('description', '')}")
    print()
    print("| engine | ok / planned | goodput Mbit/s 1 flow | goodput Mbit/s 8 flows | loss-aware p99 ms (1 / 8) | received-only p99 ms (1 / 8) | probe loss % (1 / 8) | TCP retransmits (1 / 8) | silent s, longest stall s (1 / 8) | zero-byte flows | wire loss % vs configured (1 / 8) | avg bytes / queued packet |")
    print("|---|---:|---|---|---|---|---|---|---|---:|---|---:|")
    for engine, rows in rows_by_engine.items():
        complete = [row for row in rows if row.get("status") == "complete"]
        failed = len(rows) - len(complete)

        def metric(key):
            return [row["metrics"][key] for row in complete if row["metrics"].get(key) is not None]

        def goodput(flows):
            values = [value * 1000 for value in metric(f"tcp_{flows}_gbit_s")]
            if not values:
                return "n/a"
            return f"{statistics.median(values):.1f} [{min(values):.1f}-{max(values):.1f}]"

        def p99(flows):
            latencies = [row["latency"].get(f"loaded_tcp_{flows}") or {} for row in complete]
            infinite = sum(1 for item in latencies if "p99" in (item.get("infinite_at") or []))
            finite = [item["p99_ms"] for item in latencies if item.get("p99_ms") is not None]
            if not latencies:
                return "n/a"
            return f"{fmt(med(finite))}" if not infinite else f"inf in {infinite}/{len(latencies)}" + (f", else {fmt(med(finite))}" if finite else "")

        def pair(key, digits=1, scale=1.0):
            return " / ".join(fmt(None if not metric(key.format(f)) else med(metric(key.format(f))) * scale, digits) for f in (1, 8))

        summaries = {f: [tcp_progress(root, row, f) for row in complete] for f in (1, 8)}
        summaries = {f: [item for item in items if item] for f, items in summaries.items()}
        stalls = " / ".join(
            f"{fmt(med([item['silent_seconds'] for item in summaries[f]]), 0)}, "
            f"{fmt(max((item['longest_silent_s'] for item in summaries[f]), default=None), 0)}"
            for f in (1, 8))
        zero = sum(1 for f in (1, 8) for item in summaries[f] if item["zero_byte"])
        wire = " / ".join(fmt(med(metric(f"tcp_{f}_wire_loss_pct")), 2) for f in (1, 8))
        matches = [value for f in (1, 8) for value in metric(f"tcp_{f}_wire_matches")]
        wire += f" ({sum(matches)}/{len(matches)} match)" if matches else ""
        print(f"| {labels.get(engine, engine)} | {len(complete)} / {len(rows)}{f' ({failed} failed)' if failed else ''} | {goodput(1)} | {goodput(8)} | {p99(1)} / {p99(8)} | "
              f"{pair('loaded_{}_p99_received_ms')} | {pair('loaded_{}_probe_loss_pct', 2)} | "
              f"{pair('tcp_{}_retransmits', 0)} | {stalls} | {zero} | {wire} | {fmt(med(metric('tcp_1_wire_avg_bytes')), 0)} |")
    failed_rows = [(row.get("row_tag"), row.get("failure_reason", row.get("status"))) for row in data["rows"] if row.get("status") != "complete"]
    if failed_rows:
        print()
        print("Failed or missing rows (counted, not averaged): " + "; ".join(f"{tag}: {reason}" for tag, reason in failed_rows))


main()
