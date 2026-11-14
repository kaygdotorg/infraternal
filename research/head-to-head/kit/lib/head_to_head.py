#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Pool cross-engine D348 holds into per-core-honest head-to-head tables (#260, J638).

Each hold is one `perf-all.sh --mixed` run: every engine once, in a Latin-square
order (lib/latin_square.py), inside one perf-run. Slow drift between holds
cancels in within-hold ratios.

The headline is Gbit/s per busy core: throughput divided by the whole
machine's busy cores in that window. Kernel WireGuard's crypto runs on any
online CPU, including the housekeeping pair (see lib/cpu_split.py), so raw
Gbit/s alone favours the kernel engines. Beside it, the report shows the cores
each engine actually used, split into side A, side B and housekeeping.

A difference between two engines counts only if every hold agrees in sign
and the mean exceeds a floor. The floor is the GotaTun calibration spread for
that metric (the max/min spread of three identical controls); RSS has no
calibration, so it has no floor.

Usage: head_to_head.py CALIBRATION_SPREAD_JSON HOLD_DIR... [--baseline TAG] [--focus TAG]
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path

CASES = {
    "gotatun": "mesh-gotatun", "kernel-plain": "mesh-kernel-plain", "kernel": "mesh-netbird",
    "infraternal": "mesh-infraternal", "tailscale": "mesh-tailscale",
    "netbird-userspace": "mesh-netbird-userspace", "wireguard-go": "mesh-wireguard-go",
    "underlay": "mesh-underlay",
}
NAMES = {
    "gotatun": "GotaTun CLI", "kernel-plain": "kernel WireGuard", "kernel": "NetBird (kernel WG)",
    "infraternal": "infraternal in-app", "tailscale": "Tailscale (userspace)",
    "netbird-userspace": "NetBird (userspace)", "wireguard-go": "wireguard-go", "underlay": "underlay",
}
# key, column title, higher is better, calibration metric used as the floor
METRICS = [
    ("gbit", "Gbit/s", True, "throughput_gbit_s"),
    ("per_core", "Gbit/s per busy core", True, "cpu_s_per_gbit"),
    ("p99", "loaded p99 ms (loss-aware)", False, "p99_loss_aware_ms"),
    ("p99r", "p99 of received probes ms", False, "p99_loss_aware_ms"),
    ("cpu", "CPU s/Gbit", False, "cpu_s_per_gbit"),
    ("rss", "RSS MiB (peak)", False, None),
]
FORMAT = {"gbit": "{:.2f}", "per_core": "{:.3f}", "cpu": "{:.3f}", "p99": "{:.2f}", "p99r": "{:.2f}", "rss": "{:.1f}"}


def plan(hold: Path) -> list[tuple[str, str]]:
    """The hold's (tag, engine) rows in the order they ran."""
    return [tuple(line.split("\t")[:2]) for line in (hold / "rows.tsv").read_text().splitlines() if line.strip()]


def row(hold: Path, tag: str, engine: str, flows: int) -> dict[str, float]:
    """One window's figures; raises if any input is missing, so it is reported, never zero."""
    case = hold / tag / CASES[engine]
    tput = json.loads((case / f"tput-lan-{flows}.json").read_text())
    icmp = dict(re.findall(r"(\S+) ([0-9.]+|inf)", (case / f"icmp-lan-{flows}.summary.txt").read_text()))
    split = json.loads((case / f"cpuset-lan-{flows}/cpu-split.json").read_text())["cores_busy"]
    return {
        "gbit": tput["gbit_per_s"], "per_core": tput["gbit_per_s"] / tput["machine_cores_busy"],
        "cpu": tput["machine_cpu_s_per_gbit"], "p99": float(icmp["p99_loss_aware"]),
        "p99r": float(icmp["p99_received"]), "lost": int(icmp["lost"]), "sent": int(icmp["sent"]),
        "rss": (tput.get("watched_rss_kb_peak") or 0) / 1024, "cores": tput["machine_cores_busy"],
        "side_a": split["side_a"], "side_b": split["side_b"], "housekeeping": split["housekeeping"],
    }


def verdict(ratios: list[float], floor: float, higher_is_better: bool) -> tuple[float, str]:
    deltas = [(ratio - 1) * 100 for ratio in ratios]
    mean = statistics.mean(deltas)
    same_sign = all(delta > 0 for delta in deltas) or all(delta < 0 for delta in deltas)
    good = (mean > 0) == higher_is_better
    if same_sign and abs(mean) > floor:
        return mean, "**better**" if good else "**worse**"
    if same_sign:
        return mean, "better, under floor" if good else "worse, under floor"
    return mean, "tie (signs split)"


def report(calibration: Path, holds: list[Path], flows: tuple[int, ...] = (1, 8),
           baseline: str | None = None, focus: str | None = None, allow_uncalibrated: bool = False) -> str:
    """The pooled Markdown report.

    A verdict compares a difference with the calibration floor (the run-to-run spread of the same
    row). Without a floor every difference would count as real, so a calibration that lacks a
    metric for a flow count raises ValueError. `allow_uncalibrated=True` uses a zero floor instead
    and puts a warning at the top of the report.
    """
    spread = json.loads(calibration.read_text()).get("spread_pct", {})
    absent = sorted({f"{key} at {count} flows" for _, _, _, key in METRICS if key for count in flows
                     if str(count) not in spread.get(key, {})})
    if absent and not allow_uncalibrated:
        raise ValueError(f"{calibration} has no calibration for: {', '.join(absent)}; run the calibration "
                         "or pass --allow-uncalibrated to use a zero floor")
    engines: dict[str, str] = {}
    data: dict[tuple[str, str, int], dict[str, float]] = {}
    missing: list[str] = []
    for hold in holds:
        for tag, engine in plan(hold):
            engines.setdefault(tag, engine)
            for count in flows:
                try:
                    data[(hold.name, tag, count)] = row(hold, tag, engine, count)
                except (OSError, KeyError, ValueError, ZeroDivisionError):
                    missing.append(f"{hold.name}/{tag}/{count}f")
    by_engine = {engine: tag for tag, engine in engines.items()}
    baseline = baseline or by_engine.get("kernel-plain")
    focus = focus or by_engine.get("gotatun")

    def name(tag: str) -> str:
        return NAMES.get(engines[tag], tag)

    lines = [f"**WARNING: NOT CALIBRATED ({', '.join(absent)}): the floor is 0, so every same-sign difference reads as real.**", ""] if absent else []
    lines += ["Holds: " + "; ".join(f"{hold.name}={','.join(tag for tag, _ in plan(hold))}" for hold in holds)]
    for count in flows:
        title = f"{count} flow{'s' if count > 1 else ''}"
        lines += ["", f"### {title}: absolute (mean over holds, min–max)", "",
                  "| engine | " + " | ".join(metric[1] for metric in METRICS) + " | cores used (A · B · housekeeping) | probes lost |",
                  "|---|" + "---:|" * len(METRICS) + "---|---|"]
        for tag in engines:
            rows = [data[(hold.name, tag, count)] for hold in holds if (hold.name, tag, count) in data]
            if not rows:
                continue
            cells = []
            for key, *_ in METRICS:
                values = [entry[key] for entry in rows]
                form = FORMAT[key]
                cells.append(f"{form.format(statistics.mean(values))} ({form.format(min(values))}–{form.format(max(values))})")
            used = " / ".join(f"{entry['cores']:.2f} (A {entry['side_a']:.2f} · B {entry['side_b']:.2f} · hk {entry['housekeeping']:.2f})" for entry in rows)
            lost = ", ".join(f"{entry['lost']}/{entry['sent']}" for entry in rows)
            lines.append(f"| {name(tag)} | " + " | ".join(cells) + f" | {used} | {lost} |")
        for anchor, heading, anchor_is_numerator in ((baseline, "each engine vs kernel WireGuard", False),
                                                     (focus, "GotaTun vs each rival (GotaTun ÷ rival)", True)):
            if anchor is None or anchor not in engines:
                continue
            lines += ["", f"### {title}: {heading}; within-hold Δ per hold, mean, floor, verdict", "",
                      "| pair | " + " | ".join(metric[1] for metric in METRICS) + " |",
                      "|---|" + "---|" * len(METRICS)]
            for tag in engines:
                if tag == anchor:
                    continue
                numerator, denominator = (anchor, tag) if anchor_is_numerator else (tag, anchor)
                cells = []
                for key, _, higher, calibration_key in METRICS:
                    ratios = [data[(hold.name, numerator, count)][key] / data[(hold.name, denominator, count)][key]
                              for hold in holds
                              if (hold.name, numerator, count) in data and (hold.name, denominator, count) in data
                              and data[(hold.name, denominator, count)][key]]
                    if not ratios:
                        cells.append("–")
                        continue
                    floor = spread.get(calibration_key, {}).get(str(count), 0.0) if calibration_key else 0.0
                    mean, word = verdict(ratios, floor, higher)
                    per_hold = "/".join(f"{(ratio - 1) * 100:+.1f}" for ratio in ratios)
                    cells.append(f"{mean:+.1f}% ({per_hold}; floor {floor:.1f}%) {word}")
                lines.append(f"| {name(numerator)} vs {name(denominator)} | " + " | ".join(cells) + " |")
    if missing:
        lines += ["", "Missing (failed) rows: " + ", ".join(missing)]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("calibration", type=Path)
    parser.add_argument("holds", type=Path, nargs="+")
    parser.add_argument("--baseline", help="row tag every engine is compared with (default: the kernel-plain row)")
    parser.add_argument("--focus", help="row tag compared with every rival (default: the gotatun row)")
    parser.add_argument("--flows", type=int, action="append", help="flow counts (default 1 and 8)")
    parser.add_argument("--allow-uncalibrated", action="store_true",
                        help="use a zero floor, with a loud warning, when the calibration lacks a metric")
    args = parser.parse_args()
    try:
        sys.stdout.write(report(args.calibration, args.holds, tuple(args.flows or (1, 8)), args.baseline, args.focus,
                                args.allow_uncalibrated))
    except ValueError as error:
        print(f"head_to_head: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
