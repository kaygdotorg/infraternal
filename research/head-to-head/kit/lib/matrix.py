#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Plan, collect, and report the matched WireGuard engine matrix (#260)."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCENARIOS: dict[str, dict[str, Any]] = {
    "best-lan": {
        "class": "best-case",
        "description": "LAN, 1 and 8 TCP flows, and a 1,420-byte inner IPv4 packet.",
        "inner_mtu_bytes": 1420,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    # The same LAN workload with longer sampling (#260): 15,000 probes at 5 ms last
    # 75 s inside an 85 s load, so every probe is loaded and about 150 samples sit
    # above p99. Explicit, not the default: the controls have not passed twice.
    "best-lan-15k": {
        "class": "best-case",
        "description": "LAN, 1 and 8 TCP flows, and a 1,420-byte inner IPv4 packet, sampled with 15,000 probes inside an 85 s load.",
        "inner_mtu_bytes": 1420,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 15000,
        "loaded_latency_interval_us": 5000,
        "tput_seconds": 85,
    },
    # Mobile-data profiles (#260, owner priority 2026-11-09). Delay, jitter, loss and rate are
    # configured per direction on both veth ends, so the round-trip delay is twice the
    # per-direction delay and an independent per-direction loss p gives about 2p round-trip
    # exposure. Loaded probes are ICMP (`ping -D -O -n`, 64 bytes at 5 ms), ranked loss-aware.
    "mobile-40ms-loss-1": {
        "class": "worst-case",
        "description": "Mobile data, 40 ms RTT (20 ms each direction) with independent 1% loss per direction.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 20,
        "jitter_each_direction_ms": 0,
        "loss_each_direction_percent": 1,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probe": "icmp",
        "shaping": "per-packet",
        "latency_probes": 10000,
        "loaded_latency_interval_us": 5000,
        "tput_seconds": 55,
        "idle_latency_probes": 2000,
        "idle_latency_interval_us": 10000,
    },
    "mobile-80ms-jitter-loss-2-50mbit": {
        "class": "worst-case",
        "description": "Mobile data, 80 ms RTT (40 ms each direction) with +/-10 ms jitter (netem reorders), independent 2% loss per direction, and a 50 Mbit/s rate limit per direction.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 40,
        "jitter_each_direction_ms": 10,
        "loss_each_direction_percent": 2,
        "rate_each_direction_mbit": 50,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probe": "icmp",
        "shaping": "per-packet",
        "latency_probes": 10000,
        "loaded_latency_interval_us": 5000,
        "tput_seconds": 55,
        "idle_latency_probes": 2000,
        "idle_latency_interval_us": 10000,
    },
    "mobile-150ms-gemodel-5": {
        "class": "worst-case",
        "description": "Mobile data, 150 ms RTT (75 ms each direction) with bursty loss per direction: Gilbert-Elliott, 5% average, bursts of about 5 packets (netem gemodel 1.05% 20% 100% 0%).",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 75,
        "jitter_each_direction_ms": 0,
        "loss_each_direction_percent": 5,
        "loss_gemodel": "1.05% 20% 100% 0%",
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probe": "icmp",
        "shaping": "per-packet",
        "latency_probes": 10000,
        "loaded_latency_interval_us": 5000,
        "tput_seconds": 55,
        "idle_latency_probes": 2000,
        "idle_latency_interval_us": 10000,
    },
    "wan-50ms": {
        "class": "worst-case",
        "description": "50 ms RTT, 5 ms one-way jitter bound, no configured loss.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 25,
        "jitter_each_direction_ms": 5,
        "loss_each_direction_percent": 0,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "wan-150ms-loss-0.5": {
        "class": "worst-case",
        "description": "150 ms RTT, 15 ms one-way jitter, independent 0.5% loss per direction.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 75,
        "jitter_each_direction_ms": 15,
        "loss_each_direction_percent": 0.5,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "wan-150ms-loss-2": {
        "class": "worst-case",
        "description": "150 ms RTT, 15 ms one-way jitter, independent 2% loss per direction.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 75,
        "jitter_each_direction_ms": 15,
        "loss_each_direction_percent": 2,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "wan-20ms-loss-1": {
        "class": "worst-case",
        "description": "20 ms RTT (10 ms ±5 ms per direction), independent 1% loss per direction.",
        "inner_mtu_bytes": 1420,
        "delay_each_direction_ms": 10,
        "jitter_each_direction_ms": 5,
        "loss_each_direction_percent": 1,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "small-udp": {
        "class": "worst-case",
        "description": "Unpaced 64-byte and 256-byte UDP payload packet-rate probes.",
        "inner_mtu_bytes": 1420,
        "udp_payload_bytes": [64, 256],
        "udp_probe_count": 100000,
        "idle_latency_probes": 3600,
        "idle_latency_interval_us": 1000,
    },
    "peer-scale": {
        "class": "worst-case",
        "description": "One active traffic peer plus inert peers at 1, 100, and 1,000 peers per endpoint.",
        "inner_mtu_bytes": 1420,
        "peer_counts_per_endpoint": [1, 100, 1000],
        "traffic_target": "the same active peer at every peer count",
        "tcp_flows": [1],
        "tput_seconds": 5,
        "latency_probes": 1000,
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "loaded_latency_interval_us": 5000,
    },
    "handshake-storm": {
        "class": "worst-case",
        "description": "30 forced peer resets followed by a first-packet handshake attempt after each reset.",
        "inner_mtu_bytes": 1420,
        "forced_rehandshakes": 30,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "cpu-contended": {
        "class": "worst-case",
        "description": "Same LAN workload with a single noisy process pinned to housekeeping CPU 5.",
        "inner_mtu_bytes": 1420,
        "noise_cpu": 5,
        "tcp_flows": [1, 8],
        "latency_payload_bytes": 1392,
        "latency_probes": 3600,
        "loaded_latency_interval_us": 2500,
        "tput_seconds": 10,
    },
    "idle": {
        "class": "worst-case",
        "description": "Warm tunnel idle CPU, 1,420-byte RTT, and 64/256-byte RTT probes; peer memory at 1/100/1,000.",
        "inner_mtu_bytes": 1420,
        "latency_payload_bytes": 1392,
        "latency_ip_packet_bytes": 1420,
        "latency_probes": 3600,
        "idle_latency_probes": 3600,
        "idle_latency_interval_us": 1000,
        "peer_counts_per_endpoint": [1, 100, 1000],
    },
}


def scenario_configuration(
    scenario: str, tcp_flows: Sequence[int] | None = None
) -> dict[str, Any]:
    """Return one canonical scenario, optionally narrowed to selected TCP flows."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    configuration = dict(SCENARIOS[scenario])
    if tcp_flows is None:
        return {"id": scenario, **configuration}

    configured_flows = configuration.get("tcp_flows")
    if not isinstance(configured_flows, list):
        raise ValueError(f"scenario {scenario} has no TCP-flow workload")
    if not tcp_flows or len(tcp_flows) != len(set(tcp_flows)):
        raise ValueError("select one or more unique TCP flow counts")
    if any(flow not in configured_flows for flow in tcp_flows):
        raise ValueError(
            f"scenario {scenario} supports only these TCP flow counts: {configured_flows}"
        )
    canonical_selection = [flow for flow in configured_flows if flow in tcp_flows]
    if list(tcp_flows) != canonical_selection:
        raise ValueError("TCP flow selections must keep the scenario's canonical order")
    configuration["tcp_flows"] = list(tcp_flows)
    return {"id": scenario, **configuration}


def scenario_result_key(scenario: str, configuration: dict[str, Any]) -> str:
    """Give a focused flow run its own directory so batches cannot overwrite each other."""
    flows = configuration.get("tcp_flows")
    if flows == SCENARIOS[scenario].get("tcp_flows"):
        return scenario
    if not isinstance(flows, list) or not flows:
        raise ValueError(f"scenario {scenario} has no selected TCP-flow workload")
    return f"{scenario}-tcp-flow-{'-'.join(str(flow) for flow in flows)}"


# The same three mobile profiles with the shaping the first lossy runs used: netem on each
# side's egress with offloads as found. A GSO batch is then dropped or spared as one loss
# event, so these rows are kept only to show how much that shaping flatters the userspace
# engines. Every row is labelled by scenario ID, so the shaping used is never ambiguous.
for _name in [name for name in SCENARIOS if name.startswith("mobile-")]:
    SCENARIOS[f"{_name}-legacy-egress"] = {
        **SCENARIOS[_name],
        "shaping": "legacy",
        "description": SCENARIOS[_name]["description"]
        + " Shaping: legacy (netem on the sender's egress, offloads on; a GSO batch is one loss decision).",
    }


KERNEL_ENGINE = {
    "id": "kernel-plain",
    "label": "plain kernel WireGuard",
    "runner_engine": "kernel-plain",
    "source_sha": None,
    "source_aliases": [],
}
WIREGUARD_GO_ENGINE = {
    "id": "wireguard-go",
    "label": "wireguard-go",
    "runner_engine": "wireguard-go",
    "source_sha": "b3bc704ef0ee21a36298601a9e1e5ff90377ac52",
    "source_aliases": [],
}
SHIPPED_GOTATUN_ID = "gotatun-shipped-84b7bb2"
SHIPPED_GOTATUN_ENGINE = {
    "id": SHIPPED_GOTATUN_ID,
    "label": "GotaTun (shipped, 84b7bb2)",
    "runner_engine": "gotatun",
    "source_sha": "84b7bb28e385d57dfb80493e78202898fad24d1e",
    "source_aliases": [{
        "source_sha": "2bb5347a8cddf3c31df64be1f52466e1a02bf75b",
        "note": "same data path; only equivalent Rust return-expression spelling differs",
    }],
}
J88I_GOTATUN_ID = "gotatun-j88i-33ca6fe"
J88I_GOTATUN_ENGINE = {
    "id": J88I_GOTATUN_ID,
    "label": "GotaTun (J88i fairness, 33ca6fe)",
    "runner_engine": "gotatun",
    "source_sha": "33ca6fe616587db506b16612f2a4b5bbd54997f3",
    "source_aliases": [],
}
J316_GOTATUN_ID = "gotatun-j316-b678934"
J316_GOTATUN_ENGINE = {
    "id": J316_GOTATUN_ID,
    "label": "GotaTun (J316 coalescing, pre-checksum-fix, b678934)",
    "runner_engine": "gotatun",
    "source_sha": "b6789348aea23216e0be06e93d44d6f5239318b3",
    "source_aliases": [],
}
J225_GOTATUN_ID = "gotatun-j225-j316-stack-3a70a7d21"
J225_GOTATUN_ENGINE = {
    "id": J225_GOTATUN_ID,
    "label": "GotaTun (J225 + J316 stack, release, 3a70a7d21)",
    "runner_engine": "gotatun",
    "source_sha": "3a70a7d21cb320e4d31a37d072df973ebfc37e0b",
    "source_aliases": [],
}
J324_GOTATUN_ID = "gotatun-j324-b36d575"
J324_GOTATUN_ENGINE = {
    "id": J324_GOTATUN_ID,
    "label": "GotaTun (J324 memory pools, b36d575)",
    "runner_engine": "gotatun",
    "source_sha": "b36d575a20e1f8747ca9e883afdd9aab4c9cd0c5",
    "source_aliases": [],
}
DEFAULT_ENGINE_SPECS: tuple[dict[str, Any], ...] = (
    KERNEL_ENGINE,
    WIREGUARD_GO_ENGINE,
    SHIPPED_GOTATUN_ENGINE,
    J88I_GOTATUN_ENGINE,
    J316_GOTATUN_ENGINE,
    J225_GOTATUN_ENGINE,
    J324_GOTATUN_ENGINE,
)
MATRIX_REPETITIONS = 5
DEFAULT_ENGINE_IDS = tuple(str(spec["id"]) for spec in DEFAULT_ENGINE_SPECS)
BASELINE_WINDOW_ORDERS = tuple(
    DEFAULT_ENGINE_IDS[offset:] + DEFAULT_ENGINE_IDS[:offset]
    for offset in range(MATRIX_REPETITIONS)
)
OWNER_DIRECTED_CALIBRATION_LABEL = "uncalibrated, owner-directed"
CALIBRATED_LABEL = "calibrated"


def row_calibration_label(calibration: str) -> str:
    """Name rows `calibrated` only when this run's own three controls passed the spread gate."""
    return CALIBRATED_LABEL if calibration == "passed" else OWNER_DIRECTED_CALIBRATION_LABEL
OWNER_REPORTED_PRIOR_SPREADS = [
    {"metric": "throughput_gbit_s", "flows": "8", "spread_pct": 0.813, "limit_pct": 0.8},
    {"metric": "p99_loss_aware_ms", "flows": "1", "spread_pct": 9.9, "limit_pct": 3.2},
]


def matrix_rows(
    engine_specs: Sequence[dict[str, Any]] = DEFAULT_ENGINE_SPECS,
) -> tuple[tuple[str, str], ...]:
    """Plan five equal repeats, one row per engine variant in each window."""
    engine_ids = tuple(str(spec["id"]) for spec in engine_specs)
    if engine_ids == tuple(spec["id"] for spec in DEFAULT_ENGINE_SPECS):
        orders = BASELINE_WINDOW_ORDERS
    else:
        orders = tuple(
            engine_ids[index % len(engine_ids):] + engine_ids[:index % len(engine_ids)]
            for index in range(MATRIX_REPETITIONS)
        )
    return tuple(
        (f"{engine_id}-{repeat}", engine_id)
        for repeat, order in enumerate(orders, start=1)
        for engine_id in order
    )


MATRIX_ROWS = matrix_rows()


def matrix_batches(
    engine_specs: Sequence[dict[str, Any]] = DEFAULT_ENGINE_SPECS,
) -> list[tuple[tuple[str, str], ...]]:
    """Return five counterbalanced shared-lock windows for the selected variants."""
    rows = matrix_rows(engine_specs)
    width = len(engine_specs)
    return [rows[index:index + width] for index in range(0, len(rows), width)]


def batch_part(
    batch: Sequence[tuple[str, str]], part: int | None, retry_tags: Sequence[str] | None = None,
) -> tuple[tuple[tuple[str, str], ...], str]:
    """Return one window's rows, or its first or second half, and the directory suffix.

    A four-row best-LAN window with the longer sampling takes about 22 minutes,
    over the 20-minute perf-lock cap, so `--part 1` and `--part 2` run the first
    and second half as two holds, keeping the window's row order. Results land in
    `window-NNa` and `window-NNb`; the aggregate matches rows by tag, not window.

    `retry_tags` re-runs named rows of the window (for example one that failed a
    pre-check before measuring) into `window-NNr-<tag>`. Move the failed attempt out of
    the window directories first: a tag that appears twice is reported as a
    duplicate, not averaged.
    """
    rows = tuple(batch)
    if retry_tags:
        if part is not None:
            raise ValueError("--retry-tag cannot be combined with --part")
        selected = tuple(row for row in rows if row[0] in set(retry_tags))
        if {row[0] for row in selected} != set(retry_tags):
            raise ValueError("--retry-tag names a row that is not in this window")
        # One directory per retried row, so several rows of a window can be retried separately.
        return selected, "r-" + "-".join(row[0] for row in selected)
    if part is None:
        return rows, ""
    if part not in (1, 2) or len(rows) < 2:
        raise ValueError("--part must be 1 or 2 and needs a window with at least two rows")
    half = (len(rows) + 1) // 2
    return (rows[:half], "a") if part == 1 else (rows[half:], "b")


def matrix_row_arguments(
    rows: Sequence[tuple[str, str]] = MATRIX_ROWS,
    engine_specs: Sequence[dict[str, Any]] = DEFAULT_ENGINE_SPECS,
) -> list[str]:
    """Map report variant IDs to the runner's three implementation names."""
    runner_engines = {str(spec["id"]): str(spec["runner_engine"]) for spec in engine_specs}
    return [
        argument
        for tag, engine_id in rows
        for argument in ("--row", f"{tag}={runner_engines[engine_id]}")
    ]


def load_json(path: Path) -> dict[str, Any] | None:
    """Read an evidence object; missing or malformed files stay missing."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def number(value: Any) -> float | int | None:
    """Accept finite numeric measurements without coercing booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return value


def cpu_snapshot() -> dict[str, int]:
    """Capture the same whole-machine busy jiffies used by the TCP probe."""
    lines = Path("/proc/stat").read_text(encoding="ascii").splitlines()
    fields = lines[0].split() if lines else []
    if not fields or fields[0] != "cpu" or len(fields) < 9:
        raise ValueError("/proc/stat has no aggregate CPU counters")
    counters = [int(value) for value in fields[1:9]]
    total = sum(counters)
    idle = counters[3] + counters[4]
    return {
        "monotonic_ns": time.monotonic_ns(),
        "busy_jiffies": total - idle,
        "hz": int(os.sysconf("SC_CLK_TCK")),
    }


def cpu_window_summary(before: dict[str, Any], after: dict[str, Any],
                       measurement: dict[str, Any]) -> dict[str, Any]:
    """Normalize whole-machine CPU over a UDP probe's received payload volume."""
    before_busy = before.get("busy_jiffies")
    after_busy = after.get("busy_jiffies")
    before_ns = before.get("monotonic_ns")
    after_ns = after.get("monotonic_ns")
    before_hz = before.get("hz")
    after_hz = after.get("hz")
    received = measurement.get("received")
    payload_bytes = measurement.get("payload_bytes")
    values = (before_busy, after_busy, before_ns, after_ns, before_hz, after_hz,
              received, payload_bytes)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        return {
            "status": "unavailable",
            "machine_cpu_busy_s": None,
            "machine_cpu_s_per_gbit": None,
            "machine_cores_busy": None,
            "measurement_window_s": None,
            "transferred_payload_gbit": None,
            "method": "whole-machine /proc/stat busy jiffies over the UDP probe window",
            "reason": "CPU snapshot or UDP payload fields are missing or invalid",
        }
    if (before_hz <= 0 or before_hz != after_hz or after_busy < before_busy
            or after_ns <= before_ns or received < 0 or payload_bytes < 0):
        reason = "CPU counters, clock rate, or monotonic window are inconsistent"
        return {
            "status": "unavailable",
            "machine_cpu_busy_s": None,
            "machine_cpu_s_per_gbit": None,
            "machine_cores_busy": None,
            "measurement_window_s": None,
            "transferred_payload_gbit": None,
            "method": "whole-machine /proc/stat busy jiffies over the UDP probe window",
            "reason": reason,
        }

    window_s = (after_ns - before_ns) / 1e9
    busy_s = (after_busy - before_busy) / before_hz
    transferred_gbit = received * payload_bytes * 8.0 / 1e9
    result = {
        "status": "measured" if transferred_gbit > 0 else "unavailable",
        "machine_cpu_busy_s": busy_s,
        "machine_cpu_s_per_gbit": busy_s / transferred_gbit if transferred_gbit > 0 else None,
        "machine_cores_busy": busy_s / window_s,
        "measurement_window_s": window_s,
        "transferred_payload_gbit": transferred_gbit,
        "method": "whole-machine /proc/stat busy jiffies over the UDP probe window, divided by received payload Gbit",
        "reason": None if transferred_gbit > 0 else "no UDP payload was received",
    }
    return result


def aggregate_metrics(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Summarize numeric and loss-infinite metrics from complete rows only."""
    infinite_by_row = [_infinite_latency_metrics(row) for row in rows]
    names = sorted({
        name
        for row in rows
        for name, value in row.get("metrics", {}).items()
        if isinstance(name, str) and number(value) is not None
    } | set().union(*infinite_by_row))
    summary: dict[str, dict[str, Any]] = {}
    for name in names:
        present: list[float | int] = []
        infinite_n = 0
        for index, row in enumerate(rows):
            if row.get("status") != "complete":
                continue
            if name in infinite_by_row[index]:
                infinite_n += 1
                continue
            value = number(row.get("metrics", {}).get(name))
            if value is not None:
                present.append(value)
        present.sort()
        n = len(present) + infinite_n
        median_is_infinite = False
        if n % 2:
            median_rank = n // 2
            median_is_infinite = median_rank >= len(present)
            median = None if median_is_infinite else present[median_rank]
        elif n:
            upper_rank = n // 2
            median_is_infinite = upper_rank >= len(present)
            median = None if median_is_infinite else statistics.median(present[upper_rank - 1:upper_rank + 1])
        else:
            median = None

        item: dict[str, Any] = {
            "n": n,
            "median": median,
            "min": present[0] if present else None,
            "max": present[-1] if present and not infinite_n else None,
        }
        if infinite_n:
            item.update({
                "infinite_n": infinite_n,
                "median_is_infinite": median_is_infinite,
                "min_is_infinite": not present,
                "max_is_infinite": True,
            })
        summary[name] = item
    # Preserve requested-but-unavailable syscall fields as n=0/null.
    for name in sorted({
        name for row in rows for name in row.get("metrics", {})
        if isinstance(name, str) and "syscalls_per_gbit" in name
    }):
        summary.setdefault(name, {"n": 0, "median": None, "min": None, "max": None})
    return summary


def _infinite_latency_metrics(row: dict[str, Any]) -> set[str]:
    """Map explicit unavailable latency ranks to their aggregate metric names."""
    latency = row.get("latency", {})
    if not isinstance(latency, dict):
        return set()
    references = {
        "idle_mtu": latency.get("idle_mtu"),
        "loaded_1": latency.get("loaded_tcp_1"),
        "loaded_8": latency.get("loaded_tcp_8"),
    }
    for size in (64, 256):
        references[f"idle_udp_{size}"] = latency.get(f"idle_udp_{size}")
        references[f"loaded_udp_{size}"] = latency.get(
            f"loaded_udp_{size}", latency.get(f"udp_{size}")
        )
    peer_scale = row.get("peer_scale", {})
    if isinstance(peer_scale, dict):
        for peers, record in peer_scale.items():
            if isinstance(record, dict):
                references[f"peer_{peers}_loaded"] = record.get("latency")

    infinite: set[str] = set()
    for prefix, value in references.items():
        if not isinstance(value, dict):
            continue
        ranks = value.get("infinite_at", [])
        if not isinstance(ranks, list):
            continue
        for rank, suffix in (("p50", "p50_ms"), ("p99", "p99_ms"), ("p999", "p999_ms")):
            if rank in ranks:
                infinite.add(f"{prefix}_{suffix}")
    return infinite


def _measurement(case_dir: Path, name: str) -> dict[str, Any] | None:
    return load_json(case_dir / "matrix" / f"{name}.json")


def _latency_values(data: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten the loss-aware latency summary without substituting received-only values."""
    result: dict[str, Any] = {"p50_ms": None, "p99_ms": None, "p999_ms": None}
    if not data:
        return result
    summary = data.get("loss_aware_rtt_ms", {})
    if not isinstance(summary, dict):
        return result
    received_only = data.get("rtt_ms", {})
    sent, lost = data.get("sent"), data.get("lost")
    return {
        "p50_ms": number(summary.get("p50")),
        "p99_ms": number(summary.get("p99")),
        "p999_ms": number(summary.get("p999")),
        "p99_received_ms": number(received_only.get("p99")) if isinstance(received_only, dict) else None,
        "probe_loss_pct": (
            round(100 * lost / sent, 3) if isinstance(sent, int) and sent > 0 and isinstance(lost, int) else None
        ),
        "infinite_at": summary.get("infinite_at", []),
        "sent": sent,
        "received": data.get("received"),
        "lost": lost,
    }


def collect_row(case_dir: Path, *, engine: str, tag: str, scenario: str, calibration: str) -> dict[str, Any]:
    """Build a normalized row from the case's immutable raw JSON and logs."""
    metrics: dict[str, Any] = {
        "tcp_1_gbit_s": None,
        "tcp_8_gbit_s": None,
        "tcp_1_retransmits": None,
        "tcp_8_retransmits": None,
        "tcp_1_silent_seconds": None,
        "tcp_8_silent_seconds": None,
        "tcp_1_longest_silent_s": None,
        "tcp_8_longest_silent_s": None,
        "tcp_1_zero_byte": None,
        "tcp_8_zero_byte": None,
        "tcp_1_wire_loss_pct": None,
        "tcp_8_wire_loss_pct": None,
        "tcp_1_wire_avg_bytes": None,
        "tcp_8_wire_avg_bytes": None,
        "tcp_1_wire_matches": None,
        "tcp_8_wire_matches": None,
        "udp_64_pps": None,
        "udp_256_pps": None,
        "udp_64_gbit_s": None,
        "udp_256_gbit_s": None,
        "cpu_s_per_gbit_udp_64": None,
        "cpu_s_per_gbit_udp_256": None,
        "idle_udp_64_p50_ms": None,
        "idle_udp_64_p99_ms": None,
        "idle_udp_64_p999_ms": None,
        "loaded_udp_64_p50_ms": None,
        "loaded_udp_64_p99_ms": None,
        "loaded_udp_64_p999_ms": None,
        "idle_udp_256_p50_ms": None,
        "idle_udp_256_p99_ms": None,
        "idle_udp_256_p999_ms": None,
        "loaded_udp_256_p50_ms": None,
        "loaded_udp_256_p99_ms": None,
        "loaded_udp_256_p999_ms": None,
        "idle_mtu_p50_ms": None,
        "idle_mtu_p99_ms": None,
        "idle_mtu_p999_ms": None,
        "loaded_1_p50_ms": None,
        "loaded_1_p99_ms": None,
        "loaded_1_p999_ms": None,
        "loaded_8_p50_ms": None,
        "loaded_8_p99_ms": None,
        "loaded_8_p999_ms": None,
        "idle_cpu_s_per_minute": None,
        "cpu_s_per_gbit_1": None,
        "cpu_s_per_gbit_8": None,
        "rss_idle_mib_1": None,
        "rss_idle_mib_100": None,
        "rss_idle_mib_1000": None,
        "rss_loaded_mib_1": None,
        "rss_loaded_mib_100": None,
        "rss_loaded_mib_1000": None,
        "rss_mib_1": None,
        "rss_mib_100": None,
        "rss_mib_1000": None,
        "rss_bytes_per_peer_1": None,
        "rss_bytes_per_peer_100": None,
        "rss_bytes_per_peer_1000": None,
        "kernel_memory_delta_bytes_1": None,
        "kernel_memory_delta_bytes_100": None,
        "kernel_memory_delta_bytes_1000": None,
        "kernel_memory_bytes_per_peer_1": None,
        "kernel_memory_bytes_per_peer_100": None,
        "kernel_memory_bytes_per_peer_1000": None,
        "artifact_size_bytes": None,
        "artifact_disk_bytes": None,
        "kernel_module_file_bytes": None,
        "kernel_module_disk_bytes": None,
        "kernel_image_bytes": None,
        "kernel_image_disk_bytes": None,
        "syscalls_per_gbit_1": None,
        "syscalls_per_gbit_8": None,
        "udp_64_syscalls_per_gbit": None,
        "udp_256_syscalls_per_gbit": None,
        "handshake_p50_ms": None,
        "handshake_p99_ms": None,
        "handshake_p999_ms": None,
    }
    tcp: dict[int, dict[str, Any] | None] = {}
    tcp_latency: dict[int, dict[str, Any]] = {}
    for flows in (1, 8):
        throughput = _measurement(case_dir, f"tcp-{flows}-throughput")
        latency = _latency_values(_measurement(case_dir, f"tcp-{flows}-latency"))
        tcp[flows] = throughput
        tcp_latency[flows] = latency
        metrics[f"tcp_{flows}_gbit_s"] = number((throughput or {}).get("gbit_per_s"))
        # Per-netns Tcp.RetransSegs delta written by mesh.sh around each TCP sample.
        retransmits = _measurement(case_dir, f"tcp-{flows}-retransmits")
        metrics[f"tcp_{flows}_retransmits"] = number((retransmits or {}).get("total_retransmits"))
        metrics[f"cpu_s_per_gbit_{flows}"] = number((throughput or {}).get("machine_cpu_s_per_gbit"))
        for percentile in ("p50_ms", "p99_ms", "p999_ms", "p99_received_ms", "probe_loss_pct"):
            metrics[f"loaded_{flows}_{percentile}"] = latency.get(percentile)
        # Receiver-side progress, sampled once a second, for lossy profiles: a flow can stay up
        # yet deliver nothing, which the average goodput hides.
        progress = _measurement(case_dir, f"tcp-{flows}-progress") or {}
        if progress.get("status") == "measured":
            metrics[f"tcp_{flows}_silent_seconds"] = number(progress.get("silent_seconds"))
            metrics[f"tcp_{flows}_longest_silent_s"] = number(progress.get("longest_silent_s"))
            metrics[f"tcp_{flows}_zero_byte"] = 1 if progress.get("zero_byte") else 0
        # What netem actually did to wire packets in the data direction (A to B).
        wire = ((_measurement(case_dir, f"tcp-{flows}-wire") or {}).get("ab")) or {}
        if wire.get("status") == "measured":
            metrics[f"tcp_{flows}_wire_loss_pct"] = number(wire.get("measured_loss_percent"))
            metrics[f"tcp_{flows}_wire_avg_bytes"] = number(wire.get("average_bytes_per_packet"))
            matches = wire.get("matches_configured")
            metrics[f"tcp_{flows}_wire_matches"] = None if matches is None else (1 if matches else 0)

    idle = _latency_values(_measurement(case_dir, "idle-latency-mtu"))
    for percentile in ("p50_ms", "p99_ms", "p999_ms"):
        metrics[f"idle_mtu_{percentile}"] = idle.get(percentile)

    udp_latency: dict[str, dict[str, Any]] = {}
    for size in (64, 256):
        small = _measurement(case_dir, f"udp-{size}-pps")
        idle_small = _latency_values(_measurement(case_dir, f"idle-latency-{size}"))
        loaded_small = _latency_values(small)
        udp_latency[f"idle_udp_{size}"] = idle_small
        udp_latency[f"loaded_udp_{size}"] = loaded_small
        udp_cpu = _measurement(case_dir, f"udp-{size}-cpu") or {}
        metrics[f"udp_{size}_pps"] = number((small or {}).get("rx_pps"))
        metrics[f"udp_{size}_gbit_s"] = number((small or {}).get("payload_gbit_per_s"))
        metrics[f"cpu_s_per_gbit_udp_{size}"] = number(udp_cpu.get("machine_cpu_s_per_gbit"))
        for percentile in ("p50_ms", "p99_ms", "p999_ms"):
            metrics[f"idle_udp_{size}_{percentile}"] = idle_small.get(percentile)
            metrics[f"loaded_udp_{size}_{percentile}"] = loaded_small.get(percentile)

    idle_cpu = _measurement(case_dir, "idle-cpu")
    metrics["idle_cpu_s_per_minute"] = number((idle_cpu or {}).get("cpu_s_per_minute"))

    memory_records: dict[str, Any] = {}
    loaded_memory_records: dict[str, Any] = {}
    for peers in (1, 100, 1000):
        idle_data = _measurement(case_dir, f"peer-{peers}-idle-memory")
        if idle_data is None:
            # Read older R4b result trees as idle-only evidence, never as loaded.
            idle_data = _measurement(case_dir, f"peer-{peers}-memory")
        loaded_data = _measurement(case_dir, f"peer-{peers}-loaded-memory")
        memory_records[str(peers)] = idle_data
        loaded_memory_records[str(peers)] = loaded_data
        for state, data in (("idle", idle_data), ("loaded", loaded_data)):
            rss_mib = number((data or {}).get("userspace_rss_mib"))
            pss_kb = number((data or {}).get("userspace_pss_kb"))
            pss_mib = pss_kb / 1024 if pss_kb is not None else None
            kernel_bytes = number((data or {}).get("kernel_peer_memory_bytes"))
            metrics[f"rss_{state}_mib_{peers}"] = rss_mib
            metrics[f"rss_{state}_bytes_per_peer_{peers}"] = (
                rss_mib * 1024 * 1024 / peers if rss_mib is not None else None
            )
            metrics[f"pss_{state}_mib_{peers}"] = pss_mib
            metrics[f"pss_{state}_bytes_per_peer_{peers}"] = (
                pss_mib * 1024 * 1024 / peers if pss_mib is not None else None
            )
            metrics[f"kernel_memory_{state}_delta_bytes_{peers}"] = kernel_bytes
            metrics[f"kernel_memory_{state}_bytes_per_peer_{peers}"] = (
                kernel_bytes / peers if kernel_bytes is not None else None
            )
            if state == "idle":
                # Retain the R4b field names for readers of earlier matrices.
                metrics[f"rss_mib_{peers}"] = rss_mib
                metrics[f"rss_bytes_per_peer_{peers}"] = metrics[f"rss_idle_bytes_per_peer_{peers}"]
                metrics[f"kernel_memory_delta_bytes_{peers}"] = kernel_bytes
                metrics[f"kernel_memory_bytes_per_peer_{peers}"] = metrics[f"kernel_memory_idle_bytes_per_peer_{peers}"]

    peer_scale_records: dict[str, Any] = {}
    if scenario == "peer-scale":
        for peers in (1, 100, 1000):
            throughput = _measurement(case_dir, f"peer-{peers}-throughput")
            latency = _latency_values(_measurement(case_dir, f"peer-{peers}-tcp-1-latency"))
            syscalls = _measurement(case_dir, f"peer-{peers}-tcp-1-syscalls") or {}
            peer_scale_records[str(peers)] = {
                "throughput": throughput,
                "latency": latency,
                "syscall_counters": syscalls,
            }
            metrics[f"peer_{peers}_tcp_gbit_s"] = number((throughput or {}).get("gbit_per_s"))
            metrics[f"peer_{peers}_cpu_s_per_gbit"] = number((throughput or {}).get("machine_cpu_s_per_gbit"))
            metrics[f"peer_{peers}_syscalls_per_gbit"] = number(syscalls.get("syscalls_per_gbit"))
            for percentile in ("p50_ms", "p99_ms", "p999_ms"):
                metrics[f"peer_{peers}_loaded_{percentile}"] = latency.get(percentile)

    artifacts = _measurement(case_dir, "artifacts") or {}
    metrics["artifact_size_bytes"] = number(artifacts.get("engine_binary_size_bytes"))
    metrics["artifact_disk_bytes"] = number(artifacts.get("engine_binary_disk_bytes"))
    in_kernel = artifacts.get("in_kernel_artifact", {})
    module_file = in_kernel.get("module") if isinstance(in_kernel, dict) else None
    image = in_kernel.get("kernel_image") if isinstance(in_kernel, dict) else None
    metrics["kernel_module_file_bytes"] = number((module_file or {}).get("size_bytes"))
    metrics["kernel_module_disk_bytes"] = number((module_file or {}).get("disk_bytes"))
    metrics["kernel_image_bytes"] = number((image or {}).get("size_bytes"))
    metrics["kernel_image_disk_bytes"] = number((image or {}).get("disk_bytes"))

    syscall_records: dict[str, Any] = {}
    for flows in (1, 8):
        data = _measurement(case_dir, f"tcp-{flows}-syscalls") or {}
        syscall_records[str(flows)] = data
        metrics[f"syscalls_per_gbit_{flows}"] = number(data.get("syscalls_per_gbit"))

    for size in (64, 256):
        data = _measurement(case_dir, f"udp-{size}-syscalls") or {}
        metrics[f"udp_{size}_syscalls_per_gbit"] = number(data.get("syscalls_per_gbit"))

    handshake_samples = []
    try:
        for line in (case_dir / "matrix/handshake-storm.jsonl").read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if value.get("ok") is True and number(value.get("elapsed_ms")) is not None:
                handshake_samples.append(float(value["elapsed_ms"]))
    except (OSError, ValueError):
        pass
    handshake_samples.sort()
    for name, fraction in (("p50", 0.50), ("p99", 0.99), ("p999", 0.999)):
        metrics[f"handshake_{name}_ms"] = (
            handshake_samples[max(0, math.ceil(len(handshake_samples) * fraction) - 1)]
            if handshake_samples else None
        )

    raw_files = sorted(
        str(path.relative_to(case_dir.parent.parent))
        for path in case_dir.rglob("*")
        if path.is_file() and (
            path.suffix in {".raw", ".json", ".jsonl", ".err", ".failed", ".txt"}
            or path.name in {"summary.json", "run.log"}
        )
    )
    return {
        "schema_version": 1,
        "row_tag": tag,
        "engine": engine,
        "scenario": scenario,
        "status": "complete",
        "calibration_status": calibration,
        "metrics": metrics,
        "latency": {
            "idle_mtu": idle,
            "loaded_tcp_1": tcp_latency[1],
            "loaded_tcp_8": tcp_latency[8],
            **udp_latency,
        },
        "throughput": {str(flows): tcp[flows] for flows in tcp},
        "peer_memory": memory_records,
        "peer_memory_loaded": loaded_memory_records,
        "peer_scale": peer_scale_records,
        "artifacts": artifacts,
        "initial_handshake": _measurement(case_dir, "warmup"),
        "syscall_counters": syscall_records,
        "measurements": raw_files,
    }


def aggregate_rows(
    scenario_root: Path,
    scenario: str,
    calibration: str,
    calibration_evidence: dict[str, Any] | None = None,
    engine_specs: Sequence[dict[str, Any]] = DEFAULT_ENGINE_SPECS,
    row_order: Sequence[tuple[str, str]] | None = None,
    scenario_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate all selected variants and retain absent, duplicate, and failed rows."""
    scenario_root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    planned_rows = tuple(row_order or matrix_rows(engine_specs))
    scenario_record = scenario_config or scenario_configuration(scenario)
    spec_by_id = {str(spec["id"]): spec for spec in engine_specs}
    window_roots = sorted(
        (path for path in scenario_root.glob("window-*") if path.is_dir()),
        key=lambda path: path.name,
    )
    for tag, engine_id in planned_rows:
        spec = spec_by_id[engine_id]
        implementation = str(spec["runner_engine"])
        candidates = [
            (window / tag / f"mesh-{implementation}", window.name)
            for window in window_roots
            if (window / tag / f"mesh-{implementation}").is_dir()
        ]
        legacy_case = scenario_root / tag / f"mesh-{implementation}"
        if legacy_case.is_dir():
            candidates.append((legacy_case, "unwindowed"))

        # A failed attempt that did not measure (for example a pre-check) is
        # superseded by exactly one completed retry of the same tag; two completed
        # attempts, or no completed one, stay a reported duplicate.
        superseded: list[str] = []
        completed: list[tuple[Path, str]] = []
        if len(candidates) > 1:
            completed = [
                candidate for candidate in candidates
                if (load_json(candidate[0] / "status.json") or {}).get("exit") == 0
                and (candidate[0] / "matrix-row.json").is_file()
            ]
            if len(completed) == 1:
                superseded = [name for case, name in candidates if (case, name) != completed[0]]
                candidates = completed
        if len(candidates) > 1:
            row = {
                "schema_version": 2,
                "row_tag": tag,
                "engine": engine_id,
                "implementation": implementation,
                "scenario": scenario,
                "status": "failed",
                "failure_reason": (
                    "duplicate row tag appears in multiple measurement windows"
                    if len(completed) > 1 else
                    f"no completed attempt among {len(candidates)} attempts: "
                    + ", ".join(name for _, name in candidates)
                ),
                "calibration_status": calibration,
                "metrics": {},
                "measurements": [],
            }
        elif candidates:
            case_dir, window_name = candidates[0]
            row = load_json(case_dir / "matrix-row.json")
            case_status = load_json(case_dir / "status.json")
            if row is not None:
                row["window"] = window_name
                if superseded:
                    row["superseded_failed_attempts"] = superseded
                if window_name != "unwindowed":
                    row["measurements"] = [
                        f"{window_name}/{path}"
                        for path in row.get("measurements", [])
                    ]
                if case_status is None:
                    row["status"] = "failed-or-missing"
                    row["case_exit_code"] = None
                elif case_status.get("exit") != 0:
                    row["status"] = "failed"
                    row["case_exit_code"] = case_status.get("exit")
        else:
            row = None
        if row is None:
            row = {
                "schema_version": 2,
                "row_tag": tag,
                "engine": engine_id,
                "implementation": implementation,
                "scenario": scenario,
                "status": "failed-or-missing",
                "calibration_status": calibration,
                "metrics": {},
                "measurements": [],
            }
        else:
            row["schema_version"] = 2
            row["implementation"] = implementation
            row["engine"] = engine_id
        row["engine_label"] = str(spec["label"])
        row["source_sha"] = spec.get("source_sha")
        row["source_aliases"] = spec.get("source_aliases", [])
        row["binary_sha256"] = spec.get("binary_sha256")
        rows.append(row)

    engines: dict[str, dict[str, Any]] = {}
    for spec in engine_specs:
        engine_id = str(spec["id"])
        selected = [row for row in rows if row["engine"] == engine_id]
        engines[engine_id] = {
            "label": str(spec["label"]),
            "implementation": str(spec["runner_engine"]),
            "source_sha": spec.get("source_sha"),
            "source_aliases": spec.get("source_aliases", []),
            "binary_sha256": spec.get("binary_sha256"),
            "repeat_count": len(selected),
            "complete_count": sum(row.get("status") == "complete" for row in selected),
            "metrics": aggregate_metrics(selected),
        }

    result = {
        "schema_version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario_record,
        "calibration_status": calibration,
        "calibration_evidence": calibration_evidence or {},
        "engine_order": [
            {key: value for key, value in spec.items() if key != "binary_path"}
            for spec in engine_specs
        ],
        "row_order": [
            {
                "tag": tag,
                "engine": engine_id,
                "implementation": spec_by_id[engine_id]["runner_engine"],
                "source_sha": spec_by_id[engine_id].get("source_sha"),
            }
            for tag, engine_id in planned_rows
        ],
        "windows": [window.name for window in window_roots],
        "engines": engines,
        "rows": rows,
    }
    (scenario_root / "matrix.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (scenario_root / "summary.md").write_text(render_summary(result), encoding="utf-8")
    return result


TABLE_METRICS = (
    ("TCP Gbit/s 1 / 8", ("tcp_1_gbit_s", "tcp_8_gbit_s"), 3),
    ("TCP retransmits 1 / 8", ("tcp_1_retransmits", "tcp_8_retransmits"), 0),
    ("UDP pps 64 / 256", ("udp_64_pps", "udp_256_pps"), 0),
    ("UDP payload Gbit/s 64 / 256", ("udp_64_gbit_s", "udp_256_gbit_s"), 3),
    ("idle MTU p50 / p99 / p99.9 ms", ("idle_mtu_p50_ms", "idle_mtu_p99_ms", "idle_mtu_p999_ms"), 3),
    ("UDP 64 idle p50 / p99 / p99.9 ms", ("idle_udp_64_p50_ms", "idle_udp_64_p99_ms", "idle_udp_64_p999_ms"), 3),
    ("UDP 64 loaded p50 / p99 / p99.9 ms", ("loaded_udp_64_p50_ms", "loaded_udp_64_p99_ms", "loaded_udp_64_p999_ms"), 3),
    ("UDP 256 idle p50 / p99 / p99.9 ms", ("idle_udp_256_p50_ms", "idle_udp_256_p99_ms", "idle_udp_256_p999_ms"), 3),
    ("UDP 256 loaded p50 / p99 / p99.9 ms", ("loaded_udp_256_p50_ms", "loaded_udp_256_p99_ms", "loaded_udp_256_p999_ms"), 3),
    ("loaded 1-flow p50 / p99 / p99.9 ms", ("loaded_1_p50_ms", "loaded_1_p99_ms", "loaded_1_p999_ms"), 3),
    ("loaded 8-flow p50 / p99 / p99.9 ms", ("loaded_8_p50_ms", "loaded_8_p99_ms", "loaded_8_p999_ms"), 3),
    ("TCP CPU s/Gbit 1 / 8", ("cpu_s_per_gbit_1", "cpu_s_per_gbit_8"), 4),
    ("UDP CPU s/Gbit 64 / 256", ("cpu_s_per_gbit_udp_64", "cpu_s_per_gbit_udp_256"), 4),
    ("idle CPU s/min", ("idle_cpu_s_per_minute",), 4),
    ("RSS idle MiB 1 / 100 / 1,000 peers", (
        "rss_idle_mib_1", "rss_idle_mib_100", "rss_idle_mib_1000",
    ), 2),
    ("RSS loaded MiB 1 / 100 / 1,000 peers", (
        "rss_loaded_mib_1", "rss_loaded_mib_100", "rss_loaded_mib_1000",
    ), 2),
    ("userspace PSS idle MiB 1 / 100 / 1,000 peers", (
        "pss_idle_mib_1", "pss_idle_mib_100", "pss_idle_mib_1000",
    ), 2),
    ("userspace PSS loaded MiB 1 / 100 / 1,000 peers", (
        "pss_loaded_mib_1", "pss_loaded_mib_100", "pss_loaded_mib_1000",
    ), 2),
    ("userspace RSS bytes per peer, idle at 1 / 100 / 1,000", (
        "rss_idle_bytes_per_peer_1", "rss_idle_bytes_per_peer_100", "rss_idle_bytes_per_peer_1000",
    ), 0),
    ("userspace RSS bytes per peer, loaded at 1 / 100 / 1,000", (
        "rss_loaded_bytes_per_peer_1", "rss_loaded_bytes_per_peer_100", "rss_loaded_bytes_per_peer_1000",
    ), 0),
    ("userspace PSS bytes per peer, idle at 1 / 100 / 1,000", (
        "pss_idle_bytes_per_peer_1", "pss_idle_bytes_per_peer_100", "pss_idle_bytes_per_peer_1000",
    ), 0),
    ("userspace PSS bytes per peer, loaded at 1 / 100 / 1,000", (
        "pss_loaded_bytes_per_peer_1", "pss_loaded_bytes_per_peer_100", "pss_loaded_bytes_per_peer_1000",
    ), 0),
    ("kernel memory idle delta bytes 1 / 100 / 1,000 (basis per row)", (
        "kernel_memory_idle_delta_bytes_1", "kernel_memory_idle_delta_bytes_100",
        "kernel_memory_idle_delta_bytes_1000",
    ), 0),
    ("kernel memory loaded delta bytes 1 / 100 / 1,000 (basis per row)", (
        "kernel_memory_loaded_delta_bytes_1", "kernel_memory_loaded_delta_bytes_100",
        "kernel_memory_loaded_delta_bytes_1000",
    ), 0),
    ("kernel memory idle bytes per peer at 1 / 100 / 1,000 (basis per row)", (
        "kernel_memory_idle_bytes_per_peer_1", "kernel_memory_idle_bytes_per_peer_100",
        "kernel_memory_idle_bytes_per_peer_1000",
    ), 1),
    ("kernel memory loaded bytes per peer at 1 / 100 / 1,000 (basis per row)", (
        "kernel_memory_loaded_bytes_per_peer_1", "kernel_memory_loaded_bytes_per_peer_100",
        "kernel_memory_loaded_bytes_per_peer_1000",
    ), 1),
    ("binary bytes / allocated bytes", ("artifact_size_bytes", "artifact_disk_bytes"), 0),
    ("kernel module size / disk bytes; kernel image size / disk bytes", (
        "kernel_module_file_bytes", "kernel_module_disk_bytes",
        "kernel_image_bytes", "kernel_image_disk_bytes",
    ), 0),
    ("syscalls/Gbit 1 / 8", ("syscalls_per_gbit_1", "syscalls_per_gbit_8"), 0),
    ("UDP syscalls/Gbit 64 B / 256 B", (
        "udp_64_syscalls_per_gbit", "udp_256_syscalls_per_gbit",
    ), 0),
    ("handshake first packet p50 / p99 / p99.9 ms", ("handshake_p50_ms", "handshake_p99_ms", "handshake_p999_ms"), 3),
    ("TCP Gbit/s at 1 / 100 / 1,000 peers", ("peer_1_tcp_gbit_s", "peer_100_tcp_gbit_s", "peer_1000_tcp_gbit_s"), 3),
    ("loaded 1-flow peer-scale p50 / p99 / p99.9 ms at 1 / 100 / 1,000 peers", (
        "peer_1_loaded_p50_ms", "peer_1_loaded_p99_ms", "peer_1_loaded_p999_ms",
        "peer_100_loaded_p50_ms", "peer_100_loaded_p99_ms", "peer_100_loaded_p999_ms",
        "peer_1000_loaded_p50_ms", "peer_1000_loaded_p99_ms", "peer_1000_loaded_p999_ms",
    ), 3),
    ("CPU s/Gbit at 1 / 100 / 1,000 peers", (
        "peer_1_cpu_s_per_gbit", "peer_100_cpu_s_per_gbit", "peer_1000_cpu_s_per_gbit",
    ), 4),
    ("syscalls/Gbit at 1 / 100 / 1,000 peers", (
        "peer_1_syscalls_per_gbit", "peer_100_syscalls_per_gbit", "peer_1000_syscalls_per_gbit",
    ), 0),
)


def _fmt(value: Any, digits: int) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}" if isinstance(value, (int, float)) else str(value)


def _fmt_metric(value: dict[str, Any] | None, digits: int) -> str:
    """Render JSON-safe infinite medians explicitly in the human table."""
    if value and value.get("median_is_infinite") is True:
        return "∞"
    return _fmt(value.get("median") if value else None, digits)


def _format_percent(value: Any) -> str:
    """Format calibration spreads without implying precision beyond the report."""
    numeric = number(value)
    if numeric is None:
        return "unavailable"
    return f"{numeric:.3f}".rstrip("0").rstrip(".")


def _calibration_spread_text(evidence: dict[str, Any]) -> str:
    """Render measured and owner-reported spread beside the diagnostic row label."""
    measured = evidence.get("spread_pct", {})
    limits = evidence.get("spread_limits_pct", {})
    metric_labels = {
        "throughput_gbit_s": "throughput",
        "p99_loss_aware_ms": "loss-aware p99",
    }
    values = []
    if isinstance(measured, dict) and isinstance(limits, dict):
        for metric, label in metric_labels.items():
            spreads = measured.get(metric, {})
            metric_limits = limits.get(metric, {})
            if not isinstance(spreads, dict) or not isinstance(metric_limits, dict):
                continue
            for flows in ("1", "8"):
                if flows not in spreads and flows not in metric_limits:
                    continue
                spread = _format_percent(spreads.get(flows))
                limit = _format_percent(metric_limits.get(flows))
                values.append(f"{flows}-flow {label} spread {spread}% (limit {limit}%)")
    measured_text = "; ".join(values) if values else "measured spread unavailable"

    owner_values = []
    for item in evidence.get("owner_reported_prior_spreads", []):
        if not isinstance(item, dict):
            continue
        label = metric_labels.get(item.get("metric"), str(item.get("metric", "metric")))
        flows = item.get("flows", "?")
        spread = _format_percent(item.get("spread_pct"))
        limit = _format_percent(item.get("limit_pct"))
        owner_values.append(f"owner-reported prior {flows}-flow {label} {spread}% (limit {limit}%)")
    if owner_values:
        measured_text += "; " + "; ".join(owner_values)
    status = evidence.get("status", "unavailable")
    return f"Control calibration: **{status}**; {measured_text}."


def render_summary(result: dict[str, Any]) -> str:
    """Render one comparable table and state its calibration/audit limits."""
    scenario = result["scenario"]
    engine_order = result.get("engine_order")
    if not isinstance(engine_order, list):
        fallback_labels = {
            "kernel-plain": "plain kernel WireGuard",
            "wireguard-go": "wireguard-go",
            "gotatun": "GotaTun",
        }
        engine_order = [
            {"id": engine_id, "label": fallback_labels.get(engine_id, engine_id)}
            for engine_id in result.get("engines", {})
        ]
    engine_names = [(str(spec["id"]), str(spec["label"])) for spec in engine_order]
    source_shas = {str(spec["id"]): spec.get("source_sha") for spec in engine_order}
    row_label = result.get("row_calibration_label", result.get("calibration_status", "uncalibrated"))
    calibration_evidence = result.get("calibration_evidence", {})
    lines = [
        f"# {scenario['id']} matched engine matrix",
        "",
        scenario["description"],
        "",
    ]
    if isinstance(scenario.get("tcp_flows"), list):
        flow_counts = " / ".join(str(flow) for flow in scenario["tcp_flows"])
        lines.extend((f"TCP flow counts measured: {flow_counts}.", ""))
    lines.extend((
        f"Row label: **{row_label}**. { _calibration_spread_text(calibration_evidence) if calibration_evidence else 'Control calibration spread: unavailable.' } Rows use the same MTU (1,420), scenario probes, D348 pinning, and fixed order.",
        "",
        "Engine values are medians across complete repeated rows; `n/a` means not measured or unavailable, never zero. Loaded peer-count memory is measured in the peer-scale scenario with the same active one-flow workload for every row. Full row values, audit summaries, and raw logs are in `matrix.json` and the row directories.",
        "",
        "| Metric | " + " | ".join(name for _, name in engine_names) + " |",
        "|---|" + "|".join(["---:"] * len(engine_names)) + "|",
    ))
    for title, names, digits in TABLE_METRICS:
        cells = []
        for engine, _ in engine_names:
            metrics = result["engines"][engine]["metrics"]
            cells.append(" / ".join(
                _fmt_metric(metrics.get(metric), digits)
                for metric in names
            ))
        lines.append(f"| {title} | " + " | ".join(cells) + " |")
    source_cells = []
    for engine, _ in engine_names:
        source_sha = source_shas.get(engine)
        if source_sha:
            source_cells.append(f"`{source_sha}`")
        elif engine == "kernel-plain":
            source_cells.append("host kernel (recorded in run JSON)")
        else:
            source_cells.append("not recorded")
    lines.append("| Source SHA | " + " | ".join(source_cells) + " |")
    rows = [result["engines"][engine] for engine, _ in engine_names]
    lines.append("| Complete rows | " + " | ".join(
        f"{row['complete_count']}/{row['repeat_count']}" for row in rows
    ) + " |")
    lines.extend((
        "",
        "Kernel memory uses a WireGuard-named `/proc/slabinfo` cache delta when available, otherwise a labeled system-wide `/proc/meminfo` Slab delta that is not per-peer attributed. Userspace RSS sums both endpoint processes. Binary allocation is filesystem blocks allocated, while binary size is logical file size. Per-row JSON retains the memory basis and whether syscall counters were available.",
        "",
    ))
    return "\n".join(lines)


def parse_assignments(values: Sequence[str], field: str) -> dict[str, str]:
    """Parse repeated ID=value CLI entries without losing spaces in values."""
    assignments: dict[str, str] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise ValueError(f"{field} entries must use ID=VALUE: {item!r}")
        if key in assignments:
            raise ValueError(f"duplicate {field} entry for {key}")
        assignments[key] = value
    return assignments


def public_engine_specs(engine_specs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep source and artifact identity while omitting transient local paths."""
    return [
        {key: value for key, value in spec.items() if key != "binary_path"}
        for spec in engine_specs
    ]


def matrix_engine_specs(args: argparse.Namespace, kit: Path) -> list[dict[str, Any]]:
    """Bind the shared controls and selected SHA-labeled GotaTun binaries."""
    binaries = parse_assignments(args.gotatun_binary, "--gotatun-binary")
    sources = parse_assignments(args.source, "--source")
    labels = parse_assignments(args.engine_label, "--engine-label")
    if set(binaries) != set(sources):
        raise ValueError("--gotatun-binary and --source must name the same variant IDs")
    if set(labels) - set(binaries):
        raise ValueError("--engine-label names a variant without a --gotatun-binary")
    fixed_sources = (
        SHIPPED_GOTATUN_ENGINE,
        J88I_GOTATUN_ENGINE,
        J316_GOTATUN_ENGINE,
        J225_GOTATUN_ENGINE,
        J324_GOTATUN_ENGINE,
    )
    fixed_source_shas = {str(spec["id"]): str(spec["source_sha"]) for spec in fixed_sources}
    for engine_id, expected_sha in fixed_source_shas.items():
        if engine_id in sources and sources[engine_id].lower() != expected_sha:
            raise ValueError(f"{engine_id} must use its pinned source SHA {expected_sha}")

    # Do not count the data-path alias as a second GotaTun candidate.
    alias_sources = {
        str(alias["source_sha"]).lower()
        for alias in SHIPPED_GOTATUN_ENGINE["source_aliases"]
    }
    duplicate_aliases = [
        engine_id
        for engine_id, source_sha in sources.items()
        if engine_id != SHIPPED_GOTATUN_ID and source_sha.lower() in alias_sources
    ]
    if duplicate_aliases:
        raise ValueError(
            "source alias has the shipped GotaTun data path and must not be measured twice: "
            + ", ".join(duplicate_aliases)
        )
    required_variants = {
        SHIPPED_GOTATUN_ID,
        J88I_GOTATUN_ID,
        J316_GOTATUN_ID,
        J225_GOTATUN_ID,
        J324_GOTATUN_ID,
    }
    selected_variants = getattr(args, "select_gotatun", None)
    if selected_variants is None:
        selected_ids = required_variants
    else:
        if len(selected_variants) != len(set(selected_variants)):
            raise ValueError("--select-gotatun IDs must be unique")
        selected_ids = set(selected_variants)
        # A private build may use its own ID when its executable and full source
        # SHA are supplied together; the missing-pair check below rejects
        # incomplete rows, and fixed IDs keep their pinned source SHAs.
        if SHIPPED_GOTATUN_ID not in selected_ids:
            raise ValueError("every selected matrix must include the shipped 84b7bb2 baseline")
    missing_variants = sorted(selected_ids - set(binaries))
    if missing_variants:
        requirement = "selected" if selected_variants is not None else "full matrix"
        if requirement == "full matrix":
            raise ValueError("the full matrix requires every pinned GotaTun source row; missing: "
                             + ", ".join(missing_variants))
        raise ValueError("selected GotaTun rows have no binary/source pair: " + ", ".join(missing_variants))

    if args.calibration_variant not in selected_ids:
        raise ValueError("--calibration-variant must be included in the selected GotaTun rows")

    specs = [dict(KERNEL_ENGINE), dict(WIREGUARD_GO_ENGINE)]
    variant_order = list(selected_variants) if selected_variants is not None else [
        str(spec["id"]) for spec in DEFAULT_ENGINE_SPECS if spec["id"] in required_variants
    ]
    for engine_id in variant_order:
        raw_path = binaries[engine_id]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", engine_id):
            raise ValueError(f"invalid GotaTun variant ID: {engine_id}")
        source_sha = sources[engine_id].lower()
        if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
            raise ValueError(f"{engine_id} source SHA must be a full 40-character commit")
        binary = Path(raw_path).resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"GotaTun binary for {engine_id} is not executable: {binary}")
        default_labels = {
            SHIPPED_GOTATUN_ID: SHIPPED_GOTATUN_ENGINE["label"],
            J88I_GOTATUN_ID: J88I_GOTATUN_ENGINE["label"],
            J316_GOTATUN_ID: J316_GOTATUN_ENGINE["label"],
            J225_GOTATUN_ID: J225_GOTATUN_ENGINE["label"],
            J324_GOTATUN_ID: J324_GOTATUN_ENGINE["label"],
        }
        default_label = default_labels.get(engine_id, f"GotaTun ({engine_id})")
        label = labels.get(engine_id, default_label)
        if "|" in label or "\n" in label or "\r" in label:
            raise ValueError(f"engine label contains a Markdown table separator: {engine_id}")
        aliases = SHIPPED_GOTATUN_ENGINE["source_aliases"] if engine_id == SHIPPED_GOTATUN_ID else []
        specs.append({
            "id": engine_id,
            "label": label,
            "runner_engine": "gotatun",
            "source_sha": source_sha,
            "source_aliases": aliases,
            "binary_path": str(binary),
            "binary_sha256": _sha256(binary),
        })

    if args.calibration_variant not in binaries:
        raise ValueError("--calibration-variant must name a supplied GotaTun binary")
    wg_binary = Path(args.wg_bin).resolve() if args.wg_bin else kit / "bin/wg"
    wireguard_go_binary = Path(args.wireguard_go_bin).resolve() if args.wireguard_go_bin else kit / "bin/wireguard-go"
    if not wg_binary.is_file() or not os.access(wg_binary, os.X_OK):
        raise ValueError(f"wireguard-tools binary is not executable: {wg_binary}")
    if not wireguard_go_binary.is_file() or not os.access(wireguard_go_binary, os.X_OK):
        raise ValueError(f"wireguard-go binary is not executable: {wireguard_go_binary}")
    specs[0]["binary_sha256"] = _sha256(wg_binary)
    specs[0]["binary_path"] = str(wg_binary)
    specs[1]["binary_sha256"] = _sha256(wireguard_go_binary)
    specs[1]["binary_path"] = str(wireguard_go_binary)
    return specs


def order_engine_specs(
    engine_specs: Sequence[dict[str, Any]],
    engine_order: Sequence[str] | None,
) -> list[dict[str, Any]]:
    """Apply a complete first-window order before the runner rotates repeats."""
    specs_by_id = {str(spec["id"]): dict(spec) for spec in engine_specs}
    if engine_order is None:
        return list(engine_specs)
    if len(engine_order) != len(set(engine_order)) or set(engine_order) != set(specs_by_id):
        raise ValueError("--engine-order must name every measured engine ID exactly once")
    return [specs_by_id[engine_id] for engine_id in engine_order]


def run_matrix(args: argparse.Namespace) -> int:
    """Run one calibrated shared-lock window with its counterbalanced row order."""
    kit = Path(args.kit).resolve()
    output = Path(args.out).resolve()
    engine_specs = order_engine_specs(
        matrix_engine_specs(args, kit), getattr(args, "engine_order", None)
    )
    spec_by_id = {str(spec["id"]): spec for spec in engine_specs}
    batches = matrix_batches(engine_specs)
    # A run may plan fewer than five windows (--windows); the table then expects only those rows.
    planned_rows = matrix_rows(engine_specs)[: (getattr(args, "windows", None) or MATRIX_REPETITIONS) * len(engine_specs)]
    if args.calibration_only and not args.calibrate:
        raise ValueError("--calibration-only requires calibration to be enabled")
    scenario_config = None
    scenario_key = None
    if not args.calibration_only:
        if args.batch is None:
            raise ValueError(f"run one shared-lock window at a time with --batch 1..{MATRIX_REPETITIONS}")
        if args.scenario == "all":
            raise ValueError("announce each scenario window separately; --scenario all is not supported for one lock window")
        scenario_config = scenario_configuration(args.scenario, getattr(args, "tcp_flow", None))
        scenario_key = scenario_result_key(args.scenario, scenario_config)

    def invoke(argv: list[str], log: Path) -> int:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(argv, cwd=kit, stdout=stream, stderr=subprocess.STDOUT, check=False)
        return completed.returncode

    calibration_spec = spec_by_id[args.calibration_variant]
    calibration_binary = Path(calibration_spec["binary_path"])
    calibration_source = str(calibration_spec["source_sha"])
    if args.calibrate and getattr(args, "skip_calibration", False):
        # Lossy profiles have no control calibration (its limits are LAN spreads): record
        # that it was not run, so the rows keep the owner-directed label.
        if output.exists():
            raise ValueError(f"results directory already exists: {output}")
        calibration_dir = output / "calibration"
        calibration_dir.mkdir(parents=True)
        calibration = "not-run"
        calibration_record = {
            "status": calibration,
            "exit_code": None,
            "report": None,
            "variant_id": args.calibration_variant,
            "source": calibration_source,
            "binary_sha256": calibration_spec["binary_sha256"],
            "row_label": row_calibration_label(calibration),
            "owner_reported_prior_spreads": OWNER_REPORTED_PRIOR_SPREADS,
        }
        (calibration_dir / "calibration-status.json").write_text(
            json.dumps(calibration_record, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )
    elif args.calibrate:
        if output.exists():
            raise ValueError(f"results directory already exists: {output}")
        output.mkdir(parents=True)
        calibration_dir = output / "calibration"
        argv = [
            str(kit / "perf-all.sh"), "--calibration",
            "--row", "control-a=gotatun", "--row", "control-b=gotatun", "--row", "control-c=gotatun",
            "--binary", f"control-a={calibration_binary}",
            "--binary", f"control-b={calibration_binary}",
            "--binary", f"control-c={calibration_binary}",
            "--source", f"control-a={calibration_source}",
            "--source", f"control-b={calibration_source}",
            "--source", f"control-c={calibration_source}",
            "--out", str(calibration_dir),
        ]
        calibration_exit = invoke(argv, output / "calibration-driver.log")
        report = load_json(calibration_dir / "calibration-spread.json")
        calibration = "passed" if calibration_exit == 0 and report and report.get("passed") else "failed"
        calibration_record = {
            "status": calibration,
            "exit_code": calibration_exit,
            "report": report,
            "variant_id": args.calibration_variant,
            "source": calibration_source,
            "binary_sha256": calibration_spec["binary_sha256"],
            "row_label": row_calibration_label(calibration),
            "owner_reported_prior_spreads": OWNER_REPORTED_PRIOR_SPREADS,
        }
        (calibration_dir / "calibration-status.json").write_text(
            json.dumps(calibration_record, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )
    else:
        if not output.is_dir():
            raise ValueError(f"run root with calibration evidence does not exist: {output}")
        calibration_record = load_json(output / "calibration" / "calibration-status.json") or {}
        if calibration_record.get("variant_id") != args.calibration_variant:
            raise ValueError("run calibration variant does not match the saved control")
        if calibration_record.get("source") != calibration_source:
            raise ValueError("run calibration source SHA does not match the saved control")
        if calibration_record.get("binary_sha256") != calibration_spec["binary_sha256"]:
            raise ValueError("GotaTun calibration binary does not match the saved control")
        calibration = str(calibration_record.get("status", "failed"))

    report = calibration_record.get("report")
    calibration_evidence = {
        "status": calibration,
        "spread_pct": report.get("spread_pct") if isinstance(report, dict) else None,
        "spread_limits_pct": report.get("spread_limits_pct") if isinstance(report, dict) else None,
        "exceedances": report.get("exceedances", []) if isinstance(report, dict) else [],
        "owner_reported_prior_spreads": OWNER_REPORTED_PRIOR_SPREADS,
    }
    public_specs = public_engine_specs(engine_specs)
    overall: dict[str, Any] = {
        "schema_version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "engine_specs": public_specs,
        "calibration_variant": args.calibration_variant,
        "kit_source_commit": (
            (kit / "SOURCE_COMMIT").read_text(encoding="utf-8").strip()
            if (kit / "SOURCE_COMMIT").is_file() else None
        ),
        "kit_manifest_sha256": _sha256(kit / "MANIFEST") if (kit / "MANIFEST").is_file() else None,
        "calibration_status": calibration,
        "row_calibration_label": row_calibration_label(calibration),
        "calibration_evidence": calibration_evidence,
        "scenario_ids": list(SCENARIOS),
        "scenarios": {},
    }
    overall_path = output / "matrix.json"
    if not args.calibrate:
        existing = load_json(overall_path)
        if existing is None:
            raise ValueError(f"run root has no matrix metadata: {overall_path}")
        if existing.get("engine_specs") != public_specs:
            raise ValueError("run engine variants, source SHAs, or binary hashes differ from calibration")
        overall["created_at"] = existing.get("created_at", overall["created_at"])
        overall["scenarios"] = existing.get("scenarios", {})

    if args.calibration_only:
        overall["calibration_only"] = True
        overall_path.write_text(json.dumps(overall, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (output / "summary.md").write_text(render_run_summary(overall), encoding="utf-8")
        return 0

    batch_number = args.batch
    batch, part_suffix = batch_part(
        batches[batch_number - 1], getattr(args, "part", None), getattr(args, "retry_tag", None)
    )
    scenario = args.scenario
    assert scenario_config is not None and scenario_key is not None
    scenario_root = output / scenario_key
    scenario_root.mkdir(parents=True, exist_ok=True)
    window_root = scenario_root / f"window-{batch_number:02d}{part_suffix}"
    if window_root.exists():
        raise ValueError(f"measurement window already exists: {window_root}")
    flow_args = [
        part
        for flow in (getattr(args, "tcp_flow", None) or [])
        for part in ("--tcp-flow", str(flow))
    ]
    argv = [
        str(kit / "perf-all.sh"), "--matrix", "--scenario", scenario, *flow_args,
        "--calibration-status", row_calibration_label(calibration),
        "--label", f"shipped {calibration_source}; {row_calibration_label(calibration)}; calibration {calibration}",
        *matrix_row_arguments(batch, engine_specs),
        "--wg-bin", str(spec_by_id["kernel-plain"]["binary_path"]),
        "--wireguard-go-bin", str(spec_by_id["wireguard-go"]["binary_path"]),
        "--out", str(window_root),
    ]
    if part_suffix:
        argv.insert(argv.index("--out"), "--partial")
    for tag, engine_id in batch:
        spec = spec_by_id[engine_id]
        if spec["runner_engine"] == "gotatun":
            argv.extend(("--binary", f"{tag}={spec['binary_path']}", "--source", f"{tag}={spec['source_sha']}"))
    status = invoke(argv, scenario_root / f"{window_root.name}.driver.log")
    window_status_path = scenario_root / "window-status.json"
    window_status = load_json(window_status_path) or {}
    window_status[window_root.name] = status
    window_status_path.write_text(json.dumps(window_status, indent=2, allow_nan=False) + "\n", encoding="utf-8")

    aggregate = aggregate_rows(
        scenario_root, scenario, row_calibration_label(calibration), calibration_evidence,
        engine_specs, planned_rows, scenario_config=scenario_config,
    )
    aggregate["row_calibration_label"] = row_calibration_label(calibration)
    aggregate["window_driver_exit_codes"] = window_status
    aggregate["latest_window_exit_code"] = status
    (scenario_root / "matrix.json").write_text(json.dumps(aggregate, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (scenario_root / "summary.md").write_text(render_summary(aggregate), encoding="utf-8")

    overall["scenarios"][scenario_key] = {
        "scenario": scenario_config,
        "complete_rows": sum(row.get("status") == "complete" for row in aggregate["rows"]),
        "expected_rows": len(planned_rows),
        "window_driver_exit_codes": window_status,
        "matrix_json": f"{scenario_key}/matrix.json",
        "summary_markdown": f"{scenario_key}/summary.md",
    }
    overall["calibration_only"] = False
    overall_path.write_text(json.dumps(overall, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output / "summary.md").write_text(render_run_summary(overall), encoding="utf-8")
    return 1 if status else 0


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render_run_summary(result: dict[str, Any]) -> str:
    """Link each scenario's table and its explicit hold status."""
    row_label = result.get("row_calibration_label", "uncalibrated")
    lines = ["# Matched WireGuard engine matrix", "", f"Row label: **{row_label}**. Control calibration: **{result['calibration_status']}**.", "",
             "| Scenario | Complete rows | Windows | Table |", "|---|---:|---:|---|"]
    for scenario, value in result["scenarios"].items():
        windows = ", ".join(f"{name}:{code}" for name, code in sorted(value["window_driver_exit_codes"].items()))
        lines.append(f"| {scenario} | {value['complete_rows']}/{value['expected_rows']} | {windows or 'pending'} | [{scenario}/summary.md]({scenario}/summary.md) |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="print the scenario catalog as JSON")
    plan = sub.add_parser("plan", help="print the fixed three-engine row order and one scenario")
    plan.add_argument("scenario", choices=[*SCENARIOS, "all"])
    config = sub.add_parser("config", help="print one canonical scenario configuration")
    config.add_argument("scenario", choices=SCENARIOS)
    config.add_argument("--tcp-flow", action="append", type=int,
                        help="keep only this configured TCP flow count; repeat to select several")
    snapshot = sub.add_parser("cpu-snapshot", help="write a whole-machine /proc/stat CPU snapshot")
    snapshot.add_argument("--output", required=True, type=Path)
    cpu_summary = sub.add_parser("cpu-window-summary", help="normalize whole-machine CPU over a UDP probe window")
    cpu_summary.add_argument("--before", required=True, type=Path)
    cpu_summary.add_argument("--after", required=True, type=Path)
    cpu_summary.add_argument("--measurement", required=True, type=Path)
    cpu_summary.add_argument("--output", required=True, type=Path)
    collect = sub.add_parser("collect-row", help="normalize one completed engine case to matrix-row.json")
    collect.add_argument("--case-dir", required=True, type=Path)
    collect.add_argument("--engine", required=True, choices=["kernel-plain", "wireguard-go", "gotatun"])
    collect.add_argument("--tag", required=True)
    collect.add_argument("--scenario", required=True, choices=SCENARIOS)
    collect.add_argument("--calibration", default="uncalibrated")
    run = sub.add_parser("run", help="run one calibration or one shared-lock scenario window through perf-all.sh")
    run.add_argument("--kit", required=True)
    run.add_argument("--scenario", required=True, choices=[*SCENARIOS, "all"])
    run.add_argument("--tcp-flow", action="append", type=int,
                     help="measure only this configured TCP flow count; repeat to select several")
    run.add_argument("--gotatun-binary", action="append", required=True, metavar="ID=PATH",
                     help="GotaTun variant executable; repeat once per shipped or candidate source")
    run.add_argument("--wg-bin", default=os.environ.get("H2H_WG_BIN"))
    run.add_argument("--wireguard-go-bin", default=os.environ.get("H2H_WIREGUARD_GO_BIN"))
    run.add_argument("--source", action="append", required=True, metavar="ID=SHA",
                     help="full source commit SHA for each --gotatun-binary")
    run.add_argument("--engine-label", action="append", default=[], metavar="ID=LABEL",
                     help="display label for a GotaTun variant; repeatable")
    run.add_argument("--select-gotatun", action="append", default=None, metavar="ID",
                     help="measure only these GotaTun rows beside both controls; repeatable")
    run.add_argument("--engine-order", action="append", default=None, metavar="ID",
                     help="first-window order of every measured engine ID; repeat to set a counterbalanced sequence")
    run.add_argument("--calibration-variant", default=SHIPPED_GOTATUN_ID,
                     help="variant ID used for the three-control calibration")
    run.add_argument("--out", required=True)
    run.add_argument("--calibrate", action=argparse.BooleanOptionalAction, default=True)
    run.add_argument("--calibration-only", action="store_true",
                     help="run only the three-control calibration and write its evidence")
    run.add_argument("--batch", type=int, choices=range(1, MATRIX_REPETITIONS + 1),
                     help="run one of five counterbalanced engine-variant windows")
    run.add_argument("--windows", type=int, choices=range(1, MATRIX_REPETITIONS + 1), default=None,
                     help="plan only this many counterbalanced windows (default five)")
    run.add_argument("--skip-calibration", action="store_true",
                     help="create the run root without running the LAN control calibration")
    run.add_argument("--retry-tag", action="append", metavar="TAG",
                     help="re-run only this row of the window (repeatable), into window-NNr")
    run.add_argument("--part", type=int, choices=(1, 2),
                     help="run only the first or second half of the window's rows (a shorter hold)")
    args = parser.parse_args()

    if args.command == "list":
        print(json.dumps(SCENARIOS, indent=2))
        return 0
    if args.command == "plan":
        scenarios = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
        print(json.dumps({"scenarios": scenarios, "rows": [
            {
                "tag": tag,
                "engine": engine_id,
                "implementation": next(spec["runner_engine"] for spec in DEFAULT_ENGINE_SPECS if spec["id"] == engine_id),
                "source_sha": next(spec.get("source_sha") for spec in DEFAULT_ENGINE_SPECS if spec["id"] == engine_id),
            }
            for tag, engine_id in MATRIX_ROWS
        ]}, indent=2))
        return 0
    if args.command == "config":
        try:
            configuration = scenario_configuration(args.scenario, args.tcp_flow)
        except ValueError as error:
            parser.error(str(error))
        print(json.dumps(configuration, indent=2))
        return 0
    if args.command == "cpu-snapshot":
        args.output.write_text(json.dumps(cpu_snapshot(), indent=2, allow_nan=False) + "\n", encoding="utf-8")
        print(args.output)
        return 0
    if args.command == "cpu-window-summary":
        result = cpu_window_summary(
            load_json(args.before) or {},
            load_json(args.after) or {},
            load_json(args.measurement) or {},
        )
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        print(args.output)
        return 0
    if args.command == "collect-row":
        result = collect_row(args.case_dir, engine=args.engine, tag=args.tag, scenario=args.scenario, calibration=args.calibration)
        output = args.case_dir / "matrix-row.json"
        output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        print(output)
        return 0
    try:
        return run_matrix(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"matrix: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
