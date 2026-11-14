#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize raw ICMP replies for the D331/J201 loss-aware p99 keep rule."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Iterable


REPLY = re.compile(r"icmp_seq=(\d+) .*time=([\d.]+) ms")
SENT = re.compile(r"(\d+) packets transmitted")


def percentile(values: list[float], fraction: float) -> float:
    """Return the nearest-rank percentile, or NaN when no replies arrived."""
    if not values:
        return math.nan
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def stats(
    paths: Iterable[str | Path], expected_sent: int = 0
) -> dict[str, int | float]:
    """Read ping output files and calculate received and loss-aware percentiles.

    Each ICMP sequence contributes at most once per file. Each missing reply is
    added as an infinite RTT before ranking, so p99 becomes infinite only when
    losses occupy the p99 rank.
    """
    received: list[float] = []
    sent = 0
    for path in paths:
        replies: dict[int, float] = {}
        text = Path(path).read_text(errors="replace")
        for match in REPLY.finditer(text):
            replies.setdefault(int(match.group(1)), float(match.group(2)))
        reported = SENT.search(text)
        sent += int(reported.group(1)) if reported else max(replies, default=0)
        received.extend(replies.values())

    sent = max(sent, len(received), expected_sent)
    lost = max(0, sent - len(received))
    p50_received = percentile(received, 0.50)
    p99_received = percentile(received, 0.99)
    p999_loss_aware = percentile(received + [math.inf] * lost, 0.999)
    p99_loss_aware = percentile(received + [math.inf] * lost, 0.99)
    return {
        "sent": sent,
        "lost": lost,
        "p50_received_ms": p50_received,
        "p99_received_ms": p99_received,
        "p99_loss_aware_ms": p99_loss_aware,
        "p999_loss_aware_ms": p999_loss_aware,
        "max_received_ms": max(received, default=math.nan),
    }


def read_replies(paths: Iterable[str | Path]) -> tuple[list[float], int]:
    """Return every received RTT (ms) and the transmitted count from ping logs."""
    received: list[float] = []
    sent = 0
    for path in paths:
        replies: dict[int, float] = {}
        text = Path(path).read_text(errors="replace")
        for match in REPLY.finditer(text):
            replies.setdefault(int(match.group(1)), float(match.group(2)))
        reported = SENT.search(text)
        sent += int(reported.group(1)) if reported else max(replies, default=0)
        received.extend(replies.values())
    return received, sent


def _finite(value: float) -> float | None:
    """JSON cannot carry inf or NaN, so those become null (and `infinite_at` says why)."""
    return value if math.isfinite(value) else None


def matrix_summary(
    paths: Iterable[str | Path], interval_us: int, expected_sent: int = 0
) -> dict[str, object]:
    """Summarize ping logs in the same shape the matrix's UDP latency probe writes.

    `loss_aware_rtt_ms` ranks every missing reply as an infinite RTT, so a
    percentile that falls inside the lost share is `null` and named in
    `infinite_at`; `rtt_ms` holds received-only percentiles, which stay finite
    under loss. Both are kept so a lossy row shows the loss-aware answer
    (the keep rule) beside the received-only one.
    """
    received, reported = read_replies(paths)
    sent = max(reported, len(received), expected_sent)
    lost = max(0, sent - len(received))
    ranked = received + [math.inf] * lost
    loss_aware = {name: percentile(ranked, fraction)
                  for name, fraction in (("p50", 0.50), ("p99", 0.99), ("p999", 0.999))}
    return {
        "interval_us": interval_us,
        "probe": "icmp",
        "sent": sent,
        "received": len(received),
        "lost": lost,
        "loss_aware_rtt_ms": {
            "n": sent,
            "lost": lost,
            "infinite_at": [name for name, value in loss_aware.items() if math.isinf(value)],
            **{name: _finite(value) for name, value in loss_aware.items()},
        },
        "rtt_ms": {
            "n": len(received),
            "p50": _finite(percentile(received, 0.50)),
            "p99": _finite(percentile(received, 0.99)),
            "max": _finite(max(received, default=math.nan)),
        },
    }


def format_ms(value: float) -> str:
    """Print finite percentiles in milliseconds and keep loss visible as `inf`."""
    if math.isinf(value):
        return "inf"
    if math.isnan(value):
        return "nan"
    return f"{value:.3f}"


def main() -> int:
    """Read one or more `ping -D -O -n` logs and print the keep metrics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected-sent",
        type=int,
        default=0,
        help="minimum expected probe count when ping exits before its summary",
    )
    parser.add_argument(
        "--matrix-json",
        action="store_true",
        help="print the matrix latency JSON (loss-aware and received-only percentiles)",
    )
    parser.add_argument(
        "--interval-us", type=int, default=0, help="probe interval recorded in --matrix-json output"
    )
    parser.add_argument("files", nargs="+", type=Path, help="raw ping output file(s)")
    arguments = parser.parse_args()
    if arguments.matrix_json:
        import json

        print(json.dumps(matrix_summary(arguments.files, arguments.interval_us,
                                        arguments.expected_sent), allow_nan=False))
        return 0
    result = stats(arguments.files, expected_sent=arguments.expected_sent)
    print(
        "sent {sent} lost {lost} p50 {p50} p99_received {p99_received} "
        "p99_loss_aware {p99_loss_aware} p99.9_loss_aware {p999} max {maximum}".format(
            sent=result["sent"],
            lost=result["lost"],
            p50=format_ms(float(result["p50_received_ms"])),
            p99_received=format_ms(float(result["p99_received_ms"])),
            p99_loss_aware=format_ms(float(result["p99_loss_aware_ms"])),
            p999=format_ms(float(result["p999_loss_aware_ms"])),
            maximum=format_ms(float(result["max_received_ms"])),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
