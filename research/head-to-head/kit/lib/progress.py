#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Turn once-a-second receiver byte counts into stall and zero-byte statistics.

`mesh.sh` samples, every second during a TCP load, the total bytes the receiving
namespace has taken in over all connections to the benchmark port. A lossy path
can leave a flow alive but silent, which an average goodput hides, so this
reports how many sampled seconds delivered nothing and the longest silent run.
It reads a TSV of `<epoch seconds> <cumulative bytes>` lines.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


def read_samples(path: Path) -> list[tuple[float, int]]:
    """Read `<time> <cumulative bytes>` lines, skipping malformed ones."""
    samples: list[tuple[float, int]] = []
    for line in path.read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            samples.append((float(fields[0]), int(fields[1])))
        except ValueError:
            continue
    return samples


def until_connections_close(samples: list[tuple[float, int]]) -> list[tuple[float, int]]:
    """Drop the samples from the first fall in the cumulative count onward.

    The sampler sums bytes over connections that exist, so when the load ends and the
    connections close the sum drops (to zero). Those trailing samples are not silence
    from the flow, so they must not be counted as silent seconds.
    """
    for index in range(1, len(samples)):
        if samples[index][1] < samples[index - 1][1]:
            return samples[:index]
    return samples


def summarize(samples: list[tuple[float, int]], low_fraction: float = 0.05) -> dict[str, Any]:
    """Count silent and very slow sampled seconds and the longest silent run.

    An interval is *silent* when no new bytes arrived and *slow* when its rate is
    under `low_fraction` of the median interval rate. The leading idle interval
    before a connection exists is counted too: a connect that takes seconds under
    loss is part of the flow's reliability. Fewer than two samples means the
    sampler produced nothing usable, which is reported, never counted as zero.
    """
    samples = until_connections_close(samples)
    if len(samples) < 2:
        return {"status": "unavailable", "samples": len(samples)}
    rates: list[float] = []
    silent_run = 0.0
    silent_seconds = longest_silent_s = 0.0
    for (t0, b0), (t1, b1) in zip(samples, samples[1:]):
        seconds = max(t1 - t0, 1e-9)
        delta = max(0, b1 - b0)
        rates.append(delta * 8 / seconds / 1e6)
        if delta == 0:
            silent_seconds += seconds
            silent_run += seconds
            longest_silent_s = max(longest_silent_s, silent_run)
        else:
            silent_run = 0.0
    median = statistics.median(rates)
    slow = sum(1 for rate in rates if median > 0 and rate < low_fraction * median)
    return {
        "status": "measured",
        "samples": len(samples),
        "intervals": len(rates),
        "bytes_total": samples[-1][1] - samples[0][1],
        "silent_seconds": round(silent_seconds, 3),
        "longest_silent_s": round(longest_silent_s, 3),
        "slow_intervals": slow,
        "median_mbit_s": round(median, 3),
        "min_mbit_s": round(min(rates), 3),
        "max_mbit_s": round(max(rates), 3),
        "zero_byte": samples[-1][1] - samples[0][1] == 0,
    }


def main() -> int:
    """Summarize one sample file into JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tsv", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = summarize(read_samples(arguments.tsv))
    arguments.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
