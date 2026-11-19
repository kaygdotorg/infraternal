#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Normalize D348 test-CPU raw syscall tracepoint counts per transferred Gbit."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


COUNT = re.compile(r"^\s*([0-9][0-9,]*)\s+raw_syscalls:sys_enter(?:\s|$)", re.MULTILINE)


def parse_perf_count(text: str) -> int | None:
    """Parse perf's raw tracepoint counter; unsupported and missing stay null."""
    match = COUNT.search(text)
    return int(match.group(1).replace(",", "")) if match else None


def summarize(text: str, gbit_per_second: float, seconds: float) -> dict[str, Any]:
    """Return a count per Gbit only when the counter and traffic window exist."""
    count = parse_perf_count(text)
    total_gbit = gbit_per_second * seconds
    if count is None:
        return {
            "status": "unavailable",
            "syscalls": None,
            "syscalls_per_gbit": None,
            "method": "perf stat raw_syscalls:sys_enter on CPUs 1-4",
            "reason": "tracepoint absent, perf unavailable, or counter permission denied",
        }
    if total_gbit <= 0:
        return {
            "status": "unavailable",
            "syscalls": count,
            "syscalls_per_gbit": None,
            "method": "perf stat raw_syscalls:sys_enter on CPUs 1-4",
            "reason": "no positive transferred-gigabit denominator",
        }
    return {
        "status": "measured",
        "syscalls": count,
        "total_gbit": total_gbit,
        "syscalls_per_gbit": count / total_gbit,
        "method": "perf stat raw_syscalls:sys_enter on CPUs 1-4",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--gbit-per-second", required=True, type=float)
    parser.add_argument("--seconds", required=True, type=float)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    text = args.log.read_text(encoding="utf-8", errors="replace") if args.log.exists() else ""
    result = summarize(text, args.gbit_per_second, args.seconds)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
