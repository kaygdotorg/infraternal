#!/usr/bin/env python3
"""Report per-step percentiles from ten locked perf-VM host provisioning runs (#190)."""
import argparse
from pathlib import Path
import re
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    for rtt in (0, 150):
        samples = sorted(args.directory.glob(f"rtt-{rtt}-[0-9][0-9].log"))
        if len(samples) != 10:
            raise ValueError(f"RTT {rtt}: expected ten runs, found {len(samples)}")
        rows = {}
        for sample in samples:
            content = sample.read_text()
            if "machine=infraternal-perf-test " not in content:
                raise ValueError(f"{sample}: wrong measurement machine")
            completion = re.findall(r"event=Done cumulative_ms=(\d+)", content)
            if len(completion) != 1 or "test result: ok." not in content:
                raise ValueError(f"{sample}: completion proof missing")
            rows.setdefault("Check → Done", []).append(float(completion[0]))
            steps = set()
            for step, value, success in re.findall(
                r"METRIC breakit2 step=(\w+) elapsed_ms=([\d.]+) ok=(true|false)",
                content,
            ):
                # An expected authentication refusal is still part of latency.
                if step in steps:
                    raise ValueError(f"{sample}: duplicate step {step}")
                steps.add(step)
                rows.setdefault(step, []).append(float(value))
        print(f"\nRTT {rtt} ms, n=10; p95 uses nearest rank (maximum of ten).")
        print("| Setup step | p50 ms | p95 ms |")
        print("| --- | ---: | ---: |")
        for step, values in rows.items():
            if len(values) != 10:
                raise ValueError(f"{step}: missing samples")
            print(f"| {step} | {statistics.median(values):.3f} | {max(values):.3f} |")


if __name__ == "__main__":
    main()
