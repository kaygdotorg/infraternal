#!/usr/bin/env python3
"""Validate ten VM profiles per link and report individual remote setup execution for #190."""
from pathlib import Path
import re
import statistics

root = Path(__file__).parent / "steps"
for rtt in (0, 150):
    print(f"\nRTT {rtt} ms; ten fresh targets per version; nearest-rank p95.")
    print("| Remote setup step | Before p50 ms | Before p95 ms | After p50 ms | After p95 ms |")
    print("| --- | ---: | ---: | ---: | ---: |")
    values = {}
    for phase in ("production-baseline", "final"):
        samples = sorted((root / phase).glob(f"rtt-{rtt}-[0-9][0-9].log"))
        assert len(samples) == 10
        for sample in samples:
            content = sample.read_text()
            assert "machine=infraternal-perf-test " in content
            assert "test result: ok. 1 passed;" in content
            done = re.findall(r"event=Done cumulative_ms=(\d+)", content)
            assert len(done) == 1
            values.setdefault((phase, "Check → Done (instrumented)"), []).append(float(done[0]))
            steps = re.findall(r"REMOTE_STEP name=(\w+) elapsed_ns=(\d+) status=(\d+)", content)
            assert sorted(name for name, _, _ in steps) == ["install", "join", "linger", "start", "upload"]
            for name, elapsed, status in steps:
                assert status == "0"
                values.setdefault((phase, name), []).append(int(elapsed) / 1_000_000)
    for step in ("Check → Done (instrumented)", "upload", "join", "install", "start", "linger"):
        before = values[("production-baseline", step)]
        after = values[("final", step)]
        print(f"| {step} | {statistics.median(before):.3f} | {max(before):.3f} | {statistics.median(after):.3f} | {max(after):.3f} |")
