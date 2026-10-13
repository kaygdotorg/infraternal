#!/usr/bin/env python3
"""Compare startup and complete action-skill generation on the locked perf VM (#198)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def invoke(binary, arguments):
    """Fix argv[0] so artifact filenames cannot change generated help."""
    start = time.perf_counter_ns()
    result = subprocess.run(["infraternal", *arguments], executable=binary,
                            capture_output=True, check=True)
    return time.perf_counter_ns() - start, result.stdout


def main():
    """Interleave both artifacts; schema output must remain identical."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--samples", type=int, default=61)
    args = parser.parse_args()
    if platform.node() != "infraternal-perf-test":
        raise SystemExit("Timing evidence requires the pinned perf VM")
    if args.samples < 1:
        parser.error("samples must be positive")
    binaries = [str(args.baseline.resolve()), str(args.candidate.resolve())]
    print(json.dumps({"machine": platform.node(), "cores": os.cpu_count(),
                      "load": os.getloadavg(), "samples": args.samples}), flush=True)
    _, index = invoke(binaries[0], ["skill", "--json"])
    commands = json.loads(index)["data"]["commands"]
    checks = [["--help"], ["skill", "--json"]]
    for command in commands:
        path = command["command"].split()
        checks.extend([["skill", *path, "--json"], [*path, "--help"]])
    for arguments in checks:
        assert invoke(binaries[0], arguments)[1] == invoke(binaries[1], arguments)[1], arguments
    print(json.dumps({"public_actions": len(commands), "identical_outputs": len(checks),
                      "index_sha256": hashlib.sha256(index).hexdigest()}), flush=True)
    for arguments in [["--help"], ["skill", "--json"], ["skill", "mesh", "up", "--json"]]:
        values = [[], []]
        for iteration in range(args.samples):
            for which in ([0, 1] if iteration % 2 == 0 else [1, 0]):
                elapsed, _ = invoke(binaries[which], arguments)
                values[which].append(elapsed)
        for which, samples in enumerate(values):
            ordered = sorted(samples)
            print(json.dumps({"artifact": ["baseline", "candidate"][which],
                              "arguments": arguments, "samples_ns": samples,
                              "p50_ns": statistics.median(ordered),
                              "p95_ns": ordered[int(0.95 * (len(ordered) - 1))],
                              "load": os.getloadavg()}), flush=True)


if __name__ == "__main__":
    main()
