#!/usr/bin/env python3
"""Measure unchanged real PTY echo and credited VT output with portable readiness (#198)."""
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from agent_fixture import Binary, cleanup, fixture_state, varint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if platform.node() != "infraternal-perf-test":
        raise SystemExit("Timing evidence requires the pinned perf VM")
    if os.environ.get("INFRATERNAL_TEST_RTT") != "0":
        raise SystemExit("This probe isolates native overhead with INFRATERNAL_TEST_RTT=0")
    state = fixture_state("sr")
    state.mkdir(mode=0o700)
    client = None
    try:
        client = Binary(args.binary.resolve(), state)
        client.open()
        client.attach()
        # Ask the real login shell for readiness: its prompt and rc mechanism
        # differ across hosts. No account shell or host profile is changed.
        client.input(b"stty raw -echo; printf 'RAT_%s' READY; cat\n")
        client.until(b"RAT_READY")
        client.wait_ack()
        samples = []
        for _ in range(1000):
            client.data.clear()
            start = time.perf_counter_ns()
            client.input(b"x")
            client.until(b"x")
            client.wait_ack()
            samples.append(time.perf_counter_ns() - start)
            assert client.data == b"x"
        ordered = sorted(samples)
        print(json.dumps({"binary": str(args.binary), "machine": platform.node(),
                          "cores": os.cpu_count(), "load": os.getloadavg(),
                          "echo_samples": len(samples), "echo_p50_ns": statistics.median(ordered),
                          "echo_p99_ns": ordered[989]}), flush=True)
        client.send(1, 0x0f, struct.pack("<H", 0) + varint(4) + b"done")
        client.open()
        client.attach()
        client.input(b"stty -echo -opost; printf 'FLOOD_%s' READY\n")
        client.until(b"FLOOD_READY")
        client.wait_ack()
        results = []
        for _ in range(3):
            client.data.clear()
            start = time.perf_counter_ns()
            client.input(b"yes | head -c 50M; printf 'FLOOD_%s' DONE\n")
            client.until(b"FLOOD_DONE")
            elapsed = time.perf_counter_ns() - start
            client.wait_ack()
            count = 50 * 1024 * 1024
            # Exclude prompts and the fence from throughput; count every exact
            # output line so a short or duplicated body cannot pass the probe.
            assert client.data.count(b"y\n") == count // 2
            results.append({"bytes": count, "elapsed_ns": elapsed,
                            "mib_per_s": count * 1e9 / elapsed / 1024 / 1024})
        print(json.dumps({"binary": str(args.binary), "credited_flood": results,
                          "load": os.getloadavg()}), flush=True)
    finally:
        if client is not None:
            client.kill()
        cleanup(state)


if __name__ == "__main__":
    main()
