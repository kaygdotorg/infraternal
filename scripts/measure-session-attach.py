#!/usr/bin/env python3
"""Measure quiet real-shim attach acknowledgement overhead without synthetic CPU load [D41], #151."""
import argparse
import json
from pathlib import Path
import statistics
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state


def run(binary, samples):
    state = fixture_state('a')
    state.mkdir(mode=0o700)
    client = None
    try:
        client = Binary(binary, state)
        client.open()
        client.attach()
        client.until(b'shim-test')
        timings = []
        for nonce in range(samples + 1):
            client.send(1, 0x0f, struct.pack('<H', 0) + b'window released')
            client.send(0, 0x08, struct.pack('<QQ', nonce, 0))
            assert client.read()[:2] == (0, 0x09)
            start = time.monotonic_ns()
            client.attach()
            # InputAck follows ownership confirmation and real shim input-state
            # recovery. This measures attach acknowledgement, not repaint/paint.
            elapsed = (time.monotonic_ns() - start) / 1_000_000
            if nonce:
                timings.append(elapsed)
        timings.sort()
        print(json.dumps(dict(binary=str(binary), samples=len(timings),
                              p50_ms=statistics.median(timings), maximum_ms=timings[-1],
                              load=Path('/proc/loadavg').read_text().strip())), flush=True)
    finally:
        if client is not None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=51)
    args = parser.parse_args()
    assert args.samples > 0
    run(args.binary.resolve(), args.samples)
