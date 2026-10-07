#!/usr/bin/env python3
"""Report credited PTY flood throughput without selecting or changing the VT engine [41]."""
import argparse
import os
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, rss

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, required=True)
args = parser.parse_args()
state = Path(f'target/fl{os.getpid()}')
state.mkdir(mode=0o700)
c = Binary(args.binary.resolve(), state)
try:
    c.open(); c.attach(); c.until(b'shim-test')
    c.input(b"stty -echo -opost; printf 'FLOOD_%s' READY\n")
    c.until(b'FLOOD_READY'); c.wait_ack(); c.data.clear()
    started = time.monotonic()
    c.input(b"yes | head -c 50M; printf 'FLOOD_%s' DONE\n")
    try:
        # This diagnostic is nonblocking on throughput, per #34. The timeout
        # only bounds a broken/stalled test; no performance budget is loosened.
        while b'FLOOD_DONE' not in c.data[-32768:]:
            assert time.monotonic() - started < 120, 'flood did not finish within observation'
            c.process()
    except BaseException:
        print(f'partial flood: bytes={len(c.data)}, cursor={c.out}, snapshots={len(c.snapshots)}, elapsed={time.monotonic()-started:.3f}s', flush=True)
        raise
    elapsed = time.monotonic() - started
    assert len(c.data) >= 50 * 1024 * 1024 and not c.snapshots, 'credited flood lost raw output'
    end = c.data.find(b'FLOOD_DONE')
    start = end - 50 * 1024 * 1024
    assert start >= 0
    # Check every flood byte in bounded slices, excluding shell prompt/control bytes.
    for begin in range(start, end, 65536):
        stop = min(begin + 65536, end)
        assert memoryview(c.data)[begin:stop] == b'y\n' * ((stop - begin) // 2), 'flood payload changed'
    print(f'credited PTY flood: {len(c.data)} bytes / {elapsed:.3f}s = {len(c.data)/elapsed/1024/1024:.3f} MiB/s; daemon RSS={rss(c.child.pid)} KiB; machine={os.uname().machine}; cores={os.cpu_count()}; load={os.getloadavg()}; throughput is nonblocking for #34', flush=True)
finally:
    c.kill(); cleanup(state)
