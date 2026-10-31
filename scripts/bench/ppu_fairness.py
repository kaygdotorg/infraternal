#!/usr/bin/env python3
"""Measure quiet-session echo against detached bulk PTYs on the named perf VM [D270].

The quiet socket has no bulk frames to decode in this driver. Flood throughput
comes from frozen Hello byte offsets, including output whose ring tail evicted.
All generators are synthetic, time-limited to 100 seconds, and stay in the
caller's isolated measurement scope. Never use build-host results as evidence.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import time

from ppu_soak import Host, Peer, percentile, sample


def children(root):
    """Capture only descendants of the host, with kernel birth identity."""
    result = []
    pending = [root]
    while pending:
        parent = pending.pop()
        try:
            descendants = Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
        except FileNotFoundError:
            continue
        for raw in descendants:
            pid = int(raw)
            try:
                birth = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            except FileNotFoundError:
                continue
            result.append((pid, birth))
            pending.append(pid)
    return result


async def head(path):
    reader, writer = await asyncio.open_unix_connection(path)
    try:
        hello = await Peer.frame(reader)
        assert hello[0] == 1
        return struct.unpack_from('<Q', hello, 43)[0]
    finally:
        writer.close()
        await writer.wait_closed()


async def run(args):
    assert os.uname().nodename == 'infraternal-perf-test'
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 4 * args.sessions + 128), hard))
    args.evidence.mkdir(parents=True, exist_ok=False)
    host = Host(args.binary.resolve(), args.evidence / 's', args.sessions, 0x2702050000)
    owned = []
    try:
        await host.ready()
        quiet = host.peers[-1]
        idle = [await quiet.echo(f'idle-{i}'.encode()) for i in range(args.samples)]
        flood_count = max(1, args.sessions // 10)
        before = []
        for i in range(flood_count):
            before.append((await head(host.path(i)), time.monotonic()))
        for peer in host.peers[:flood_count]:
            await peer.send(0x10, b"timeout 100 yes '012345678901234567890123456789012345678901234567890123456789012345678901' &\n")
            await peer.close()
        await asyncio.sleep(1)
        owned = children(host.pid)
        start = time.monotonic()
        flooding = [await quiet.echo(f'flood-{i}'.encode()) for i in range(args.samples)]
        elapsed = time.monotonic() - start
        after = []
        for i in range(flood_count):
            after.append((await head(host.path(i)), time.monotonic()))
        # Each producer has its own offset/time boundaries, covering startup
        # and the one-second warm-up as well as the quiet echo sample window.
        row = dict(machine=os.uname().nodename, load_average=os.getloadavg(),
            binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            sessions=args.sessions, flooders=flood_count, samples=args.samples,
            idle_p50_ms=percentile(idle, .5), idle_p99_ms=percentile(idle, .99),
            flood_p50_ms=percentile(flooding, .5), flood_p99_ms=percentile(flooding, .99),
            flood_max_ms=max(flooding), extra_p99_ms=percentile(flooding, .99)-percentile(idle, .99),
            measured_echo_window_s=elapsed,
            flood_output_bytes=sum(b[0]-a[0] for a,b in zip(before,after)),
            flood_throughput_bytes_per_s=sum((b[0]-a[0])/(b[1]-a[1]) for a,b in zip(before,after)),
            host=sample(host.pid))
        (args.evidence / 'fairness.json').write_text(json.dumps(row, indent=2)+'\n')
        print(json.dumps(row), flush=True)
        return row['extra_p99_ms'] <= 2
    finally:
        owned = children(host.pid) if host.child.poll() is None else owned
        for pid, birth in reversed(owned):
            with contextlib.suppress(ProcessLookupError, FileNotFoundError):
                if Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19] == birth:
                    os.kill(pid, signal.SIGKILL)
        await host.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--sessions', type=int, default=1000)
    parser.add_argument('--samples', type=int, default=1000)
    args = parser.parse_args()
    assert 10 <= args.sessions <= 1000 and args.samples >= 1000
    raise SystemExit(0 if asyncio.run(run(args)) else 1)


if __name__ == '__main__':
    main()
