#!/usr/bin/env python3
"""Measure a terminal reattach after a gap, by backlog size (#583, D13, D381).

A browser that comes back after a long gap reattaches at the output cursor it
last received. The shim then either replays the raw bytes it still holds from
that cursor, or sends a Snapshot (the screen plus a short history tail) and
only the output after it. This benchmark times that choice from the server's
side of the real binary, with a real shim and PTY.

Each round:

1. With echo and the prompt off, the shell is told to wait briefly and then
   print `size` bytes of `seq` output.
2. The client closes its stream before any of that output exists, the way the
   server closes a stream when a browser socket drops. The shim keeps running
   and keeps reading the PTY into its ring and screen.
3. Once the output is complete, the client reattaches the same stream id at its
   old cursor and grants the browser's opening window (1 MiB plus the 64 KiB
   repaint reserve), returning credit in 64 KiB batches as Output arrives.
4. The round ends at `terminal.replay_complete`: the client then holds every
   byte the shim had when the link opened, or a Snapshot standing for them.

It reports, per size, the median and maximum time from Attach to that marker,
the time to the first frame, and the raw and Snapshot bytes sent. Set
`--reset` to print RIS first. Since #521 a live shell's engine
exports an exact Snapshot without it; `--reset` stays for comparison
with older builds, which could export exactly only after RIS. Set `INFRATERNAL_TEST_RTT` (milliseconds) to add the latency proxy's round trip
between this client and the agent. `--save DIR` keeps one round's received
bytes per size (`raw-<size>.bin`, or `snapshot-<size>.bin` and the
raw `tail-<size>.bin` after it) for the browser-side
parse benchmark (`apps/tracer/perf/reattach-parse.bench.ts`).

Run it through `perf-run` on the perf VM, with a release binary:

    perf-run -- env INFRATERNAL_TEST_RTT=0 python3 scripts/bench-reattach-backlog.py \\
        --binary ~/j1190/infraternal --save ~/j1190/bytes-0
"""
import argparse
import json
from pathlib import Path
import statistics
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import HANG, Binary, cleanup, event_object, fixture_state, varint

# The browser's opening grant: the 1 MiB bulk window plus the 64 KiB it keeps
# for a key repaint (D381), sent as one Credit on every attach.
BROWSER_OPENING = 1024 * 1024 + 64 * 1024
# Default backlog sizes: the four the task names, plus points inside the 8 MiB
# ring that locate the crossover.
SIZES = (64 << 10, 256 << 10, 1 << 20, 2 << 20, 4 << 20, 7 << 20, 16 << 20, 128 << 20)


def detach(client):
    """Close the terminal stream as the server does for a dropped browser socket."""
    client.send(client.stream, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
    client.fence()


def reattach(client):
    """Reattach at the client's cursor and time it until the replay is complete.

    Returns a dict with the elapsed times and the byte counts. Output must start
    exactly at the cursor (the fixture asserts it); a Snapshot moves the cursor
    to the Snapshot's offset and the raw tail follows from there.
    """
    out_before = client.out
    snapshots_before = len(client.snapshots)
    client.data.clear()
    start = time.monotonic()
    client.send(client.stream, 0x16, client.id.bytes + struct.pack('<QQ', client.out, client.acked))
    client.credit_pending = 0
    client.credit_available = BROWSER_OPENING
    client.send(client.stream, 0x14, struct.pack('<I', BROWSER_OPENING))
    first = None
    frames = 0
    # The last Snapshot body, and the raw bytes received after it (or since Attach).
    snapshot = None
    tail = bytearray()
    deadline = start + HANG
    while True:
        assert time.monotonic() < deadline, 'reattach did not complete'
        frame = client.read()
        stream, kind, body = frame
        if stream == client.stream and kind in (0x11, 0x15):
            frames += 1
            if first is None:
                first = time.monotonic()
            if kind == 0x15:
                snapshot = bytes(body[8:])
                tail.clear()
            else:
                tail.extend(body[8:])
        client.process(credit=True, frame=frame)
        if kind == 0x33 and stream == client.stream and event_object(body).get('type') == 'terminal.replay_complete':
            break
    done = time.monotonic()
    snapshots = client.snapshots[snapshots_before:]
    snapshot_bytes = sum(length for _, length in snapshots)
    return dict(
        complete_ms=(done - start) * 1000,
        first_frame_ms=((first or done) - start) * 1000,
        raw_bytes=len(client.data),
        snapshot_bytes=snapshot_bytes,
        snapshots=len(snapshots),
        frames=frames,
        backlog=client.out - out_before,
        snapshot=snapshot,
        tail=bytes(tail),
    )


def round_trip(client, state, size, number):
    """Produce `size` bytes of output while detached, then time the reattach."""
    marker = state.resolve() / f'flood-{number}'
    # `seq` output is ordinary scrolling text; `head` cuts it at exactly `size`.
    # The short sleep lets the client close its stream before the first byte.
    client.input(f"sleep 0.3; seq 1 99999999 | head -c {size}; : > '{marker}'\n".encode())
    client.wait_ack()
    detach(client)
    deadline = time.monotonic() + HANG
    while not marker.exists():
        assert time.monotonic() < deadline, 'flood did not finish'
        # sleep: polls a file the shell creates; no event exists for it.
        time.sleep(0.01)
    # sleep: the shim drains the last PTY buffer (at most a few KiB) after
    # `head` exits; give it time so the backlog is complete at Attach.
    time.sleep(0.3)
    return reattach(client)


def run(binary, sizes, rounds, save, reset):
    """Run `rounds` reattaches per backlog size and print one JSON line per size.

    With `reset`, the shell first prints RIS. Builds before #521 could export
    a live shell exactly only after such a reset; since #521 the shim's engine
    starts with prompt redraw on, so a plain shell session exports exactly too.
    """
    state = fixture_state('rb')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        client.attach()
        client.wait_for_shell()
        reset_bytes = "printf '\\033c'; " if reset else ''
        client.input(f"stty -echo; PS1=''; PS2=''; {reset_bytes}printf 'READY_%s\\n' OK\n".encode())
        client.until(b'READY_OK')
        client.wait_ack()
        number = 0
        for size in sizes:
            samples = []
            for repeat in range(rounds):
                number += 1
                result = round_trip(client, state, size, number)
                snapshot = result.pop('snapshot')
                tail = result.pop('tail')
                if save is not None and repeat == 0:
                    save.mkdir(parents=True, exist_ok=True)
                    if snapshot is None:
                        (save / f'raw-{size}.bin').write_bytes(tail)
                    else:
                        (save / f'snapshot-{size}.bin').write_bytes(snapshot)
                        (save / f'tail-{size}.bin').write_bytes(tail)
                samples.append(result)
            times = sorted(sample['complete_ms'] for sample in samples)
            print(json.dumps(dict(
                size=size,
                rounds=rounds,
                complete_p50_ms=round(statistics.median(times), 2),
                complete_max_ms=round(times[-1], 2),
                first_frame_p50_ms=round(statistics.median(s['first_frame_ms'] for s in samples), 2),
                raw_bytes=samples[-1]['raw_bytes'],
                snapshot_bytes=samples[-1]['snapshot_bytes'],
                snapshots=samples[-1]['snapshots'],
                frames=samples[-1]['frames'],
                backlog=samples[-1]['backlog'],
            )), flush=True)
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--sizes', type=lambda text: tuple(int(part) for part in text.split(',')), default=SIZES)
    parser.add_argument('--save', type=Path)
    parser.add_argument('--reset', action='store_true', help='print RIS first (before #521 only then could the shim export exactly)')
    args = parser.parse_args()
    assert args.rounds > 0
    run(args.binary, args.sizes, args.rounds, args.save, args.reset)
