#!/usr/bin/env python3
"""Measure the real shim's 32 concurrent viewers with bounded per-round input [13][41]."""
import sys
sys.dont_write_bytecode = True
from collections import Counter
import os
from pathlib import Path
import struct
import time
from agent_fixture import Binary, cleanup, rss
from idle_canary import session_shim_pid

state = Path(f'target/ms{os.getpid()}')
state.mkdir(mode=0o700)
c = Binary(Path(sys.argv[sys.argv.index('--binary') + 1]).resolve(), state)
try:
    c.open(); c.attach(); c.send(1, 0x14, struct.pack('<I', 1048576)); c.until(b'shim-test')
    c.input(b"stty raw -echo; printf 'SCALE_%s' READY; cat\n")
    c.until(b'SCALE_READY'); c.wait_ack()
    # Read-only PID discovery avoids consuming a 33rd peer at the limit.
    shim_pid = session_shim_pid(c.id)
    offsets = {s: c.out for s in range(1, 33)}
    acks = {s: None for s in offsets}
    acks[1] = c.entered
    initial = {s: c.entered if s == 1 else 0 for s in offsets}
    data = {s: bytearray() for s in offsets}
    pending = {}
    latency = []
    def receive():
        s, kind, body = c.read()
        assert s in offsets
        if kind == 0x13:
            value = struct.unpack('<Q', body)[0]
            assert acks[s] is None or value >= acks[s]
            acks[s] = value
            if s in pending and value >= pending[s][0]:
                latency.append((time.perf_counter() - pending.pop(s)[1]) * 1000)
        elif kind == 0x11:
            seq = struct.unpack('<Q', body[:8])[0]
            assert seq == offsets[s]
            offsets[s] += len(body) - 8
            data[s].extend(body[8:])
            # Initial 1 MiB credit covers all 19,200 bytes. Per-frame tiny
            # refunds would saturate the bounded eight-command queue.
        else:
            raise AssertionError((s, kind))
    for s in range(2, 33):
        c.send(s, 0x16, c.id.bytes + struct.pack('<QQ', c.out, 0))
        c.send(s, 0x14, struct.pack('<I', 1048576))
    while any(value is None for value in acks.values()): receive()
    assert acks == initial, 'a fresh writer inherited another writer Ack'
    started = time.perf_counter()
    for round_index in range(200):
        for s in offsets:
            pending[s] = (initial[s] + (round_index + 1) * 3, time.perf_counter())
            c.send(s, 0x10, struct.pack('<Q', initial[s] + round_index * 3) + f'{s:02d};'.encode())
        target = (round_index + 1) * 96
        while any(acks[s] < initial[s] + (round_index + 1) * 3 or len(data[s]) < target for s in offsets):
            receive()
    elapsed = time.perf_counter() - started
    reference = bytes(data[1])
    assert all(bytes(value) == reference for value in data.values()), 'viewers disagree'
    assert Counter(reference.decode().split(';')[:-1]) == Counter({f'{s:02d}': 200 for s in offsets})
    assert len(latency) == 6400
    latency.sort()
    print(f'32 writers/viewers x 200 inputs: PASS; 6400 inputs, 19200 unique accounted bytes/viewer, 614400 delivered bytes; elapsed={elapsed:.3f}s; Input-to-PTY Ack n=6400 p50={latency[3200]:.3f}ms p99={latency[6336]:.3f}ms; daemon RSS={rss(c.child.pid)} KiB; shim RSS={rss(shim_pid)} KiB; machine={os.uname().machine}; cores={os.cpu_count()}; load={os.getloadavg()}')
finally:
    c.kill(); cleanup(state)
