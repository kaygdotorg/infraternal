#!/usr/bin/env python3
"""Shared dispatch stays responsive while one real shim handshake stalls [41][81]."""
import argparse
import os
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import AckBarrier, Binary, cleanup, fixture_state, varint


def run(binary):
    state = fixture_state('ti')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    barrier = None
    try:
        client.open()
        stalled = client.id
        client.attach()
        client.wait_for_shell()
        cursor = client.out
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        # Open a sibling before holding the first session's handshake.
        client.open()
        client.send(3, 0x16, client.id.bytes + struct.pack('<QQ', 0, 0))
        client.send(3, 0x14, struct.pack('<I', 1048576))
        barrier = AckBarrier(state, stalled, kind=0x1a)
        barrier.threshold = 0
        client.send(1, 0x16, stalled.bytes + struct.pack('<QQ', cursor, 0))
        assert barrier.held.wait(20)
        started = time.monotonic()
        # Credit is fungible flow allowance, so overload the ordered Input
        # FIFO while this shim cannot drain it. Its eight-slot bound and the
        # one-second control/sibling deadline remain unchanged.
        for seq in range(9):
            client.send(1, 0x10, struct.pack('<Q', seq) + b'x')
        client.send(3, 0x10, struct.pack('<Q', 0) + b"printf 'SIBLING_%s' OK\n")
        client.send(0, 8, struct.pack('<QQ', 123, 456))
        client.sock.settimeout(1)
        pong = closed = False
        output = bytearray()
        while not (pong and closed and b'SIBLING_OK' in output):
            stream, kind, body = client.read_ignoring_replay_complete(
                {1: stalled, 3: client.id}
            )
            if (stream, kind) == (0, 9):
                assert body == struct.pack('<QQ', 123, 456)
                pong = True
            elif (stream, kind) == (1, 15):
                closed = True
            elif (stream, kind) == (3, 0x11):
                output.extend(body[8:])
            else:
                assert (stream, kind) == (3, 0x13), (stream, kind, body)
        elapsed = time.monotonic() - started
        assert elapsed < 1, elapsed
        assert not barrier.release.is_set()
        assert client.child.poll() is None
        print(f'held shim State + 9 ordered inputs: overloaded stream Close, sibling input/output, control Pong before barrier release in {elapsed*1000:.3f} ms: PASS', flush=True)
    finally:
        if barrier:
            barrier.close()
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
