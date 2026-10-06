#!/usr/bin/env python3
"""Tiny Snapshot credit never stalls independent shell progress [75][81]."""
import argparse
import os
from pathlib import Path
import select
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, varint


def completed(marker):
    deadline = time.monotonic() + 90
    while not marker.exists():
        assert time.monotonic() < deadline, f'shell blocked: {marker}'
        time.sleep(.01)


def run(binary):
    state = Path(f'target/ts{os.getpid()}')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        client.attach()
        client.until(b'shim-test')
        client.input(b"stty -echo -opost; printf 'READY_%s' OK\n")
        client.until(b'READY_OK')
        client.wait_ack()
        for iteration in range(3):
            marker = state.resolve() / f'completed-{iteration}'
            client.input(f"yes | head -c 12M; : > '{marker}'\n".encode())
            while select.select([client.sock], [], [], .5)[0]:
                client.process(credit=False)
            completed(marker)
            # Pay prior repaint debt, leaving exactly one byte of usable credit.
            debt = client.snapshots[-1][1] - 1 if client.snapshots else 0
            client.send(1, 0x14, struct.pack('<I', debt + 1))
            count = len(client.snapshots)
            while len(client.snapshots) == count:
                client.process(credit=False)
            assert client.snapshots[-1][1] > 1
            print(f'catch-up {iteration}: 12 MiB shell completed; credit=1, Snapshot={client.snapshots[-1][1]} bytes seq={client.out}: PASS', flush=True)
        # No further grant: another full flood still completes after detachment.
        marker = state.resolve() / 'final'
        client.input(f"yes | head -c 12M; : > '{marker}'\n".encode())
        while select.select([client.sock], [], [], .5)[0]:
            client.process(credit=False)
        completed(marker)
        # A fresh attachment to overwritten history starts with a ring-wrap
        # Snapshot, using the same credit accounting as explicit catch-up.
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.out = 0
        client.attach()
        count = len(client.snapshots)
        while len(client.snapshots) == count:
            client.process(credit=False)
        assert client.out > 8 * 1024 * 1024
        print(f'initial ring-wrap attachment: Snapshot={client.snapshots[-1][1]} bytes seq={client.out}: PASS', flush=True)
        print('four 12 MiB floods completed; three tiny-credit Snapshots; no Close needed: PASS', flush=True)
    finally:
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
