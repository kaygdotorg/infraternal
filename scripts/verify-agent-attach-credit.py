#!/usr/bin/env python3
"""Real PTY replay cannot precede explicit Credit or restart siblings on attach (#66)."""
import argparse
from pathlib import Path
import select
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state


def run(binary):
    state = fixture_state('ac')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        # Open has retained the shell's prompt. Deliberately separate Attach and
        # Credit: production has separate queues/tasks and must tolerate either
        # leg's scheduling without a free implicit grant.
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, 0))
        assert client.process(credit=False) == 0x13, 'attach must confirm the input cursor'
        deadline = time.monotonic() + 0.35
        while time.monotonic() < deadline:
            if select.select([client.sock], [], [], deadline - time.monotonic())[0]:
                kind = client.process(credit=False)
                assert kind == 0x13, f'unfunded attach emitted frame 0x{kind:02x}'
        client.send(0, 0x08, struct.pack('<QQ', 66, 0))
        stream, kind, _ = client.read()
        assert (stream, kind) == (0, 0x09), 'credit-starved replay blocked sibling control'
        # Cross the 250 ms starvation deadline, then fund retained replay.
        start = time.monotonic()
        client.send(1, 0x14, struct.pack('<I', 1))
        while not client.data:
            client.process(credit=False)
        assert len(client.data) == 1, 'replay exceeded its exact 1-byte grant'
        while select.select([client.sock], [], [], 0.02)[0]:
            assert client.process(credit=False) == 0x13, 'replay borrowed implicit credit'
        client.send(1, 0x14, struct.pack('<I', 1048575))
        client.until(b'shim-test', credit=False)
        assert client.out > 0, 'funded replay omitted retained prompt'
        print(f'Attach without Credit: no Output/Snapshot for 350 ms; control responsive; funded replay {client.out} bytes in {(time.monotonic()-start)*1000:.1f} ms: PASS')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
