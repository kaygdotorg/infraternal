#!/usr/bin/env python3
"""A reaped shim's final output and exit survive a viewer that grants credit after starvation [D13], #151."""
import argparse
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, exact, fixture_state


def run(binary):
    state = fixture_state('e')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        path = state / 'sessions' / f'{client.id.hex}.sock'
        # First observe the fixture prompt directly, so the unfunded relay has
        # actual retained output before the shell is killed. No scheduler sleep
        # stands in for that output barrier.
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(10)
            peer.connect(str(path))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
            assert hello[11:27] == client.id.bytes
            pid = struct.unpack('<I', hello[27:31])[0]
            for body in [b'\x02' + struct.pack('<Q', 0), b'\x13' + struct.pack('<Q', 0)]:
                peer.sendall(struct.pack('<I', len(body)) + body)
            tail = b''
            while b'shim-test' not in tail:
                frame = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
                assert frame[0] == 0x11
                tail = (tail + frame[9:])[-256:]
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, 0))
        assert client.process(credit=False) == 0x13
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        assert len(children) == 1
        os.kill(int(children[0]), signal.SIGKILL)
        deadline = time.monotonic() + 1
        while path.exists():
            assert time.monotonic() < deadline, 'shim did not retire after writing its exit'
            time.sleep(.005)
        # Cross the existing one-shot 250 ms relay starvation deadline with no
        # Credit. The socket's unread final output/exit is now the sole source.
        time.sleep(.35)
        client.send(1, 0x14, struct.pack('<I', 1048576))
        while not client.events:
            client.process(credit=False)
        assert client.events[-1]['status'] == -signal.SIGKILL
        assert client.events[-1]['final_seq'] == client.out
        print('Reaped shim final output and ordered exit survive delayed credit: PASS')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
