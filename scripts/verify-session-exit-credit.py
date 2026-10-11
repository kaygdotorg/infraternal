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
from agent_fixture import Binary, cleanup, exact, fixture_state, shim_socket_count


def run(binary, exit_after_detach=False):
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
            retained_owner = bool(struct.unpack('<Q', hello[3:11])[0] & 8)
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
        if exit_after_detach:
            # Observe data-link detachment: only the listener and, when
            # negotiated, the independent owner remain. The window is still open.
            deadline = time.monotonic() + 5
            while True:
                sockets = shim_socket_count(pid, path)
                if sockets == (2 if retained_owner else 1):
                    break
                assert time.monotonic() < deadline, 'relay did not detach'
                time.sleep(.005)
            # Control-only input emits final bytes and a known exit status,
            # without turning the probe into another output viewer.
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(5)
                peer.connect(str(path))
                exact(peer, struct.unpack('<I', exact(peer, 4))[0])
                for body in [b'\x02' + struct.pack('<Q', 0), b'\x10' + b"printf 'FINAL_%s\\n' OUTPUT; exit 7\n"]:
                    peer.sendall(struct.pack('<I', len(body)) + body)
        else:
            os.kill(int(children[0]), signal.SIGKILL)
        if not retained_owner:
            deadline = time.monotonic() + 1
            while path.exists():
                assert time.monotonic() < deadline, 'shim did not retire after writing its exit'
                time.sleep(.005)
        # Cross the existing one-shot 250 ms relay starvation deadline with no
        # Credit. Legacy shims retain socket bytes; new shims retain owned state.
        time.sleep(.35)
        client.send(1, 0x14, struct.pack('<I', 1048576))
        received = bytearray()
        while not client.events:
            frame = client.read()
            if frame[1] in (0x11, 0x15):
                # A funded recovery may carry a repaint rather than raw bytes.
                received.extend(frame[2][8:])
            client.process(credit=False, frame=frame)
        assert client.events[-1]['status'] == (7 if exit_after_detach else -signal.SIGKILL)
        assert client.events[-1]['final_seq'] == client.out
        if exit_after_detach:
            assert b'FINAL_OUTPUT' in received, 'final output was not delivered'
        deadline = time.monotonic() + 1
        while path.exists():
            assert time.monotonic() < deadline, 'shim did not retire after ordered delivery'
            time.sleep(.005)
        print('Reaped shim final output and ordered exit survive delayed credit: PASS')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--exit-after-detach', action='store_true')
    args = parser.parse_args()
    run(args.binary, args.exit_after_detach)
