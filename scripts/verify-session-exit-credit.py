#!/usr/bin/env python3
"""A reaped shim's final output and exit survive a viewer that grants credit after starvation [D13], #151."""
import argparse
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, exact, fixture_state


def run(binary, exit_after_detach=False):
    state = fixture_state('e')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        path = state / 'sessions' / f'{client.id.hex}.sock'
        # Read the session receipt before attaching so the test retains the
        # shim's ownership metadata without depending on prompt formatting.
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(10)
            peer.connect(str(path))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
            assert hello[11:27] == client.id.bytes
            pid = struct.unpack('<I', hello[27:31])[0]
            retained_owner = bool(struct.unpack('<Q', hello[3:11])[0] & 8)
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, 0))
        assert client.process(credit=False) == 0x13
        ready_file = state / 'shell-ready'
        shell_command = (
            "printf 'shell-ready-%s\\n' check; : > "
            + shlex.quote(str(ready_file.resolve()))
            + "\n"
        ).encode()
        client.input(shell_command)
        client.wait_ack()
        deadline = time.monotonic() + 10
        while not ready_file.exists():
            assert time.monotonic() < deadline, 'login shell did not execute the readiness command'
            time.sleep(.005)
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        assert len(children) == 1
        if exit_after_detach:
            # Use the wire to prove starvation detached the local data link.
            client.wait_for_starvation_detach()
            # Control-only input emits final bytes and a known exit status,
            # without turning the probe into another output viewer.
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(5)
                peer.connect(str(path))
                exact(peer, struct.unpack('<I', exact(peer, 4))[0])
                final_input = b"printf 'FINAL_%s\\n' OUTPUT; exit 7\n"
                for body in [
                    b'\x02' + struct.pack('<Q', 0),
                    b'\x10' + final_input,
                ]:
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
        terminal_exit = None
        while terminal_exit is None:
            frame = client.read()
            if frame[1] in (0x11, 0x15):
                # A funded recovery may carry a repaint rather than raw bytes.
                received.extend(frame[2][8:])
            client.process(credit=False, frame=frame)
            terminal_exit = next(
                (event for event in reversed(client.events) if event.get('type') == 'terminal.exited'),
                None,
            )
        assert b'shell-ready-check' in received, 'retained shell output was not delivered'
        assert terminal_exit['status'] == (7 if exit_after_detach else -signal.SIGKILL)
        assert terminal_exit['final_seq'] == client.out
        if exit_after_detach:
            assert b'FINAL_OUTPUT' in received, (
                f'final output was not delivered: cursor={client.out}, '
                f'terminal_exit={terminal_exit!r}, tail={received[-256:]!r}'
            )
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
