#!/usr/bin/env python3
"""Real-shim bound, persisted reconnect status and stream-local ended answers [D13,D218], #151."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, exact, fixture_state


def shim_frame(peer):
    return exact(peer, struct.unpack('<I', exact(peer, 4))[0])


def send_shim(peer, body):
    peer.sendall(struct.pack('<I', len(body)) + body)


def ended(client, identity):
    stream, kind, body = client.read()
    assert (stream, kind) == (1, 0x33), (stream, kind, body)
    assert body[:4] == bytes(4)
    event = json.loads(body[4:])
    assert event['type'] == 'terminal.exited'
    assert event['session_id'] == str(identity) and event['status'] == 7
    assert event['final_seq'] > 0
    stream, kind, body = client.read()
    assert (stream, kind) == (1, 0x0f)
    assert struct.unpack('<H', body[:2])[0] == 4404 and body[2:] == b'session ended'
    return event


def run(binary):
    state = fixture_state('r')
    identity = uuid.uuid4()
    path = state / 'sessions' / f'{identity.hex}.sock'
    env = dict(os.environ, ZDOTDIR=str(Path('crates/infraternal/tests/profile').resolve()))
    shim = subprocess.Popen([str(binary), '__shim', '--session', identity.hex,
                             '--uid', str(os.getuid()), '--state', str(state),
                             '--exit-retention-ms', '1000'], env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    client = None
    try:
        deadline = time.monotonic() + 10
        while not path.exists():
            assert time.monotonic() < deadline and shim.poll() is None
            time.sleep(.005)
        client = Binary(binary, state)
        client.id = identity
        client.send(1, 0x16, identity.bytes + bytes(16))
        assert client.process(credit=False) == 0x13
        # The prompt supplies output so the unfunded data link hits its deadline.
        deadline = time.monotonic() + 5
        while True:
            sockets = 0
            for fd in Path(f'/proc/{shim.pid}/fd').iterdir():
                try:
                    sockets += os.readlink(fd).startswith('socket:')
                except FileNotFoundError:
                    pass
            if sockets == 2:
                break
            assert time.monotonic() < deadline, 'data link did not detach'
            time.sleep(.005)
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(5)
            peer.connect(str(path))
            shim_frame(peer)
            send_shim(peer, b'\x02' + bytes(8))
            send_shim(peer, b'\x10' + b"printf 'FINAL_%s\\n' OUTPUT; exit 7\n")
            children = Path(f'/proc/{shim.pid}/task/{shim.pid}/children')
            deadline = time.monotonic() + 5
            while children.read_text().strip():
                assert time.monotonic() < deadline
                time.sleep(.005)
        assert path.exists(), 'owned shim retired before its bound'
        first = ended(client, identity)  # No credit: owner EOF must wake the relay.
        assert shim.wait(timeout=2) == 0, shim.stderr.read()
        assert not path.exists()
        client.kill()
        # Recreate the daemon: the record must not depend on its old registry.
        client = Binary(binary, state)
        client.send(1, 0x16, identity.bytes + bytes(16))
        assert ended(client, identity) == first
        client.send(0, 0x08, struct.pack('<QQ', 151, 0))
        assert client.read()[:2] == (0, 0x09), 'ended stream closed the channel'
        client.send(3, 0x16, uuid.uuid4().bytes + bytes(16))
        stream, kind, body = client.read()
        assert (stream, kind) == (3, 0x0f) and struct.unpack('<H', body[:2])[0] == 4404
        print('Bounded owned exit, unfunded notification, restarted reconnect status, unknown session: PASS')
    finally:
        if client is not None:
            client.kill()
        if shim.poll() is None:
            shim.kill()
        shim.wait(timeout=5)
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve())
