#!/usr/bin/env python3
"""Verify inherited-account cleanup admission with a full set of live owner links [D18,D240]."""
import json
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import socket
import struct
import sys
import uuid

sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, exact, control, detach, marker, select_terminal


def frame(kind, body=b''):
    return struct.pack('<I', len(body) + 1) + bytes([kind]) + body


def receive(peer):
    return exact(peer, struct.unpack('<I', exact(peer, 4))[0])


def main():
    assert os.geteuid() != 0
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / ('p' + uuid.uuid4().hex[:8])
    root.mkdir(mode=0o700, parents=True)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    client = None
    pin = None
    peers = []
    person = uuid.uuid4()
    try:
        client = Binary(Path(sys.argv[1]).resolve(), root)
        values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name, uid=os.geteuid(), cols=80, rows=24)
        session = control(client, 1, 'terminal.open', values)['session_id']
        select_terminal(client, session)
        pid_path = root / 'shell.pid'
        client.input(f'printf "%s\\n" "$$" > {shlex.quote(str(pid_path))}\n'.encode())
        marker(client, 'review-capacity-ready')
        pin = os.pidfd_open(int(pid_path.read_text().strip()))
        detach(client)
        path = root / 'sessions' / (uuid.UUID(session).hex + '.sock')
        # Each completed ownership barrier proves this peer occupies an admitted
        # slot. These links never select writers or request terminal output.
        refused = 0
        for _ in range(64):
            peer = socket.socket(socket.AF_UNIX)
            peer.settimeout(5)
            peer.connect(str(path))
            try:
                assert receive(peer)[0] == 1
                peer.sendall(frame(2, struct.pack('<Q', 8)) + frame(0x19))
                assert receive(peer)[0] == 0x1a
                peers.append(peer)
            except EOFError:
                peer.close()
                refused += 1
        assert len(peers) == 32 and refused == 32, 'fixture did not prove the ordinary peer limit and overflow'
        client.send(0, 0x30, struct.pack('<I', 2) + bytes([len('terminal.login.revoke')]) + b'terminal.login.revoke' + json.dumps(dict(person=str(person))).encode())
        while True:
            item = client.read()
            if item[:2] == (0, 0x31):
                body = item[2]
                assert struct.unpack('<I', body[:4])[0] == 2
                acknowledged = body[4] == 1
                result = json.loads(body[5:])
                break
            client.process(frame=item)
        stopped = bool(select.select([pin], [], [], 0)[0])
        print(json.dumps(dict(owner_links=len(peers), refused_owner_links=refused, cleanup_confirmed=acknowledged, shell_stopped=stopped, result=result)), flush=True)
        assert acknowledged and stopped, 'live owner links refused person cleanup while its shell remained running'
    finally:
        for peer in peers:
            peer.close()
        if client is not None:
            try:
                control(client, 3, 'terminal.login.revoke', dict(person=str(person)))
            except (OSError, EOFError, RuntimeError):
                pass
            client.kill()
        cleanup(root)
        if pin is not None:
            # Cleanup targets only this fixture's pinned shell if the protocol
            # could not stop it. A recycled numeric PID is never signalled.
            if not select.select([pin], [], [], 0)[0]:
                import signal
                signal.pidfd_send_signal(pin, signal.SIGKILL)
            os.close(pin)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
