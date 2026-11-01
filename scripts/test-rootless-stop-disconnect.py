#!/usr/bin/env python3
"""Verify a complete lifecycle request survives sender disconnect before shim readiness [D18,D240,D247]."""
import json
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import signal
import socket
import sys
import time
import uuid

sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'scripts'))
from agent_fixture import Binary, cleanup, shim_socket_count, control, detach, marker, select_terminal


def main():
    assert os.geteuid() != 0
    root = Path.home() / '.cache/codex-scratch/real-logins-review' / ('e' + uuid.uuid4().hex[:8])
    root.mkdir(mode=0o700, parents=True)
    os.environ['INFRATERNAL_TEST_RTT'] = '0'
    client = None
    shell_pin = shim_pin = None
    paused = False
    try:
        client = Binary(Path(sys.argv[1]).resolve(), root)
        person = uuid.uuid4()
        values = dict(person=str(person), account=pwd.getpwuid(os.geteuid()).pw_name,
                      uid=os.geteuid(), cols=80, rows=24)
        session = control(client, 1, 'terminal.open', values)['session_id']
        select_terminal(client, session)
        pid_path = root / 'shell.pid'
        client.input(f'printf "%s\\n" "$$" > {shlex.quote(str(pid_path))}\n'.encode())
        marker(client, 'review-shell-started')
        shell_pid = int(pid_path.read_text().strip())
        shell_pin = os.pidfd_open(shell_pid)
        # The local shell is a direct child of its shim. Pinned descriptors
        # limit every fixture signal to these exact owned processes.
        shim_pid = int(Path(f'/proc/{shell_pid}/stat').read_text().rsplit(') ', 1)[1].split()[1])
        shim_pin = os.pidfd_open(shim_pid)
        detach(client)
        endpoint = root / 'sessions' / (uuid.UUID(session).hex + '.stop')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect(str(endpoint))
            deadline = time.monotonic() + 5
            # Listener plus the accepted socket proves kernel-credential
            # admission completed before the caller writes and disconnects.
            while shim_socket_count(shim_pid, endpoint) < 2:
                assert time.monotonic() < deadline, 'cleanup admission barrier not reached'
                time.sleep(.005)
            signal.pidfd_send_signal(shim_pin, signal.SIGSTOP)
            paused = True
            while Path(f'/proc/{shim_pid}/stat').read_text().rsplit(') ', 1)[1].split()[0] != 'T':
                assert time.monotonic() < deadline, 'shim pause barrier not reached'
                time.sleep(.005)
            peer.sendall(b'!')
        signal.pidfd_send_signal(shim_pin, signal.SIGCONT)
        paused = False
        stopped = bool(select.select([shell_pin], [], [], 5)[0])
        print(json.dumps(dict(cleanup_byte_written=True, sender_disconnected=True,
                              owned_shell_stopped=stopped)), flush=True)
        # Always retire the fixture through the normal production controller,
        # including on the pre-fix path, before checking the lost-request result.
        control(client, 2, 'terminal.login.revoke', dict(person=str(person)))
        assert stopped, 'a complete disconnected lifecycle request retained its owned shell'
    finally:
        if paused and shim_pin is not None:
            signal.pidfd_send_signal(shim_pin, signal.SIGCONT)
        if client is not None:
            client.kill()
        cleanup(root)
        for fd in (shell_pin, shim_pin):
            if fd is not None:
                os.close(fd)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
