#!/usr/bin/env python3
"""Check shim-only THP opt-out and unchanged shell policy across exec (#24).

SPDX-License-Identifier: AGPL-3.0-only
"""
import ctypes
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def thp_enabled(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    return int(next(line.split()[1] for line in status.splitlines()
                    if line.startswith('THP_enabled:')))


def receive(peer, count):
    data = b''
    while len(data) < count:
        chunk = peer.recv(count - len(data))
        assert chunk, 'shim closed before Hello'
        data += chunk
    return data


def check(binary, inherited_disabled, detach):
    libc = ctypes.CDLL(None, use_errno=True)

    def policy():
        if libc.prctl(41, inherited_disabled, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'set fixture THP policy')

    root = os.environ.get('INFRATERNAL_TEST_STATE_ROOT', str(Path.home()))
    with tempfile.TemporaryDirectory(prefix='thp-', dir=root) as state:
        session = 'e' * 32
        process = subprocess.Popen(
            [binary, '__shim', '--session', session, '--uid', str(os.getuid()),
             '--cols', '80', '--rows', '24', '--state', state, '--readiness',
             *(['--detach'] if detach else [])],
            preexec_fn=policy, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        shim = process.pid
        children = []
        try:
            deadline = time.monotonic() + 10
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(10)
                while True:
                    try:
                        peer.connect(str(Path(state) / 'sessions' / f'{session}.sock'))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        if time.monotonic() >= deadline:
                            raise AssertionError('shim socket startup timed out')
                        time.sleep(.01)
                # Cleanup trusts the kernel's peer identity, never a decoded PID.
                shim, _, _ = struct.unpack('3i', peer.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                # Hello is emitted only after PTY spawn and terminal initialization.
                size, = struct.unpack('<I', receive(peer, 4))
                hello = receive(peer, size)
                assert hello[0] == 1, 'expected Hello'
                hello_pid, = struct.unpack_from('<I', hello, 27)
                assert hello_pid == shim, 'Hello PID differs from socket owner'
                children = [int(pid) for pid in Path(
                    f'/proc/{shim}/task/{shim}/children').read_text().split()]
                assert len(children) == 1, children
                assert thp_enabled(shim) == 0, 'shim remains THP-enabled'
                assert thp_enabled(children[0]) == 1 - inherited_disabled, 'shell THP policy changed'
                print(f'inherited_disabled={inherited_disabled} detach={detach} '
                      f'shim_THP_enabled=0 shell_THP_enabled={1 - inherited_disabled}')
        finally:
            for pid in children + ([shim] if shim != process.pid else []):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


if __name__ == '__main__':
    for disabled in (0, 1):
        for detached in (False, True):
            check(sys.argv[1], disabled, detached)
