#!/usr/bin/env python3
"""Pause one fixture-owned upstream through a pidfd; EOF always resumes it (#199)."""
import os
from pathlib import Path
import signal
import socket
import struct
import sys


# Reuse the frozen shim greeting reader used by the other private PTY fixtures.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts'))
from agent_fixture import exact


kind, server_pid, shim_state, session_id = sys.argv[1:]
if kind == 'daemon':
    children = set()
    for task in Path(f'/proc/{int(server_pid)}/task').iterdir():
        children.update((task / 'children').read_text().split())
    if len(children) != 1:
        raise SystemExit('expected exactly one fixture-owned daemon')
    pid = int(next(iter(children)))
    if Path(f'/proc/{pid}').stat().st_uid != os.getuid():
        raise SystemExit('fixture child uid mismatch')
else:
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(3)
        peer.connect(str(Path(shim_state) / 'sessions' / f'{session_id}.sock'))
        length = struct.unpack('<I', exact(peer, 4))[0]
        if not 31 <= length <= 256:
            raise SystemExit('invalid fixture greeting size')
        hello = exact(peer, length)
        if hello[0] != 1 or hello[11:27].hex() != session_id:
            raise SystemExit('fixture shim identity mismatch')
        _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid():
            raise SystemExit('fixture shim uid mismatch')
        pid = struct.unpack('<I', hello[27:31])[0]
handle = os.pidfd_open(pid)
try:
    signal.pidfd_send_signal(handle, signal.SIGSTOP)
    print(f'paused {pid}', flush=True)
    sys.stdin.readline()
finally:
    try:
        signal.pidfd_send_signal(handle, signal.SIGCONT)
    except ProcessLookupError:
        pass  # The fixture server may already have replaced/reaped its daemon.
    os.close(handle)
