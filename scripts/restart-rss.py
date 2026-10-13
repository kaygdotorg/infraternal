#!/usr/bin/env python3
"""Measure only private perf-VM fixture shims and the fixture server's child (#199)."""
import os
from pathlib import Path
import socket
import struct
import sys

from agent_fixture import exact


def rss(pid):
    """Kernel resident pages, without reading process arguments or environments."""
    return int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')


if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
    raise SystemExit('private perf-VM mount namespace required')
state = Path(sys.argv[1])
server = int(sys.argv[2])
values = []
for path in sorted((state / 'sessions').glob('*.sock')):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(2)
        peer.connect(str(path))
        hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
        if hello[0] != 1 or hello[11:27].hex() != path.stem:
            raise SystemExit('fixture rendezvous identity mismatch')
        pid = struct.unpack('<I', hello[27:31])[0]
        _, actual_uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        # Detached shims inherit their listener across a double fork, so its
        # credential PID belongs to the launcher. Hello names the surviving shim.
        if actual_uid != os.getuid():
            raise SystemExit('fixture shim peer mismatch')
        values.append(rss(pid))
children = set()
for task in Path(f'/proc/{server}/task').iterdir():
    children.update((task / 'children').read_text().split())
if len(children) != 1:
    raise SystemExit('expected one fixture-owned embedded daemon')
print(f'METRIC shim_count={len(values)} shim_rss_mean_bytes={sum(values)//len(values)} '
      f'shim_rss_total_bytes={sum(values)} shim_rss_max_bytes={max(values)} '
      f'daemon_rss_bytes={rss(int(next(iter(children))))} server_rss_bytes={rss(server)}')
