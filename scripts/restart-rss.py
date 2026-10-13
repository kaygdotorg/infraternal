#!/usr/bin/env python3
"""Measure only private perf-VM fixture shims and the fixture server's child (#199)."""
import os
from pathlib import Path
import socket
import struct
import sys
import time

from agent_fixture import exact


def rss(pid):
    """Kernel resident pages, without reading process arguments or environments."""
    return int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')


if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
    raise SystemExit('private perf-VM mount namespace required')
state = Path(sys.argv[1])
server = int(sys.argv[2])
values = []
shim_pids = []
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
        shim_pids.append(pid)
children = set()
for task in Path(f'/proc/{server}/task').iterdir():
    children.update((task / 'children').read_text().split())
if len(children) != 1:
    raise SystemExit('expected one fixture-owned embedded daemon')
print(f'METRIC shim_count={len(values)} shim_rss_mean_bytes={sum(values)//len(values)} '
      f'shim_rss_total_bytes={sum(values)} shim_rss_max_bytes={max(values)} '
      f'daemon_rss_bytes={rss(int(next(iter(children))))} server_rss_bytes={rss(server)}')

if os.environ.get('RESTART_CPU_SAMPLE') == '1':
    daemon = int(next(iter(children)))
    def ticks(pid):
        """Read user/system CPU ticks only; process command lines remain unread."""
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return int(fields[11]) + int(fields[12])
    tracked = [server, daemon, *shim_pids]
    before = [ticks(pid) for pid in tracked]
    started = time.monotonic()
    time.sleep(5)
    elapsed = time.monotonic() - started
    percentages = [(ticks(pid) - initial) / os.sysconf('SC_CLK_TCK') / elapsed * 100
                   for pid, initial in zip(tracked, before)]
    print(f'METRIC attached_sessions={len(shim_pids)} idle_sample_seconds={elapsed:.3f} '
          f'server_cpu_percent={percentages[0]:.3f} daemon_cpu_percent={percentages[1]:.3f} '
          f'shim_cpu_total_percent={sum(percentages[2:]):.3f} '
          f'load={Path("/proc/loadavg").read_text().strip()}')
