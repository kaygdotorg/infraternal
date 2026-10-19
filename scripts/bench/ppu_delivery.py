#!/usr/bin/env python3
"""Conservative driver-delay bounds from numeric own-host writes, never admission [#205]."""
import asyncio
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import time
import ppu_soak as suite
import ppu_trace as trace

original_echo = suite.Peer.echo
original_ready = suite.Host.ready
original_trace = trace.Trace
probes = []
fd_sessions = {}


def number(body, field):
    """Trace event fields use decimal; the syscall printer uses bare hex."""
    match = re.search(rb'\b' + field + rb'(=|:\s*)(-?(?:0x)?[0-9a-fA-F]+)\b', body)
    if not match:
        return None
    separator, token = match.groups()
    try:
        value = int(token, 16 if separator != b'=' or b'0x' in token else 10)
    except ValueError:
        return None
    return value - (1 << 64) if value >= 1 << 63 else value


async def ready(host):
    await original_ready(host)
    # Only numeric identities from this fixture's own sockets survive parsing.
    prefix = str(host.root / 'sessions') + '/'
    inodes = {}
    for line in Path('/proc/net/unix').read_text().splitlines():
        parts = line.split()
        if len(parts) != 8 or parts[3] != '00000000' or parts[5] != '03' or not parts[-1].startswith(prefix):
            continue
        name = Path(parts[-1]).name
        if re.fullmatch(r'[0-9a-f]{32}\.sock', name):
            index = int(name[:-5], 16) - host.origin
            if 0 <= index < host.count:
                inodes[parts[6]] = index
    for path in Path(f'/proc/{host.pid}/fd').iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target.startswith('socket:[') and target[8:-1] in inodes:
            fd_sessions[int(path.name)] = inodes[target[8:-1]]
    active = set(range(host.count - max(1, host.count // 10), host.count))
    assert active <= set(fd_sessions.values()), 'active socket identity missing'


async def echo(peer, marker, command=b''):
    if not marker.startswith(b'probe-'):
        return await original_echo(peer, marker, command)
    _, index, count = marker.split(b'-')
    before = time.monotonic()
    elapsed = await original_echo(peer, marker, command)
    after = time.monotonic()
    # The original echo takes its start after this wrapper. Thus this sum
    # cannot be later than its true receive timestamp; no CPU is subtracted.
    probes.append(dict(session=int(index), number=int(count), before=before,
        receive_lower=before + elapsed / 1000, after=after, rtt_ms=elapsed))
    return elapsed


class DeliveryTrace(original_trace):
    def __init__(self, pid):
        self.writes = []
        self.entered_fd = None
        super().__init__(pid)

    def drain(self):
        pending = b''
        while not self.stop.is_set():
            if trace.select.select([self.fd], [], [], .05)[0]:
                try:
                    lines = (pending + os.read(self.fd, 262144)).split(b'\n')
                except BlockingIOError:
                    continue
                pending = lines.pop()
                for line in lines:
                    event = trace.parse_event(line, self.pid)
                    if not event:
                        continue
                    self.events.append(event)
                    stamp, kind, _ = event
                    if kind == 'sys_enter_sendto':
                        self.entered_fd = number(line, b'fd')
                    elif kind == 'sys_exit_sendto':
                        result = number(line, b'ret')
                        if result is None:
                            returned = re.search(rb'->\s*(-?(?:0x)?[0-9a-fA-F]+)\b', line)
                            if returned:
                                result = int(returned[1], 16)
                                if result >= 1 << 63: result -= 1 << 64
                        if self.entered_fd in fd_sessions and result is not None and result > 0:
                            self.writes.append((stamp, fd_sessions[self.entered_fd]))
                        self.entered_fd = None

    def close(self):
        summary = super().close()
        by_session = {}
        for stamp, session in sorted(self.writes):
            by_session.setdefault(session, []).append(stamp)
        rows = []
        for probe in probes:
            writes = by_session.get(probe['session'], [])
            at = bisect.bisect_right(writes, probe['after']) - 1
            if at < 0 or writes[at] < probe['before']:
                continue
            # A later unrelated Ack only reduces this bound. Actual marker
            # delivery cannot predate its host's final successful write exit.
            rows.append(probe | dict(last_write_exit=writes[at],
                driver_delay_lower_ms=max(0, (probe['receive_lower'] - writes[at]) * 1000)))
        if not rows or len(rows) != len(probes):
            summary['complete'] = False
            summary['delivery_error'] = 'incomplete probe correlation; syscall printer or socket identity unsupported'
        summary['delivery'] = dict(budget_admission=False, probe_count=len(probes),
            correlated_count=len(rows), write_count=len(self.writes), rows=rows)
        return summary


original_record_write = suite.Recorder.write

def record_write(record, kind, **fields):
    if kind == 'environment':
        fields.update(delivery_diagnostic_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      mapped_own_socket_fds=len(fd_sessions))
    return original_record_write(record, kind, **fields)

def main():
    """Install hooks only in this diagnostic process, never on test import."""
    suite.Recorder.write = record_write
    suite.Peer.echo = echo
    suite.Host.ready = ready
    trace.Trace = DeliveryTrace
    parser = trace.argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=90)
    parser.add_argument('--host-slice-us', type=int, default=0)
    parser.add_argument('--without-trace', action='store_true')
    arguments = parser.parse_args()
    asyncio.run(trace.run(arguments))
    if not arguments.without_trace:
        result = json.loads((arguments.evidence / 'trace-summary.json').read_text())
        if not result['complete']:
            raise SystemExit(2)


if __name__ == '__main__':
    main()
