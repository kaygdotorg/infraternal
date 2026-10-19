#!/usr/bin/env python3
"""Attribute mixed-load host stalls with private numeric scheduler/syscall traces [D270].

This is a diagnostic run: tracing overhead precludes using it as a budget run.
No output, input, pathname arguments or process environment enter the receipt.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import asyncio
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import re
import resource
import select
import threading
from types import SimpleNamespace

from ppu_soak import Host, Recorder, percentile, soak


def scheduler_slice(pid, microseconds):
    """Measure a normal-scheduler slice without changing nice value or policy."""
    assert os.uname().machine == 'x86_64', 'experiment syscall numbers are x86_64 only'
    class Attributes(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint32), ('policy', ctypes.c_uint32),
                    ('flags', ctypes.c_uint64), ('nice', ctypes.c_int32),
                    ('priority', ctypes.c_uint32), ('runtime', ctypes.c_uint64),
                    ('deadline', ctypes.c_uint64), ('period', ctypes.c_uint64),
                    ('util_min', ctypes.c_uint32), ('util_max', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    attributes = Attributes()
    size = ctypes.sizeof(attributes)
    def get():
        if libc.syscall(315, pid, ctypes.byref(attributes), size, 0):
            raise OSError(ctypes.get_errno(), 'fixture sched_getattr failed')
        assert attributes.policy == attributes.priority == 0
        return dict(policy=attributes.policy, nice=attributes.nice, runtime_ns=attributes.runtime)
    before = get()
    attributes.runtime = microseconds * 1000
    if libc.syscall(314, pid, ctypes.byref(attributes), 0):
        raise OSError(ctypes.get_errno(), 'fixture sched_setattr failed')
    after = get()
    assert after['runtime_ns'] == microseconds * 1000 and before['nice'] == after['nice']
    return dict(before=before, after=after)


def parse_event(line, pid):
    """Support both syscall trace printers; never retain syscall argument text."""
    match = re.search(rb' (\d+\.\d+): (.*)', line)
    if not match:
        return None
    stamp, body = match.groups()
    state = ''
    if body.startswith(b'sched_switch:'):
        kind = 'sched_switch'
        if re.search(rb'prev_pid=' + str(pid).encode() + rb'\b', body):
            state = 'out-runnable' if b'prev_state=R' in body else 'out-sleeping'
        else:
            state = 'in'
    elif body.startswith(b'sched_wakeup:'):
        kind = 'sched_wakeup'
    else:
        call = re.match(rb'(sys_(?:enter|exit)_\w+):', body)
        if call:
            kind = call[1].decode()
        else:
            call = re.match(rb'sys_(\w+)(\(|\s+->)', body)
            if not call:
                return None
            kind = 'sys_' + ('enter_' if call[2] == b'(' else 'exit_') + call[1].decode()
    return float(stamp), kind, state


class Trace:
    """Stream only the fixture host's events from an independently owned instance."""
    def __init__(self, pid):
        self.pid = pid
        self.owned = False
        self.root = Path('/sys/kernel/tracing/instances') / f'ppu-stalls-{os.getpid()}'
        self.stop = threading.Event()
        self.thread = None
        self.fd = None
        self.events = []
        self.error = None
        try:
            self.root.mkdir()
            self.owned = True
            (self.root / 'tracing_on').write_text('0')
            (self.root / 'trace_clock').write_text('mono')
            (self.root / 'buffer_size_kb').write_text('16384')
            self.enable('sched/sched_switch', f'prev_pid == {pid} || next_pid == {pid}')
            self.enable('sched/sched_wakeup', f'pid == {pid}')
            self.enable('syscalls', f'common_pid == {pid}')
            self.fd = os.open(self.root / 'trace_pipe', os.O_RDONLY | os.O_NONBLOCK)
            (self.root / 'tracing_on').write_text('1')
            self.thread = threading.Thread(target=self.drain, daemon=True)
            self.thread.start()
        except OSError as error:
            self.error = type(error).__name__

    def enable(self, event, condition):
        root = self.root / 'events' / event
        (root / 'filter').write_text(condition)
        (root / 'enable').write_text('1')

    def drain(self):
        pending = b''
        while not self.stop.is_set():
            if select.select([self.fd], [], [], .05)[0]:
                with contextlib.suppress(BlockingIOError):
                    lines = (pending + os.read(self.fd, 262144)).split(b'\n')
                    pending = lines.pop()
                    for line in lines:
                        # Discard syscall arguments immediately. Keep just time,
                        # event name and the host's scheduler state transition.
                        event = parse_event(line, self.pid)
                        if event:
                            self.events.append(event)

    def close(self):
        if self.owned and self.root.exists():
            with contextlib.suppress(OSError):
                (self.root / 'tracing_on').write_text('0')
        self.stop.set()
        if self.thread:
            self.thread.join()
        if self.fd is not None:
            os.close(self.fd)
        overruns = 0
        if self.owned and self.root.exists():
            for path in (self.root / 'per_cpu').glob('cpu*/stats'):
                for line in path.read_text().splitlines():
                    key, _, value = line.partition(':')
                    if key.strip() in ('overrun', 'commit overrun'):
                        overruns += int(value)
            for path in (self.root / 'events').glob('*/*/enable'):
                with contextlib.suppress(OSError):
                    path.write_text('0')
            self.root.rmdir()
            self.owned = False
        return summarize(self.events) | dict(error=self.error, overruns=overruns,
                                              complete=self.error is None and overruns == 0)


def summarize(events):
    """Separate blocked/runnable descheduling from synchronous work between syscalls."""
    values = {}
    last_exit = None
    entered = {}
    switched = None
    off_cpu = 0
    awakened = None
    for stamp, kind, state in sorted(events):
        if kind == 'sched_wakeup':
            awakened = stamp
        elif kind == 'sched_switch':
            if state.startswith('out-'):
                switched = (stamp, state)
            else:
                if awakened is not None:
                    values.setdefault('wakeup-to-running', []).append(stamp - awakened)
                    awakened = None
                if switched:
                    elapsed = stamp - switched[0]
                    values.setdefault(switched[1], []).append(elapsed)
                    off_cpu += elapsed
                    switched = None
        elif kind.startswith('sys_enter_'):
            if last_exit is not None:
                values.setdefault('userspace-between-syscalls', []).append(max(0, stamp - last_exit - off_cpu))
            entered[kind[10:]] = stamp
            last_exit = None
        elif kind.startswith('sys_exit_'):
            syscall = kind[9:]
            if syscall in entered:
                values.setdefault(syscall, []).append(stamp - entered.pop(syscall))
            last_exit, off_cpu = stamp, 0
    return {key: dict(count=len(rows), total_ms=sum(rows) * 1000,
                      p99_ms=percentile(rows, .99) * 1000, max_ms=max(rows) * 1000)
            for key, rows in values.items()}


async def run(args):
    assert os.uname().nodename == 'infraternal-perf-test'
    assert args.host_slice_us == 0 or 100 <= args.host_slice_us <= 10000
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 16384), hard))
    args.evidence.mkdir(parents=True, exist_ok=False)
    host = Host(args.binary.resolve(), args.evidence / 's', 1000, 0x2702050000)
    trace = None
    record = Recorder(args.evidence)
    try:
        await host.ready()
        scheduling = scheduler_slice(host.pid, args.host_slice_us) if args.host_slice_us else None
        record.write('environment', machine=os.uname().nodename, load_average=os.getloadavg(),
                     binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                     driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     scheduling=scheduling, traced=not args.without_trace, budget_admission=False)
        trace = None if args.without_trace else Trace(host.pid)
        print('mixed load started', flush=True)
        await soak(host, SimpleNamespace(mode='soak', seconds=args.seconds, warmup=30,
                   interval=1, memory_tolerance_kib=1024, echo_ratio=1.25), record, random.Random(270205))
    finally:
        if trace:
            summary = trace.close()
            (args.evidence / 'trace-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            # These sanitized events make attribution independently inspectable.
            with (args.evidence / 'trace-events.jsonl').open('w') as output:
                for event in trace.events:
                    output.write(json.dumps(event) + '\n')
            print(json.dumps(summary), flush=True)
        record.file.close()
        await host.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=180)
    parser.add_argument('--host-slice-us', type=int, default=0)
    parser.add_argument('--without-trace', action='store_true')
    asyncio.run(run(parser.parse_args()))
