#!/usr/bin/env python3
"""Observe scheduler, off-CPU stacks and reclaim beside exact echo stages [D270].

This is diagnostic only: numeric stages, extra PID setup and tracing affect the
workload. Reuse the corrected marker endpoint and original shell commands. A
private reader process discards syscall arguments and fault addresses before
writing receipts. Never enable events in the global trace instance.
SPDX-License-Identifier: AGPL-3.0-only
"""
import contextlib
import json
import os
from pathlib import Path
import re
import select
import time
from types import SimpleNamespace

import ppu_compare as compare
from ppu_delivery import number
import ppu_soak as suite
import ppu_stages as stages
import ppu_trace as trace
from ppu_trace_process import CONTEXT, Drain

BASE_TRACE = trace.Trace
ORIGINAL_WAKEUPS = suite.Wakeups
ROLES = {}
ROOT = None
CURRENT = None


def numeric_events(line, known):
    """Retain owned scheduler identities and event names, never raw arguments."""
    match = re.search(rb' (\d+\.\d+): (.*)', line)
    if not match:
        return []
    stamp, body = float(match[1]), match[2]
    if body.startswith(b'sched_switch:'):
        previous = re.search(rb'prev_pid=(\d+)\b', body)
        following = re.search(rb'next_pid=(\d+)\b', body)
        rows = []
        if previous and int(previous[1]) in known:
            rows.append((stamp, int(previous[1]), 'sched_switch',
                         'out-runnable' if b'prev_state=R' in body else 'out-sleeping'))
        if following and int(following[1]) in known:
            rows.append((stamp, int(following[1]), 'sched_switch', 'in'))
        return rows
    if body.startswith((b'sched_wakeup:', b'sched_waking:')):
        pid = re.search(rb'pid=(\d+)\b', body)
        return [(stamp, int(pid[1]), body.split(b':', 1)[0].decode(), '')] if pid and int(pid[1]) in known else []
    task = re.search(rb'-(\d+)\s+\[', line)
    if not task or int(task[1]) not in known:
        return []
    pid = int(task[1])
    event = trace.parse_event(line, pid)
    if event:
        return [(stamp, pid, event[1], event[2])]
    kind = body.split(b':', 1)[0]
    if kind.startswith((b'page_fault_', b'mm_vmscan_', b'mm_shrink_')) or b'<stack trace>' in body:
        return [(stamp, pid, 'stack' if b'<stack trace>' in body else kind.decode(), '')]
    return []


def futex_fields(line, kind, pid, reader, counter, identities):
    """Keep relative wait identities and return codes, never native addresses."""
    if kind == 'sys_enter_futex':
        address = number(line, b'uaddr')
        if address is None:
            address = number(line, b'uaddr1')
        operation = number(line, b'op')
        if address is not None and operation is not None:
            owner = reader if pid in (reader, counter) else pid
            identity = identities.setdefault((owner, address), len(identities) + 1)
            return dict(futex_lock=identity, futex_op=operation)
    elif kind == 'sys_exit_futex':
        result = number(line, b'ret')
        if result is None:
            match = re.search(rb'->\s*(-?(?:0x)?[0-9a-fA-F]+)\b', line)
            if match:
                result = int(match[1], 16)
                if result >= 1 << 63:
                    result -= 1 << 64
        if result is not None:
            return dict(futex_result=result)
    return {}


def read_fields(line, kind):
    """Identify short-read retries without retaining buffer addresses or bytes."""
    if kind == 'sys_enter_read':
        return {name: value for name, field in (('read_fd', b'fd'), ('read_count', b'count'))
                if (value := number(line, field)) is not None}
    if kind == 'sys_exit_read':
        value = number(line, b'ret')
        if value is None:
            match = re.search(rb'->\s*(-?(?:0x)?[0-9a-fA-F]+)\b', line)
            if match:
                value = int(match[1], 16)
                if value >= 1 << 63:
                    value -= 1 << 64
        return {} if value is None else dict(read_result=value)
    return {}


def task_counters(pid):
    """Separate page faults, run-queue time and timer slack from stage durations."""
    path = Path('/proc') / str(pid)
    fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(minor_faults=int(fields[7]), major_faults=int(fields[9]),
                schedstat=list(map(int, (path / 'schedstat').read_text().split())),
                timer_slack_ns=int((path / 'timerslack_ns').read_text()))


class RoleTrace(BASE_TRACE):
    """Trace verified fixture roles; bounded range filters precede exact decoding."""
    def __init__(self, pid):
        global CURRENT
        self.counter_tid = CONTEXT.Value('i', 0)
        self.known = set(ROLES.values())
        self.syscall_pids = {ROLES[name] for name in ('host', 'reader', 'session-971', 'session-993')}
        self.setup_error = None
        CURRENT = self
        super().__init__(pid)
        if self.error is not None:
            self.close()
            raise RuntimeError(f'private tail trace unavailable: {self.setup_error}')

    def enable(self, event, condition):
        low, high = min(self.known), max(self.known)
        # A range keeps the kernel expression below its one-page limit for 102
        # roles. The decoder still accepts only the verified exact PID set.
        if event == 'sched/sched_switch':
            condition = f'(prev_pid>={low}&&prev_pid<={high})||(next_pid>={low}&&next_pid<={high})'
        elif event in ('sched/sched_wakeup', 'sched/sched_waking'):
            condition = f'pid>={low}&&pid<={high}'
        elif event == 'syscalls':
            selected = self.syscall_pids | ({self.counter_tid.value} if self.counter_tid.value else set())
            condition = '||'.join(f'common_pid=={pid}' for pid in sorted(selected))
        try:
            super().enable(event, condition)
            if event == 'sched/sched_wakeup':
                super().enable('sched/sched_waking', condition)
            if event == 'syscalls' and not self.counter_tid.value:
                selected = '||'.join(f'common_pid=={pid}' for pid in sorted(self.syscall_pids))
                for group in ('exceptions/page_fault_user', 'exceptions/page_fault_kernel',
                              'vmscan/mm_vmscan_direct_reclaim_begin', 'vmscan/mm_vmscan_direct_reclaim_end',
                              'vmscan/mm_vmscan_memcg_reclaim_begin', 'vmscan/mm_vmscan_memcg_reclaim_end'):
                    super().enable(group, selected)
                # Capture kernel wait stacks only for the four syscall roles.
                # User stack unwinding needs a different build/tool and is not
                # inferred from these kernel symbols.
                sleeping = '||'.join(f'prev_pid=={pid}' for pid in sorted(self.syscall_pids))
                (self.root / 'events/sched/sched_switch/trigger').write_text(
                    f'stacktrace if prev_state!=0&&({sleeping})')
        except OSError as error:
            self.setup_error = dict(event=event, errno=error.errno)
            raise

    def drain(self):
        pending = b''
        stack = None
        events = stacks = 0
        identities = {}
        with (ROOT / 'tail-events.jsonl').open('w', buffering=1048576) as output:
            def emit(row):
                output.write(json.dumps(row, separators=(',', ':')) + '\n')
            while not self.stop.is_set():
                if not select.select([self.fd], [], [], .05)[0]:
                    continue
                with contextlib.suppress(BlockingIOError):
                    lines = (pending + os.read(self.fd, 262144)).split(b'\n')
                    pending = lines.pop()
                    known = self.known | ({self.counter_tid.value} if self.counter_tid.value else set())
                    for line in lines:
                        # Stack continuation lines contain symbols, not event
                        # arguments. Discard addresses/offsets before retention.
                        if line.lstrip().startswith(b'=>'):
                            symbol = re.match(rb'\s*=>\s*([A-Za-z_][A-Za-z_0-9.]*)', line)
                            if stack is not None and symbol:
                                stack['symbols'].append(symbol[1].decode())
                            continue
                        if stack is not None:
                            emit(stack)
                            stacks += 1
                            stack = None
                        for stamp, pid, kind, state in numeric_events(line, known):
                            if kind == 'stack':
                                stack = dict(kind='stack', ns=round(stamp * 1e9), pid=pid, symbols=[])
                            else:
                                emit(dict(kind=kind, ns=round(stamp * 1e9), pid=pid, state=state,
                                    **read_fields(line, kind),
                                    **futex_fields(line, kind, pid, ROLES['reader'],
                                                   self.counter_tid.value, identities)))
                                events += 1
            if stack is not None:
                emit(stack)
                stacks += 1
        (ROOT / 'tail-reader.json').write_text(json.dumps(dict(events=events, stacks=stacks)) + '\n')

    def close(self):
        # Remove our trigger before disabling/removing this private instance.
        if self.owned:
            with contextlib.suppress(OSError):
                (self.root / 'events/sched/sched_switch/trigger').write_text('!stacktrace')
        result = super().close()
        result.update(roles=ROLES, syscall_sessions=[971, 993], kernel_stacks_only=True)
        (ROOT / 'tail-roles.json').write_text(json.dumps(ROLES) + '\n')
        return result


class Wakeups(ORIGINAL_WAKEUPS):
    """Include only our original counter thread in the diagnostic syscall filter."""
    def __init__(self, pid):
        super().__init__(pid)
        if self.thread is None or self.error:
            self.close()
            raise RuntimeError('counter thread unavailable')
        tid = self.thread.native_id
        ROLES['counter'] = tid
        CURRENT.counter_tid.value = tid
        CURRENT.known.add(tid)
        for event in ('sched/sched_switch', 'sched/sched_wakeup', 'syscalls'):
            CURRENT.enable(event, '')


async def ready(host):
    global ROOT
    await stages.ready(host)
    ROOT = host.root.parent
    ROLES.update(host=host.pid, reader=os.getpid())
    owned = set(host.owned_shells())
    for index in range(900, 1000):
        path = host.root / f'pid-{index}'
        await host.peers[index].echo(f'pid-ready-{index}'.encode(), f"printf '%s' $$ > '{path}'; ".encode())
        pid = int(path.read_text())
        assert pid in owned
        ROLES[f'session-{index}'] = pid


def write(record, kind, **fields):
    if kind == 'sample':
        fields['machine_receipt'] = compare.lock_receipt()
        fields['task_counters'] = {name: task_counters(pid) for name, pid in ROLES.items()}
        fields['memory_pressure'] = Path('/proc/pressure/memory').read_text()
        fields['cpu_counters'] = Path('/proc/stat').read_text().splitlines()[0]
    return stages.write(record, kind, **fields)


if __name__ == '__main__':
    trace.Trace = RoleTrace
    trace.threading = SimpleNamespace(Event=CONTEXT.Event, Thread=Drain)
    suite.Host.__init__ = stages.init
    suite.Host.ready = ready
    suite.Peer.frame = staticmethod(stages.frame)
    suite.Peer.send = stages.send
    suite.Peer.echo = stages.echo
    suite.soak = stages.soak
    suite.Recorder.write = write
    suite.Wakeups = Wakeups
    suite.main()
