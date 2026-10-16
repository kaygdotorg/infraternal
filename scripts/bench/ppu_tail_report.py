#!/usr/bin/env python3
"""Intersect corrected echo ranges with owned scheduler/fault/wait evidence [D270].

Scheduled-running is an upper bound that includes interrupts and virtual CPU
steal. Overlapping stage/role intervals cannot be added or subtracted from an
admission result. Missing scheduler coverage stays explicitly unknown.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import bisect
from collections import defaultdict
import json
from pathlib import Path

from ppu_stage_report import report as stage_report
from ppu_soak import percentile


class Timeline:
    """Build explicit running/runnable/sleeping intervals from exact task events."""
    def __init__(self, events):
        self.spans = []
        state, previous = 'unknown', None
        for row in sorted(events, key=lambda item: item['ns']):
            if row['kind'] == 'sched_switch':
                following = {'in': 'running', 'out-runnable': 'runnable',
                             'out-sleeping': 'sleeping'}[row['state']]
            elif row['kind'] == 'sched_wakeup' and state != 'running':
                following = 'runnable'
            else:
                continue
            stamp = row['ns']
            if previous is not None and stamp > previous:
                self.spans.append((previous, stamp, state))
            state, previous = following, stamp
        self.starts = [row[0] for row in self.spans]

    def overlap(self, begin, end):
        totals = dict(running_upper=0, runnable=0, sleeping=0, unknown=0)
        low = max(0, bisect.bisect_right(self.starts, begin) - 1)
        high = bisect.bisect_left(self.starts, end)
        for first, last, state in self.spans[low:high]:
            overlap = max(0, min(end, last) - max(begin, first))
            totals['running_upper' if state == 'running' else state] += overlap
        totals['unknown'] += max(0, end - begin - sum(totals.values()))
        return {key: value / 1e6 for key, value in totals.items()}


def waits(events):
    """Pair sleeping transitions with their own nearby kernel stack, if present."""
    result = []
    pending = stack = None
    for row in sorted(events, key=lambda item: item['ns']):
        if row['kind'] == 'sched_switch':
            if row['state'] == 'out-sleeping':
                pending, stack = row['ns'], None
            elif row['state'] == 'in' and pending is not None:
                result.append(dict(begin_ns=pending, end_ns=row['ns'], symbols=stack))
                pending = stack = None
        elif row['kind'] == 'stack' and pending is not None and 0 <= row['ns'] - pending <= 100_000:
            stack = row['symbols']
    return result


def futex_waits(events):
    """Pair actual syscall bounds; a timeout remains distinct from a wakeup."""
    pending = None
    result = []
    for row in sorted(events, key=lambda item: item['ns']):
        if row['kind'] == 'sys_enter_futex':
            pending = row
        elif row['kind'] == 'sys_exit_futex' and pending is not None:
            result.append(dict(begin_ns=pending['ns'], end_ns=row['ns'],
                operation=pending.get('futex_op'), lock=pending.get('futex_lock'),
                result=row.get('futex_result')))
            pending = None
    return result


def runqlat(events):
    """Include wakeups and runnable preemption; ignore an already running wakeup."""
    values = []
    pending = None
    running = False
    for row in sorted(events, key=lambda item: item['ns']):
        if row['kind'] == 'sched_switch':
            if row['state'] == 'in':
                if pending is not None:
                    values.append((row['ns'] - pending) / 1e6)
                pending, running = None, True
            else:
                running = False
                pending = row['ns'] if row['state'] == 'out-runnable' else None
        elif row['kind'] == 'sched_wakeup' and not running and pending is None:
            pending = row['ns']
    return dict(count=len(values), p50_ms=percentile(values, .5),
                p99_ms=percentile(values, .99), max_ms=max(values, default=None))


def report(root, warmup):
    meta = json.loads((root / 'stage-probes.json').read_text())
    assert meta['complete'] and meta['overruns'] == 0, 'incomplete scheduler capture'
    correlated = stage_report(root)
    assert correlated['complete'], 'incomplete stage correlation'
    roles = json.loads((root / 'tail-roles.json').read_text())
    events = defaultdict(list)
    for line in (root / 'tail-events.jsonl').read_text().splitlines():
        row = json.loads(line)
        events[row['pid']].append(row)
    timelines = {pid: Timeline(rows) for pid, rows in events.items()}
    blocked = {pid: waits(rows) for pid, rows in events.items()}
    faults = {pid: [row for row in data if row['kind'].startswith(('page_fault_', 'mm_vmscan_'))]
              for pid, data in events.items()}
    fault_starts = {pid: [row['ns'] for row in data] for pid, data in faults.items()}
    wait_ends = {pid: [row['end_ns'] for row in data] for pid, data in blocked.items()}
    reader_waits = futex_waits(events[roles['reader']])
    counter_ops = [row for row in events.get(roles.get('counter'), [])
                   if row['kind'] == 'sys_enter_futex']
    start = meta['started_ns'] + int(warmup * 1e9)
    rows = [row for row in correlated['rows'] if row['send_before_ns'] >= start]
    for row in rows:
        windows = dict(ingress=(row['send_before_ns'], row['queued_ns']),
                       pty_to_read=(row['pty_written_ns'], row['pty_read_ns']),
                       parse=(row['pty_read_ns'], row['parsed_ns']),
                       socket_to_reader=(row['socket_start_ns'], row['receive_ns']))
        role_ids = dict(host=roles['host'], reader=roles['reader'],
                        shell=roles[f"session-{row['session']}"])
        row['scheduler_ms'] = {stage: {name: timelines[pid].overlap(*window)
                                      for name, pid in role_ids.items()}
                               for stage, window in windows.items()}
        begin, end = row['send_before_ns'], row['receive_ns']
        row['reader_futex'] = [wait | dict(
            duration_ms=(wait['end_ns'] - wait['begin_ns']) / 1e6,
            post_socket_overlap_ms=max(0, min(end, wait['end_ns']) -
                max(row['socket_done_ns'], wait['begin_ns'])) / 1e6,
            counter_same_lock=[dict(ns=op['ns'], operation=op.get('futex_op'))
                for op in counter_ops if wait['lock'] is not None
                and op.get('futex_lock') == wait['lock']
                and wait['begin_ns'] <= op['ns'] <= wait['end_ns']])
            for wait in reader_waits if wait['end_ns'] > begin and wait['begin_ns'] < end]
        row['fault_reclaim_events'] = {}
        row['kernel_waits'] = {}
        for name, pid in role_ids.items():
            counts = defaultdict(int)
            low = bisect.bisect_left(fault_starts[pid], begin)
            high = bisect.bisect_right(fault_starts[pid], end)
            for event in faults[pid][low:high]:
                counts[event['kind']] += 1
            row['fault_reclaim_events'][name] = dict(counts)
            low = bisect.bisect_right(wait_ends[pid], begin)
            high = bisect.bisect_right(wait_ends[pid], end) + 1
            row['kernel_waits'][name] = [wait | dict(overlap_ms=(min(end, wait['end_ns']) -
                max(begin, wait['begin_ns'])) / 1e6) for wait in blocked[pid][low:high]
                if wait['end_ns'] > begin and wait['begin_ns'] < end]
    end = max((row['receive_ns'] for row in rows), default=start)
    queue = {name: runqlat([row for row in events[pid] if start <= row['ns'] <= end])
             for name, pid in roles.items()}
    result = dict(diagnostic_only=True, complete=True, warmup_s=warmup,
                  kernel_stacks_only=True, probes=len(rows), run_queue=queue,
                  caveat='Scheduled-running upper bounds overlap across roles; tracing changes timing. No admission subtraction.',
                  slowest=sorted(rows, key=lambda row: row['rtt_ms'], reverse=True)[:20])
    (root / 'tail-report.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--warmup', type=float, default=120)
    args = parser.parse_args()
    result = report(args.root, args.warmup)
    print(json.dumps(dict(complete=result['complete'], probes=result['probes'],
                         slowest_ms=result['slowest'][0]['rtt_ms'] if result['slowest'] else None)))
