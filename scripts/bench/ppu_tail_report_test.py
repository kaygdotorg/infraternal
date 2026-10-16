#!/usr/bin/env python3
"""Check scheduler intersections, wakeup races and kernel-stack identity [D270]."""
import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import ppu_tail_report as reporter
from ppu_tail_report import Timeline, waits, runqlat, futex_waits


def event(stamp, kind, state='', **fields):
    return dict(ns=stamp * 1_000_000, kind=kind, state=state, **fields)


class Timing(unittest.TestCase):
    def test_unknown_coverage_cannot_be_silently_counted_as_running(self):
        timeline = Timeline([event(2, 'sched_switch', 'out-sleeping'),
                             event(4, 'sched_wakeup'), event(7, 'sched_switch', 'in'),
                             event(9, 'sched_switch', 'out-runnable')])
        self.assertEqual(timeline.overlap(0, 10_000_000),
                         dict(unknown=3, sleeping=2, runnable=3, running_upper=2))

    def test_run_queue_includes_preemption_and_ignores_running_wakeup(self):
        rows = [event(0, 'sched_switch', 'in'), event(1, 'sched_wakeup'),
                event(2, 'sched_switch', 'out-runnable'), event(5, 'sched_switch', 'in'),
                event(6, 'sched_switch', 'out-sleeping'), event(10, 'sched_wakeup'),
                event(12, 'sched_switch', 'in')]
        result = runqlat(rows)
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['max_ms'], 3)

    def test_kernel_wait_separates_blocked_time_from_wakeup_queueing(self):
        rows = [event(1, 'sched_switch', 'out-sleeping'),
                event(1.01, 'stack', symbols=['pipe_read']),
                event(4, 'sched_wakeup'), event(9, 'sched_switch', 'in')]
        result = waits(rows)[0]
        self.assertEqual(result['ready_ns'], 4_000_000)

    def test_futex_timeout_is_paired_with_its_actual_syscall_bounds(self):
        rows = [event(1, 'sys_enter_futex', futex_lock=2, futex_op=137),
                event(6, 'sys_exit_futex', futex_result=-110),
                event(7, 'sys_exit_futex', futex_result=0)]
        self.assertEqual(futex_waits(rows), [dict(begin_ns=1_000_000,
            end_ns=6_000_000, lock=2, operation=137, result=-110)])

    def test_stack_must_belong_to_the_same_sleep_transition(self):
        rows = [event(1, 'sched_switch', 'out-sleeping'),
                event(1.01, 'stack', symbols=['pipe_read']), event(4, 'sched_switch', 'in'),
                event(5, 'sched_switch', 'out-sleeping'),
                event(5.5, 'stack', symbols=['unrelated']), event(8, 'sched_switch', 'in')]
        result = waits(rows)
        self.assertEqual(result[0]['symbols'], ['pipe_read'])
        self.assertIsNone(result[1]['symbols'])


class Coverage(unittest.TestCase):
    def test_untraced_shell_faults_are_unknown_not_zero(self):
        roles = dict(host=1, reader=2, counter=6, **{'session-900': 3,
                     'session-971': 4, 'session-993': 5})
        probe = dict(session=900, number=0, rtt_ms=.00008, send_before_ns=10,
            queued_ns=20, pty_written_ns=30, pty_read_ns=50, parsed_ns=55,
            socket_start_ns=60, socket_done_ns=65, receive_ns=90)
        events = [dict(pid=pid, ns=stamp, kind='sched_switch', state=state)
                  for pid in roles.values() for stamp, state in [(0, 'in'), (100, 'out-sleeping')]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'stage-probes.json').write_text(json.dumps(dict(complete=True, overruns=0, started_ns=0)))
            (root / 'tail-roles.json').write_text(json.dumps(roles))
            (root / 'tail-events.jsonl').write_text('\n'.join(map(json.dumps, events)))
            (root / 'stages.log').write_text('')
            with patch.object(reporter, 'stage_report', return_value=dict(complete=True, rows=[probe])):
                result = reporter.report(root, 0)
        self.assertIsNone(result['slowest'][0]['fault_reclaim_events']['shell'])
        self.assertEqual(result['slowest'][0]['fault_reclaim_events']['host'], {})


if __name__ == '__main__':
    unittest.main()
