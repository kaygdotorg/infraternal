#!/usr/bin/env python3
"""Check scheduler intersections, wakeup races and kernel-stack identity [D270]."""
import unittest
from ppu_tail_report import Timeline, waits, runqlat


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

    def test_stack_must_belong_to_the_same_sleep_transition(self):
        rows = [event(1, 'sched_switch', 'out-sleeping'),
                event(1.01, 'stack', symbols=['pipe_read']), event(4, 'sched_switch', 'in'),
                event(5, 'sched_switch', 'out-sleeping'),
                event(5.5, 'stack', symbols=['unrelated']), event(8, 'sched_switch', 'in')]
        result = waits(rows)
        self.assertEqual(result[0]['symbols'], ['pipe_read'])
        self.assertIsNone(result[1]['symbols'])


if __name__ == '__main__':
    unittest.main()
