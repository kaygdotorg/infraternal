#!/usr/bin/env python3
"""Validate syscall attribution and sanitize receipts for host-stall diagnostics [#205].

SPDX-License-Identifier: AGPL-3.0-only
"""
import contextlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ppu_trace import Trace, parse_event, summarize


class Attribution(unittest.TestCase):
    def test_failed_instance_admission_never_changes_an_existing_trace(self):
        scratch = Path.home() / '.cache/codex-scratch/ppu-trace-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            parent = Path(directory)
            instance = parent / f'ppu-stalls-{os.getpid()}'
            instance.mkdir()
            knob = instance / 'tracing_on'
            knob.write_text('existing trace stays enabled')
            with patch('ppu_trace.Path', return_value=parent):
                observer = Trace(123)
            result = None
            with contextlib.suppress(OSError):
                result = observer.close()
            self.assertEqual(knob.read_text(), 'existing trace stays enabled')
            self.assertTrue(instance.exists())
            self.assertIsNotNone(result)
            self.assertFalse(result['complete'])

    def test_both_syscall_printers_discard_arguments(self):
        for body, expected in [(b'sys_read(fd: 3, buf: 0xabcd, count: 0x1000)', 'sys_enter_read'),
                               (b'sys_read -> 0x1000', 'sys_exit_read'),
                               (b'sys_enter_read: fd=3', 'sys_enter_read'),
                               (b'sys_exit_read: ret=4096', 'sys_exit_read')]:
            self.assertEqual(parse_event(b'host-42 [001] .... 123.000000: ' + body, 42),
                             (123., expected, ''))

    def test_userspace_gap_excludes_runnable_descheduling(self):
        rows = [(1., 'sys_exit_write', ''), (1.001, 'sched_switch', 'out-runnable'),
                (1.010, 'sched_switch', 'in'), (1.012, 'sys_enter_read', ''),
                (1.013, 'sys_exit_read', '')]
        result = summarize(rows)
        self.assertAlmostEqual(result['userspace-between-syscalls']['max_ms'], 3)
        self.assertAlmostEqual(result['out-runnable']['max_ms'], 9)
        self.assertAlmostEqual(result['read']['max_ms'], 1)


if __name__ == '__main__':
    unittest.main()
