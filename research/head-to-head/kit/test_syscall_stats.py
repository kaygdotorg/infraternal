#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check the optional test-CPU syscall counter parser."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "lib/syscall_stats.py"
SPEC = importlib.util.spec_from_file_location("h2h_syscall_stats", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
syscall_stats = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(syscall_stats)


class SyscallCounterTest(unittest.TestCase):
    """Keep unsupported counters explicit and parse raw syscall counts."""

    def test_parses_supported_raw_syscall_tracepoint(self) -> None:
        self.assertEqual(syscall_stats.parse_perf_count("  123,456 raw_syscalls:sys_enter\n"), 123456)

    def test_unsupported_event_is_unavailable_not_zero(self) -> None:
        self.assertIsNone(syscall_stats.parse_perf_count("<not supported> raw_syscalls:sys_enter\n"))

    def test_normalizes_count_by_transferred_gigabits(self) -> None:
        result = syscall_stats.summarize("4000 raw_syscalls:sys_enter", 2.0, 10.0)
        self.assertEqual(result["syscalls_per_gbit"], 200)


if __name__ == "__main__":
    unittest.main()
