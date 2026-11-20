#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Protect WireGuard kernel-worker matching across bound and unbound pools."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "lib/kernel_idle_cpu.py"
SPEC = importlib.util.spec_from_file_location("h2h_kernel_idle_cpu", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
kernel_idle_cpu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernel_idle_cpu)


class KernelIdleCpuTest(unittest.TestCase):
    """Keep engine processes, crypto workers, and softirq CPU in the sample."""

    @staticmethod
    def stat_line(pid: int, ppid: int, user_ticks: int, system_ticks: int) -> str:
        fields = ["S", str(ppid)] + ["0"] * 9 + [str(user_ticks), str(system_ticks)]
        return f"{pid} (sample) {' '.join(fields)}\n"

    def test_matches_unbound_wireguard_crypto_worker(self) -> None:
        self.assertIsNotNone(kernel_idle_cpu.CRYPTO.match("kworker/u16:7-wg-crypt-wgA"))

    def test_matches_bound_wireguard_crypto_worker(self) -> None:
        self.assertIsNotNone(kernel_idle_cpu.CRYPTO.match("kworker/3:7-wg-crypt-wgB"))

    def test_collects_selected_processes_and_descendants_by_thread(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-idle-proc-") as temporary:
            proc = Path(temporary)
            for pid, ppid, user_ticks, system_ticks in ((10, 1, 1, 1), (11, 10, 1, 1), (12, 1, 1, 1)):
                process = proc / str(pid)
                task = process / "task" / str(pid)
                task.mkdir(parents=True)
                (process / "stat").write_text(self.stat_line(pid, ppid, user_ticks, system_ticks))
                (task / "stat").write_text(self.stat_line(pid, ppid, user_ticks, system_ticks))

            ticks = kernel_idle_cpu.process_ticks([10], proc_root=proc)

            self.assertEqual(ticks, {"10:10": 2, "11:11": 2})

    def test_idle_cpu_total_includes_engine_process_and_network_softirq(self) -> None:
        before = {
            "engine_process": {"10:10": 100},
            "wireguard_crypto": {},
            "network_softirq": {"2": 50},
        }
        after = {
            "engine_process": {"10:10": 200},
            "wireguard_crypto": {},
            "network_softirq": {"2": 150},
        }

        result = kernel_idle_cpu.summarize_window(before, after, seconds=10, hz=100)

        self.assertEqual(result["engine_cpu_s_per_minute"], 6.0)
        self.assertEqual(result["network_softirq_cpu_s_per_minute"], 6.0)
        self.assertEqual(result["cpu_s_per_minute"], 12.0)


if __name__ == "__main__":
    unittest.main()
