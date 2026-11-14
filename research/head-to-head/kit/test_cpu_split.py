#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-window CPU split: which CPUs an engine actually used (#260, J638)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT / "lib"))
import cpu_split  # noqa: E402

# user nice system idle iowait irq softirq steal
BEFORE = "\n".join([
    "cpu  0 0 0 0 0 0 0 0 0 0",
    "cpu0 0 0 0 1000 0 0 0 0 0 0",
    "cpu1 0 0 0 1000 0 0 0 0 0 0",
    "cpu2 0 0 0 1000 0 0 0 0 0 0",
    "cpu3 0 0 0 1000 0 0 0 0 0 0",
    "cpu4 0 0 0 1000 0 0 0 0 0 0",
    "cpu5 0 0 0 1000 0 0 0 0 0 0",
    "intr 1",
]) + "\n"
# Over 100 ticks per CPU: cpu0 50 busy (30 softirq + 20 system), cpu1-4 90 busy, cpu5 10 busy + 10 steal.
AFTER = "\n".join([
    "cpu  0 0 0 0 0 0 0 0 0 0",
    "cpu0 0 0 20 1050 0 0 30 0 0 0",
    "cpu1 80 0 10 1010 0 0 0 0 0 0",
    "cpu2 80 0 10 1010 0 0 0 0 0 0",
    "cpu3 80 0 10 1010 0 0 0 0 0 0",
    "cpu4 80 0 10 1010 0 0 0 0 0 0",
    "cpu5 0 0 10 1080 0 0 0 10 0 0",
]) + "\n"


class CpuSplitTest(unittest.TestCase):
    def test_split_counts_busy_cores_per_d348_group_and_excludes_steal(self) -> None:
        split = cpu_split.split(BEFORE, AFTER)
        self.assertEqual(split["per_cpu_busy_pct"], {"0": 50.0, "1": 90.0, "2": 90.0, "3": 90.0, "4": 90.0, "5": 10.0})
        self.assertAlmostEqual(split["cores_busy"]["side_a"], 1.8)
        self.assertAlmostEqual(split["cores_busy"]["side_b"], 1.8)
        self.assertAlmostEqual(split["cores_busy"]["housekeeping"], 0.6)
        self.assertAlmostEqual(split["cores_busy"]["total"], 4.2)
        self.assertEqual(split["per_cpu_steal_pct"]["5"], 10.0)
        self.assertAlmostEqual(split["housekeeping_softirq_pct"], 15.0)

    def test_cli_writes_cpu_split_json_beside_the_audit_snapshots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-split-") as temporary:
            audit = Path(temporary)
            (audit / "proc-stat.before.txt").write_text(BEFORE)
            (audit / "proc-stat.after.txt").write_text(AFTER)
            result = subprocess.run([sys.executable, "-I", str(KIT / "lib/cpu_split.py"), str(audit)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = json.loads((audit / "cpu-split.json").read_text())
            self.assertAlmostEqual(written["cores_busy"]["total"], 4.2)

    def test_audit_stop_writes_the_split_for_every_window(self) -> None:
        common = (KIT / "lib/common.sh").read_text()
        stop = common.split("h2h_cpu_audit_stop() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('lib/cpu_split.py', stop)

    def test_cli_fails_loudly_without_snapshots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-split-") as temporary:
            result = subprocess.run([sys.executable, "-I", str(KIT / "lib/cpu_split.py"), temporary],
                                    capture_output=True, text=True, check=False, env=os.environ)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
