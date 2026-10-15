#!/usr/bin/env python3
"""Verify fair measurement lock ownership, cleanup and failure propagation without remote access (#189)."""

import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("native_timing_runner",
                                            Path(__file__).with_name("native-timing-runner.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class MeasurementLockTests(unittest.TestCase):
    def test_held_owner_is_visible_and_failure_cleans_up_before_unlocking(self):
        scratch = Path(os.environ.get("INFRATERNAL_TEST_STATE_ROOT",
                       str(Path.home() / ".cache/codex-scratch/addhost-instant/lock-test")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            lock, owner = root / "lock", root / "owner with spaces"
            program = "grep -q '^addhost-instant started=' " + shlex.quote(str(owner)) + " || exit 1; exit 7"
            command = runner.locked_measurement(program, str(lock), str(owner))
            self.assertIn("1750", shlex.split(command))
            result = subprocess.run(shlex.split(command), check=False)
            self.assertEqual(result.returncode, 7)
            self.assertFalse(owner.exists())
            self.assertEqual(subprocess.run(["flock", "-n", str(lock), "true"], check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
