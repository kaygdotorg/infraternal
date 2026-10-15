#!/usr/bin/env python3
"""Verify fair measurement lock ownership, cleanup and failure propagation without remote access (#189)."""

import importlib.util
import os
from pathlib import Path
import shlex
import select
import signal
import sys
import subprocess
import tempfile
import unittest

sys.dont_write_bytecode = True

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
            quoted_owner = shlex.quote(str(owner))
            program = ("grep -q '^addhost-instant started=' " + quoted_owner
                       + ' || exit 1; [ "$(wc -l < ' + quoted_owner
                       + ')" -eq 1 ] || exit 2; exit 7')
            command = runner.locked_measurement(program, str(lock), str(owner))
            self.assertIn("1750", shlex.split(shlex.split(command)[-1]))
            result = subprocess.run(shlex.split(command), check=False)
            self.assertEqual(result.returncode, 7)
            self.assertFalse(owner.exists())
            self.assertEqual(subprocess.run(["flock", "-n", str(lock), "true"], check=False).returncode, 0)

    def test_forced_measurement_stop_cleans_owner_before_unlocking(self):
        scratch = Path(os.environ.get("INFRATERNAL_TEST_STATE_ROOT",
                       str(Path.home() / ".cache/codex-scratch/addhost-instant/lock-test")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            lock, owner = root / "lock", root / "owner with spaces"
            # A benchmark child may ignore the first stop signal. Exercise the
            # actual process-group fallback without a long wait or CPU work.
            command = shlex.split(runner.locked_measurement(
                "trap '' TERM; sleep 60", str(lock), str(owner),
                duration=0.05, kill_grace=0.05))
            result = subprocess.run(command, check=False, timeout=5)
            self.assertIn(result.returncode, (124, 137))
            self.assertFalse(owner.exists(), "stopped measurement left a stale owner receipt")
            self.assertEqual(subprocess.run(["flock", "-n", str(lock), "true"], check=False).returncode, 0)

    def test_detached_session_child_does_not_keep_the_measurement_lock(self):
        scratch = Path(os.environ.get("INFRATERNAL_TEST_STATE_ROOT",
                       str(Path.home() / ".cache/codex-scratch/addhost-instant/lock-test")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            lock, owner, pidfile = root / "lock", root / "owner", root / "child-pid"
            source = ("import subprocess; from pathlib import Path; "
                      "child = subprocess.Popen(['sleep', '60'], close_fds=False, "
                      "start_new_session=True, stdin=subprocess.DEVNULL, "
                      "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                      f"Path({str(pidfile)!r}).write_text(str(child.pid))")
            command = runner.locked_measurement(
                shlex.join([sys.executable, "-c", source]) + "; exit 7",
                str(lock), str(owner))
            try:
                result = subprocess.run(shlex.split(command), check=False, timeout=5)
                self.assertEqual(result.returncode, 7)
                self.assertFalse(owner.exists())
                live = os.pidfd_open(int(pidfile.read_text()))
                try:
                    self.assertFalse(select.select([live], [], [], 0)[0],
                                     "the detached session must survive its launcher")
                finally:
                    os.close(live)
                self.assertEqual(subprocess.run(["flock", "-n", str(lock), "true"], check=False).returncode, 0,
                                 "a surviving session inherited the measurement lock")
            finally:
                if pidfile.exists():
                    # Target only the child this private fixture started; a
                    # pidfd keeps cleanup from signaling a recycled process id.
                    descriptor = os.pidfd_open(int(pidfile.read_text()))
                    try:
                        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                        self.assertTrue(select.select([descriptor], [], [], 5)[0],
                                        "the fixture child did not stop")
                    finally:
                        os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
