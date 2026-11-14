#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Hold cap: a capped hold leaves nothing running when perf-run releases the lock (#260, J676)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parent

# A tree that mimics a hold: a runner that starts a load, a load that ignores TERM (like a
# stuck engine), and one grandchild in its own process group (like a root part started with
# setpriv). Every pid is written to $PIDS so the test can look for survivors.
TREE = r"""
import os, signal, subprocess, sys, time
pids = sys.argv[1]
sleeper = "import time; time.sleep(600)"
stubborn = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"
kids = [
    subprocess.Popen([sys.executable, "-c", sleeper]),
    subprocess.Popen([sys.executable, "-c", stubborn]),
    subprocess.Popen([sys.executable, "-c", sleeper], process_group=0),
    # Its own session and group: only the parent chain or the hold's environment tag finds it.
    subprocess.Popen([sys.executable, "-c", sleeper], start_new_session=True),
    # Same, but its parent exits at once, so it is re-parented to init before the stop.
    subprocess.Popen(["bash", "-c", f"setsid {sys.executable} -c '{sleeper}' >/dev/null 2>&1 & echo $! > {pids}.orphan"]),
]
kids[-1].wait()
time.sleep(0.5)
kids.append(type("P", (), {"pid": int(open(pids + ".orphan").read())}))
with open(pids, "w") as out:
    out.write("\n".join(str(k.pid) for k in kids) + "\n")
time.sleep(600)
"""


def alive(pid: int) -> bool:
    """True when `pid` is a live process; a zombie waiting to be reaped does not count."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


def wait_for_file(path: Path) -> None:
    for _ in range(100):
        if path.exists() and path.read_text().count("\n") >= 5:
            return
        time.sleep(0.1)  # sleep: the child writes the file a moment after it starts
    raise AssertionError(f"{path} was never written")


class HoldCapTest(unittest.TestCase):
    def cap(self, seconds: str, *command: str, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
        environment = dict(os.environ, H2H_CAP_GRACE_S="2", **(env or {}))
        return subprocess.Popen(["bash", str(KIT / "hold-cap.sh"), seconds, "--", *command],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)

    def test_cap_stops_the_whole_tree_before_returning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j676-cap-") as temporary:
            pids = Path(temporary) / "pids"
            process = self.cap("2s", "python3", "-c", TREE, str(pids))
            try:
                _, stderr = process.communicate(timeout=60)
            finally:
                if process.poll() is None:
                    process.kill()
            self.assertEqual(process.returncode, 124, stderr)
            wait_for_file(pids)
            survivors = [int(p) for p in pids.read_text().split() if alive(int(p))]
            for pid in survivors:
                os.kill(pid, 9)
            self.assertEqual(survivors, [], "the cap returned while hold processes were still running")

    def test_real_exit_status_passes_through(self) -> None:
        process = self.cap("30s", "bash", "-c", "exit 7")
        process.communicate(timeout=30)
        self.assertEqual(process.returncode, 7)

    def test_leftover_after_a_normal_exit_is_killed_and_reported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j676-cap-") as temporary:
            pid_file = Path(temporary) / "pid"
            script = f"python3 -c 'import time; time.sleep(600)' & echo $! > {pid_file}; exit 0"
            process = self.cap("30s", "bash", "-c", script)
            _, stderr = process.communicate(timeout=30)
            leftover = int(pid_file.read_text())
            if alive(leftover):
                os.kill(leftover, 9)
                self.fail("a background process outlived the hold")
            self.assertEqual(process.returncode, 125, stderr)
            self.assertIn("left running", stderr)

    def test_outer_term_stops_the_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j676-cap-") as temporary:
            pids = Path(temporary) / "pids"
            process = self.cap("300s", "python3", "-c", TREE, str(pids))
            wait_for_file(pids)
            process.terminate()
            process.communicate(timeout=60)
            survivors = [int(p) for p in pids.read_text().split() if alive(int(p))]
            for pid in survivors:
                os.kill(pid, 9)
            self.assertEqual(survivors, [])
            self.assertEqual(process.returncode, 143)

    def test_killing_the_cap_itself_still_stops_the_hold(self) -> None:
        # SIGKILL cannot be trapped, so the hold side must notice the cap is gone (#260, J688).
        with tempfile.TemporaryDirectory(prefix="j688-cap-") as temporary:
            pids = Path(temporary) / "pids"
            process = self.cap("300s", "python3", "-c", TREE, str(pids))
            wait_for_file(pids)
            members = [int(p) for p in pids.read_text().split()]
            os.kill(process.pid, 9)
            process.communicate(timeout=30)
            for _ in range(150):
                if not any(alive(pid) for pid in members):
                    break
                time.sleep(0.2)  # sleep: the watchdog stops the hold a moment after the cap dies
            survivors = [pid for pid in members if alive(pid)]
            for pid in survivors:
                os.kill(pid, 9)
            self.assertEqual(survivors, [], "the hold outlived a SIGKILLed cap")

    def test_unrelated_process_in_its_own_session_survives_a_cap_stop(self) -> None:
        bystander = subprocess.Popen(["python3", "-c", "import time; time.sleep(600)"], start_new_session=True)
        try:
            process = self.cap("1s", "bash", "-c", "sleep 600")
            _, stderr = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 124, stderr)
            self.assertTrue(alive(bystander.pid), "the cap killed a process that is not part of the hold")
        finally:
            bystander.kill()
            bystander.wait()

    def test_rejects_a_bad_cap(self) -> None:
        process = self.cap("soon", "true")
        process.communicate(timeout=10)
        self.assertEqual(process.returncode, 2)


if __name__ == "__main__":
    unittest.main()
