#!/usr/bin/python3
"""Exercise queue admission and safe reap decisions with private files and fake holders."""
import importlib.machinery
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("build-slot")
slot = importlib.machinery.SourceFileLoader("build_slot", str(SOURCE)).load_module()


class BuildSlotTest(unittest.TestCase):
    """Each test gets independent queue and lock files."""

    def setUp(self):
        """Install a local copy of the launcher and disable disk constraints for the fake work."""
        scratch = self.enterContext(tempfile.TemporaryDirectory())
        self.home = Path(scratch)
        self.state = self.home / "state"
        self.state.mkdir()
        self.cli = self.home / "build-slot"
        shutil.copy2(SOURCE, self.cli)
        for name, value in (("slots", "1"), ("reserved-nightly", "1"), ("min-free-gb", "0")):
            (self.home / name).write_text(value)
        self.env = dict(os.environ, BUILD_SLOT_STATE_DIR=str(self.state), CARGO_TARGET_DIR=scratch,
                        BUILD_SLOT_JOB="J1365-fixture", BB_THREAD_ID="thr_fixture")
        self.enterContext(mock.patch.object(slot, "STATE", self.state))

    def wait_for(self, predicate):
        """Wait for a fixture state transition, with a bound for failures."""
        end = time.monotonic() + 16
        while not predicate():
            if time.monotonic() >= end:
                self.fail("timed out waiting for fixture")
            time.sleep(0.02)

    def start(self, *args):
        """Start the launcher; clean up only our own processes if a check fails."""
        process = subprocess.Popen([self.cli, *args], env=self.env, start_new_session=True)
        self.addCleanup(self.finish, process)
        return process

    def finish(self, process):
        """Stop and join a launcher from this test."""
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(10)

    def test_reserve_and_fifo(self):
        """An ordinary queue cannot use idle reserved capacity, and its oldest ticket wins."""
        holder = self.start("sleep", "60")
        record = self.state / "slot.1.owner"
        self.wait_for(record.exists)
        active = json.loads(record.read_text())
        self.assertEqual((active["job"], active["thread"], active["pid"], active["waiter_pid"]),
                         ("J1365-fixture", "thr_fixture", active["pgid"], holder.pid))
        trace = self.home / "trace"
        append = 'printf "%s\\n" "$1" >> "$2"'
        first = self.start("sh", "-c", append, "sh", "first", str(trace))
        self.wait_for(lambda: any((self.state / "queue").glob(f"*.{first.pid}")))
        second = self.start("sh", "-c", append, "sh", "second", str(trace))
        self.wait_for(lambda: any((self.state / "queue").glob(f"*.{second.pid}")))
        nightly = self.start("--reserved", "nightly", "sh", "-c", append, "sh", "nightly", str(trace))
        self.assertEqual(nightly.wait(5), 0)
        self.assertEqual(trace.read_text(), "nightly\n")
        self.finish(holder)
        self.assertEqual(first.wait(15), 0)
        self.assertEqual(second.wait(15), 0)
        self.assertEqual(trace.read_text(), "nightly\nfirst\nsecond\n")
        self.assertFalse(record.exists())

    def age_samples(self, record, ticket):
        """Seed historical samples for this real group so a test never waits one hour."""
        now = time.monotonic()
        members = slot.members(ticket, slot.processes())
        self.assertTrue(members)
        slot.save(record.with_suffix(".cpu"), {"ticket": ticket["ticket"], "since": now - 3601, "members": members})
        return now

    def test_expired_controller_lease_reaps_only_idle_group(self):
        """A fresh lease or recent CPU progress prevents signals. Dry run leaves the same holder alive."""
        owner = self.home / "controller.lease"
        owner.touch()
        self.env["BUILD_SLOT_OWNER_LEASE"] = str(owner)
        holder = self.start("sleep", "60")
        record = self.state / "slot.1.owner"
        self.wait_for(lambda: record.with_suffix(".lease").exists())
        ticket = slot.load(record)
        # Wait until exec has finished so the monotonic sample represents the sleeping command.
        self.wait_for(lambda: Path(f"/proc/{ticket['pgid']}/comm").read_text().strip() == "sleep")
        now = self.age_samples(record, ticket)
        slot.reap_locked(False, now)
        self.assertIsNone(holder.poll())
        os.utime(owner, (time.time() - 601, time.time() - 601))
        sample = slot.load(record.with_suffix(".cpu"))
        sample["members"][str(ticket["pid"])][1] -= 1
        slot.save(record.with_suffix(".cpu"), sample)
        slot.reap_locked(False, now)
        self.assertIsNone(holder.poll())
        slot.reap_locked(False, now + 3599)
        self.assertIsNone(holder.poll())
        now = self.age_samples(record, ticket)
        slot.reap_locked(True, now)
        self.assertIsNone(holder.poll())
        self.assertFalse((self.state / "reaper.log").exists())
        slot.reap_locked(False, now)
        self.assertEqual(holder.wait(10), 137)
        self.assertIn("expired lease and no CPU progress", (self.state / "reaper.log").read_text())

    def test_dead_group_and_reused_pid_are_never_signalled(self):
        """Remove stale records by identity, even if a different session now has the same numeric PID."""
        record = self.state / "slot.1.owner"
        holder = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(self.finish, holder)
        slot.save(record, {"ticket": "1.1", "pgid": holder.pid, "start_ticks": slot.proc(holder.pid)[2] - 1,
                           "job": "expired", "thread": "", "boot": slot.BOOT})
        with mock.patch.object(slot.os, "killpg", side_effect=AssertionError("unexpected signal")):
            slot.reap_locked(True, time.monotonic())
            self.assertTrue(record.exists())
            slot.reap_locked(False, time.monotonic())
        self.assertFalse(record.exists())
        self.assertIsNone(holder.poll())

    def test_dead_supervisor_keeps_its_slots_until_group_is_gone(self):
        """An interrupted wrapper cannot release a live child's inherited flock prematurely."""
        holder = self.start("sleep", "60")
        record = self.state / "slot.1.owner"
        self.wait_for(lambda: record.with_suffix(".lease").exists())
        ticket = slot.load(record)
        self.addCleanup(self.stop_group, ticket)
        os.killpg(holder.pid, signal.SIGKILL)
        self.assertEqual(holder.wait(5), -9)
        self.assertIsNone(slot.lock(self.state / "slot.1"))
        slot.reap_locked(False, time.monotonic())
        self.assertTrue(record.exists())
        self.stop_group(ticket)
        self.wait_for(lambda: not slot.members(ticket, slot.processes()))
        slot.reap_locked(False, time.monotonic())
        self.assertFalse(record.exists())

    def stop_group(self, ticket):
        """Signal only the fake group recorded by the current test."""
        if slot.members(ticket, slot.processes()):
            os.killpg(ticket["pgid"], signal.SIGKILL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
