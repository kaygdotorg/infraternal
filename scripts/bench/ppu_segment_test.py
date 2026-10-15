#!/usr/bin/env python3
"""Verify freeze-clock ownership and time accounting without generating load [#205]."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import ppu_clock
import ppu_segment


class Segments(unittest.TestCase):
    def test_lock_timeout_retries_without_thawing_the_fixture(self):
        first, second = Mock(), Mock()
        first.wait.return_value = 1
        second.wait.return_value = 0
        notices = []
        with patch.object(ppu_segment.subprocess, 'Popen', side_effect=[first, second]), \
                patch.object(ppu_segment, 'frozen') as thaw:
            ppu_segment.acquire(Mock(fileno=lambda: 19), lambda *args, **kw: notices.append((args, kw)))
        self.assertTrue(notices)
        thaw.assert_not_called()

    def test_long_wait_records_owner_before_continuing_to_wait(self):
        waiter = Mock()
        waiter.wait.side_effect = [ppu_segment.subprocess.TimeoutExpired('flock', 2700), 0]
        notices = []
        with patch.object(ppu_segment.subprocess, 'Popen', return_value=waiter), \
                patch.object(Path, 'read_text', return_value='other-job started-now'):
            ppu_segment.acquire(Mock(fileno=lambda: 19), lambda *args, **kw: notices.append((args, kw)))
        self.assertEqual(notices, [(('lock-wait-45m',), {'owner': 'other-job started-now'})])
        waiter.terminate.assert_not_called()

    def test_existing_foreign_unit_cannot_be_frozen_or_retired(self):
        properties = 'ControlGroup=/system.slice/ppu-soak-collision.scope\nDescription=other job\n'
        with patch.object(ppu_segment.subprocess, 'check_output', return_value=properties):
            with self.assertRaises(ValueError):
                ppu_segment.owned_group('ppu-soak-collision', 'our invocation')
            child = Mock()
            child.poll.return_value = None
            with patch.object(ppu_segment.subprocess, 'run') as kill_unit:
                ppu_segment.retire(child, 'ppu-soak-collision', 'our invocation')
            kill_unit.assert_not_called()
            child.terminate.assert_called_once()

    def test_pause_changes_existing_mapping_without_replacing_its_inode(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'clock'
            path.write_bytes(bytes(8))
            clock = ppu_clock.ActiveClock(path)
            try:
                inode = path.stat().st_ino
                with patch.object(ppu_clock.time, 'monotonic', return_value=12):
                    self.assertEqual(clock.now(), 12)
                    ppu_segment.publish_pause(path, 7_500_000_000)
                    self.assertEqual(clock.now(), 4.5)
                self.assertEqual(path.stat().st_ino, inode)
            finally:
                clock.mapping.close()

    def test_bad_clock_length_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'clock'
            path.write_bytes(b'short')
            with self.assertRaises(ValueError):
                ppu_clock.ActiveClock(path)

    def test_kernel_acknowledgement_required_for_freeze_and_thaw(self):
        with tempfile.TemporaryDirectory() as root:
            group = Path(root)
            (group / 'cgroup.events').write_text('populated 1\nfrozen 1\n')
            ppu_segment.frozen(group, True)
            self.assertEqual((group / 'cgroup.freeze').read_text(), '1')
            (group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
            ppu_segment.frozen(group, False)
            self.assertEqual((group / 'cgroup.freeze').read_text(), '0')
            with self.assertRaises(TimeoutError):
                ppu_segment.frozen(group, True, timeout=0)

    def test_foreign_scope_and_long_hold_refused_before_side_effects(self):
        for unit, seconds in [('other-job', 100), ('ppu-soak-owned', 1800)]:
            with self.subTest(unit=unit, seconds=seconds), self.assertRaises(ValueError):
                ppu_segment.run(SimpleNamespace(unit=unit, segment_seconds=seconds))


if __name__ == '__main__':
    unittest.main()
