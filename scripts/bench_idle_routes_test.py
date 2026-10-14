"""Check idle fixture ownership, worker accounting and shared browser probe cadence [81], #199."""
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location('idle_routes', Path(__file__).with_name('bench-idle-routes.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class PeerInspection(unittest.TestCase):
    def test_long_runtime_preserves_peer_identity(self):
        scratch = Path(os.environ.get('TMPDIR', Path.home() / '.cache/codex-scratch/idle-cpu-199'))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            runtime = Path(temporary) / ('long-fixture-' * 8)
            sessions = runtime / 'infraternal/sessions'
            sessions.mkdir(parents=True)
            endpoint = sessions / 'fixture.sock'
            self.assertGreater(len(os.fsencode(endpoint)), 108)
            directory = os.open(sessions, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(f'/proc/self/fd/{directory}/{endpoint.name}')
                    listener.listen(1)
                    self.assertEqual(fixture.shim_pids(runtime), [os.getpid()])
            finally:
                os.close(directory)


class SampleAccounting(unittest.IsolatedAsyncioTestCase):
    async def test_incoming_and_timer_samples_share_one_probe_cadence(self):
        browser = fixture.Browser.__new__(fixture.Browser)
        browser.last_ping = float('-inf')
        browser.next_nonce = 1 << 63
        browser.pending = {}
        browser.rtt = None
        browser.adaptive = False
        browser.send = AsyncMock()
        with patch.object(fixture.time, 'monotonic', side_effect=[10, 10.001, 10.026]):
            await browser.sample_probe()
            await browser.sample_probe()
            await browser.sample_probe()
        self.assertEqual(browser.send.await_count, 2)
        self.assertEqual(len(browser.pending), 2)

    async def test_adaptive_idle_cadence_matches_browser_and_preserves_answered_deadline(self):
        browser = fixture.Browser.__new__(fixture.Browser)
        browser.last_ping = 10
        browser.last_pong = 9.85
        browser.rtt = .150
        browser.adaptive = True
        browser.fast_until = 9
        browser.next_nonce = 1 << 63
        browser.pending = {1 << 63: (10_000_000, 10)}
        browser.send = AsyncMock()
        with patch.object(fixture.time, 'monotonic', side_effect=[10.05, 10.155, 10.16, 10.17]):
            await browser.sample_probe()
            self.assertEqual(browser.send.await_count, 0, 'idle does not pipeline')
            browser.pending.clear()
            browser.last_pong = 10.15
            await browser.sample_probe()
            self.assertEqual(browser.send.await_count, 0, 'allow scheduling after the answer')
            await browser.sample_probe()
            self.assertEqual(browser.send.await_count, 1)
            self.assertEqual(browser.last_pong, 10.15, 'a new request cannot renew the lease')
            await browser.sample_probe()
            self.assertEqual(browser.send.await_count, 1)

    async def test_adaptive_first_probe_starts_unknown_rtt_grace(self):
        browser = fixture.Browser.__new__(fixture.Browser)
        browser.last_ping = float('-inf')
        browser.last_pong = 0
        browser.rtt = None
        browser.adaptive = True
        browser.fast_until = 0
        browser.next_nonce = 1 << 63
        browser.pending = {}
        browser.send = AsyncMock()
        with patch.object(fixture.time, 'monotonic', return_value=1.999):
            await browser.sample_probe()
        self.assertEqual(browser.last_pong, 1.999)

    async def test_late_local_callback_preserves_only_the_unissued_reply_allowance(self):
        browser = fixture.Browser.__new__(fixture.Browser)
        browser.last_ping = 10
        browser.last_pong = 10.001
        browser.rtt = .001
        browser.adaptive = True
        browser.fast_until = 0
        browser.next_nonce = 1 << 63
        browser.pending = {}
        browser.send = AsyncMock()
        with patch.object(fixture.time, 'monotonic', side_effect=[10.036, 10.045]):
            await browser.sample_probe()
            self.assertAlmostEqual(browser.last_pong, 10.012)
            await browser.sample_probe()
            self.assertAlmostEqual(browser.last_pong, 10.012, msg='outstanding deadline cannot move')
        self.assertEqual(browser.send.await_count, 1)

    async def test_exited_thread_invalidates_sample(self):
        # Dropping a worker must not turn its accumulated CPU into apparent idle.
        with patch.object(fixture, 'snapshot', side_effect=[{1: (100, 0, 2), 2: (500, 0, 7)}, {1: (110, 0, 3)}]), patch.object(fixture.asyncio, 'sleep', new=AsyncMock()), patch.object(Path, 'read_text', return_value='worker'):
            with self.assertRaisesRegex(AssertionError, 'thread set changed'):
                await fixture.measure(123, 60)


if __name__ == '__main__':
    unittest.main()
