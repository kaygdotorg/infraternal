"""Check ownership-safe idle fixture peer inspection across long Unix socket paths [81], #199."""
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
    async def test_exited_thread_invalidates_sample(self):
        # Dropping a worker must not turn its accumulated CPU into apparent idle.
        with patch.object(fixture, 'snapshot', side_effect=[{1: (100, 0, 2), 2: (500, 0, 7)}, {1: (110, 0, 3)}]), patch.object(fixture.asyncio, 'sleep', new=AsyncMock()), patch.object(Path, 'read_text', return_value='worker'):
            with self.assertRaisesRegex(AssertionError, 'thread set changed'):
                await fixture.measure(123, 60)


if __name__ == '__main__':
    unittest.main()
