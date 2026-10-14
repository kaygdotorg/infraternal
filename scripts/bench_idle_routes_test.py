"""Check ownership-safe idle fixture peer inspection across long Unix socket paths [81], #199."""
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
