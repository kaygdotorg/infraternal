#!/usr/bin/env python3
"""Validate binary paths and private socket roots before real-binary fixtures launch."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from contextlib import redirect_stderr
import io
import os
import runpy
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

from agent_fixture import Binary, cleanup, fixture_state


class BinaryPathTests(unittest.TestCase):
    def test_oracle_without_build_root_requires_a_binary_before_allocating_state(self):
        script = Path(__file__).with_name('verify-agent.py')
        with patch.dict(os.environ), patch.object(sys, 'argv', [str(script), '--functional']):
            os.environ.pop('CARGO_TARGET_DIR', None)
            with patch('agent_fixture.fixture_state', side_effect=AssertionError('allocated state')):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    runpy.run_path(str(script), run_name='__main__')
            self.assertEqual(error.exception.code, 2)

    def test_missing_binary_names_path_before_opening_sockets(self):
        binary = Path(__file__).resolve().parent / 'missing-fixture-binary'
        with patch('agent_fixture.socket.socketpair', side_effect=AssertionError('opened socket')):
            with self.assertRaisesRegex(FileNotFoundError, str(binary)):
                Binary(binary, Path('unused-state'))

    def test_non_executable_binary_names_path_before_opening_sockets(self):
        binary = Path(__file__).resolve()
        with patch('agent_fixture.socket.socketpair', side_effect=AssertionError('opened socket')):
            with self.assertRaisesRegex(PermissionError, str(binary)):
                Binary(binary, Path('unused-state'))


class FixtureStateTests(unittest.TestCase):
    def test_deep_roots_use_private_short_sockets_and_release_the_parent(self):
        with tempfile.TemporaryDirectory(prefix='ift-', dir='/tmp') as scratch:
            deep = str(Path(scratch) / ('deep-worktree-' * 12))
            for override in (None, 'INFRATERNAL_TEST_STATE_ROOT',
                             'INFRATERNAL_AGENT_TEST_STATE_ROOT'):
                with self.subTest(override=override), patch.dict(os.environ):
                    for key in ('INFRATERNAL_TEST_STATE_ROOT',
                                'INFRATERNAL_AGENT_TEST_STATE_ROOT'):
                        os.environ.pop(key, None)
                    os.environ.update(HOME=deep, TMPDIR=deep)
                    if override is not None:
                        os.environ[override] = deep
                    state = fixture_state('rr257')
                    parent = state.parent
                    try:
                        self.assertEqual(parent.parent, Path('/tmp'))
                        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
                        self.assertFalse(state.exists())
                        sessions = state / 'sessions'
                        sessions.mkdir(parents=True, mode=0o700)
                        for suffix in ('.sock', '.upstream'):
                            path = sessions / ('a' * 32 + suffix)
                            self.assertLess(len(os.fsencode(path)), 108)
                            with socket.socket(socket.AF_UNIX) as listener:
                                listener.bind(str(path))
                    finally:
                        cleanup(state)
                    self.assertFalse(parent.exists())


if __name__ == '__main__':
    unittest.main()
