#!/usr/bin/env python3
"""Reject implicit or invalid binary paths before allocating real-binary fixtures."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from contextlib import redirect_stderr
import io
import os
import runpy
import unittest
from unittest.mock import patch

from agent_fixture import Binary


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


if __name__ == '__main__':
    unittest.main()
