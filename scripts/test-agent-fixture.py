#!/usr/bin/env python3
"""Reject invalid real-binary fixture paths before allocating sockets or workers."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import unittest
from unittest.mock import patch

from agent_fixture import Binary


class BinaryPathTests(unittest.TestCase):
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
