#!/usr/bin/env python3
"""Regression checks for measurement marker detection; no benchmark timings run here."""
import unittest
from measure import echoed

class EchoMarkers(unittest.TestCase):
    def test_marker_inside_large_flood_frame_is_detected(self):
        marker = b'ECHO_00000001'
        matched, _ = echoed(b'', b'flood\n'*1000 + marker+b'\r\n'+b'flood\n'*1000, marker)
        self.assertTrue(matched)

    def test_fragmented_marker_with_large_suffix_is_detected(self):
        marker = b'ECHO_00000002'
        matched, tail = echoed(b'', b'flood\n'+marker[:7], marker)
        self.assertFalse(matched)
        matched, _ = echoed(tail, marker[7:]+b'\r\n'+b'flood\n'*1000, marker)
        self.assertTrue(matched)

    def test_printf_command_echo_is_not_the_generated_marker(self):
        matched, _ = echoed(b'', b"printf 'ECHO_%08x\\n' 1\r\n", b'ECHO_00000001')
        self.assertFalse(matched)

if __name__ == '__main__':
    unittest.main()
