#!/usr/bin/env python3
"""Keep numeric syscall decoding exact without retaining trace arguments [D270]."""
import unittest

from ppu_delivery import number


class NumericFields(unittest.TestCase):
    def test_named_trace_fields_are_decimal_unless_explicitly_hexadecimal(self):
        self.assertEqual(number(b'sys_enter_sendto: fd=42 len=13', b'fd'), 42)
        self.assertEqual(number(b'sys_enter_sendto: fd=0x2a len=13', b'fd'), 42)

    def test_syscall_printer_fields_are_hexadecimal_even_without_a_prefix(self):
        self.assertEqual(number(b'sys_sendto(fd: c2, len: d)', b'fd'), 194)
        self.assertEqual(number(b'sys_sendto(fd: 42, len: d)', b'fd'), 66)
        self.assertEqual(number(b'sys_sendto(fd: 0xc2, len: d)', b'fd'), 194)

    def test_signed_returns_and_missing_fields(self):
        self.assertEqual(number(b'sys_exit_sendto: ret=-11', b'ret'), -11)
        self.assertEqual(number(b'sys_exit_sendto: ret=0xfffffffffffffff5', b'ret'), -11)
        self.assertIsNone(number(b'sys_sendto()', b'fd'))


if __name__ == '__main__':
    unittest.main()
