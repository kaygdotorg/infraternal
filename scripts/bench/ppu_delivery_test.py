#!/usr/bin/env python3
"""Keep numeric syscall decoding exact without retaining trace arguments [D270]."""
import unittest
from unittest.mock import patch

import ppu_delivery as delivery
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

    def test_unknown_decimal_field_is_refused_without_stopping_the_reader(self):
        self.assertIsNone(number(b'sys_enter_sendto: fd=bad', b'fd'))


class Completeness(unittest.TestCase):
    def result(self, writes):
        probes = [dict(session=session, number=0, before=10, after=12,
                       receive_lower=11.5, rtt_ms=1500) for session in (1, 2)]
        observer = delivery.DeliveryTrace.__new__(delivery.DeliveryTrace)
        observer.writes = writes
        with patch.object(delivery, 'probes', probes), \
                patch.object(delivery.original_trace, 'close', return_value={'complete': True}):
            return observer.close()

    def test_partial_correlation_is_incomplete(self):
        result = self.result([(10.5, 1)])
        self.assertFalse(result['complete'])
        self.assertEqual(result['delivery']['correlated_count'], 1)

    def test_no_correlated_writes_is_incomplete(self):
        self.assertFalse(self.result([])['complete'])

    def test_every_probe_correlated_is_complete(self):
        result = self.result([(10.5, 1), (10.5, 2)])
        self.assertTrue(result['complete'])
        self.assertEqual(result['delivery']['correlated_count'], 2)


if __name__ == '__main__':
    unittest.main()
