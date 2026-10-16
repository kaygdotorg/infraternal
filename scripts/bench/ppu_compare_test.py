#!/usr/bin/env python3
"""Check that comparison receipts follow the original timed cohort [D270]."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import ppu_compare as compare


class Receipts(unittest.TestCase):
    def test_each_sample_preserves_native_echo_and_records_lock_metadata(self):
        output = []
        receipt = dict(owner='owned-scope', load='0 0 0', locks=[['FLOCK']])
        with patch.object(compare, 'lock_receipt', return_value=receipt), \
             patch.object(compare, 'original_write', side_effect=lambda rec, kind, **row: output.append(row)):
            compare.write(SimpleNamespace(), 'sample', echo_ms=[1, 8], monotonic_ns=100)
        self.assertEqual(output[0]['echo_ms'], [1, 8])
        self.assertEqual(output[0]['monotonic_ns'], 100)
        self.assertEqual(output[0]['machine_receipt'], receipt)

    def test_environment_discloses_first_shim_wakeup_scope(self):
        output = []
        with patch.object(compare, 'INDEPENDENT', True), \
             patch.object(compare, 'original_write', side_effect=lambda rec, kind, **row: output.append(row)):
            compare.write(SimpleNamespace(), 'environment')
        self.assertEqual(output[0]['wakeup_scope'], 'first-shim-only')
        self.assertEqual(output[0]['architecture'], 'independent-session-processes')


if __name__ == '__main__':
    unittest.main()
