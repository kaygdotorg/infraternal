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

    def test_scope_names_alone_do_not_establish_background_activity(self):
        def read(path):
            return {'locks': '1: FLOCK ADVISORY WRITE 42 00:00:3 0 EOF',
                    'perf-bench.owner': 'our run', 'loadavg': '0 0 0',
                    'cpu.stat': 'usage_usec 123\nuser_usec 100\n'}[path.name]
        replies = ['idle.scope loaded active running example\n',
                   'Id=idle.scope\nControlGroup=/system.slice/idle.scope\n']
        with patch.object(compare, 'control_scopes', return_value=['own.scope']), \
             patch.object(compare.Path, 'stat', return_value=SimpleNamespace(st_dev=0, st_ino=3)), \
             patch.object(compare.Path, 'exists', return_value=True), \
             patch.object(compare.Path, 'read_text', read), \
             patch.object(compare.subprocess, 'check_output', side_effect=replies):
            result = compare.lock_receipt()
        self.assertEqual(result['scope_cpu']['idle.scope']['usage_usec'], '123')
        self.assertEqual(result['locks'][0][4], '42')

    def test_environment_discloses_first_shim_wakeup_scope(self):
        output = []
        with patch.object(compare, 'lock_receipt', return_value={}), \
             patch.object(compare, 'INDEPENDENT', True), \
             patch.object(compare, 'original_write', side_effect=lambda rec, kind, **row: output.append(row)):
            compare.write(SimpleNamespace(), 'environment')
        self.assertEqual(output[0]['wakeup_scope'], 'first-shim-only')
        self.assertEqual(output[0]['architecture'], 'independent-session-processes')


if __name__ == '__main__':
    unittest.main()
