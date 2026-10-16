#!/usr/bin/env python3
"""Verify baseline diagnostics preserve the original native marker bounds [D270]."""
import unittest
from ppu_baseline_tail import receipts


class Endpoints(unittest.TestCase):
    def test_every_probe_needs_a_matching_marker_within_its_native_rtt(self):
        probe = dict(session=971, number=2, rtt_ms=1., send_before_s=10.)
        marker = dict(receive_active_s=10.0005)
        self.assertEqual(receipts([probe], {(971, 2): marker}), [probe | marker])
        with self.assertRaises(ValueError):
            receipts([probe], {})
        with self.assertRaises(ValueError):
            receipts([probe], {(971, 2): dict(receive_active_s=11.)})


if __name__ == '__main__':
    unittest.main()
