#!/usr/bin/env python3
"""Validate causal stage correlation, partial writes and cross-process bounds [D270]."""
import unittest
from unittest.mock import MagicMock
from ppu_stage_report import correlate, report


def record(stage, stamp, offset=0, size=0, fd=3, extra=0):
    return dict(stage=stage, ns=stamp * 1_000_000, session=17, offset=offset,
                bytes=size, fd=fd, extra=extra)


def fixture():
    probe = dict(session=7, number=2, writer=0, input_start=10, input_end=20, output_end=120,
                 send_before_ns=0, receive_ns=9_000_000, completed_ns=10_000_000, rtt_ms=9, send_before_s=0, receive_active_s=.009)
    rows = [record(2, 1, 10, 10, fd=8), record(4, 2, 20, 10), record(5, 3, 100, 30),
            record(6, 4, 100, 30), record(14, 5, 100, fd=8),
            record(7, 6, 100, 30, fd=8, extra=43), record(8, 7, fd=8),
            record(9, 8, 43, 43, fd=8, extra=43)]
    return probe, rows


class CorrelationTests(unittest.TestCase):
    def test_stages_are_correlated_by_byte_range_and_descriptor(self):
        probe, rows = fixture()
        result = correlate(probe, rows, 10)
        self.assertEqual(result['shell_and_read_wait_ms'], 1)
        self.assertEqual(result['parse_ms'], 1)
        self.assertEqual(result['frame_build_ms'], 1)
        self.assertEqual(result['socket_syscall_ms'], 1)
        self.assertEqual(result['reader_delay_lower_ms'], 1)
        self.assertEqual(result['reader_delay_upper_ms'], 2)

    def test_receipt_span_cannot_exceed_the_original_timed_echo(self):
        probe, rows = fixture()
        probe.update(send_before_s=0, receive_active_s=.009, rtt_ms=4)
        with self.assertRaisesRegex(ValueError, 'receipt span exceeds timed echo'):
            correlate(probe, rows, 10)

    def test_reader_cpu_requires_paired_integer_bounds_inside_the_timed_echo(self):
        for fields in (dict(send_before_thread_cpu_ns=0),
                       dict(send_before_thread_cpu_ns=2, receive_thread_cpu_ns=1),
                       dict(send_before_thread_cpu_ns=-1, receive_thread_cpu_ns=0),
                       dict(send_before_thread_cpu_ns=0, receive_thread_cpu_ns=9_000_001),
                       dict(send_before_thread_cpu_ns=0, receive_thread_cpu_ns=float('nan')),
                       dict(send_before_thread_cpu_ns=False, receive_thread_cpu_ns=1)):
            with self.subTest(fields=fields):
                probe, rows = fixture()
                probe.update(fields)
                with self.assertRaisesRegex(ValueError, 'reader CPU'):
                    correlate(probe, rows, 10)
        probe, rows = fixture()
        probe.update(send_before_thread_cpu_ns=700, receive_thread_cpu_ns=9_000_700)
        self.assertEqual(correlate(probe, rows, 10)['receive_thread_cpu_ns'], 9_000_700)

    def test_legacy_or_nonfinite_marker_receipts_cannot_certify_causality(self):
        root = MagicMock()
        (root / 'stage-probes.json').read_text.return_value = '{}'
        with self.assertRaisesRegex(ValueError, 'legacy marker receipt'):
            report(root)
        for value in (float('nan'), float('inf')):
            probe, rows = fixture()
            probe['receive_active_s'] = value
            with self.assertRaisesRegex(ValueError, 'invalid marker receipt'):
                correlate(probe, rows, 10)

    def test_partial_or_unrelated_socket_write_cannot_complete_the_frame(self):
        probe, rows = fixture()
        rows.insert(-1, record(9, 7.5, 8, 8, fd=8, extra=43))
        rows.insert(-1, record(9, 7.5, 43, 43, fd=9, extra=43))
        result = correlate(probe, rows, 10)
        self.assertEqual(result['socket_done_ns'], 8_000_000)
        with self.assertRaisesRegex(ValueError, 'missing stage 9'):
            correlate(probe, rows[:-1], 10)

    def test_another_viewer_cannot_supply_the_frame_completion(self):
        probe, rows = fixture()
        rows.insert(4, record(14, 4.5, 100, fd=9))
        rows.insert(5, record(7, 4.6, 100, 30, fd=9, extra=43))
        self.assertEqual(correlate(probe, rows, 10)['frame_built_ns'], 6_000_000)

    def test_another_writer_with_the_same_offsets_is_not_this_input(self):
        probe, rows = fixture()
        rows[0]['extra'] = 1
        with self.assertRaisesRegex(ValueError, 'missing stage 2'):
            correlate(probe, rows, 10)

    def test_reader_may_finish_before_the_post_syscall_record_is_scheduled(self):
        probe, rows = fixture()
        rows[-1]['ns'] = 11_000_000
        result = correlate(probe, rows, 10)
        self.assertEqual(result['reader_delay_lower_ms'], 0)
        self.assertEqual(result['reader_delay_upper_ms'], 2)

    def test_wrong_session_or_range_is_never_a_correlated_input_write(self):
        probe, rows = fixture()
        rows[1]['session'] = 18
        with self.assertRaisesRegex(ValueError, 'missing stage 4'):
            correlate(probe, rows, 10)
        rows[1]['session'] = 17
        rows[1]['offset'] = 19
        with self.assertRaisesRegex(ValueError, 'missing stage 4'):
            correlate(probe, rows, 10)


if __name__ == '__main__':
    unittest.main()
