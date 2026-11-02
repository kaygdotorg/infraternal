"""Role: reject ambiguous cohorts and contradictory clock evidence before reporting input latency (#146)."""
import pathlib
import runpy
import json
import tempfile
import unittest

analysis = runpy.run_path(str(pathlib.Path(__file__).with_name('attribute-input.py')))


class AttributionTests(unittest.TestCase):
    def test_surface_partition_preserves_all_queue_pixel_and_write_work(self):
        row = dict(capture_ns='1', fresh='true', callback_ns='1000000', dequeued_ns='2000000',
                   prepared_ns='3000000', output_begin_ns='8000000', output_end_ns='9000000')
        encoded = dict(capture_ns='1', encode_finished_ns='7000000', encode_ns='3000000')
        stages = analysis['surface_delivery_stages'](row, encoded)
        self.assertEqual(stages, dict(callback_to_dequeue=1, dequeue_to_pixels_ready=1,
                                     pixels_ready_to_encode_begin=1, encode_duration=3,
                                     encoded_to_output_begin=1, native_output_write=1))
        self.assertEqual(sum(stages.values()), 8)
        for changed in (dict(fresh='false'), dict(capture_ns='2'), dict(dequeued_ns='0'),
                        dict(prepared_ns='5000000'), dict(output_end_ns='6000000')):
            with self.assertRaises(ValueError):
                analysis['surface_delivery_stages']({**row, **changed}, encoded)

    def test_post_selects_execution_when_mouse_receives_share_the_key_window(self):
        commands = [{'receive_ns': '100', 'dispatch_ns': str(begin), 'finished_ns': str(end)}
                    for begin, end in ((110, 120), (125, 130), (135, 140))]
        self.assertIs(analysis['command_for_post'](commands, 138), commands[2])

    def test_missing_or_overlapping_dispatches_are_not_guessed(self):
        match = analysis['command_for_post']
        with self.assertRaises(ValueError): match([], 138)
        with self.assertRaises(ValueError): match([{'dispatch_ns': '110', 'finished_ns': '120'}], 138)
        with self.assertRaises(ValueError): match([{'dispatch_ns': '110', 'finished_ns': '140'},
                                                 {'dispatch_ns': '135', 'finished_ns': '145'}], 138)

    def test_source_callback_split_preserves_a_future_display_stamp(self):
        stages = analysis['source_callback_stages'](100_000_000, 120_000_000, 110_000_000, 140_000_000, 20_000_000)
        self.assertEqual(stages, {'draw_end_to_callback': 10, 'display_stamp_to_callback': -10,
                                 'callback_to_encode_begin': 10, 'encode_duration': 20})
        self.assertEqual(sum(stages[k] for k in ('draw_end_to_callback', 'callback_to_encode_begin', 'encode_duration')), 40)

    def test_source_callback_split_refuses_missing_or_reversed_encoder_receipts(self):
        split = analysis['source_callback_stages']
        with self.assertRaises(ValueError): split(100, 120, 0, 140, 20)
        with self.assertRaises(ValueError): split(100, 120, 110, 140, 40)
        with self.assertRaises(ValueError): split(100, 120, 110, 140, -1)

    def test_arrival_spacing_matches_without_synchronized_wall_clocks(self):
        reference = [0, 37_000_000, 93_000_000, 144_000_000, 206_000_000]
        offset = 1_700_000_000_000_000_000
        matching = [offset + value + jitter for value, jitter in zip(reference, (0, 1000, -1000, 2000, 0))]
        candidates = [offset - 900_000_000, *matching, offset + 2_000_000_000]
        rows, score = analysis['align_ordered'](reference, candidates, lambda value: value)
        self.assertEqual(rows, matching)
        self.assertLess(score, .003)

    def test_a_missing_or_ambiguous_cohort_is_never_silently_aligned(self):
        match = analysis['align_ordered']
        with self.assertRaises(ValueError): match([0, 10, 20], [100, 110], lambda value: value)
        with self.assertRaises(ValueError): match([0, 10, 20], [100, 110, 120, 130], lambda value: value)
        with self.assertRaises(ValueError): match([0, 1], [0, 1], lambda value: value)

    def test_intervening_mouse_commands_do_not_break_the_quiet_key_cohort(self):
        commands = [{'receive_ns': str(i * 50_000_000)} for i in range(5)]
        candidates = [700_000_000 + int(row['receive_ns']) for row in commands]
        selected = [commands[i] for i in (0, 2, 4)]
        rows, score = analysis['align_command_stream'](selected, commands, candidates,
                                                       'receive_ns', lambda value: value)
        self.assertEqual(rows, [candidates[i] for i in (0, 2, 4)])
        self.assertEqual(score, 0)

    def test_unrelated_later_phases_do_not_change_the_measured_cohort(self):
        commands = [{'receive_ns': str(value)} for value in
                    (0, 100_000_000, 1_000_000_000, 1_200_000_000, 1_500_000_000, 3_000_000_000)]
        candidates = [7_000_000_000, 8_100_000_000, 9_000_000_000,
                      9_200_000_000, 9_500_000_000, 12_000_000_000]
        rows, score = analysis['align_command_stream'](commands[2:5], commands, candidates,
                                                       'receive_ns', lambda value: value)
        self.assertEqual(rows, candidates[2:5])
        self.assertEqual(score, 0)

    def test_complete_command_alignment_keeps_ambiguity_and_identity_guards(self):
        match = analysis['align_command_stream']
        commands = [{'receive_ns': str(i * 10_000_000)} for i in range(3)]
        with self.assertRaises(ValueError):
            match(commands, commands, [100_000_000 + i * 10_000_000 for i in range(4)],
                  'receive_ns', lambda value: value)
        with self.assertRaises(ValueError):
            match(commands, [commands[0], commands[0], commands[2]], [0, 10, 20],
                  'receive_ns', lambda value: value)
        with self.assertRaises(ValueError):
            match([{'receive_ns': '1'}], commands, [0, 10_000_000, 20_000_000],
                  'receive_ns', lambda value: value)

    def test_local_causality_bounds_the_clock_without_symmetric_delays(self):
        bounds = analysis['source_clock_bounds']([1012, 1045], [1020, 1050], [10, 40], [24, 53])
        self.assertEqual(bounds, (997, 1002))
        self.assertLessEqual(bounds[0], 1000)
        self.assertGreaterEqual(bounds[1], 1000)

    def test_contradictory_or_incomplete_clock_evidence_fails_closed(self):
        bounds = analysis['source_clock_bounds']
        with self.assertRaises(ValueError): bounds([1012], [1020], [10], [12])
        with self.assertRaises(ValueError): bounds([1012, 1045], [1020], [10, 40], [24, 53])
        with self.assertRaises(ValueError): bounds([], [], [], [])
        with self.assertRaises(ValueError): bounds([1012], [1011], [10], [24])
        with self.assertRaises(ValueError): bounds([1012], [1020], [24], [10])


class ReportCausalityTests(unittest.TestCase):
    """The report must reject a local phase whose end precedes its start."""

    def test_reversed_companion_dispatch_and_injection_stamps_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            controller_rows = [{
                'kind': 'clocks', 'timebase': {'numer': 1, 'denom': 1},
                'native': {'lower': 0, 'upper': 0}, 'browser': {'lower': 0, 'upper': 0},
            }]
            source_draws = []
            helper_rows = []
            server_rows = []
            for index in range(4):
                base = 10_000_000 * (index + 1)
                capture = base + 80_000
                sequence = index + 1
                dispatch = base + (100_000 if index == 0 else 20_000)
                source_receive = 0 if index == 0 else base - 1_000_000
                source_ack = 0 if index == 0 else base + 300_000
                server_receive = 1_000_000 if index == 0 else base
                controller_rows.append({
                    'kind': 'input_sample', 'index': index,
                    'events': [{'probe': {
                        'domInputs': [{'at': base / 1e6 + .0001, 'eventAt': base / 1e6}],
                        'inputs': [{'at': base / 1e6 + .0002, 'kind': 'text'}], 'roundTrips': [],
                    }}],
                    'effect': {'begin': base / 1e6 + 1, 'frame': {
                        'captureNs': str(capture), 'sequence': sequence, 'receivedAt': base / 1e6 + .14,
                    }},
                })
                source_draws.extend([
                    {'kind': 'input', 'ticks': base + 60_000, 'sequence': sequence, 'characters': 'x'},
                    {'kind': 'draw', 'sequence': sequence, 'begin_ticks': base + 61_000, 'end_ticks': base + 70_000},
                ])
                helper_rows.extend([
                    f'METRIC native_input receive_ns={base} dispatch_ns={dispatch} finished_ns={base + 200_000} accepted=true',
                    f'METRIC native_input_post at_ns={base + 50_000} type=10',
                    f'METRIC encode_ns=10000 encode_finished_ns={capture + 10_000} bytes=10 capture_ns={capture} codec=h264',
                    f'METRIC app_window_stage pid=40 stage=source_send_end at_ns={base + 110_000} capture_ns={capture} sequence={sequence} bytes=10',
                ])
                server_rows.extend([
                    f'METRIC app_window_control pid=40 stage=source_control_receive at_ns={source_receive} kind=4',
                    f'METRIC app_window_control pid=40 stage=source_control_ack at_ns={source_ack} kind=67',
                    f'METRIC app_window_stage pid=70 stage=server_input_receive at_ns={server_receive} kind=4 capture_ns=0 sequence=0 bytes=0',
                    f'METRIC app_window_stage pid=70 stage=server_input_write_begin at_ns={base + 10_000} kind=4 capture_ns=0 sequence=0 bytes=0',
                    f'METRIC app_window_stage pid=70 stage=server_input_write_end at_ns={base + 20_000} kind=4 capture_ns=0 sequence=0 bytes=0',
                    f'METRIC app_window_stage pid=70 stage=relay_receive at_ns={base + 120_000} capture_ns={capture} sequence={sequence} bytes=10',
                    f'METRIC app_window_stage pid=70 stage=browser_socket_end at_ns={base + 130_000} capture_ns={capture} sequence={sequence} bytes=10',
                ])
            (root / 'source-draws.json').write_text(json.dumps(source_draws))
            (root / 'helper-metrics.log').write_text('\n'.join(helper_rows) + '\n')
            (root / 'native-metrics.log').write_text('')
            (root / 'server-stages.log').write_text('\n'.join(server_rows) + '\n')
            controller = root / 'controller.log'
            controller.write_text('\n'.join(json.dumps(row) for row in controller_rows) + '\n')

            report = analysis['analyze'](root, controller)
            self.assertAlmostEqual(report['metrics']['Mac_native_total']['p50'], 1.11)
            self.assertAlmostEqual(report['metrics']['Mac_native_non_encode_total']['p50'], 1.10)
            self.assertAlmostEqual(report['metrics']['Mac_local_total']['p50'], 1.9702)
            self.assertAlmostEqual(report['metrics']['Mac_non_encode_total']['p50'], 1.9602)
            self.assertEqual(report['valid_sample_count'], 3)
            self.assertEqual(report['invalid_sample_count'], 1)
            self.assertEqual(report['invalid_samples'], [{'index': 0, 'reason': 'injection_before_dispatch'}])
            for event in report['events']:
                self.assertTrue(all(duration >= 0 for duration in event['local_ms'].values()))
            # Companion and Rust helper appenders must not share a diagnostic
            # stream. Splitting their files preserves every core attribution.
            companion_rows = [row for row in helper_rows if not row.startswith('METRIC app_window_stage ')]
            rust_rows = [row for row in helper_rows if row.startswith('METRIC app_window_stage ')]
            (root / 'companion-metrics.log').write_text('\n'.join(companion_rows) + '\n')
            (root / 'helper-metrics.log').write_text('\n'.join(rust_rows) + '\n')
            self.assertEqual(analysis['analyze'](root, controller), report)



if __name__ == '__main__':
    unittest.main()
