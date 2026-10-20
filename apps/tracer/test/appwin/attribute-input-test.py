"""Role: reject ambiguous cohorts and contradictory clock evidence before reporting input latency (#146)."""
import pathlib
import runpy
import unittest

analysis = runpy.run_path(str(pathlib.Path(__file__).with_name('attribute-input.py')))


class AttributionTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
