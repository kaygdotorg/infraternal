#!/usr/bin/env python3
"""Check the D375 latency report: row format, gating, missing rows, and the TypeScript copy of the targets [D375]."""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import latency_targets as targets  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def full_log(**overrides):
    """A log with a passing line for every D375 row; `overrides` replaces chosen rows' lines."""
    lines = []
    for row in targets.ROWS:
        lines.append(overrides.get(row.key) or targets.row_line(row.key, source="test", n=100, value=1.0, unit="ms", target=8.3))
    return "\n".join(lines)


class ReportTests(unittest.TestCase):
    """The report must list all ten rows, gate them, and never let a row disappear."""

    def test_all_rows_pass(self):
        table, passed = targets.report(full_log())
        self.assertTrue(passed)
        self.assertEqual(table.count("| PASS |"), len(targets.ROWS))

    def test_missing_row_fails(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_idle_agent_rss" not in line)
        table, passed = targets.report(log)
        self.assertFalse(passed)
        self.assertIn("| Idle infraternal agent | under 15 MB RSS | - | - | - | MISSING |", table)

    def test_failed_row_fails(self):
        slow = targets.row_line("predicted_glyph", source="test", n=100, value=9.0, unit="ms", target=targets.FRAME_MS)
        self.assertIn("result=FAIL", slow)
        _, passed = targets.report(full_log(predicted_glyph=slow))
        self.assertFalse(passed)

    def test_overhead_gates_on_baseline_until_target_is_reached(self):
        line = targets.row_line("own_overhead", source="test", n=100, value=20.0, unit="ms",
                                target=targets.FRAME_MS, gate=targets.OWN_OVERHEAD_BASELINE_MS)
        self.assertIn("target_met=no result=PASS", line)
        worse = targets.row_line("own_overhead", source="test", n=100, value=26.0, unit="ms",
                                 target=targets.FRAME_MS, gate=targets.OWN_OVERHEAD_BASELINE_MS)
        self.assertIn("result=FAIL", worse)

    def test_frame_rate_compares_upwards(self):
        self.assertIn("result=PASS", targets.row_line("render_10mbps", source="t", n=1, value=121, unit="fps",
                                                      target=120, higher_is_better=True))
        self.assertIn("result=FAIL", targets.row_line("render_10mbps", source="t", n=1, value=60, unit="fps",
                                                      target=120, higher_is_better=True))

    def test_no_samples_or_nan_never_pass(self):
        self.assertIn("result=FAIL", targets.row_line("real_echo", source="t", n=0, value=1, unit="ms", target=9))
        self.assertIn("result=FAIL", targets.row_line("real_echo", source="t", n=5, value=float("nan"), unit="ms", target=9))

    def test_playwright_prefix_and_last_line_wins(self):
        first = targets.row_line("real_echo", source="t", n=5, value=400, unit="ms", target=346.67)
        second = targets.row_line("real_echo", source="t", n=5, value=320, unit="ms", target=346.67)
        rows = targets.parse(f"[chromium] › spec  {first}\n{second}")
        self.assertEqual(rows["real_echo"]["value"], "320.00")

    def test_unknown_row_is_refused(self):
        with self.assertRaises(ValueError):
            targets.row_line("made_up", source="t", n=1, value=1, unit="ms", target=1)


class TypeScriptCopyTests(unittest.TestCase):
    """`apps/tracer/test/latency-targets.ts` must carry the same numbers as the Python table."""

    def test_constants_match(self):
        source = (ROOT / "apps/tracer/test/latency-targets.ts").read_text()
        self.assertIn("export const FRAME_MS = 1000 / 120;", source)
        self.assertEqual(targets.FRAME_MS, 1000 / 120)
        for name, value in (("RECONNECT_ALLOWANCE_MS", targets.RECONNECT_ALLOWANCE_MS),
                            ("FIRST_PAINT_MS", targets.FIRST_PAINT_MS), ("RENDER_FPS", targets.RENDER_FPS)):
            match = re.search(rf"export const {name} = ([0-9.]+);", source)
            self.assertIsNotNone(match, name)
            self.assertEqual(float(match.group(1)), value, name)
        self.assertIn("rttMs + (rttMs === 0 ? 0 : 30)", source)
        self.assertEqual(targets.round_trip_bound_ms(300, 30), 330)

    def test_browser_row_keys_are_known(self):
        source = (ROOT / "apps/tracer/test/latency-targets.ts").read_text()
        union = re.search(r"key:\s*((?:\|\s*\"\w+\"\s*)+);", source)
        self.assertIsNotNone(union)
        keys = set(re.findall(r'"(\w+)"', union.group(1)))
        self.assertTrue(keys)
        self.assertLessEqual(keys, {row.key for row in targets.ROWS})


if __name__ == "__main__":
    unittest.main(verbosity=1)
