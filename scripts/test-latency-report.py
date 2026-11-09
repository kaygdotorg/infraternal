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
        self.assertIn("| Idle infraternal agent | under 15 MB RSS | - | - | - | - | MISSING |", table)

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

    def test_own_overhead_is_composed_from_both_shares(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_own_overhead" not in line)
        parts = ("METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=0.74 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=20 p50_ms=3 p99_ms=6.10 result=REPORT\n"
                 "METRIC name=frame_pacing display=unthrottled idle_fps=250")
        table, passed = targets.report(log + "\n" + parts)
        self.assertTrue(passed)
        self.assertIn("| 6.84 ms (n=20) | - | yes | PASS |", table)
        _, passed = targets.report(log + "\n" + parts.splitlines()[0] + "\n" + parts.splitlines()[2])
        self.assertFalse(passed, "one share alone must leave the row MISSING")

    def test_unthrottled_gates_and_60hz_is_shown_beside_it(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_predicted_glyph" not in line)
        fast = targets.row_line("predicted_glyph", source="t", display="unthrottled", n=20, value=4.0, unit="ms",
                                target=targets.FRAME_MS)
        paced = targets.row_line("predicted_glyph", source="t", display="60hz", n=20, value=15.0, unit="ms",
                                 target=targets.FRAME_MS)
        pacing = "METRIC name=frame_pacing display=unthrottled idle_fps=240.0\nMETRIC name=frame_pacing display=60hz idle_fps=60.0"
        table, passed = targets.report("\n".join([log, paced, fast, pacing]))
        self.assertTrue(passed, table)
        self.assertIn("| 4.00 ms (n=20) | 15.00 ms | yes | PASS |", table)
        self.assertIn("unthrottled 240.0", table)

    def test_60hz_alone_cannot_gate(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_predicted_glyph" not in line)
        paced = targets.row_line("predicted_glyph", source="t", display="60hz", n=20, value=4.0, unit="ms",
                                 target=targets.FRAME_MS)
        table, passed = targets.report(log + "\n" + paced)
        self.assertFalse(passed)
        self.assertIn("| 4.00 ms | - | MISSING |", table)

    def test_unthrottled_run_still_at_60hz_fails(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_predicted_glyph" not in line)
        fast = targets.row_line("predicted_glyph", source="t", display="unthrottled", n=20, value=4.0, unit="ms",
                                target=targets.FRAME_MS)
        table, passed = targets.report("\n".join([log, fast, "METRIC name=frame_pacing display=unthrottled idle_fps=60.1"]))
        self.assertFalse(passed)
        self.assertIn("did not run above 70 fps", table)

    def test_own_overhead_per_display(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_own_overhead" not in line)
        parts = ("METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=0.70 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=20 p50_ms=1 p99_ms=3.30 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=60hz n=20 p50_ms=3 p99_ms=17.30 result=REPORT\n"
                 "METRIC name=frame_pacing display=unthrottled idle_fps=300")
        table, passed = targets.report(log + "\n" + parts)
        self.assertTrue(passed, table)
        self.assertIn("| 4.00 ms (n=20) | 18.00 ms | yes | PASS |", table)

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
        self.assertEqual(rows["real_echo"]["native"]["value"], "320.00")

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
