#!/usr/bin/env python3
"""Check the D375 latency report: row format, gating, missing rows, and the TypeScript copy of the targets [D375]."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
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
        lines.append(overrides.get(row.key) or targets.row_line(row.key, source="test", n=100, value=1.0, unit="ms", target=8.3,
                                                              display=row.display))
    # The rows a person typing and a phone network see: gating ones pass, reported ones print REPORT.
    for row in targets.EXTRA_ROWS:
        lines.append(overrides.get(row.key) or targets.row_line(row.key, source="test", n=100, value=1.0, unit="ms", target=8.3,
                                                              report_only=not row.gating))
    return "\n".join(lines)


class ReportTests(unittest.TestCase):
    """The report must list all eleven rows, gate them, and never let a row disappear."""

    def test_all_rows_pass(self):
        table, passed = targets.report(full_log())
        self.assertTrue(passed)
        self.assertEqual(table.count("| PASS |"), len(targets.ROWS) + sum(row.gating for row in targets.EXTRA_ROWS))
        self.assertEqual(table.count("| REPORT |"), sum(not row.gating for row in targets.EXTRA_ROWS))

    def test_row_one_gates_at_60hz_on_own_work_and_shows_unthrottled_beside_it(self):
        """Row 1 is about frames, so it gates where a frame is a real wait (owner, 2026-11-21)."""
        log = "\n".join(line for line in full_log().splitlines() if "d375_predicted_glyph" not in line)
        paced = targets.row_line("predicted_glyph", source="t", display="60hz", n=100, value=0.4, unit="ms",
                                 target=targets.PREDICTED_GLYPH_WORK_MS)
        fast = targets.row_line("predicted_glyph", source="t", display="unthrottled", n=100, value=0.3, unit="ms",
                                target=targets.PREDICTED_GLYPH_WORK_MS)
        table, passed = targets.report("\n".join([log, paced, fast]))
        self.assertTrue(passed, table)
        self.assertIn("| 0.40 ms (n=100) | 0.30 ms | yes | PASS |", table)
        slow = targets.row_line("predicted_glyph", source="t", display="60hz", n=100, value=4.5, unit="ms",
                                target=targets.PREDICTED_GLYPH_WORK_MS)
        _, passed = targets.report("\n".join([log, slow, fast]))
        self.assertFalse(passed)
        _, passed = targets.report("\n".join([log, fast]))
        self.assertFalse(passed, "an unthrottled run alone cannot gate row 1")

    def test_reported_rows_never_fail_and_gating_extra_rows_do(self):
        log = full_log()
        _, passed = targets.report(log)
        self.assertTrue(passed)
        reported = targets.row_line("first_paint_3g_connected", source="t", n=5, value=99999.0, unit="ms", target=1000.0,
                                    report_only=True)
        table, passed = targets.report("\n".join([log, reported]))
        self.assertTrue(passed, table)
        self.assertIn("99999.00 ms (n=5)", table)
        slow = targets.row_line("real_paint_after_ws", source="t", n=100, value=9.0, unit="ms", target=targets.FRAME_MS)
        _, passed = targets.report("\n".join([log, slow]))
        self.assertFalse(passed)
        missing = "\n".join(line for line in log.splitlines() if "d375_real_echo_shell" not in line)
        table, passed = targets.report(missing)
        self.assertFalse(passed)
        self.assertIn("MISSING", table)

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

    def test_overhead_gates_at_12ms_until_target_is_reached(self):
        line = targets.row_line("own_overhead", source="test", n=100, value=11.0, unit="ms",
                                target=targets.FRAME_MS, gate=targets.OWN_OVERHEAD_GATE_MS)
        self.assertIn("target_met=no result=PASS", line)
        worse = targets.row_line("own_overhead", source="test", n=100, value=12.5, unit="ms",
                                 target=targets.FRAME_MS, gate=targets.OWN_OVERHEAD_GATE_MS)
        self.assertIn("result=FAIL", worse)
        self.assertEqual(targets.OWN_OVERHEAD_GATE_MS, 12.0)

    def test_own_overhead_is_composed_from_both_shares(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_own_overhead" not in line)
        parts = ("METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=0.74 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=100 p50_ms=3 p99_ms=6.10 result=REPORT\n"
                 "METRIC name=frame_pacing display=unthrottled phase=rows n=5000 fps=250")
        table, passed = targets.report(log + "\n" + parts)
        self.assertTrue(passed)
        self.assertIn("| 6.84 ms (n=100) | - | yes | PASS |", table)
        _, passed = targets.report(log + "\n" + parts.splitlines()[0] + "\n" + parts.splitlines()[2])
        self.assertFalse(passed, "one share alone must leave the row MISSING")

    def test_unthrottled_gates_and_60hz_is_shown_beside_it(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_real_echo " not in line)
        fast = targets.row_line("real_echo", source="t", display="unthrottled", n=100, value=4.0, unit="ms",
                                target=targets.FRAME_MS)
        paced = targets.row_line("real_echo", source="t", display="60hz", n=100, value=15.0, unit="ms",
                                 target=targets.FRAME_MS)
        pacing = ("METRIC name=frame_pacing display=unthrottled phase=rows n=7000 fps=240.0\n"
                  "METRIC name=frame_pacing display=60hz phase=rows n=1800 fps=60.0\n"
                  "METRIC name=frame_pacing display=unthrottled n=240 idle_fps=350.0")
        table, passed = targets.report("\n".join([log, paced, fast, pacing]))
        self.assertTrue(passed, table)
        self.assertIn("| 4.00 ms (n=100) | 15.00 ms | yes | PASS |", table)
        self.assertIn("unthrottled 240.0", table)

    def test_60hz_alone_cannot_gate(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_real_echo " not in line)
        paced = targets.row_line("real_echo", source="t", display="60hz", n=20, value=4.0, unit="ms",
                                 target=targets.FRAME_MS)
        table, passed = targets.report(log + "\n" + paced)
        self.assertFalse(passed)
        self.assertIn("| 4.00 ms | - | MISSING |", table)

    def test_unthrottled_run_under_120_fps_while_rows_ran_fails(self):
        """A fast idle page does not count: the floor is the rate measured while the rows ran (J459 review)."""
        log = "\n".join(line for line in full_log().splitlines() if "d375_real_echo " not in line)
        fast = targets.row_line("real_echo", source="t", display="unthrottled", n=20, value=4.0, unit="ms",
                                target=targets.FRAME_MS)
        pacing = ("METRIC name=frame_pacing display=unthrottled n=240 idle_fps=350.0\n"
                  "METRIC name=frame_pacing display=unthrottled phase=rows n=3300 fps=110.0")
        table, passed = targets.report("\n".join([log, fast, pacing]))
        self.assertFalse(passed)
        self.assertIn("stayed under 120 fps", table)
        _, passed = targets.report("\n".join([log, fast, "METRIC name=frame_pacing display=unthrottled n=240 idle_fps=350.0"]))
        self.assertFalse(passed, "an idle rate alone must not satisfy the floor")

    def test_own_overhead_per_display(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_own_overhead" not in line)
        parts = ("METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=0.70 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=100 p50_ms=1 p99_ms=3.30 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=60hz n=100 p50_ms=3 p99_ms=17.30 result=REPORT\n"
                 "METRIC name=frame_pacing display=unthrottled phase=rows n=9000 fps=300")
        table, passed = targets.report(log + "\n" + parts)
        self.assertTrue(passed, table)
        self.assertIn("| 4.00 ms (n=100) | 18.00 ms | yes | PASS |", table)

    def test_too_few_samples_fail_the_row(self):
        """A p99 of a handful of samples is just their maximum, so the report refuses it (J468 review)."""
        few = targets.row_line("real_echo", source="t", display="unthrottled", n=20, value=1.0, unit="ms",
                               target=targets.FRAME_MS)
        self.assertIn("result=PASS", few)
        log = "\n".join(line for line in full_log().splitlines() if "d375_real_echo " not in line)
        pacing = "METRIC name=frame_pacing display=unthrottled phase=rows n=9000 fps=300"
        table, passed = targets.report("\n".join([log, few, pacing]))
        self.assertFalse(passed)
        self.assertIn("FAIL (n 20 < 100)", table)

    def test_own_overhead_shares_keep_the_slower_run(self):
        log = "\n".join(line for line in full_log().splitlines() if "d375_own_overhead" not in line)
        parts = ("METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=9.00 result=REPORT\n"
                 "METRIC name=own_overhead_agent source=a n=100 p50_ms=0.4 p99_ms=0.70 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=100 p50_ms=1 p99_ms=4.00 result=REPORT\n"
                 "METRIC name=own_overhead_browser source=b display=unthrottled n=100 p50_ms=1 p99_ms=2.00 result=REPORT\n"
                 "METRIC name=frame_pacing display=unthrottled phase=rows n=9000 fps=300")
        table, passed = targets.report(log + "\n" + parts)
        self.assertFalse(passed, table)
        self.assertIn("| 13.00 ms (n=100) |", table)

    def test_frame_rate_compares_upwards(self):
        self.assertIn("result=PASS", targets.row_line("render_10mbps", source="t", n=1, value=121, unit="fps",
                                                      target=120, higher_is_better=True))
        self.assertIn("result=FAIL", targets.row_line("render_10mbps", source="t", n=1, value=60, unit="fps",
                                                      target=120, higher_is_better=True))

    def test_no_samples_or_nan_never_pass(self):
        self.assertIn("result=FAIL", targets.row_line("real_echo", source="t", n=0, value=1, unit="ms", target=9))
        self.assertIn("result=FAIL", targets.row_line("real_echo", source="t", n=5, value=float("nan"), unit="ms", target=9))

    def test_a_rerun_never_hides_a_failure(self):
        """Worst of reruns wins, not the last line (J459 review): a later PASS cannot hide an earlier FAIL."""
        first = targets.row_line("real_echo", source="t", n=5, value=400, unit="ms", target=346.67)
        second = targets.row_line("real_echo", source="t", n=5, value=320, unit="ms", target=346.67)
        rows = targets.parse(f"[chromium] › spec  {first}\n{second}")
        self.assertEqual(rows["real_echo"]["native"]["value"], "400.00")
        self.assertEqual(rows["real_echo"]["native"]["runs"], "2")
        log = "\n".join(line for line in full_log().splitlines() if "d375_real_echo" not in line)
        table, passed = targets.report("\n".join([log, first, second]))
        self.assertFalse(passed)
        self.assertIn("(n=5, worst of 2 runs)", table)

    def test_worst_of_passing_reruns_is_the_slower_one(self):
        slow = targets.row_line("real_echo", source="t", n=5, value=330, unit="ms", target=346.67)
        quick = targets.row_line("real_echo", source="t", n=5, value=310, unit="ms", target=346.67)
        self.assertEqual(targets.parse(f"{quick}\n{slow}\n{quick}")["real_echo"]["native"]["value"], "330.00")
        high = targets.row_line("render_10mbps", source="t", n=5, value=700, unit="fps", target=120, higher_is_better=True)
        low = targets.row_line("render_10mbps", source="t", n=5, value=500, unit="fps", target=120, higher_is_better=True)
        self.assertEqual(targets.parse(f"{high}\n{low}\n{high}")["render_10mbps"]["native"]["value"], "500.00")

    def test_unknown_row_is_refused(self):
        with self.assertRaises(ValueError):
            targets.row_line("made_up", source="t", n=1, value=1, unit="ms", target=1)

    def test_protocol_tag_labels_first_paint_rows(self):
        """Rows carrying `protocol=` / `wire=` show HTTP/2 or HTTP/1.1 in the D375 report table (#573)."""
        self.assertEqual(targets.protocol_label({"protocol": "http2", "wire": "h2"}), "HTTP/2")
        self.assertEqual(targets.protocol_label({"protocol": "http1", "wire": "http/1.1"}), "HTTP/1.1")
        self.assertEqual(targets.protocol_label({"wire": "h2"}), "HTTP/2")
        self.assertEqual(targets.protocol_label({"protocol": "http3"}), "http3")
        self.assertIsNone(targets.protocol_label({}))

        base = "\n".join(line for line in full_log().splitlines() if "d375_first_paint_4g_" not in line)
        h2 = targets.row_line("first_paint_4g_signin", source="real-server-tracer-production-build",
                              display="60hz", n=5, value=503.3, unit="ms", target=targets.FIRST_PAINT_MS,
                              report_only=True, extra="p50_ms=498.60 protocol=http2 wire=h2")
        h1 = targets.row_line("first_paint_4g_connected", source="real-server-tracer-production-build",
                              display="60hz", n=5, value=1731.5, unit="ms", target=targets.FIRST_PAINT_MS,
                              report_only=True, extra="p50_ms=1704.90 protocol=http1 wire=http/1.1")
        table, passed = targets.report("\n".join([base, h2, h1]))
        self.assertTrue(passed, table)
        self.assertIn("| First paint, 4G 9 Mbps/170 ms: sign-in visible (HTTP/2) |", table)
        self.assertIn("| First paint, 4G 9 Mbps/170 ms: terminal connected (HTTP/1.1) |", table)


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
        match = re.search(r"export const PREDICTED_GLYPH_WORK_MS = ([0-9.]+);", source)
        self.assertIsNotNone(match)
        self.assertEqual(float(match.group(1)), targets.PREDICTED_GLYPH_WORK_MS)
        match = re.search(r"export const PHONE_CPU_SLOWDOWN = ([0-9.]+);", source)
        self.assertIsNotNone(match)
        self.assertEqual(float(match.group(1)), targets.PHONE_CPU_SLOWDOWN)
        self.assertEqual(targets.UNTHROTTLED_MIN_FPS, targets.RENDER_FPS)

    def test_jitter_literal_matches_the_real_relay(self):
        """The `30` in roundTripBoundMs must be the relay's real jitter bound (scripts/latency_proxy.py)."""
        import latency_proxy
        source = (ROOT / "apps/tracer/test/latency-targets.ts").read_text()
        match = re.search(r"rttMs \+ \(rttMs === 0 \? 0 : (\d+)\)", source)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), latency_proxy.DEFAULT_JITTER_MS)
        config = latency_proxy.LatencyConfig(rtt_ms=300)
        self.assertEqual(config.jitter_ms, int(match.group(1)))
        self.assertEqual(latency_proxy.LatencyConfig(rtt_ms=0, jitter_ms=0).jitter_ms, 0)
        self.assertEqual(targets.round_trip_bound_ms(300, config.jitter_ms), 330)

    def test_python_only_gates_match_their_written_targets(self):
        """OWN_OVERHEAD_GATE_MS and IDLE_AGENT_RSS_MB have no TypeScript copy; check them against the table and §6."""
        rows = {row.key: row for row in targets.ROWS}
        self.assertIn(f"gate {targets.OWN_OVERHEAD_GATE_MS:g} ms", rows["own_overhead"].target)
        self.assertIn(f"under {targets.IDLE_AGENT_RSS_MB:g} MB", rows["idle_agent_rss"].target)
        process = (ROOT / "docs/PROCESS.md").read_text()
        self.assertIn(f"then the gate is **{targets.OWN_OVERHEAD_GATE_MS:g} ms**", process)
        self.assertIn(f"| Idle infraternal agent | under {targets.IDLE_AGENT_RSS_MB:g} MB RSS |", process)

    def test_typescript_rows_decide_like_python_rows(self):
        """d375Row() and row_line() must print the same line, so both copies pass and fail alike."""
        # Fails rather than skips without bun: a skipped check would let the two copies drift unseen (J468 review).
        bun = shutil.which("bun")
        self.assertIsNotNone(bun, "bun is required to compare d375Row() with row_line()")
        cases = [
            dict(key="predicted_glyph", n=100, value=1.1, unit="ms", target=targets.PREDICTED_GLYPH_WORK_MS),
            dict(key="predicted_glyph", n=100, value=4.2, unit="ms", target=targets.PREDICTED_GLYPH_WORK_MS),
            dict(key="real_typed_letter", n=100, value=300.0, unit="ms", target=targets.FRAME_MS, report=True),
            dict(key="real_echo", n=0, value=1.0, unit="ms", target=346.67),
            dict(key="render_10mbps", n=50, value=119.0, unit="fps", target=120.0, higher=True),
            dict(key="render_10mbps", n=50, value=714.3, unit="fps", target=120.0, higher=True),
            dict(key="first_paint_phone", n=20, value=1000.0, unit="ms", target=1000.0, gate=1200.0),
            dict(key="second_burst_extra_frames", n=40, value=1.0, unit="frames", target=0.0),
        ]
        script = ("import { d375Row } from './apps/tracer/test/latency-targets.ts';"
                  "for (const c of JSON.parse(process.argv[1])) console.log(d375Row({ key: c.key, source: 't', n: c.n,"
                  " value: c.value, unit: c.unit, target: c.target, gate: c.gate, higherIsBetter: c.higher, reportOnly: c.report }).line);")
        result = subprocess.run([bun, "-e", script, json.dumps(cases)], cwd=ROOT, capture_output=True, text=True,
                                env={**os.environ, "INFRATERNAL_LATENCY_DISPLAY": "unthrottled"}, check=True)
        expected = [targets.row_line(c["key"], source="t", display="unthrottled", n=c["n"], value=c["value"],
                                     unit=c["unit"], target=c["target"], gate=c.get("gate"),
                                     higher_is_better=c.get("higher", False), report_only=c.get("report", False)) for c in cases]
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_browser_row_keys_are_known(self):
        source = (ROOT / "apps/tracer/test/latency-targets.ts").read_text()
        union = re.search(r"key:\s*((?:\|\s*\"\w+\"\s*)+);", source)
        self.assertIsNotNone(union)
        keys = set(re.findall(r'"(\w+)"', union.group(1)))
        self.assertTrue(keys)
        self.assertLessEqual(keys, targets.ROW_KEYS)


if __name__ == "__main__":
    unittest.main(verbosity=1)
