#!/usr/bin/env python3
"""Check the nightly D375 latency run's decisions: what regressed, what fails, the comment, and atomic publishing [D375, #447]."""
import importlib.machinery
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import latency_targets as targets  # noqa: E402

SPEC = importlib.util.spec_from_file_location("nightly_latency", HERE / "nightly-latency.py")
nightly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nightly)


def log_with(**values):
    """A profile log with one METRIC line per D375 row; `values` overrides a row's p99 (ms)."""
    lines = []
    for row in targets.ROWS:
        value = values.get(row.key, 200.0 if row.key == "render_10mbps" else 1.0)
        unit = "fps" if row.key == "render_10mbps" else "ms"
        lines.append(targets.row_line(row.key, source="test", n=100, value=value, unit=unit,
                                      target=100.0 if unit == "ms" else 120.0, higher_is_better=unit == "fps",
                                      display=row.display))
    for row in targets.EXTRA_ROWS:
        lines.append(targets.row_line(row.key, source="test", n=100, value=values.get(row.key, 1.0), unit="ms",
                                      target=100.0, report_only=not row.gating))
    return "\n".join(lines)


class DecisionTests(unittest.TestCase):
    """Failing rows are always reported; slower rows only past both the share and the noise floor."""

    def rows(self, **values):
        """Gated rows of a synthetic log."""
        return nightly.gated_rows(targets, log_with(**values))

    def test_quiet_night_has_nothing_to_say(self):
        """No failure and no regression gives no comment."""
        now = self.rows()
        self.assertEqual(nightly.failing(targets, now), [])
        self.assertEqual(nightly.regressions(now, now), [])
        self.assertEqual(nightly.comment_text({"sha": "a" * 40, "run": "r"}, [], [], "t", "p"), "")

    def test_ten_percent_and_floor_both_needed(self):
        """+20 % of 10 ms is 2 ms (reported); +20 % of 1 ms is 0.2 ms (jitter); +9 % of 100 ms is under 10 %."""
        before = self.rows(predicted_glyph=10.0, real_echo=1.0, flood_effect=50.0)
        after = self.rows(predicted_glyph=12.0, real_echo=1.2, flood_effect=54.5)
        slower = nightly.regressions(before, after)
        self.assertEqual([item["key"] for item in slower], ["predicted_glyph"])
        self.assertAlmostEqual(slower[0]["percent"], 20.0)

    def test_frame_rate_regresses_downward(self):
        """For fps a drop is the regression and a rise never is."""
        before, drop, rise = self.rows(render_10mbps=100.0), self.rows(render_10mbps=80.0), self.rows(render_10mbps=130.0)
        self.assertEqual([item["key"] for item in nightly.regressions(before, drop)], ["render_10mbps"])
        self.assertEqual(nightly.regressions(before, rise), [])

    def test_no_previous_night_compares_nothing(self):
        """The first night has nothing to regress against."""
        self.assertEqual(nightly.regressions({}, self.rows(real_echo=90.0)), [])

    def test_failed_and_missing_rows_are_reported(self):
        """A row over its gate fails, and a row that is not in the log counts as not measured."""
        text = "\n".join(line for line in log_with(real_echo=500.0).splitlines() if "d375_first_paint_phone" not in line)
        bad = nightly.failing(targets, nightly.gated_rows(targets, text))
        self.assertEqual(sorted(key for key, _, _ in bad), ["first_paint_phone", "real_echo"])

    def test_too_few_samples_fail(self):
        """A p99 from fewer samples than the row's minimum cannot pass."""
        line = targets.row_line("predicted_glyph", source="test", n=5, value=1.0, unit="ms", target=8.3, display="60hz")
        rows = nightly.gated_rows(targets, line)
        self.assertTrue(rows["predicted_glyph"]["result"].startswith("FAIL"))

    def test_comment_lists_each_problem_briefly(self):
        """The comment names the commit, each failing and slower row, and where the full table is."""
        meta = {"sha": "abcdef0123456789" * 2 + "abcdef01", "run": "20261121T000000Z-abcdef012345", "previous": "yesterday"}
        text = nightly.comment_text(meta, [("real_echo", "Real echo", "500.00 ms against a gate of 346.67")],
                                    [{"measure": "Own overhead", "before": 2.0, "now": 3.0, "unit": "ms", "percent": 50.0}],
                                    "| table |", "~/nightly-latency/published/x")
        for needle in ("abcdef012345", "FAIL Real echo", "SLOWER Own overhead", "+50 %", "| table |", "published/x"):
            self.assertIn(needle, text)

    def test_protocol_tag_is_parsed_for_60hz_reported_rows_and_guards_regressions(self):
        """Nightly parsing keeps 60hz first-paint rows, records protocol/wire, and skips cross-protocol diffs (#573)."""
        base = "\n".join(line for line in log_with().splitlines() if "d375_first_paint_4g_signin" not in line)
        h1_line = targets.row_line("first_paint_4g_signin", source="real-server-tracer-production-build",
                                   display="60hz", n=5, value=620.0, unit="ms", target=targets.FIRST_PAINT_MS,
                                   report_only=True, extra="p50_ms=615.00 protocol=http1 wire=http/1.1")
        h2_fast = targets.row_line("first_paint_4g_signin", source="real-server-tracer-production-build",
                                   display="60hz", n=5, value=500.0, unit="ms", target=targets.FIRST_PAINT_MS,
                                   report_only=True, extra="p50_ms=495.00 protocol=http2 wire=h2")
        h2_slow = targets.row_line("first_paint_4g_signin", source="real-server-tracer-production-build",
                                   display="60hz", n=5, value=750.0, unit="ms", target=targets.FIRST_PAINT_MS,
                                   report_only=True, extra="p50_ms=740.00 protocol=http2 wire=h2")

        rows_h1 = nightly.gated_rows(targets, base + "\n" + h1_line)
        rows_h2_fast = nightly.gated_rows(targets, base + "\n" + h2_fast)
        rows_h2_slow = nightly.gated_rows(targets, base + "\n" + h2_slow)

        self.assertEqual(nightly.failing(targets, rows_h2_fast), [])
        self.assertEqual(rows_h2_fast["first_paint_4g_signin"]["protocol"], "http2")
        self.assertEqual(rows_h2_fast["first_paint_4g_signin"]["wire"], "h2")
        self.assertEqual(rows_h2_fast["first_paint_4g_signin"]["display"], "60hz")
        self.assertIn("(HTTP/2)", rows_h2_fast["first_paint_4g_signin"]["measure"])
        self.assertEqual(rows_h1["first_paint_4g_signin"]["protocol"], "http1")
        self.assertIn("(HTTP/1.1)", rows_h1["first_paint_4g_signin"]["measure"])

        # Same protocol: +50% slowdown is flagged as a regression with the protocol label.
        slower = nightly.regressions(rows_h2_fast, rows_h2_slow)
        self.assertEqual([item["key"] for item in slower], ["first_paint_4g_signin"])
        self.assertIn("(HTTP/2)", slower[0]["measure"])
        # Different protocol (http1 -> http2, even if slower): not compared across protocols.
        self.assertEqual(nightly.regressions(rows_h1, rows_h2_slow), [])

    def test_run_verify_defaults_first_paint_protocol_to_http2_and_allows_override(self):
        """`run_verify` passes FIRST_PAINT_PROTOCOL=http2 by default and keeps http1 selectable (#573)."""
        seen_envs = []

        class FakeChild:
            """Stand-in subprocess handle returning exit status 0."""

            pid = 12345

            def wait(self, timeout=None):
                """Return a clean exit code without spawning a process."""
                return 0

        def fake_popen(argv, *, cwd, env, stdout, stderr, start_new_session):
            """Capture the child environment passed to `scripts/verify latency`."""
            seen_envs.append(dict(env))
            return FakeChild()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(nightly, "prepare_tracer"), \
                    mock.patch.object(nightly.subprocess, "Popen", side_effect=fake_popen):
                with mock.patch.dict(nightly.os.environ, {}, clear=False):
                    nightly.os.environ.pop("FIRST_PAINT_PROTOCOL", None)
                    self.assertEqual(nightly.run_verify(root, root / "bin", root, root / "log1", root), 0)
                with mock.patch.dict(nightly.os.environ, {"FIRST_PAINT_PROTOCOL": "http1"}, clear=False):
                    self.assertEqual(nightly.run_verify(root, root / "bin", root, root / "log2", root), 0)
        self.assertEqual(seen_envs[0]["FIRST_PAINT_PROTOCOL"], "http2")
        self.assertEqual(seen_envs[1]["FIRST_PAINT_PROTOCOL"], "http1")


class PublishTests(unittest.TestCase):
    """A night appears whole or not at all, and `latest` always names a complete night."""

    def test_publish_moves_latest_and_keeps_staging_out_of_view(self):
        """After publishing, `latest` resolves to the new night; no hidden staging folder is left behind."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nightly.publish(root, "n1", {"rows.json": json.dumps({"a": 1}), "table.md": "t"})
            nightly.publish(root, "n2", {"rows.json": json.dumps({"a": 2}), "table.md": "t"})
            name, rows = nightly.previous_night(root)
            self.assertEqual((name, rows), ("n2", {"a": 2}))
            self.assertEqual(sorted(entry.name for entry in (root / "published").iterdir()), ["latest", "n1", "n2"])

    def test_failed_publish_leaves_the_previous_night(self):
        """A write that fails midway removes its staging folder and leaves `latest` on the old night."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nightly.publish(root, "n1", {"rows.json": "{}"})
            with self.assertRaises(FileNotFoundError):
                nightly.publish(root, "n2", {"rows.json": "{}", "log": root / "missing"})
            self.assertEqual(nightly.previous_night(root)[0], "n1")
            self.assertEqual(sorted(entry.name for entry in (root / "published").iterdir()), ["latest", "n1"])

    def test_retention_keeps_the_newest_nights(self):
        """Only KEEP_NIGHTS complete nights stay."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(nightly.KEEP_NIGHTS + 3):
                nightly.publish(root, f"n{index:03d}", {"rows.json": "{}"})
            nights = [entry.name for entry in (root / "published").iterdir() if entry.name != "latest"]
            self.assertEqual(len(nights), nightly.KEEP_NIGHTS)
            self.assertNotIn("n000", nights)

    def test_no_previous_night(self):
        """With nothing published yet there is no previous night."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(nightly.previous_night(Path(tmp)), (None, {}))


LOADER = importlib.machinery.SourceFileLoader("install_nightly_latency", str(HERE / "install-nightly-latency"))
INSTALLER = importlib.util.spec_from_loader(LOADER.name, LOADER)
installer = importlib.util.module_from_spec(INSTALLER)
LOADER.exec_module(installer)


class InstallerTests(unittest.TestCase):
    """The installer writes the program and units once and leaves a second run alone."""

    def test_second_install_changes_nothing(self):
        """Two installs: the first writes three files and reloads; the second touches nothing and does not reload."""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            recorder = home / "calls"
            fake = home / "fake-systemctl"
            fake.write_text(f"#!/bin/sh\necho \"$@\" >> {recorder}\n")
            fake.chmod(0o755)
            source = HERE / "nightly-latency.py"
            first = installer.install(home, source, "/usr/bin", systemctl=[str(fake)])
            self.assertEqual(len(first), 3)
            second = installer.install(home, source, "/usr/bin", systemctl=[str(fake)])
            self.assertEqual(second, [])
            calls = recorder.read_text().splitlines()
            self.assertEqual(calls.count("daemon-reload"), 1)
            self.assertEqual(calls.count("enable --now infraternal-nightly-latency.timer"), 2)

    def test_timer_avoids_the_dev_02_window(self):
        """03:30 IST is before the 05:30 to 07:45 IST dev-02 window and the timer is in IST."""
        timer = installer.unit_texts(Path("/x"), "/usr/bin")["infraternal-nightly-latency.timer"]
        self.assertIn("OnCalendar=*-*-* 03:30:00 Asia/Kolkata", timer)


# The perf VM's installed perf-run takes only `[--cold] [--root] [--out DIR] -- <cmd>` (its usage line).
# It has no `status` subcommand; a call that uses one fails on the VM with exit status 2 (#447).
PERF_RUN_FLAGS = r"(?:--cold|--root|--out \S+)"


def perf_run_calls(text):
    """Every `perf-run ... -- ` invocation written in `text`, as the flags between the name and the `--`."""
    return re.findall(r"perf-run((?: " + PERF_RUN_FLAGS + r")*) -- ", text)


class PerfRunInterfaceTests(unittest.TestCase):
    """Every perf-run call the nightly makes, and the installer's preflight, use the interface the perf VM has."""

    def test_nightly_calls_use_only_the_installed_interface(self):
        """Each perf-run call in the coordinator is `perf-run [--cold|--root|--out DIR]... -- <cmd>`."""
        text = (HERE / "nightly-latency.py").read_text(encoding="utf-8")
        calls = perf_run_calls(text)
        self.assertTrue(calls, "expected the coordinator to call perf-run")
        for flags in calls:
            self.assertRegex(flags, r"^(?: " + PERF_RUN_FLAGS + r")*$")

    def test_no_status_subcommand_anywhere_in_the_nightly_scripts(self):
        """The nightly scripts never call `perf-run status`, which the perf VM does not have."""
        for name in ("nightly-latency.py", "install-nightly-latency"):
            self.assertNotIn("perf-run status", (HERE / name).read_text(encoding="utf-8"))

    def test_preflight_command_is_a_real_invocation(self):
        """The preflight is `perf-run -- <cmd>`, a call the perf VM accepts (exit 0 on `true`)."""
        self.assertEqual(perf_run_calls(installer.PERF_PREFLIGHT + " "), [""])
        self.assertTrue(installer.PERF_PREFLIGHT.endswith("-- true"))

    def test_preflight_sends_that_command_to_the_perf_vm(self):
        """preflight() runs PERF_PREFLIGHT on the perf VM through netbird ssh, and reports a non-zero exit."""
        seen = []

        def fake_run(argv, **_):
            seen.append(argv)
            return subprocess_result(0 if argv[2] != installer.PERF_HOST else 2, "usage: perf-run")

        with mock.patch.object(installer.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(installer.subprocess, "run", side_effect=fake_run):
            problems = installer.preflight()
        perf = [argv for argv in seen if argv[2] == installer.PERF_HOST]
        self.assertEqual(perf, [["netbird", "ssh", installer.PERF_HOST, installer.PERF_PREFLIGHT]])
        self.assertEqual(len(problems), 1)
        self.assertIn(installer.PERF_PREFLIGHT, problems[0])

    def test_preflight_reports_a_timeout_instead_of_crashing(self):
        """A perf VM that does not answer within the timeout is one reported problem, not a traceback."""
        def fake_run(argv, **_):
            if argv[2] == installer.PERF_HOST:
                raise subprocess.TimeoutExpired(argv, 120)
            return subprocess_result(0, "")

        with mock.patch.object(installer.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(installer.subprocess, "run", side_effect=fake_run):
            problems = installer.preflight()
        self.assertEqual(len(problems), 1)
        self.assertIn("did not finish within 120 s", problems[0])


def subprocess_result(code, stderr):
    """A stand-in for subprocess.CompletedProcess with the fields preflight() reads."""
    return subprocess.CompletedProcess(args=[], returncode=code, stdout="", stderr=stderr)


if __name__ == "__main__":
    unittest.main()
