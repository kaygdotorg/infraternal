#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The home-router bufferbloat profile on dev (D381, #260, J638; first built by J512)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from test_engine_rows import PerfAllRun

KIT = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT / "lib"))
import bufferbloat  # noqa: E402


class BufferbloatPlanTest(unittest.TestCase):
    def test_plan_rows_map_kit_engines_to_profile_engines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-bb-") as temporary:
            plan = Path(temporary) / "rows.tsv"
            plan.write_text("bare\tunderlay\t\t\ng\tgotatun\t/k/bin/g\tabc1234\nk\tkernel-plain\t\t\nw\twireguard-go\t\t\n")
            engines, gotatun = bufferbloat.read_plan(plan)
            self.assertEqual(engines, ["bare", "gotatun", "kernel", "wireguard-go"])
            self.assertEqual(gotatun, Path("/k/bin/g"))

    def test_plan_refuses_engines_the_profile_cannot_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-bb-") as temporary:
            plan = Path(temporary) / "rows.tsv"
            plan.write_text("t\ttailscale\t\t\n")
            with self.assertRaisesRegex(ValueError, "tailscale"):
                bufferbloat.read_plan(plan)

    def test_shaping_matches_the_documented_home_link(self) -> None:
        source = (KIT / "lib/bufferbloat.py").read_text()
        for setting in ("'481.5mbit'", "'778.9mbit'", "'target', '5ms'", "'interval', '100ms'", "default=3500000",
                        "src,dst,proto,proto-src,proto-dst"):
            self.assertIn(setting, source)


class BufferbloatCliTest(PerfAllRun):
    def binary(self, root: Path) -> Path:
        path = root / "gotatun"
        path.write_text("#!/usr/bin/env bash\nexit 0\n")
        path.chmod(0o755)
        return path

    def test_bufferbloat_hold_reaches_the_runner_with_its_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-bb-") as temporary:
            root = Path(temporary)
            result, received = self.perf_all(root, [
                "--bufferbloat", "--profile", "fq_codel", "--label", "bb1",
                "--row", "bare=underlay", "--row", "gotatun=gotatun", "--binary", f"gotatun={self.binary(root)}",
                "--source", f"gotatun={'b' * 40}", "--row", "kernel-wg=kernel-plain", "--out", str(root / "out")])
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("bufferbloat", received)
            self.assertIn("H2H_HOME_PROFILE=fq_codel", received)
            self.assertEqual(received.count("--root"), 1)
        overlay = (KIT / "runner-overlays/J88i-pinned-run.sh").read_text()
        self.assertIn('lib/bufferbloat.py" --kit "$kit" --plan "$plan"', overlay)

    def test_bufferbloat_refuses_a_bad_profile_or_engine(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-bb-") as temporary:
            root = Path(temporary)
            result, _ = self.perf_all(root, ["--bufferbloat", "--profile", "cake", "--label", "x",
                                             "--row", "bare=underlay", "--out", str(root / "out")])
            self.assertEqual(result.returncode, 2)
            self.assertIn("--profile must be fifo or fq_codel", result.stderr)
        with tempfile.TemporaryDirectory(prefix="j638-bb-") as temporary:
            root = Path(temporary)
            result, _ = self.perf_all(root, ["--bufferbloat", "--profile", "fifo", "--label", "x",
                                             "--row", "t=tailscale", "--out", str(root / "out")])
            self.assertEqual(result.returncode, 2)
            self.assertIn("--bufferbloat runs underlay, gotatun, kernel-plain and wireguard-go rows", result.stderr)


if __name__ == "__main__":
    unittest.main()
