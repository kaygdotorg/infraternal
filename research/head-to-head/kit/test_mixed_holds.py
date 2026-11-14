#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-engine holds: `perf-all.sh --mixed`, Williams orders and the pooled report (#260, J638)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_engine_rows import PerfAllRun

KIT = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT / "lib"))
import head_to_head  # noqa: E402
import latin_square  # noqa: E402


class MixedHoldCliTest(PerfAllRun):
    def binary(self, root: Path, name: str) -> Path:
        path = root / name
        path.write_text("#!/usr/bin/env bash\nexit 0\n")
        path.chmod(0o755)
        return path

    def mixed(self, root: Path, rows: list[str], label: str | None = "h1") -> tuple[subprocess.CompletedProcess[str], list[str]]:
        arguments = ["--mixed", "--out", str(root / "out")]
        if label:
            arguments += ["--label", label]
        gotatun, infraternal = self.binary(root, "gotatun"), self.binary(root, "infraternal")
        for row in rows:
            tag, engine = row.split("=")
            arguments += ["--row", row]
            if engine in ("gotatun", "infraternal"):
                arguments += ["--binary", f"{tag}={gotatun if engine == 'gotatun' else infraternal}",
                              "--source", f"{tag}={'a' * 40}"]
        return self.perf_all(root, arguments)

    def test_mixed_runs_different_engines_in_the_given_order_in_one_hold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-mixed-") as temporary:
            root = Path(temporary)
            rows = ["gotatun=gotatun", "kernel-wg=kernel-plain", "infraternal=infraternal", "netbird-kernel=kernel"]
            result, received = self.mixed(root, rows)
            self.assertEqual(result.returncode, 23, result.stderr)
            plan = [line.split("\t")[:2] for line in (root / "out/rows.tsv").read_text().splitlines()]
            self.assertEqual(plan, [row.split("=") for row in rows])
            self.assertEqual(received.count("--root"), 1)
            self.assertIn("H2H_CALIBRATION_ONLY=1", received)
            self.assertIn("H2H_LAN_PING_COUNT=8000", received)
            self.assertIn("mixed", received)
        overlay = (KIT / "runner-overlays/J88i-pinned-run.sh").read_text()
        self.assertRegex(overlay, r"calibration\|hold\|matrix\|ab\|mixed\)")

    def test_mixed_refuses_repeated_engines_too_many_rows_and_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-mixed-") as temporary:
            root = Path(temporary)
            result, _ = self.mixed(root, ["a=kernel-plain", "b=kernel-plain"])
            self.assertEqual(result.returncode, 2)
            self.assertIn("each engine at most once", result.stderr)
        with tempfile.TemporaryDirectory(prefix="j638-mixed-") as temporary:
            root = Path(temporary)
            result, _ = self.mixed(root, ["a=kernel-plain", "b=kernel", "c=tailscale", "d=netbird-userspace", "e=wireguard-go"])
            self.assertEqual(result.returncode, 2)
            self.assertIn("--mixed takes two to four rows", result.stderr)
        with tempfile.TemporaryDirectory(prefix="j638-mixed-") as temporary:
            root = Path(temporary)
            result, _ = self.mixed(root, ["a=kernel-plain", "b=kernel"], label=None)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--mixed requires --label", result.stderr)
        with tempfile.TemporaryDirectory(prefix="j638-mixed-") as temporary:
            root = Path(temporary)
            binary = self.binary(root, "gotatun")
            result, _ = self.perf_all(root, ["--mixed", "--label", "x", "--row", "g=gotatun", "--binary", f"g={binary}",
                                             "--row", "k=kernel-plain", "--out", str(root / "out")])
            self.assertEqual(result.returncode, 2)
            self.assertIn("row g needs --source g=SHA", result.stderr)


class LatinSquareTest(unittest.TestCase):
    def test_even_williams_square_matches_j629s_order(self) -> None:
        self.assertEqual(latin_square.williams(["G", "K", "N", "I"]),
                         [["G", "K", "I", "N"], ["K", "N", "G", "I"], ["N", "I", "K", "G"], ["I", "G", "N", "K"]])

    def test_every_square_is_balanced_for_position_and_first_order_carryover(self) -> None:
        for size in range(2, 8):
            items = [str(index) for index in range(size)]
            square = latin_square.williams(items)
            self.assertEqual(len(square), size if size % 2 == 0 else 2 * size)
            for order in square:
                self.assertEqual(sorted(order), sorted(items))
            for position in range(size):
                counts = {item: sum(order[position] == item for order in square) for item in items}
                self.assertEqual(len(set(counts.values())), 1, (size, position, counts))
            pairs: dict[tuple[str, str], int] = {}
            for order in square:
                for first, second in zip(order, order[1:]):
                    pairs[(first, second)] = pairs.get((first, second), 0) + 1
            self.assertEqual(len(pairs), size * (size - 1))
            self.assertEqual(len(set(pairs.values())), 1)


def write_row(hold: Path, tag: str, case: str, flows: int, gbit: float, cores: float, p99: float,
              lost: int = 0, rss_kb: int = 0, housekeeping: float = 0.05) -> None:
    directory = hold / tag / case
    (directory / f"cpuset-lan-{flows}").mkdir(parents=True, exist_ok=True)
    (directory / f"tput-lan-{flows}.json").write_text(json.dumps({
        "gbit_per_s": gbit, "machine_cores_busy": cores, "machine_cpu_s_per_gbit": cores / gbit,
        "watched_rss_kb_peak": rss_kb, "seconds": 72.0}))
    (directory / f"icmp-lan-{flows}.summary.txt").write_text(
        f"sent 8000 lost {lost} p50 1.0 p99_received {p99:.3f} p99_loss_aware {'inf' if lost else f'{p99:.3f}'} max 9\n")
    (directory / f"cpuset-lan-{flows}/cpu-split.json").write_text(json.dumps({"cores_busy": {
        "side_a": (cores - housekeeping) / 2, "side_b": (cores - housekeeping) / 2,
        "housekeeping": housekeeping, "total": cores}}))


class PooledReportTest(unittest.TestCase):
    def test_pool_reports_per_core_used_cores_and_verdicts_against_kernel(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-pool-") as temporary:
            root = Path(temporary)
            calibration = root / "calibration-spread.json"
            calibration.write_text(json.dumps({"spread_pct": {
                "throughput_gbit_s": {"8": 1.0}, "cpu_s_per_gbit": {"8": 1.0}, "p99_loss_aware_ms": {"8": 2.0}}}))
            holds = []
            for index, kernel_gbit in enumerate((4.7, 4.6)):
                hold = root / f"h{index + 1}"
                hold.mkdir()
                order = [("gotatun", "gotatun"), ("kernel-wg", "kernel-plain")]
                if index:
                    order.reverse()
                (hold / "rows.tsv").write_text("".join(f"{tag}\t{engine}\t\t\n" for tag, engine in order))
                write_row(hold, "gotatun", "mesh-gotatun", 8, 4.7, 3.4, 8.8, rss_kb=38000)
                write_row(hold, "kernel-wg", "mesh-kernel-plain", 8, kernel_gbit, 4.7, 3.3, housekeeping=1.4)
                holds.append(hold)
            report = head_to_head.report(calibration, holds, flows=(8,))
            self.assertIn("| GotaTun CLI | 4.70", report)
            # Per busy core: 4.7 / 3.4 = 1.382; kernel 4.7 / 4.7 = 1.000 and 4.6 / 4.7 = 0.979.
            self.assertIn("1.382", report)
            # The cores each engine actually used, split by D348 group.
            self.assertIn("4.70 (A 1.65 · B 1.65 · hk 1.40)", report)
            self.assertRegex(report, r"GotaTun CLI vs kernel WireGuard \| [^|]*\| \+[0-9.]+% \([^)]*\) \*\*better\*\*")
            self.assertIn("Holds: h1=gotatun,kernel-wg; h2=kernel-wg,gotatun", report)

    def test_a_missing_row_is_named_never_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-pool-") as temporary:
            root = Path(temporary)
            calibration = root / "calibration-spread.json"
            calibration.write_text(json.dumps({"spread_pct": {
                "throughput_gbit_s": {"8": 1.0}, "cpu_s_per_gbit": {"8": 1.0}, "p99_loss_aware_ms": {"8": 2.0}}}))
            hold = root / "h1"
            hold.mkdir()
            (hold / "rows.tsv").write_text("gotatun\tgotatun\t\t\ntailscale\ttailscale\t\t\n")
            write_row(hold, "gotatun", "mesh-gotatun", 8, 4.7, 3.4, 8.8)
            report = head_to_head.report(calibration, [hold], flows=(8,))
            self.assertIn("Missing (failed) rows: h1/tailscale/8f", report)

    def test_missing_calibration_is_refused_unless_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j688-pool-") as temporary:
            root = Path(temporary)
            calibration = root / "calibration-spread.json"
            calibration.write_text(json.dumps({"spread_pct": {"throughput_gbit_s": {"8": 1.0}}}))
            hold = root / "h1"
            hold.mkdir()
            (hold / "rows.tsv").write_text("gotatun\tgotatun\t\t\n")
            write_row(hold, "gotatun", "mesh-gotatun", 8, 4.7, 3.4, 8.8)
            with self.assertRaisesRegex(ValueError, "cpu_s_per_gbit.*8 flows"):
                head_to_head.report(calibration, [hold], flows=(8,))
            report = head_to_head.report(calibration, [hold], flows=(8,), allow_uncalibrated=True)
            self.assertIn("WARNING: NOT CALIBRATED", report)


if __name__ == "__main__":
    unittest.main()
