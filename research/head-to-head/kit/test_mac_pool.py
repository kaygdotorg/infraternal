#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check the Mac window orders and the pooled report (#260, J674)."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("mac_pool", Path(__file__).parent / "mac/mac_pool.py")
POOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POOL)  # type: ignore[union-attr]


def write_case(window: Path, engine: str, cell: str, gbit: float, p99: float, lost: int = 0, cpu_s: float = 10.0) -> None:
    """Write the three receipts of one case, shaped like `mac-window.sh` writes them."""
    folder = window / engine
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{cell}.source.json").write_text(json.dumps({"gbit_per_s": gbit, "secs": 10, "stall_seconds": 0}))
    (folder / f"{cell}.probe.json").write_text(json.dumps({"sent": 1000, "lost": lost, "loss_aware_p99_ms": p99}))
    (folder / f"{cell}.meta.json").write_text(json.dumps({"mac_cpu_s": cpu_s, "footprint_mac": 50 * 2**20}))


class OrdersTest(unittest.TestCase):
    """The Williams design must balance positions and carry-over."""

    def test_four_engines_take_every_position_once_and_every_follow_once(self) -> None:
        """Four engines need four windows; each position and each ordered pair appears once."""
        orders = POOL.williams(["pin", "cand", "tailscale", "netbird"])
        self.assertEqual(len(orders), 4)
        for position in range(4):
            self.assertEqual(len({order[position] for order in orders}), 4)
        pairs = {(a, b) for order in orders for a, b in zip(order, order[1:])}
        self.assertEqual(len(pairs), 12)

    def test_three_engines_get_the_mirror_too(self) -> None:
        """An odd count doubles the design."""
        self.assertEqual(len(POOL.williams(["a", "b", "c"])), 6)

    def test_repeat_runs_the_design_again(self) -> None:
        """`orders --repeat 3` prints the two-engine design three times."""
        import contextlib, io, sys
        out = io.StringIO()
        argv, sys.argv = sys.argv, ["mac_pool.py", "orders", "--repeat", "3", "pin", "cand"]
        try:
            with contextlib.redirect_stdout(out):
                self.assertEqual(POOL.main(), 0)
        finally:
            sys.argv = argv
        self.assertEqual(out.getvalue().split(), ["pin,cand", "cand,pin"] * 3)

    def test_one_engine_is_refused(self) -> None:
        """A square needs two engines."""
        with self.assertRaises(ValueError):
            POOL.williams(["a"])


class ReportTest(unittest.TestCase):
    """The report is built from per-window ratios to the baseline."""

    def windows(self, root: Path, faster_every_time: bool) -> list[Path]:
        """Two windows with `pin` as baseline and `cand` faster in both, or in only one."""
        result = []
        for index, (order, cand_gbit) in enumerate([(["pin", "cand"], 2.2), (["cand", "pin"], 2.2 if faster_every_time else 1.8)]):
            window = root / f"w{index}"
            window.mkdir()
            (window / "rows.tsv").write_text("".join(f"{e}\t{e}\n" for e in order))
            for cell in POOL.CELLS:
                write_case(window, "pin", cell, 2.0, 5.0)
                write_case(window, "cand", cell, cand_gbit, 4.0)
            result.append(window)
        return result

    def test_every_window_agreeing_is_better(self) -> None:
        """A candidate ahead in every window is called better on goodput and p99."""
        with tempfile.TemporaryDirectory(prefix="j674-pool-") as tmp:
            text = POOL.report("pin", self.windows(Path(tmp), True))
        self.assertIn("gbit better", text)
        self.assertIn("p99 better", text)
        self.assertIn("pin: #1×1, #2×1", text)

    def test_a_split_is_unclear(self) -> None:
        """A candidate that is ahead in one window and behind in the other is unclear."""
        with tempfile.TemporaryDirectory(prefix="j674-pool-") as tmp:
            text = POOL.report("pin", self.windows(Path(tmp), False))
        self.assertIn("gbit unclear", text)

    def test_loss_above_one_percent_is_infinite_p99(self) -> None:
        """A lossy loaded probe never reports a finite p99."""
        with tempfile.TemporaryDirectory(prefix="j674-pool-") as tmp:
            window = Path(tmp) / "w"
            write_case(window, "pin", "lan-mac-tx-1f", 2.0, 5.0, lost=20)
            self.assertEqual(POOL.load(window, "pin", "lan-mac-tx-1f")["p99"], float("inf"))

    def test_missing_receipts_are_skipped(self) -> None:
        """A case that never wrote its receipts is not counted."""
        with tempfile.TemporaryDirectory(prefix="j674-pool-") as tmp:
            self.assertIsNone(POOL.load(Path(tmp), "pin", "lan-mac-tx-1f"))

    def test_a_window_listed_twice_is_refused(self) -> None:
        """A reused window id would count one window twice, so the report refuses it."""
        with tempfile.TemporaryDirectory() as tmp:
            window = Path(tmp) / "w1"
            write_case(window, "pin", "lan-mac-tx-1f", 0.2, 1.0)
            (window / "rows.tsv").write_text("0\tpin\n")
            with self.assertRaises(SystemExit):
                POOL.report("pin", [window, Path(tmp) / "x" / ".." / "w1"])

    def test_unknown_baseline_is_refused(self) -> None:
        """Naming a baseline no window ran stops the report."""
        with tempfile.TemporaryDirectory(prefix="j674-pool-") as tmp:
            windows = self.windows(Path(tmp), True)
            with self.assertRaises(SystemExit):
                POOL.report("nope", windows)


if __name__ == "__main__":
    unittest.main()
