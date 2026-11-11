"""Checks the recovery metrics recorded by the GotaTun break-it suite."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gotatun_break_it.report import Probe, report_case


class RecoveryReportTests(unittest.TestCase):
    """Keep the break-it report honest about recovery, loss and manual fixes."""

    def test_reports_loss_aware_p99_and_unverified_bytes(self):
        """Include lost probes in p99 and count payload bytes without verified delivery."""
        probes = [
            Probe(sequence, 1_000_000_000 + sequence * 1_000_000, 1.0)
            for sequence in range(1, 101)
        ]
        probes[-1] = Probe(100, 1_100_000_000, None)
        probes.append(Probe(101, 1_200_000_000, 10.0))

        report = report_case(
            case="packet-loss-1pct",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=1_200_000_000,
            probes=probes,
            bytes_sent=10_000,
            bytes_verified=9_700,
            integrity_ok=True,
        )

        self.assertEqual(report["recovery_ms_from_fault_start"], 210.0)
        self.assertEqual(report["recovery_ms_after_fault_cleared"], 10.0)
        self.assertEqual(report["bytes_unverified"], 300)
        self.assertEqual(report["recovery_probe_loss_pct"], 0.9901)
        self.assertEqual(report["p99_recovery_ms"], 10.0)
        self.assertEqual(report["p99_state"], "finite")
        self.assertEqual(report["outcome"], "PASS")

    def test_manual_intervention_fails_even_if_the_link_recovers(self):
        """A case that needed a manual fix never reports as a pass."""
        report = report_case(
            case="link-down-up",
            platform="macos",
            fault_started_ns=10,
            fault_cleared_ns=20,
            probes=[Probe(1, 20, 5.0), Probe(2, 30, 5.0)],
            bytes_sent=20,
            bytes_verified=20,
            integrity_ok=True,
            manual_fixes=["restart the interface"],
        )

        self.assertEqual(report["manual_fix"], True)
        self.assertEqual(report["outcome"], "FAIL")

    def test_missing_recovery_is_a_failure_without_invented_latency(self):
        """Report a missing recovery explicitly instead of fabricating a duration."""
        report = report_case(
            case="endpoint-rebind",
            platform="linux",
            fault_started_ns=10,
            fault_cleared_ns=20,
            probes=[Probe(1, 10, None), Probe(2, 20, None)],
            bytes_sent=20,
            bytes_verified=0,
            integrity_ok=False,
        )

        self.assertIsNone(report["recovery_ms_from_fault_start"])
        self.assertIsNone(report["recovery_ms_after_fault_cleared"])
        self.assertEqual(report["p99_state"], "infinite_due_to_loss")
        self.assertEqual(report["outcome"], "FAIL")


if __name__ == "__main__":
    unittest.main()
