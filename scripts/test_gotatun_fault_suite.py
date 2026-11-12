"""Keep the Linux GotaTun fault matrix and its measurements repeatable."""

from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gotatun_break_it.report import Probe, report_case

try:
    from gotatun_break_it.linux_faults import (
        bytes_stalled,
        build_fault_matrix,
        build_netem_command,
        build_next_config_chunks,
    )
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.linux_faults":
        raise
    bytes_stalled = None
    build_fault_matrix = None
    build_netem_command = None
    build_next_config_chunks = None


class LinuxFaultPlanTests(unittest.TestCase):
    """Keep each requested network failure in the runnable case matrix."""

    def test_matrix_covers_the_requested_linux_reliability_cases(self):
        """Use stable case IDs for rebinding, faults, restart, churn, and scale."""
        self.assertIsNotNone(build_fault_matrix, "the Linux fault matrix should be available")
        assert build_fault_matrix is not None
        names = {case.name for case in build_fault_matrix()}
        self.assertEqual(
            names,
            {
                "endpoint-ip-rebind",
                "nat-port-rebind",
                "loss-1pct",
                "loss-5pct",
                "loss-20pct",
                "reorder",
                "duplicate",
                "link-down-up",
                "rekey-under-load",
                "rekey-timer-expiry-under-load",
                "agent-restart",
                "server-restart",
                "coordinator-peer-churn",
                "mtu-change-mid-flow",
                "peer-scale-50",
                "peer-scale-200",
            },
        )

    def test_netem_loss_command_uses_a_repeatable_seed_and_private_link(self):
        """Put deterministic loss only on the suite's two disposable veths."""
        self.assertIsNotNone(build_netem_command, "the netem command builder should be available")
        assert build_netem_command is not None
        self.assertEqual(
            build_netem_command(Path("/usr/sbin/tc"), "underlay0", loss_pct=5),
            [
                "/usr/sbin/tc",
                "qdisc",
                "replace",
                "dev",
                "underlay0",
                "root",
                "netem",
                "loss",
                "5%",
                "seed",
                "526",
            ],
        )

    def test_netem_command_keeps_reordering_and_duplication_separate(self):
        """Make reorder and duplicate profiles independently reproducible."""
        self.assertIsNotNone(build_netem_command, "the netem command builder should be available")
        assert build_netem_command is not None
        self.assertEqual(
            build_netem_command(
                Path("/usr/sbin/tc"),
                "underlay1",
                reorder_pct=25,
                reorder_correlation_pct=50,
            )[-5:],
            ["reorder", "25%", "50%", "seed", "526"],
        )
        self.assertEqual(
            build_netem_command(Path("/usr/sbin/tc"), "underlay1", duplicate_pct=2)[-4:],
            ["duplicate", "2%", "seed", "526"],
        )

    def test_stalled_byte_count_is_sender_progress_not_acknowledged(self):
        """Count bytes queued by the sender that the remote receiver has not acked."""
        self.assertIsNotNone(bytes_stalled, "the fault runner should measure stalled bytes")
        assert bytes_stalled is not None
        self.assertEqual(bytes_stalled(8192, 5120), 3072)

    def test_next_config_chunks_advance_the_full_coordinator_snapshot(self):
        """Version a freshly compiled full snapshot after a coordinator restart."""
        self.assertIsNotNone(build_next_config_chunks, "the config version helper should be available")
        assert build_next_config_chunks is not None
        chunks = [
            {"from_version": None, "version": 1, "index": 0, "last": False},
            {"from_version": None, "version": 1, "index": 1, "last": True},
        ]
        advanced = build_next_config_chunks(chunks, current_version=7)
        self.assertEqual(
            [(chunk["from_version"], chunk["version"]) for chunk in advanced],
            [(7, 8), (7, 8)],
        )
        self.assertEqual([chunk["index"] for chunk in advanced], [0, 1])
        self.assertEqual([chunk["last"] for chunk in advanced], [False, True])


class FaultReportStallTests(unittest.TestCase):
    """Keep bytes stalled at fault-clear time beside recovery and loss metrics."""

    def test_report_accepts_and_returns_fault_clear_stalled_bytes(self):
        """Record the exact TCP progress gap when the injected fault clears."""
        self.assertIn("bytes_stalled", inspect.signature(report_case).parameters)
        report = report_case(
            case="link-down-up",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=2_000_000_000,
            probes=[Probe(1, 2_000_000_000, 8.0)],
            bytes_sent=8192,
            bytes_verified=8192,
            bytes_stalled=3072,
            integrity_ok=True,
        )
        self.assertEqual(report["bytes_stalled"], 3072)
        self.assertEqual(report["bytes_unverified"], 0)
        self.assertEqual(report["outcome"], "PASS")


if __name__ == "__main__":
    unittest.main()
