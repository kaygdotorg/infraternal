"""Keep the Linux GotaTun fault matrix and its measurements repeatable."""

from __future__ import annotations

import json
import inspect
import select
import socket
import subprocess
import sys
import tempfile
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

try:
    from gotatun_break_it.tcp_progress import transfer_integrity_ok
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.tcp_progress":
        raise
    transfer_integrity_ok = None


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

    def test_tcp_transfer_integrity_requires_matching_lengths_and_hashes(self):
        """Pass only when the receiver verified the sender's full byte stream."""
        self.assertIsNotNone(transfer_integrity_ok, "the TCP progress helper should be available")
        assert transfer_integrity_ok is not None
        sender = {"bytes": 4096, "sha256": "abc123"}
        self.assertTrue(transfer_integrity_ok(sender, {"bytes": 4096, "sha256": "abc123"}))
        self.assertFalse(transfer_integrity_ok(sender, {"bytes": 2048, "sha256": "abc123"}))
        self.assertFalse(transfer_integrity_ok(sender, {"bytes": 4096, "sha256": "different"}))

    def test_tcp_sender_and_receiver_publish_a_matching_real_stream(self):
        """Exercise the real bounded sender and receiver over a local TCP socket."""
        self.assertIsNotNone(transfer_integrity_ok, "the TCP progress helper should be available")
        assert transfer_integrity_ok is not None
        helper = Path(__file__).parent / "gotatun_break_it" / "tcp_progress.py"
        self.assertTrue(helper.is_file(), "the TCP progress command should exist")
        with tempfile.TemporaryDirectory(prefix="j526-tcp-") as directory:
            root = Path(directory)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            progress = root / "receiver-progress.json"
            result_path = root / "receiver-result.json"
            receiver = subprocess.Popen(
                [
                    sys.executable,
                    str(helper),
                    "serve",
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--progress",
                    str(progress),
                    "--result",
                    str(result_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert receiver.stdout is not None
                readable, _, _ = select.select([receiver.stdout], [], [], 10)
                self.assertTrue(readable, "the TCP receiver should publish readiness")
                self.assertEqual(json.loads(receiver.stdout.readline()), {"ready": True, "port": port})
                sender = subprocess.run(
                    [
                        sys.executable,
                        str(helper),
                        "send",
                        "--target",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--seconds",
                        "1",
                        "--rate-mbit",
                        "10",
                        "--progress",
                        str(root / "sender-progress.json"),
                        "--result",
                        str(root / "sender-result.json"),
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(sender.returncode, 0, sender.stderr)
                self.assertEqual(receiver.wait(timeout=15), 0)
                sent = json.loads(sender.stdout.strip().splitlines()[-1])
                received = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertTrue(transfer_integrity_ok(sent, received), (sent, received))
                self.assertEqual(json.loads(progress.read_text(encoding="utf-8")), received)
            finally:
                if receiver.poll() is None:
                    receiver.kill()
                    receiver.wait(timeout=5)
                if receiver.stdout is not None:
                    receiver.stdout.close()
                if receiver.stderr is not None:
                    receiver.stderr.close()
                assert receiver.stdout is not None
                assert receiver.stderr is not None
                self.assertTrue(receiver.stdout.closed)
                self.assertTrue(receiver.stderr.closed)


if __name__ == "__main__":
    unittest.main()
