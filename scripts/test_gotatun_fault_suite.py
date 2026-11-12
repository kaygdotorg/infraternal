"""Keep the Linux GotaTun fault matrix and its measurements repeatable."""

from __future__ import annotations

import json
import inspect
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gotatun_break_it import linux_faults as linux_faults_module
from gotatun_break_it.report import Probe, report_case

try:
    from gotatun_break_it.report import failed_case_report
except ImportError:
    failed_case_report = None

try:
    from gotatun_break_it.linux_faults import (
        bytes_stalled,
        build_fault_matrix,
        build_netem_command,
        build_next_config_chunks,
        select_fault_cases,
    )
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.linux_faults":
        raise
    bytes_stalled = None
    build_fault_matrix = None
    build_netem_command = None
    build_next_config_chunks = None
    select_fault_cases = None

build_bidirectional_netem_commands = getattr(
    linux_faults_module,
    "build_bidirectional_netem_commands",
    None,
)

try:
    from gotatun_break_it.tcp_progress import transfer_integrity_ok
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.tcp_progress":
        raise
    transfer_integrity_ok = None

try:
    from gotatun_break_it.app_fixture import CoordinatorFixture
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.app_fixture":
        raise
    CoordinatorFixture = None

try:
    from gotatun_break_it.dns_probe import build_a_query, parse_a_answers
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.dns_probe":
        raise
    build_a_query = None
    parse_a_answers = None

try:
    from gotatun_break_it.packet_trace import is_wireguard_handshake_initiation
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.packet_trace":
        raise
    is_wireguard_handshake_initiation = None


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

    def test_case_selector_preserves_matrix_order_for_requested_cases(self):
        """Run selected case IDs in their stable suite order."""
        self.assertIsNotNone(select_fault_cases, "the Linux case selector should be available")
        assert select_fault_cases is not None
        selected = select_fault_cases(["loss-20pct", "endpoint-ip-rebind"])
        self.assertEqual(
            [case.name for case in selected],
            ["endpoint-ip-rebind", "loss-20pct"],
        )

    def test_case_selector_rejects_unknown_and_repeated_case_ids(self):
        """Refuse silent omissions and duplicate runs in an explicit case list."""
        self.assertIsNotNone(select_fault_cases, "the Linux case selector should be available")
        assert select_fault_cases is not None
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_fault_cases(["endpoint-ip-rebind", "typo"])
        with self.assertRaisesRegex(ValueError, "repeated"):
            select_fault_cases(["loss-5pct", "loss-5pct"])

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

    def test_netem_profiles_shape_both_directions_of_the_underlay(self):
        """Apply the same seeded impairment to each end of the isolated veth pair."""
        self.assertIsNotNone(
            build_bidirectional_netem_commands,
            "the bidirectional netem command builder should be available",
        )
        assert build_bidirectional_netem_commands is not None
        commands = build_bidirectional_netem_commands(Path("/usr/sbin/tc"), loss_pct=5)
        self.assertEqual([command[4] for command in commands], ["underlay0", "underlay1"])
        self.assertEqual(commands[0][7:], ["loss", "5%", "seed", "526"])
        self.assertEqual(commands[1][7:], ["loss", "5%", "seed", "526"])

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

    def test_failed_case_report_preserves_partial_transfer_progress(self):
        """Keep useful byte and recovery evidence when the traffic join fails."""
        self.assertIsNotNone(failed_case_report, "the failure report helper should be available")
        assert failed_case_report is not None
        report = failed_case_report(
            case="link-down-up",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=2_000_000_000,
            probes=[Probe(1, 2_100_000_000, 20.0)],
            bytes_sent=8192,
            bytes_verified=5120,
            bytes_stalled=3072,
            error="TimeoutError: TCP sender did not finish",
        )
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(report["error"], "TimeoutError: TCP sender did not finish")
        self.assertEqual(report["bytes_sent"], 8192)
        self.assertEqual(report["bytes_verified"], 5120)
        self.assertEqual(report["bytes_stalled"], 3072)
        self.assertEqual(report["bytes_unverified"], 3072)
        self.assertEqual(report["recovery_ms_after_fault_cleared"], 120.0)

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


class CoordinatorFixtureTests(unittest.TestCase):
    """Keep control requests available after the one-time identity enrollment."""

    def test_rotation_transition_can_omit_identities_after_enrollment(self):
        """Send a later rekey phase over the same coordinator process without re-enrolling nodes."""
        self.assertIsNotNone(CoordinatorFixture, "the production coordinator fixture should be available")
        assert CoordinatorFixture is not None
        with tempfile.TemporaryDirectory(prefix="j526-coordinator-") as directory:
            root = Path(directory)
            executable = root / "fixture"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "for line in sys.stdin:\n"
                " print(json.dumps(json.loads(line)), flush=True)\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            coordinator = CoordinatorFixture(
                executable,
                state_path=root / "coordinator.sqlite",
            )
            try:
                operation_id = "12345678-1234-4234-8234-123456789abc"
                request = coordinator.request("rotation-begin", operation_id=operation_id)
                self.assertEqual(request["mode"], "rotation-begin")
                self.assertEqual(request["operation_id"], operation_id)
                self.assertNotIn("identities", request)
                coordinator.current_version = 7
                previous_pid = coordinator.process.pid
                coordinator.restart()
                self.assertNotEqual(coordinator.process.pid, previous_pid)
                self.assertEqual(coordinator.current_version, 7)
                peer_change = coordinator.request("peer-add", count=50)
                self.assertEqual(peer_change["count"], 50)
                self.assertNotIn("identities", peer_change)
                with self.assertRaisesRegex(ValueError, "between 1 and 200"):
                    coordinator.request("peer-add", count=201)
            finally:
                coordinator.close()


class MeshDnsProbeTests(unittest.TestCase):
    """Keep the direct DNS check inside the same routed data-plane fixture."""

    def test_dns_query_encodes_one_inet_a_question(self):
        """Ask for one canonical mesh DNS host without a host resolver dependency."""
        self.assertIsNotNone(build_a_query, "the bounded mesh DNS query builder should be available")
        assert build_a_query is not None
        query = build_a_query("proof.internal", transaction_id=0x526)
        self.assertEqual(query[:12], bytes.fromhex("052601000001000000000000"))
        self.assertEqual(query[12:], b"\x05proof\x08internal\x00\x00\x01\x00\x01")

    def test_dns_parser_returns_only_valid_ipv4_answers(self):
        """Read a compressed A answer and reject response IDs that belong to other queries."""
        self.assertIsNotNone(parse_a_answers, "the bounded mesh DNS response parser should be available")
        assert parse_a_answers is not None
        transaction_id = 0x526
        question = b"\x05proof\x08internal\x00\x00\x01\x00\x01"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x01\x02\x03"
        response = bytes.fromhex("052681800001000100000000") + question + answer
        self.assertEqual(parse_a_answers(response, transaction_id=transaction_id), ("10.1.2.3",))
        with self.assertRaisesRegex(ValueError, "transaction"):
            parse_a_answers(response, transaction_id=transaction_id + 1)


class HandshakeCaptureTests(unittest.TestCase):
    """Count real outgoing GotaTun handshake packets during peer-scale stress."""

    def test_packet_parser_distinguishes_initiation_from_other_udp_payloads(self):
        """Recognize the four-byte WireGuard initiation type in one IPv4 UDP frame."""
        self.assertIsNotNone(
            is_wireguard_handshake_initiation,
            "the handshake capture packet parser should be available",
        )
        assert is_wireguard_handshake_initiation is not None

        def frame(message_type: int) -> bytes:
            """Build the untagged IPv4/UDP envelope the namespace veth emits."""
            payload = struct.pack("<I", message_type) + bytes(4)
            udp = struct.pack("!HHHH", 51820, 51820, 8 + len(payload), 0) + payload
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(udp),
                1,
                0,
                64,
                socket.IPPROTO_UDP,
                0,
                socket.inet_aton("10.220.0.1"),
                socket.inet_aton("10.220.0.2"),
            )
            return bytes(12) + b"\x08\x00" + ip + udp

        self.assertTrue(is_wireguard_handshake_initiation(frame(1)))
        self.assertFalse(is_wireguard_handshake_initiation(frame(4)))
        self.assertFalse(is_wireguard_handshake_initiation(frame(1)[:30]))


if __name__ == "__main__":
    unittest.main()
