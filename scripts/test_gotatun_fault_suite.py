"""Keep the Linux GotaTun fault matrix and its measurements repeatable."""

from __future__ import annotations

import importlib
import json
import os
import inspect
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
    from gotatun_break_it.app_fixture import CoordinatorFixture, MeshNode, ServerProcessFixture
except ModuleNotFoundError as error:
    if error.name != "gotatun_break_it.app_fixture":
        raise
    CoordinatorFixture = None
    MeshNode = None
    ServerProcessFixture = None

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


class BreakItRunGuideTests(unittest.TestCase):
    """Keep documented Nix shell commands from losing their tools on launch."""

    def test_run_commands_preserve_nix_tools_in_child_shell(self):
        """Use a non-login shell so Nix package paths remain available to the matrix."""
        guide = Path(__file__).with_name("gotatun_break_it").joinpath("README.md")
        text = guide.read_text(encoding="utf-8")
        self.assertNotIn("--command bash -lc", text)
        self.assertEqual(text.count("--command bash -c"), 2)

    def test_linux_matrix_output_path_must_be_fresh(self):
        """Prevent wrappers from pre-creating a run directory the matrix owns."""
        guide = Path(__file__).with_name("gotatun_break_it").joinpath("README.md")
        text = guide.read_text(encoding="utf-8")
        self.assertIn("must not already exist", text)

    def test_linux_matrix_documents_the_d41_switch_recovery_budget(self):
        """Explain the 300 ms network-switch threshold beside the emitted report fields."""
        guide = Path(__file__).with_name("gotatun_break_it").joinpath("README.md")
        text = guide.read_text(encoding="utf-8")
        self.assertIn("D41's 300 ms reconnect budget", text)


    def test_linux_matrix_selects_gotatun_by_the_variable_the_agent_reads(self):
        """Choose the engine with the exact variable name the agent reads, not a misspelling."""
        matrix = Path(__file__).with_name("gotatun_break_it").joinpath("linux_matrix.py")
        text = matrix.read_text(encoding="utf-8")
        self.assertIn('{"INFRATERNAL_MESH_ENGINE": "gotatun"}', text)
        self.assertNotIn("INFRATERAL_MESH_ENGINE", text)

class LinuxFaultPlanTests(unittest.TestCase):
    """Keep each requested network failure in the runnable case matrix."""

    def test_agent_runtime_state_root_fits_a_private_unix_socket_path(self):
        """Keep product socket state short while evidence paths grow independently."""
        app_fixture = importlib.import_module("gotatun_break_it.app_fixture")
        create_runtime_root = getattr(app_fixture, "new_private_agent_runtime_root", None)
        self.assertIsNotNone(create_runtime_root, "short private agent state root is missing")
        assert create_runtime_root is not None
        runtime_root = create_runtime_root()
        try:
            self.assertEqual(runtime_root.parent, Path.home())
            self.assertEqual(runtime_root.stat().st_mode & 0o777, 0o700)
            socket_path = runtime_root / "a-12345678" / "mesh" / "control.sock"
            self.assertLess(len(str(socket_path).encode("utf-8")), 108)
        finally:
            runtime_root.rmdir()

    def test_fault_injection_waits_for_sustained_verified_payload(self):
        """Do not call a one-block seed a loaded flow ready for fault injection."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        warmed_up = getattr(matrix, "_traffic_warmed_up", None)
        self.assertTrue(callable(warmed_up), "the fault runner needs a sustained-flow gate")
        assert callable(warmed_up)
        self.assertFalse(warmed_up(65_536, 65_536))
        self.assertFalse(warmed_up(1_048_576, 65_536))
        self.assertTrue(warmed_up(1_048_576, 1_048_576))

    def test_traffic_startup_failure_closes_any_started_children(self):
        """Release the probe and payload processes when warmup cannot finish."""
        traffic_type = importlib.import_module("gotatun_break_it.linux_matrix").Traffic
        with (
            patch.object(traffic_type, "_start_servers"),
            patch.object(traffic_type, "_start_clients", side_effect=RuntimeError("warmup")),
            patch.object(traffic_type, "close") as close,
        ):
            with self.assertRaisesRegex(RuntimeError, "warmup"):
                traffic_type(SimpleNamespace(), Path("/tmp"), duration_seconds=1)
        close.assert_called_once()

    def test_failed_warmup_keeps_progress_when_traffic_constructor_did_not_return(self):
        """Report bytes written before a failed Traffic constructor returned."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        snapshot = getattr(matrix, "_partial_traffic_progress", None)
        self.assertTrue(callable(snapshot), "partial warmup progress must remain reportable")
        assert callable(snapshot)
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            (output / "sender-progress.json").write_text('{"bytes":65536}\n', encoding="utf-8")
            (output / "receiver-progress.json").write_text('{"bytes":32768}\n', encoding="utf-8")
            sent, verified, probes = snapshot(output, None)
        self.assertEqual((sent, verified), (65_536, 32_768))
        self.assertEqual(probes, [])

    def test_linux_matrix_script_help_works_without_package_context(self):
        """Keep the documented direct script invocation's package imports valid."""
        script = Path(__file__).resolve().parent / "gotatun_break_it" / "linux_matrix.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux GotaTun failure matrix", result.stdout)

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
                "coordinator-restart",
                "server-restart",
                "coordinator-peer-churn",
                "mtu-change-mid-flow",
                "peer-scale-50",
                "peer-scale-200",
            },
        )

    def test_server_restart_targets_the_product_process_not_the_coordinator_fixture(self):
        """Restart the real server while keeping coordinator restart a separate fault."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        case = next(case for case in build_fault_matrix() if case.name == "server-restart")

        class Coordinator:
            """Fail the regression if the server fault restarts only its fixture."""

            restart_count = 0

            def restart(self):
                """Count coordinator restarts without changing its fake process."""
                self.restart_count += 1

        class Server:
            """Return distinct process IDs as a product server restart would."""

            pid = 101
            state_root = Path("/private/server-data")

            def restart(self):
                """Advance the fake server process while preserving its state directory."""
                previous = self.pid
                self.pid += 1
                return {
                    "server_pid_before": previous,
                    "server_pid_after": self.pid,
                    "server_health_status": 200,
                    "server_data_directory_preserved": True,
                }

        coordinator = Coordinator()
        server = Server()
        pair = SimpleNamespace(
            coordinator=coordinator,
            server=server,
            left=object(),
            right=object(),
        )
        with patch.object(matrix, "_tool", return_value="/nix/bin/ip"):
            event = matrix._apply_fault(case, pair)

        self.assertEqual(coordinator.restart_count, 0)
        self.assertEqual(server.pid, 102)
        self.assertEqual(event["server_pid_before"], 101)
        self.assertEqual(event["server_pid_after"], 102)
        self.assertEqual(event["server_health_status"], 200)
        self.assertTrue(event["server_data_directory_preserved"])
        self.assertEqual(event["server_data_directory"], str(server.state_root))

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

    def test_network_switch_cases_enforce_the_d41_reconnect_budget(self):
        """Apply D41's 300 ms reconnect budget to underlay changes and link restore."""
        cases = {case.name: case for case in build_fault_matrix()}
        for name in ("endpoint-ip-rebind", "nat-port-rebind", "link-down-up"):
            self.assertEqual(cases[name].recovery_budget_ms, 300)

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
            ),
            [
                "/usr/sbin/tc",
                "qdisc",
                "replace",
                "dev",
                "underlay1",
                "root",
                "netem",
                "delay",
                "10ms",
                "reorder",
                "25%",
                "50%",
                "seed",
                "526",
            ],
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

    def test_snapshot_applies_all_chunks_before_requiring_a_committed_version(self):
        """Accept staged config chunks and require success only from the final chunk."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        pair_type = matrix.NamespacePair

        class ChunkedNode:
            """Return the production configure response shape for a staged snapshot."""

            label = "fixture"

            def __init__(self):
                self.seen = []

            def configure(self, chunk):
                self.seen.append(chunk["index"])
                return {
                    "applied": chunk["last"],
                    "version": 8 if chunk["last"] else None,
                    "apply_us": 12,
                }

        pair = object.__new__(pair_type)
        pair.left = ChunkedNode()
        pair.right = ChunkedNode()
        chunks = [
            [
                {"index": 0, "version": 8, "last": False},
                {"index": 1, "version": 8, "last": True},
            ],
            [
                {"index": 0, "version": 8, "last": False},
                {"index": 1, "version": 8, "last": True},
            ],
        ]

        applied = pair._apply_snapshot({"chunks": chunks})

        self.assertEqual(pair.left.seen, [0, 1])
        self.assertEqual(pair.right.seen, [0, 1])
        self.assertEqual(applied, [12, 12, 12, 12])

    def test_peer_counter_summary_keeps_only_route_and_handshake_metrics(self):
        """Summarize simulated peers without retaining their public keys."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        summarize = getattr(matrix, "_peer_transfer_summary", None)
        self.assertTrue(callable(summarize), "peer-scale evidence needs bounded counter summaries")
        assert callable(summarize)
        summary = summarize(
            [
                {
                    "node": 2,
                    "peer": {
                        "key": [1] * 32,
                        "addresses": {"ipv4": "10.254.0.2"},
                        "endpoint": "10.220.0.2:51820",
                    },
                    "counters": {"sent_bytes": 64, "handshake_secs": 9},
                },
                {
                    "node": 3,
                    "peer": {
                        "key": [2] * 32,
                        "addresses": {"ipv4": "10.254.0.3"},
                        "endpoint": None,
                    },
                    "counters": {"sent_bytes": 0, "handshake_secs": 0},
                },
                {
                    "node": 4,
                    "peer": {
                        "key": [3] * 32,
                        "addresses": {"ipv4": "10.254.0.4"},
                        "endpoint": "10.220.0.2:51820",
                    },
                    "counters": {"sent_bytes": 148, "handshake_secs": 0},
                },
            ]
        )
        self.assertEqual(summary["peer_count"], 3)
        self.assertEqual(summary["unique_ipv4_count"], 3)
        self.assertEqual(summary["peer_count_with_endpoint"], 2)
        self.assertEqual(summary["peer_count_with_sent_bytes"], 2)
        self.assertEqual(summary["peer_count_with_handshake"], 1)
        self.assertEqual(summary["peer_count_with_unconfirmed_handshake"], 1)
        self.assertEqual(summary["endpoint_ports"], [51820])
        self.assertNotIn("key", summary["sample"][0])

    def test_scale_handshake_count_uses_config_time_peer_counters(self):
        """Count attempted handshakes from counters collected before the traffic phase."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        summarize = getattr(matrix, "_peer_scale_handshake_summary", None)
        self.assertTrue(callable(summarize), "scale reports need config-time handshake evidence")
        assert callable(summarize)
        rows = [
            {"counters": {"sent_bytes": 148, "handshake_secs": 0}},
            {"counters": {"sent_bytes": 148, "handshake_secs": 0}},
            {"counters": {"sent_bytes": 2048, "handshake_secs": 12}},
        ]

        result = summarize(rows, expected_peer_count=2)

        self.assertEqual(result["handshake_attempt_peer_count_after_config"], 2)
        self.assertEqual(result["handshake_storm_source"], "initial_config_commit")
        self.assertTrue(result["handshake_storm_complete"])


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

    def test_endpoint_recovery_uses_switch_time_and_enforces_d41_budget(self):
        """Fail a slow rebind even when probes recover after the injected mapping clears."""
        self.assertIn("recovery_started_ns", inspect.signature(report_case).parameters)
        report = report_case(
            case="nat-port-rebind",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=4_000_000_000,
            recovery_started_ns=1_000_000_000,
            recovery_budget_ms=300,
            probes=[
                Probe(1, 1_050_000_000, None),
                Probe(2, 1_150_000_000, None),
                Probe(3, 2_000_000_000, 12.0),
                Probe(4, 4_100_000_000, 5.0),
            ],
            bytes_sent=65_536,
            bytes_verified=65_536,
            bytes_stalled=65_536,
            integrity_ok=True,
        )

        self.assertEqual(report["recovery_ms_from_reference"], 1_012.0)
        self.assertFalse(report["recovery_budget_met"])
        self.assertEqual(report["recovered_probe_sequence"], 3)
        self.assertEqual(report["outcome"], "FAIL")

    def test_probe_relapse_after_recovery_fails_the_case(self):
        """Fail a tunnel that recovers once and then dies, as #517's NAT row did."""
        # Two answered probes right after the switch, then every probe lost to the end.
        probes = [Probe(1, 1_050_000_000, 0.9), Probe(2, 1_100_000_000, 0.8)]
        probes += [
            Probe(3 + index, 1_150_000_000 + index * 50_000_000, None) for index in range(60)
        ]
        report = report_case(
            case="nat-port-rebind",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=4_000_000_000,
            recovery_started_ns=1_000_000_000,
            recovery_budget_ms=300,
            probes=probes,
            bytes_sent=65_536,
            bytes_verified=65_536,
            integrity_ok=True,
        )

        self.assertTrue(report["recovery_budget_met"])
        self.assertEqual(report["recovery_probe_loss_count"], 0)
        self.assertEqual(report["post_recovery_probe_loss_count"], 60)
        self.assertEqual(report["post_recovery_longest_outage_ms"], 2_950.0)
        self.assertEqual(report["outcome"], "FAIL")

    def test_single_lost_probe_after_recovery_is_not_a_relapse(self):
        """Keep one dropped probe under load from failing an otherwise healthy row."""
        probes = [
            Probe(1, 1_050_000_000, 0.9),
            Probe(2, 1_100_000_000, None),
            Probe(3, 1_150_000_000, 0.7),
            Probe(4, 1_200_000_000, None),
        ]
        report = report_case(
            case="loss-1pct",
            platform="linux",
            fault_started_ns=1_000_000_000,
            fault_cleared_ns=1_000_000_000,
            probes=probes,
            bytes_sent=4096,
            bytes_verified=4096,
            integrity_ok=True,
        )

        self.assertEqual(report["post_recovery_probe_loss_count"], 2)
        self.assertEqual(report["post_recovery_longest_outage_ms"], 50.0)
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

    def test_unrecovered_failure_keeps_observed_probe_window_without_claiming_clear(self):
        """Keep the rekey probe window when config application fails before completion."""
        self.assertIsNotNone(failed_case_report, "the failure report helper should be available")
        assert failed_case_report is not None
        report = failed_case_report(
            case="rekey-under-load",
            platform="linux",
            fault_started_ns=100,
            fault_cleared_ns=None,
            observed_through_ns=1_000_000_100,
            probes=[Probe(1, 100, 3.0), Probe(2, 1_000_000_100, 5.0)],
            bytes_sent=4096,
            bytes_verified=4096,
            bytes_stalled=0,
            error="RuntimeError: mesh.configure refused the retiring key",
        )
        self.assertIsNone(report["fault_duration_ms"])
        self.assertIsNone(report["recovery_ms_from_fault_start"])
        self.assertIsNone(report["recovery_ms_after_fault_cleared"])
        self.assertEqual(report["p99_recovery_ms"], 5.0)
        self.assertEqual(report["recovery_probe_count"], 2)


class NatPortRebindFaultTests(unittest.TestCase):
    """Keep the changed NAT mapping active after its temporary rule is removed."""

    def test_nat_rebind_removes_rule_without_flushing_the_active_mapping(self):
        """Preserve conntrack's changed source port while traffic continues after recovery."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        events = []
        clock_value = 0

        def record_run(command):
            """Remember one namespace command without changing the test host."""
            events.append(("run", tuple(command)))
            return ""

        def record_wait(seconds):
            """Record the bounded time that the changed NAT mapping stays active."""
            events.append(("wait", seconds))

        def monotonic_ns():
            """Give the fault interval ordered timestamps and record their position."""
            nonlocal clock_value
            clock_value += 100
            events.append(("clock", clock_value))
            return clock_value

        pair = SimpleNamespace(
            coordinator=object(),
            left=SimpleNamespace(identity={"port": 51820}),
            right=SimpleNamespace(identity={"port": 51821}),
            peer_pid=4321,
        )
        case = matrix.FaultCase("nat-port-rebind", "nat-port")
        with (
            patch.object(matrix, "_tool", side_effect=lambda name: f"/nix/bin/{name}"),
            patch.object(matrix, "_run", side_effect=record_run),
            patch.object(matrix, "_wait_for_duration", side_effect=record_wait),
            patch.object(matrix.time, "monotonic_ns", side_effect=monotonic_ns),
        ):
            event = matrix._apply_fault(case, pair)

        self.assertIn(("wait", 3), events)
        delete_index = next(
            index
            for index, (kind, command) in enumerate(events)
            if kind == "run"
            and command[-5].rsplit("/", 1)[-1] == "nft"
            and command[-4:] == ("delete", "table", "ip", "j526")
        )
        conntrack_commands = [
            command
            for kind, command in events
            if kind == "run"
            and any(part.rsplit("/", 1)[-1] == "conntrack" for part in command)
        ]
        # Only the underlay UDP mapping goes; a full flush would also wipe the inner TCP
        # flow's state, which the product firewall then drops as a non-SYN new flow.
        self.assertTrue(all("-F" not in command for command in conntrack_commands))
        flush_indices = [
            index
            for index, (kind, command) in enumerate(events)
            if kind == "run"
            and "conntrack" in " ".join(command)
            and command[-9:]
            == (
                "-D",
                "-p",
                "udp",
                "--orig-src",
                "10.220.0.2",
                "--orig-dst",
                "10.220.0.1",
                "--orig-port-src",
                "51821",
            )
        ]
        self.assertEqual(len(flush_indices), 1)
        recovery_clock_index = next(
            index
            for index, (kind, _) in enumerate(events)
            if kind == "clock" and index > flush_indices[0]
        )
        clear_clock_index = max(
            index for index, (kind, _) in enumerate(events) if kind == "clock"
        )
        wait_index = next(index for index, (kind, _) in enumerate(events) if kind == "wait")
        self.assertLess(flush_indices[0], recovery_clock_index)
        self.assertLess(recovery_clock_index, wait_index)
        self.assertLess(wait_index, delete_index)
        self.assertLess(delete_index, clear_clock_index)
        self.assertEqual(event["recovery_started_ns"], events[recovery_clock_index][1])
        self.assertEqual(event["fault_cleared_ns"], events[clear_clock_index][1])


class PathSwitchRecoveryStartTests(unittest.TestCase):
    """Start D41 recovery measurement when a new address or link becomes usable."""

    def test_endpoint_ip_rebind_starts_recovery_after_the_new_address_is_added(self):
        """Measure from the active new underlay address, not the next probe window."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        commands = []
        timestamps = iter((100, 200, 300))
        pair = SimpleNamespace(coordinator=object(), left=object(), right=object(), peer_pid=4321)
        with (
            patch.object(matrix, "_tool", side_effect=lambda name: f"/nix/bin/{name}"),
            patch.object(matrix, "_run", side_effect=lambda command: commands.append(tuple(command)) or ""),
            patch.object(matrix, "_in_namespace", side_effect=lambda pid, *command: ["nsenter", str(pid), *command]),
            patch.object(matrix.time, "monotonic_ns", side_effect=lambda: next(timestamps)),
        ):
            event = matrix._apply_fault(matrix.FaultCase("endpoint-ip-rebind", "endpoint-ip"), pair)

        self.assertEqual(event["recovery_started_ns"], 200)
        self.assertEqual(event["fault_cleared_ns"], 300)
        self.assertIn(("nsenter", "4321", "/nix/bin/ip", "addr", "add", "10.220.0.3/24", "dev", "underlay1"), commands)

    def test_link_recovery_starts_after_the_underlay_is_up(self):
        """Apply the 300 ms reconnect budget after the deliberate link outage ends."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        commands = []
        timestamps = iter((100, 200, 300))
        pair = SimpleNamespace(coordinator=object(), left=object(), right=object(), peer_pid=4321)
        with (
            patch.object(matrix, "_tool", side_effect=lambda name: f"/nix/bin/{name}"),
            patch.object(matrix, "_run", side_effect=lambda command: commands.append(tuple(command)) or ""),
            patch.object(matrix, "_in_namespace", side_effect=lambda pid, *command: ["nsenter", str(pid), *command]),
            patch.object(matrix, "_wait_for_duration"),
            patch.object(matrix.time, "monotonic_ns", side_effect=lambda: next(timestamps)),
        ):
            event = matrix._apply_fault(matrix.FaultCase("link-down-up", "link-down-up"), pair)

        self.assertEqual(event["recovery_started_ns"], 200)
        self.assertLess(
            commands.index(("/nix/bin/ip", "link", "set", "underlay0", "up")),
            2,
        )
        self.assertEqual(event["fault_cleared_ns"], 300)

    def test_tcp_transfer_integrity_requires_matching_lengths_and_hashes(self):
        """Pass only when the receiver verified the sender's full byte stream."""
        self.assertIsNotNone(transfer_integrity_ok, "the TCP progress helper should be available")
        assert transfer_integrity_ok is not None
        sender = {"bytes": 4096, "sha256": "abc123"}
        self.assertTrue(transfer_integrity_ok(sender, {"bytes": 4096, "sha256": "abc123"}))
        self.assertFalse(transfer_integrity_ok(sender, {"bytes": 2048, "sha256": "abc123"}))
        self.assertFalse(transfer_integrity_ok(sender, {"bytes": 4096, "sha256": "different"}))

    def test_nonblocking_tcp_sender_uses_the_write_ready_socket_set(self):
        """Send another block after select reports the TCP socket writable."""
        tcp_progress = importlib.import_module("gotatun_break_it.tcp_progress")

        class FakeConnection:
            """Count deterministic payload accepted by the sender's socket calls."""

            def __init__(self):
                """Start with an empty stream."""
                self.bytes_sent = 0

            def __enter__(self):
                """Return this connection for the sender's context manager."""
                return self

            def __exit__(self, *_):
                """Allow the sender's context manager to finish normally."""
                return False

            def sendall(self, payload):
                """Record the seed block accepted before the nonblocking loop."""
                self.bytes_sent += len(payload)

            def setblocking(self, _blocking):
                """Accept the sender's nonblocking-mode request."""
                return None

            def send(self, payload):
                """Record one writable-socket payload and return its full length."""
                self.bytes_sent += len(payload)
                return len(payload)

            def shutdown(self, _how):
                """Accept the sender's half-close after the deterministic loop."""
                return None

        connection = FakeConnection()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with (
                patch.object(tcp_progress.socket, "create_connection", return_value=connection),
                patch.object(
                    tcp_progress.select,
                    "select",
                    side_effect=[([], [], []), ([], [connection], [])],
                ),
                patch.object(
                    tcp_progress.time,
                    "monotonic_ns",
                    side_effect=[0, 0, 0, 0, 6_553_601, 2_000_000_000, 2_000_000_001],
                ),
            ):
                tcp_progress.send(
                    "127.0.0.1",
                    5201,
                    1,
                    80,
                    root / "sender-progress.json",
                    root / "sender-result.json",
                )
        self.assertEqual(connection.bytes_sent, 2 * 65_536)

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


class ServerProcessFixtureTests(unittest.TestCase):
    """Keep real server startup failures diagnosable without capturing stdout secrets."""

    def test_failed_server_start_records_stderr_outside_the_removed_data_directory(self):
        """Preserve bounded server stderr when startup exits before the health probe."""
        if os.environ.get("J526_NAMESPACE_TEST") != "1":
            self.skipTest("run inside the suite's private user and mount namespace")
        self.assertIsNotNone(ServerProcessFixture, "the product server fixture should be available")
        assert ServerProcessFixture is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "server"
            executable.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'fixture startup failed' >&2\nexit 17\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            state_root = root / "server-data"
            stderr_path = root / "server.stderr.log"

            with self.assertRaisesRegex(RuntimeError, "fixture startup failed") as failure:
                ServerProcessFixture(executable, state_root)

            self.assertIn(str(stderr_path), str(failure.exception))
            self.assertEqual(stderr_path.read_text(encoding="utf-8"), "fixture startup failed\n")
            self.assertFalse(state_root.exists())

    def test_product_server_fixture_uses_a_separate_network_namespace(self):
        """Keep the fixture server's embedded Mesh link away from both transfer peers."""
        if os.environ.get("J526_NAMESPACE_TEST") != "1":
            self.skipTest("run inside the suite's private user and mount namespace")
        self.assertIsNotNone(ServerProcessFixture, "the product server fixture should be available")
        assert ServerProcessFixture is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "server"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, socket, sys\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "args = sys.argv\n"
                "data = pathlib.Path(args[args.index('--data') + 1])\n"
                "socket_path = data / 'setup-token.sock'\n"
                "try: socket_path.unlink()\n"
                "except FileNotFoundError: pass\n"
                "control = socket.socket(socket.AF_UNIX)\n"
                "control.bind(str(socket_path))\n"
                "class Handler(BaseHTTPRequestHandler):\n"
                " def do_GET(self):\n"
                "  self.send_response(200 if self.path == '/healthz' else 404)\n"
                "  self.end_headers()\n"
                " def log_message(self, format, *args): pass\n"
                "host, port = args[args.index('--listen') + 1].rsplit(':', 1)\n"
                "HTTPServer((host, int(port)), Handler).serve_forever()\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            fixture = ServerProcessFixture(
                executable,
                root / "server-data",
                stderr_path=evidence / "server.stderr.log",
            )
            try:
                current_namespace = os.readlink("/proc/self/ns/net")
                server_namespace = os.readlink(f"/proc/{fixture.pid}/ns/net")
                self.assertNotEqual(server_namespace, current_namespace)
                self.assertLess(len(str(fixture.state_root / "setup-token.sock")), 108)
                restart = fixture.restart()
                self.assertNotEqual(restart["server_pid_before"], restart["server_pid_after"])
                self.assertEqual(restart["server_health_status"], 200)
                self.assertTrue(restart["server_data_directory_preserved"])
            finally:
                fixture.close()


class CoordinatorFixtureTests(unittest.TestCase):
    """Keep control requests available after the one-time identity enrollment."""

    def test_coordinator_snapshot_exposes_names_that_a_mesh_dns_node_can_answer(self):
        """Give the live DNS check named members instead of hidden placeholders."""
        executable = os.environ.get("J526_COORDINATOR_FIXTURE")
        if not executable:
            self.skipTest("set J526_COORDINATOR_FIXTURE to the built production-schema fixture")
        self.assertIsNotNone(CoordinatorFixture, "the production coordinator fixture should be available")
        assert CoordinatorFixture is not None
        identities = [
            {
                "public_key": list(range(32)),
                "port": 51820,
                "compact_access": True,
                "dns_names": True,
                "key_rotation": True,
                "authority_epoch": True,
            },
            {
                "public_key": list(range(32, 64)),
                "port": 51821,
                "compact_access": True,
                "dns_names": True,
                "key_rotation": True,
                "authority_epoch": True,
            },
        ]
        coordinator = CoordinatorFixture(Path(executable))
        try:
            snapshot = coordinator.configuration("allow", identities)
        finally:
            coordinator.close()

        self.assertEqual(snapshot["chunks"][0][0].get("name"), "server")
        self.assertEqual(snapshot["chunks"][1][0].get("name"), "proof")
        self.assertEqual(set(snapshot["chunks"][0][0].get("peer_names", {}).values()), {"proof"})

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

    def test_authority_epoch_change_keeps_a_full_snapshot_after_restart(self):
        """Do not turn a new authority's required full snapshot into a delta."""
        self.assertIsNotNone(CoordinatorFixture, "the production coordinator fixture should be available")
        assert CoordinatorFixture is not None
        with tempfile.TemporaryDirectory(prefix="j526-coordinator-epoch-") as directory:
            root = Path(directory)
            executable = root / "fixture"
            snapshot = {
                "chunks": [
                    [
                        {
                            "index": 0,
                            "last": True,
                            "version": 1,
                            "from_version": None,
                            "authority_epoch": "new-authority",
                        }
                    ],
                    [
                        {
                            "index": 0,
                            "last": True,
                            "version": 1,
                            "from_version": None,
                            "authority_epoch": "new-authority",
                        }
                    ],
                ]
            }
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                f"snapshot = {json.dumps(snapshot)!r}\n"
                "for line in sys.stdin:\n"
                " print(snapshot, flush=True)\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            coordinator = CoordinatorFixture(executable)
            coordinator.current_version = 3
            coordinator.current_authority_epoch = "old-authority"
            try:
                result = coordinator.request("allow")
            finally:
                coordinator.close()

        self.assertIsNone(result["chunks"][0][0]["from_version"])
        self.assertEqual(result["chunks"][0][0]["version"], 1)
        self.assertEqual(coordinator.current_authority_epoch, "new-authority")


class MeshNodeFixtureCleanupTests(unittest.TestCase):
    """Keep normal test cleanup from leaving a persisted tunnel behind."""

    def test_close_turns_mesh_off_before_stopping_the_agent(self):
        """Disable the mesh and verify its state before terminating a live agent."""
        self.assertIsNotNone(MeshNode, "the infraternal agent fixture should be available")
        assert MeshNode is not None
        with tempfile.TemporaryDirectory(prefix="j526-mesh-close-") as directory:
            state = Path(directory) / "agent-state"
            state.mkdir()
            node = object.__new__(MeshNode)
            node.state = state
            node.process = SimpleNamespace(poll=lambda: None)
            node.channel = object()
            node.log = None
            events = []

            def call(action, _value):
                """Record fixture shutdown actions and report an off mesh state."""
                events.append(action)
                return {"state": "Off"} if action == "mesh.status" else {}

            def stop_process():
                """Mark where normal cleanup stops the fixture process."""
                events.append("stop-process")

            node.call = call
            node._stop_process = stop_process
            node.close()

        self.assertEqual(events, ["mesh.down", "mesh.status", "stop-process"])
        self.assertFalse(state.exists())


class MeshNodeControlChannelTests(unittest.TestCase):
    """Keep the fixture's control errors useful when a real agent refuses a call."""

    def test_rejected_action_includes_the_agent_reason(self):
        """Preserve the product's refusal text so a failed config stage is diagnosable."""
        self.assertIsNotNone(MeshNode, "the infraternal agent fixture should be available")
        assert MeshNode is not None
        app_fixture = importlib.import_module("gotatun_break_it.app_fixture")
        encode_varint = app_fixture._encode_varint
        client, server = socket.socketpair()
        try:
            refusal = b'{"error":"Plugin action refused."}'
            body = bytes([0x31]) + struct.pack("<I", 1) + bytes([0]) + refusal
            server.sendall(encode_varint(0) + encode_varint(len(body)) + body)
            node = object.__new__(MeshNode)
            node.channel = client
            node._call_id = 0

            with self.assertRaisesRegex(RuntimeError, "Plugin action refused"):
                node.call("mesh.configure", {"version": 7})
        finally:
            client.close()
            server.close()

    def test_snapshot_refusal_records_node_stage_and_safe_status(self):
        """Report which node and chunk failed, while keeping status key material out."""
        matrix = importlib.import_module("gotatun_break_it.linux_matrix")
        pair = object.__new__(matrix.NamespacePair)

        class FixtureNode:
            """Return one healthy status and refuse one config chunk."""

            def __init__(self, label):
                """Keep the fixture node name used in config failure evidence."""
                self.label = label
                self.log_path = Path(f"/private/{label}.stderr.log")

            def configure(self, _chunk):
                """Refuse the right node config and accept the left node config."""
                if self.label == "right":
                    raise RuntimeError("Plugin action refused.")
                return {"applied": True, "version": 8, "apply_us": 2}

            def call(self, action, _value):
                """Expose safe status and identity fields plus a sentinel secret field."""
                if action == "mesh.identity":
                    return {"public_key": [1, 2, 3]}
                if action == "mesh.status":
                    return {
                        "state": "On",
                        "version": 7,
                        "peer_count": 2,
                        "local_private_key": "must-not-appear",
                    }
                raise AssertionError(f"unexpected action: {action}")

        pair.left = FixtureNode("left")
        pair.right = FixtureNode("right")
        chunk = {
            "version": 8,
            "from_version": 7,
            "local_key": [1, 2, 3],
            "index": 0,
            "last": True,
        }

        with self.assertRaises(RuntimeError) as raised:
            pair._apply_snapshot(
                {"chunks": [[chunk], [chunk]]},
                stage="rekey overlap",
            )

        message = str(raised.exception)
        self.assertIn("stage=rekey overlap", message)
        self.assertIn("node=right", message)
        self.assertIn("chunk=0", message)
        self.assertIn("from_version=7", message)
        self.assertIn("version=8", message)
        self.assertIn("local_key_matches_identity=True", message)
        self.assertIn("agent_stderr_log=/private/right.stderr.log", message)
        self.assertIn("Plugin action refused", message)
        self.assertIn("'state': 'On'", message)
        self.assertIn("'version': 7", message)
        self.assertNotIn("must-not-appear", message)


class MeshDnsProbeTests(unittest.TestCase):
    """Keep the direct DNS check inside the same routed data-plane fixture."""

    def test_peer_dns_probe_uses_the_coordinator_assigned_mesh_name(self):
        """Read the actual peer DNS label instead of assuming the enrollment label wins."""
        import gotatun_break_it.linux_matrix as linux_matrix

        node_dns_name = getattr(linux_matrix, "_node_dns_name", None)
        self.assertIsNotNone(node_dns_name, "the coordinator name reader should be available")
        assert node_dns_name is not None
        snapshot = {"chunks": [[{"name": "server"}], [{"name": "host-proof"}]]}
        name = node_dns_name(snapshot, 1)
        with patch.object(linux_matrix, "query_a", return_value=("10.254.0.2",)) as query:
            linux_matrix._verify_peer_dns("10.254.0.1", "10.254.0.2", name)

        query.assert_called_once_with("10.254.0.1", "host-proof.internal")

    def test_peer_name_probe_uses_the_local_node_dns_view(self):
        """Resolve the remote node through this node's own filtered DNS listener."""
        import gotatun_break_it.linux_matrix as linux_matrix

        verify_peer_dns = getattr(linux_matrix, "_verify_peer_dns", None)
        self.assertIsNotNone(verify_peer_dns, "the local-view DNS check should be available")
        assert verify_peer_dns is not None
        with patch.object(linux_matrix, "query_a", return_value=("10.254.0.2",)) as query:
            result = verify_peer_dns("10.254.0.1", "10.254.0.2", "proof")

        query.assert_called_once_with("10.254.0.1", "proof.internal")
        self.assertEqual(
            result,
            {
                "resolver": "10.254.0.1",
                "query": "proof.internal",
                "answers": ["10.254.0.2"],
                "expected_answer": "10.254.0.2",
            },
        )

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

    def test_capture_drains_packets_while_peer_triggers_are_sent(self):
        """Keep a bounded packet socket from dropping a simultaneous handshake burst."""
        packet_trace = importlib.import_module("gotatun_break_it.packet_trace")

        def frame(destination_port: int) -> bytes:
            """Build one outgoing handshake with the requested endpoint port."""
            payload = struct.pack("<I", 1) + bytes(144)
            udp = struct.pack("!HHHH", 51820, destination_port, 8 + len(payload), 0) + payload
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

        class BoundedPacketSocket:
            """Drop a new frame if capture does not drain the one-frame receive queue."""

            def __init__(self):
                """Start with one empty packet slot."""
                self.pending = []
                self.dropped = 0

            def bind(self, _address):
                """Accept the disposable interface binding."""
                return None

            def setsockopt(self, *_values):
                """Accept the production receive-buffer request."""
                return None

            def settimeout(self, _seconds):
                """Accept the production packet polling interval."""
                return None

            def recvfrom(self, _size):
                """Return one queued packet or an immediate timeout when empty."""
                if not self.pending:
                    raise TimeoutError
                return self.pending.pop(0), (
                    "underlay0",
                    0,
                    getattr(socket, "PACKET_OUTGOING", 4),
                    0,
                    b"",
                )

            def close(self):
                """Close the disposable capture socket."""
                return None

        class TriggerSocket:
            """Enqueue one outgoing handshake frame for each simulated peer."""

            def __init__(self, capture):
                """Keep the bounded packet capture that receives emitted handshakes."""
                self.capture = capture

            def sendto(self, _payload, _address):
                """Emit a frame unless the capture side has left its single slot full."""
                if self.capture.pending:
                    self.capture.dropped += 1
                else:
                    self.capture.pending.append(frame(51820))

            def close(self):
                """Close the disposable trigger socket."""
                return None

        capture = BoundedPacketSocket()
        trigger = TriggerSocket(capture)
        with patch.object(packet_trace.socket, "socket", side_effect=[capture, trigger]):
            result = packet_trace.trigger_handshake_storm(
                "underlay0",
                ["10.254.0.3", "10.254.0.4"],
                endpoint_port=51820,
                duration_seconds=0.01,
            )

        self.assertEqual(capture.dropped, 0)
        self.assertEqual(result["handshake_initiation_count"], 2)


if __name__ == "__main__":
    unittest.main()
