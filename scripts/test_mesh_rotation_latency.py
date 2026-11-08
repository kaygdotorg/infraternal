"""Tests for the loss-aware ICMP summaries in the GotaTun rotation proof."""

import importlib.util
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

import mesh_rotation_latency
from mesh_rotation_latency import (
    cpu_mask_for_namespace,
    parse_ping_reply,
    summarize_latency,
)


class PingReplyTests(unittest.TestCase):
    """Check that raw ping output keeps the timestamp, sequence and RTT together."""

    def test_parses_timestamp_sequence_and_rtt(self):
        """Read one timestamped reply from iputils ping."""
        line = "[1762434000.123456] 64 bytes from 10.254.0.2: icmp_seq=7 ttl=64 time=0.125 ms"
        self.assertEqual(parse_ping_reply(line), (1762434000.123456, 7, 0.125))

    def test_ignores_ping_headers_and_summaries(self):
        """Ignore non-reply lines while retaining packet loss from the summary."""
        self.assertIsNone(parse_ping_reply("PING 10.254.0.2 (10.254.0.2): 56 data bytes"))
        self.assertIsNone(parse_ping_reply("3 packets transmitted, 2 received, 33% packet loss"))


class LossAwareLatencyTests(unittest.TestCase):
    """Apply the D348 nearest-rank and loss-aware p99 rule to one probe window."""

    def test_reports_nearest_rank_percentiles_when_every_probe_replies(self):
        """Return finite p50 and p99 when the full window has no lost probes."""
        replies = [(sequence, float(sequence) / 10) for sequence in range(1, 101)]

        report = summarize_latency(range(1, 101), replies)

        self.assertEqual(report["sent"], 100)
        self.assertEqual(report["received"], 100)
        self.assertEqual(report["lost"], 0)
        self.assertEqual(report["p50_ms"], 5.0)
        self.assertEqual(report["p99_loss_aware_ms"], 9.9)

    def test_one_percent_loss_keeps_the_nearest_rank_p99_finite(self):
        """Count a lost probe as infinity without moving p99 before its rank."""
        replies = [(sequence, float(sequence) / 10) for sequence in range(1, 100)]

        report = summarize_latency(range(1, 101), replies)

        self.assertEqual(report["sent"], 100)
        self.assertEqual(report["received"], 99)
        self.assertEqual(report["lost"], 1)
        self.assertEqual(report["loss_pct"], 1.0)
        self.assertEqual(report["p99_loss_aware_ms"], 9.9)
        self.assertEqual(report["p99_state"], "finite")

    def test_loss_above_one_percent_makes_the_nearest_rank_p99_infinite(self):
        """Mark p99 infinite when lost probes occupy its nearest-rank position."""
        replies = [(sequence, float(sequence) / 10) for sequence in range(1, 99)]

        report = summarize_latency(range(1, 101), replies)

        self.assertEqual(report["sent"], 100)
        self.assertEqual(report["received"], 98)
        self.assertEqual(report["lost"], 2)
        self.assertEqual(report["loss_pct"], 2.0)
        self.assertIsNone(report["p99_loss_aware_ms"])
        self.assertEqual(report["p99_state"], "infinite_due_to_loss")


class D348CpuPlacementTests(unittest.TestCase):
    """Keep endpoint namespaces on the D348 side that owns their workload."""

    def test_assigns_the_two_endpoints_to_disjoint_cpu_pairs(self):
        """Place the relay endpoints on their configured pairs and relay work on housekeeping."""
        self.assertEqual(cpu_mask_for_namespace("nodeA", "1-2", "3-4", "0,5"), "1-2")
        self.assertEqual(cpu_mask_for_namespace("nodeB", "1-2", "3-4", "0,5"), "3-4")
        self.assertEqual(cpu_mask_for_namespace("relay1", "1-2", "3-4", "0,5"), "0,5")

    def test_scope_names_select_only_the_two_measured_sides_for_the_audit(self):
        """Audit A/B workloads while keeping housekeeping namespaces outside test CPU checks."""
        self.assertTrue(
            hasattr(mesh_rotation_latency, "cpu_scope_unit_name"),
            "the D348 audit requires a j88i-prefixed scope name",
        )
        self.assertEqual(
            mesh_rotation_latency.cpu_scope_unit_name("nodeA", 123, 456),
            "j88i-j279-nodeA-123-456.scope",
        )
        self.assertEqual(
            mesh_rotation_latency.cpu_scope_unit_name("relay1", 123, 456),
            "j279-relay1-123-456.scope",
        )


class RelayStreamDescriptorTests(unittest.TestCase):
    """Protect descriptors owned by concurrent D348 latency probes."""

    def test_stream_cleanup_does_not_close_a_reused_probe_pipe(self):
        """Do not close a probe pipe when gate descriptors were already closed."""
        proof_path = Path(__file__).with_name("mesh-relay-proof.py")
        spec = importlib.util.spec_from_file_location("mesh_relay_proof", proof_path)
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)

        report = json.dumps({"bytes": 128, "sha256": "fixture", "seconds": 0.1})

        class CompletedProcess:
            """Supply one fixture's complete JSON result without launching a tunnel."""

            def __init__(self, output, stdout=None):
                """Keep the response text and optional readiness stream for one fake process."""
                self.output = output
                self.stdout = stdout

            def communicate(self, timeout=None):
                """Return the prepared output in the subprocess API's tuple shape."""
                return self.output, None

        def spawn(namespace, *args, **kwargs):
            """Return a receiver or sender fixture with the matching output stream."""
            stdout = io.StringIO("ready\n") if namespace == "nodeB" else None
            return CompletedProcess(report, stdout), 12345

        real_pipe = os.pipe
        allocated_pipes = []

        def record_pipe():
            """Remember each real pipe so the test can prove descriptor-number reuse."""
            descriptors = real_pipe()
            allocated_pipes.append(descriptors)
            return descriptors

        borrowed_pipe = []

        def during(_sender, _gate_read, _resume_write):
            """Allocate probe descriptors during the callback, after parent endpoints close."""
            borrowed_pipe.extend(proof.os.pipe())

        try:
            with (
                mock.patch.object(proof, "spawn_namespace_process", side_effect=spawn),
                mock.patch.object(proof.os, "pipe", side_effect=record_pipe),
            ):
                sender, receiver = proof.stream(
                    "nodeA", "nodeB", "127.0.0.1", 5205, 128,
                    during=during, gate_after=64,
                )

            self.assertEqual(sender["bytes"], 128)
            self.assertEqual(receiver["bytes"], 128)
            self.assertEqual(len(allocated_pipes), 3)
            self.assertEqual(borrowed_pipe[0], allocated_pipes[0][1])
            self.assertEqual(borrowed_pipe[1], allocated_pipes[1][0])
            os.fstat(borrowed_pipe[0])
            os.fstat(borrowed_pipe[1])
        finally:
            for descriptor in borrowed_pipe:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
