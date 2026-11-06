"""Tests for the loss-aware ICMP summaries in the GotaTun rotation proof."""

import unittest

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

    def test_any_lost_probe_makes_the_loss_aware_p99_infinite(self):
        """Never publish a finite p99 for a window with a missing reply."""
        replies = [(sequence, float(sequence) / 10) for sequence in range(1, 100)]

        report = summarize_latency(range(1, 101), replies)

        self.assertEqual(report["sent"], 100)
        self.assertEqual(report["received"], 99)
        self.assertEqual(report["lost"], 1)
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


if __name__ == "__main__":
    unittest.main()
