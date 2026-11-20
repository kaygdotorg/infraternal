#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that raw ping percentiles count missing replies as infinite RTT."""

from __future__ import annotations

import importlib.util
import math
import tempfile
import unittest
from pathlib import Path


class PingStatsTest(unittest.TestCase):
    """Protect the loss-aware percentile rule used by the R4b keep table."""

    def test_loss_above_one_percent_makes_p99_infinite(self) -> None:
        """A loss rate above one percent pushes the p99 rank to infinity."""
        script = Path(__file__).parent / "lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 98)
            )
            sample.write_text(replies + "100 packets transmitted, 97 received\n")

            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (100, 3))
        self.assertAlmostEqual(summary["p50_received_ms"], 0.049)
        self.assertAlmostEqual(summary["p99_received_ms"], 0.097)
        self.assertTrue(math.isinf(summary["p99_loss_aware_ms"]))
        self.assertTrue(math.isinf(summary["p999_loss_aware_ms"]))
        self.assertAlmostEqual(summary["max_received_ms"], 0.097)

    def test_loss_below_one_percent_keeps_exact_p99_finite(self) -> None:
        """The p99 rank includes drops at infinity, while a sub-one-percent loss stays finite."""
        script = Path(__file__).parent / "lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat_low_loss", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-low-loss-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 996)
            )
            sample.write_text(replies + "1000 packets transmitted, 995 received\n")

            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (1000, 5))
        self.assertAlmostEqual(summary["p99_received_ms"], 0.986)
        self.assertAlmostEqual(summary["p99_loss_aware_ms"], 0.990)
        self.assertTrue(math.isinf(summary["p999_loss_aware_ms"]))
        self.assertAlmostEqual(summary["max_received_ms"], 0.995)

    def test_no_loss_keeps_p99_equal_to_received_p99(self) -> None:
        """With no drops, the keep metric is the observed raw p99."""
        script = Path(__file__).parent / "lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-clean-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 101)
            )
            sample.write_text(replies + "100 packets transmitted, 100 received\n")
            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (100, 0))
        self.assertAlmostEqual(summary["p99_loss_aware_ms"], summary["p99_received_ms"])

    def test_expected_probe_count_covers_an_incomplete_ping_summary(self) -> None:
        """A killed ping process cannot hide probes absent from its final summary."""
        script = Path(__file__).parent / "lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat_incomplete", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-incomplete-") as temporary:
            sample = Path(temporary) / "ping.txt"
            sample.write_text(
                "[1.000000] 64 bytes from peer: icmp_seq=1 ttl=64 time=0.050 ms\n"
                "[1.005000] 64 bytes from peer: icmp_seq=2 ttl=64 time=0.060 ms\n"
            )
            summary = module.stats([sample], expected_sent=3)

        self.assertEqual((summary["sent"], summary["lost"]), (3, 1))
        self.assertTrue(math.isinf(summary["p99_loss_aware_ms"]))


def load_module(name: str):
    """Load one kit library module by file name."""
    script = Path(__file__).parent / "lib" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MatrixSummaryTest(unittest.TestCase):
    """The matrix latency JSON built from a ping log keeps both percentile rules."""

    def write_ping(self, directory: Path, received: int, sent: int) -> Path:
        """Write a ping log with `received` replies at 100 + n/100 ms among `sent` probes."""
        lines = [f"[1.0] 64 bytes from 10.66.0.2: icmp_seq={seq} ttl=64 time={100 + seq / 100:.2f} ms"
                 for seq in range(1, received + 1)]
        lines.append(f"{sent} packets transmitted, {received} received")
        path = directory / "ping.raw"
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_loss_makes_loss_aware_p99_null_but_keeps_the_received_one(self) -> None:
        module = load_module("pingstat")
        with tempfile.TemporaryDirectory(prefix="j317c-ping-") as temporary:
            path = self.write_ping(Path(temporary), received=950, sent=1000)
            result = module.matrix_summary([path], interval_us=5000)
        self.assertEqual((result["sent"], result["received"], result["lost"]), (1000, 950, 50))
        loss_aware = result["loss_aware_rtt_ms"]
        self.assertIsNone(loss_aware["p99"])
        self.assertEqual(loss_aware["infinite_at"], ["p99", "p999"])
        self.assertIsNotNone(loss_aware["p50"])
        self.assertIsNotNone(result["rtt_ms"]["p99"])

    def test_clean_run_has_finite_percentiles_and_json_round_trips(self) -> None:
        import json

        module = load_module("pingstat")
        with tempfile.TemporaryDirectory(prefix="j317c-ping-") as temporary:
            path = self.write_ping(Path(temporary), received=1000, sent=1000)
            result = module.matrix_summary([path], interval_us=5000)
        self.assertEqual(result["loss_aware_rtt_ms"]["infinite_at"], [])
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)


class ProgressTest(unittest.TestCase):
    """Stall counting from once-a-second receiver byte counts."""

    def test_silent_seconds_and_longest_run(self) -> None:
        module = load_module("progress")
        result = module.summarize([(0, 0), (1, 1_000_000), (2, 1_000_000), (3, 1_000_000), (4, 3_000_000)])
        self.assertEqual(result["silent_seconds"], 2.0)
        self.assertEqual(result["longest_silent_s"], 2.0)
        self.assertFalse(result["zero_byte"])

    def test_samples_after_the_connections_close_are_not_silence(self) -> None:
        module = load_module("progress")
        result = module.summarize([(0, 0), (1, 1_000_000), (2, 2_000_000), (3, 0), (4, 0), (5, 0)])
        self.assertEqual(result["silent_seconds"], 0.0)
        self.assertEqual(result["intervals"], 2)
        self.assertEqual(result["bytes_total"], 2_000_000)

    def test_a_flow_that_never_delivers_is_a_zero_byte_case(self) -> None:
        module = load_module("progress")
        result = module.summarize([(0, 0), (1, 0), (2, 0)])
        self.assertTrue(result["zero_byte"])
        self.assertEqual(result["silent_seconds"], 2.0)

    def test_too_few_samples_are_unavailable_not_zero(self) -> None:
        module = load_module("progress")
        self.assertEqual(module.summarize([(0, 5)])["status"], "unavailable")
        self.assertEqual(module.summarize([])["status"], "unavailable")


class WireLossTest(unittest.TestCase):
    """Wire-packet loss accounting from netem counters before and after a sample."""

    def write_pair(self, directory: Path, direction: str, before: tuple[int, int, int], after: tuple[int, int, int]) -> None:
        """Write before/after `tc -s -j` snapshots with (bytes, packets, drops) tuples."""
        import json

        for stage, values in (("before", before), ("after", after)):
            (directory / f"s-{stage}-{direction}.json").write_text(json.dumps([
                {"kind": "netem", "bytes": values[0], "packets": values[1], "drops": values[2]},
            ]))

    def test_mtu_sized_packets_match_the_configured_loss(self) -> None:
        module = load_module("wire_loss")
        with tempfile.TemporaryDirectory(prefix="j317c-wire-") as temporary:
            directory = Path(temporary)
            self.write_pair(directory, "ab", (0, 0, 0), (148_500_000, 99_000, 1_000))
            self.write_pair(directory, "ba", (0, 0, 0), (3_000_000, 49_500, 500))
            result = module.summarize(directory / "s", "per-packet", 1.0, "")
        self.assertEqual(result["ab"]["measured_loss_percent"], 1.0)
        self.assertFalse(result["ab"]["aggregated_packets"])
        self.assertTrue(result["ab"]["matches_configured"])

    def test_super_packets_are_flagged_as_aggregated(self) -> None:
        module = load_module("wire_loss")
        with tempfile.TemporaryDirectory(prefix="j317c-wire-") as temporary:
            directory = Path(temporary)
            self.write_pair(directory, "ab", (0, 0, 0), (3_000_000_000, 99_000, 1_000))
            self.write_pair(directory, "ba", (0, 0, 0), (0, 0, 0))
            result = module.summarize(directory / "s", "legacy", 1.0, "")
        self.assertTrue(result["ab"]["aggregated_packets"])
        self.assertGreater(result["ab"]["average_bytes_per_packet"], 2000)

    def test_a_loss_rate_far_from_the_configured_one_does_not_match(self) -> None:
        module = load_module("wire_loss")
        with tempfile.TemporaryDirectory(prefix="j317c-wire-") as temporary:
            directory = Path(temporary)
            self.write_pair(directory, "ab", (0, 0, 0), (148_500_000, 99_900, 100))
            self.write_pair(directory, "ba", (0, 0, 0), (0, 0, 0))
            result = module.summarize(directory / "s", "per-packet", 1.0, "")
        self.assertFalse(result["ab"]["matches_configured"])

    def test_gemodel_average_and_missing_snapshots(self) -> None:
        module = load_module("wire_loss")
        self.assertAlmostEqual(module.configured_loss_percent(0, "1.05% 20% 100% 0%"), 5.0, delta=0.05)
        with tempfile.TemporaryDirectory(prefix="j317c-wire-") as temporary:
            result = module.summarize(Path(temporary) / "none", "legacy", 1.0, "")
        self.assertEqual(result["ab"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
