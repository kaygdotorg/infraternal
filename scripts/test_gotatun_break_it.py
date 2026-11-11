"""Checks the recovery metrics recorded by the GotaTun break-it suite."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gotatun_break_it import trace as trace_module
from gotatun_break_it import mesh_ix_soak as mesh_ix_soak_module
from gotatun_break_it.report import Probe, report_case
from gotatun_break_it.trace import (
    CounterSample,
    GoodputSample,
    SchedulerEvent,
    goodput_from_counters,
    load_counter_samples,
    load_probe_samples,
    parse_perf_sched,
    summarize_soak,
)
from gotatun_break_it.udp_probe import decode_probe, encode_probe
from gotatun_break_it.mesh_ix_soak import flatten_node_counters, process_counters


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

        self.assertEqual(report["fault_duration_ms"], 200.0)
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


class SoakTraceTests(unittest.TestCase):
    """Keep a long loaded-latency report aligned with GotaTun's diagnostic streams."""

    def test_reports_stall_with_correlated_goodput_counters_and_scheduler_waits(self):
        """A probe stall retains the queue, throughput and runnable-delay evidence at its time."""
        report = summarize_soak(
            probes=[
                Probe(1, 1_000_000_000, 8.0),
                Probe(2, 1_100_000_000, 120.0),
                Probe(3, 1_200_000_000, 240.0),
                Probe(4, 1_300_000_000, 8.0),
            ],
            goodput=[GoodputSample(1_150_000_000, 900_000_000)],
            counters=[
                CounterSample(
                    1_150_000_000,
                    {"crypto_queue_depth": 12, "completion_lock_wait_ns": 45_000_000},
                ),
                CounterSample(
                    1_200_000_000,
                    {"crypto_queue_depth": 16, "completion_lock_wait_ns": 0},
                ),
            ],
            scheduler_events=[
                SchedulerEvent(
                    1_200_000_000,
                    task="gotatun-crypto-0",
                    event="runnable_delay",
                    delay_ns=250_000_000,
                )
            ],
        )

        self.assertEqual(report["p99_ms"], 240.0)
        self.assertEqual(report["stall_bursts"][0]["first_probe_sequence"], 2)
        self.assertEqual(report["stall_bursts"][0]["last_probe_sequence"], 3)
        self.assertEqual(report["stall_bursts"][0]["probe_count"], 2)
        self.assertEqual(report["stall_bursts"][0]["goodput_min_bps"], 900_000_000)
        self.assertEqual(report["stall_bursts"][0]["counter_max"]["crypto_queue_depth"], 16)
        self.assertEqual(
            report["stall_bursts"][0]["counter_max"]["completion_lock_wait_ns"],
            45_000_000,
        )
        self.assertEqual(report["stall_bursts"][0]["scheduler_wait_max_ns"], 250_000_000)
        self.assertEqual(report["correlation_status"], "complete")

    def test_derives_one_second_goodput_from_gotatun_peer_byte_counters(self):
        """Use monotonic counter samples to measure each interval's delivered rate."""
        samples = [
            CounterSample(1_000_000_000, {"gotatun_tx_bytes": 100}),
            CounterSample(2_000_000_000, {"gotatun_tx_bytes": 1_100}),
            CounterSample(4_000_000_000, {"gotatun_tx_bytes": 3_100}),
        ]

        self.assertEqual(
            goodput_from_counters(samples, "gotatun_tx_bytes"),
            [
                GoodputSample(2_000_000_000, 8_000),
                GoodputSample(4_000_000_000, 8_000),
            ],
        )

    def test_parses_perf_sched_wakeup_to_runqueue_delay(self):
        """Correlate a task's wakeup with the switch that next schedules it."""
        events = parse_perf_sched(
            """
worker 123/123 [002] 20.000000: sched:sched_wakeup: comm=worker pid=123 prio=120 target_cpu=002
worker 123/123 [002] 20.250000: sched:sched_switch: prev_comm=idle prev_pid=0 prev_prio=120 prev_state=S ==> next_comm=worker next_pid=123 next_prio=120
"""
        )

        self.assertEqual(
            events,
            [
                SchedulerEvent(
                    20_250_000_000,
                    task="worker/123",
                    event="runnable_delay",
                    delay_ns=250_000_000,
                )
            ],
        )

    def test_aligns_pipeline_queue_events_to_the_host_monotonic_clock(self):
        """Convert J525's per-process pipeline times to the host probe clock."""
        parser = getattr(trace_module, "parse_pipeline_queue_events", None)
        self.assertTrue(callable(parser), "pipeline queue time alignment is missing")
        events = parser(
            [
                "pipeline mono_ns=1000000 stage=crypto_queue_push queued_jobs=4",
                "pipeline mono_ns=1700000 stage=crypto_queue_pop queued_jobs=3",
                "pipeline mono_ns=2000000 stage=tun_write bytes=1500",
            ],
            monotonic_offset_ns=12_345_000_000,
            side="a",
        )

        self.assertEqual(
            events,
            [
                CounterSample(12_346_000_000, {"a_crypto_queue_jobs": 4}),
                CounterSample(12_346_700_000, {"a_crypto_queue_jobs": 3}),
            ],
        )

    def test_scheduler_capture_must_cover_a_stall_before_correlation_is_complete(self):
        """A scheduler file from another clock window cannot certify this stall."""
        report = summarize_soak(
            probes=[
                Probe(1, 1_000_000_000, 8.0),
                Probe(2, 1_100_000_000, 120.0),
                Probe(3, 1_200_000_000, 8.0),
            ],
            goodput=[GoodputSample(1_150_000_000, 900_000_000)],
            counters=[CounterSample(1_150_000_000, {"crypto_queue_depth": 8})],
            scheduler_events=[
                SchedulerEvent(
                    2_000_000_000,
                    task="gotatun-crypto-0/42",
                    event="runnable_delay",
                    delay_ns=250_000_000,
                )
            ],
        )

        self.assertEqual(report["correlation_status"], "incomplete")
        self.assertEqual(report["stall_bursts"][0]["correlation_status"], "incomplete")

    def test_empty_long_wait_list_is_complete_when_the_trace_covers_the_soak(self):
        """A valid scheduler trace with no long waits still proves that interval."""
        try:
            report = summarize_soak(
                probes=[
                    Probe(1, 1_000_000_000, 8.0),
                    Probe(2, 1_100_000_000, 120.0),
                    Probe(3, 1_200_000_000, 8.0),
                ],
                goodput=[GoodputSample(1_150_000_000, 900_000_000)],
                counters=[CounterSample(1_150_000_000, {"crypto_queue_depth": 8})],
                scheduler_events=[],
                scheduler_trace_window_ns=(900_000_000, 1_300_000_000),
            )
        except TypeError as error:
            self.fail(f"scheduler trace coverage is not part of the report: {error}")

        self.assertEqual(report["correlation_status"], "complete")
        self.assertEqual(report["stall_bursts"][0]["correlation_status"], "complete")

    def test_probe_payload_round_trips_sequence_and_monotonic_send_time(self):
        """Keep each fixed-rate probe tied to its original monotonic send time."""
        self.assertEqual(decode_probe(encode_probe(42, 9_876_543_210)), (42, 9_876_543_210))

    def test_probe_payload_rejects_wrong_size(self):
        """Ignore malformed echo packets instead of treating them as a probe reply."""
        self.assertIsNone(decode_probe(b"short"))

    def test_loads_raw_probe_and_counter_rows_without_losing_stall_markers(self):
        """Keep a missed sender deadline distinguishable from network packet loss."""
        with tempfile.TemporaryDirectory() as directory:
            probe_path = Path(directory) / "probes.jsonl"
            counter_path = Path(directory) / "counters.jsonl"
            probe_path.write_text(
                json.dumps(
                    {
                        "sequence": 1,
                        "sent_ns": 10,
                        "rtt_ms": None,
                        "sender_stalled": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            counter_path.write_text(
                json.dumps({"timestamp_ns": 10, "counters": {"gotatun_tx_bytes": 20}})
                + "\n",
                encoding="utf-8",
            )

            probes = load_probe_samples(probe_path)
            counters = load_counter_samples(counter_path)

        self.assertIs(probes[0].sender_stalled, True)
        self.assertEqual(counters[0].counters["gotatun_tx_bytes"], 20)

    def test_flattens_product_peer_and_engine_counters_for_the_trace(self):
        """Retain GotaTun health and peer byte counters without public key material."""
        counters = flatten_node_counters(
            {
                "engine": {
                    "stopped": False,
                    "restarts": 2,
                    "refused_frames": 3,
                    "tx_queue_len": 1024,
                }
            },
            {
                "peers": [
                    {"peer": {"key": "ephemeral-public-key"}, "counters": {"sent_bytes": 40, "received_bytes": 30}},
                    {"peer": {"key": "other-key"}, "counters": {"sent_bytes": 50, "received_bytes": 60}},
                ]
            },
        )

        self.assertEqual(counters["gotatun_restarts"], 2)
        self.assertEqual(counters["gotatun_tx_bytes"], 90)
        self.assertEqual(counters["gotatun_rx_bytes"], 90)
        self.assertNotIn("ephemeral-public-key", json.dumps(counters))

    def test_reads_resource_counters_for_an_agent_process(self):
        """Capture cumulative CPU, resident memory, threads, descriptors and context switches."""
        counters = process_counters(os.getpid())

        self.assertGreater(counters["rss_bytes"], 0)
        self.assertGreater(counters["fd_count"], 0)
        self.assertGreater(counters["thread_count"], 0)

    def test_counter_sampler_sleeps_while_waiting_for_start_marker(self):
        """Keep the counter process idle until the soak start marker arrives."""
        timeout = getattr(mesh_ix_soak_module, "counter_poll_timeout_ns", None)
        self.assertIsNotNone(timeout, "counter sampler wait calculation is missing")

        self.assertEqual(
            timeout(now_ns=1_000, next_sample_ns=0, sampling_active=False),
            1_000_000_000,
        )
        self.assertEqual(
            timeout(now_ns=1_000, next_sample_ns=1_250, sampling_active=True),
            250,
        )
        self.assertEqual(
            timeout(now_ns=1_500, next_sample_ns=1_250, sampling_active=True),
            0,
        )

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
