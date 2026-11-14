#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Protect the scenario matrix shape and honest aggregation rules."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parent / "lib/matrix.py"
SPEC = importlib.util.spec_from_file_location("h2h_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


class MatrixPlanTest(unittest.TestCase):
    """Keep every engine on the same scenario contract and fixed row order."""

    def test_catalog_covers_the_requested_best_and_worst_cases(self) -> None:
        self.assertEqual(
            set(matrix.SCENARIOS),
            {
                "best-lan",
                "best-lan-15k",
                "mobile-40ms-loss-1",
                "mobile-80ms-jitter-loss-2-50mbit",
                "mobile-150ms-gemodel-5",
                "mobile-40ms-loss-1-legacy-egress",
                "mobile-80ms-jitter-loss-2-50mbit-legacy-egress",
                "mobile-150ms-gemodel-5-legacy-egress",
                "wan-50ms",
                "wan-150ms-loss-0.5",
                "wan-150ms-loss-2",
                "wan-20ms-loss-1",
                "small-udp",
                "peer-scale",
                "handshake-storm",
                "cpu-contended",
                "idle",
            },
        )
        self.assertEqual(matrix.SCENARIOS["best-lan"]["inner_mtu_bytes"], 1420)
        self.assertEqual(matrix.SCENARIOS["best-lan"]["tcp_flows"], [1, 8])
        self.assertEqual(matrix.SCENARIOS["small-udp"]["udp_payload_bytes"], [64, 256])
        self.assertEqual(matrix.SCENARIOS["wan-20ms-loss-1"]["delay_each_direction_ms"], 10)
        self.assertEqual(matrix.SCENARIOS["wan-20ms-loss-1"]["jitter_each_direction_ms"], 5)
        self.assertEqual(matrix.SCENARIOS["wan-20ms-loss-1"]["loss_each_direction_percent"], 1)
        self.assertEqual(matrix.SCENARIOS["peer-scale"]["peer_counts_per_endpoint"], [1, 100, 1000])
        self.assertEqual(matrix.SCENARIOS["handshake-storm"]["forced_rehandshakes"], 30)
        self.assertEqual(matrix.SCENARIOS["cpu-contended"]["noise_cpu"], 5)

    def test_config_cli_selects_one_flow_without_mutating_the_default_scenario(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "config", "best-lan", "--tcp-flow", "8"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["tcp_flows"], [8])
        self.assertEqual(matrix.SCENARIOS["best-lan"]["tcp_flows"], [1, 8])

    def test_five_equal_repetitions_cover_controls_and_each_gotatun_variant(self) -> None:
        rows = matrix.MATRIX_ROWS
        engines = [engine for _, engine in rows]
        batches = matrix.matrix_batches()

        self.assertEqual(len(rows), len(matrix.DEFAULT_ENGINE_SPECS) * 5)
        self.assertEqual(
            {name: engines.count(name) for name in set(engines)},
            {engine_id: 5 for engine_id in matrix.DEFAULT_ENGINE_IDS},
        )
        self.assertEqual([len(batch) for batch in batches], [len(matrix.DEFAULT_ENGINE_SPECS)] * 5)
        for batch in batches:
            self.assertEqual({engine for _, engine in batch}, set(matrix.DEFAULT_ENGINE_IDS))

    def test_engine_order_is_counterbalanced_across_five_windows(self) -> None:
        ids = matrix.DEFAULT_ENGINE_IDS
        expected = [list(ids[offset:] + ids[:offset]) for offset in range(matrix.MATRIX_REPETITIONS)]
        actual = [[engine_id for _, engine_id in batch] for batch in matrix.matrix_batches()]
        self.assertEqual(actual, expected)

    def test_selected_matrix_uses_the_requested_first_window_order(self) -> None:
        """Keep run_matrix's first batch aligned with its explicit counterbalance order."""
        with tempfile.TemporaryDirectory(prefix="h2h-selected-order-") as temporary:
            root = Path(temporary)
            kit = root / "kit"
            (kit / "bin").mkdir(parents=True)
            binaries = {}
            for name in ("shipped", "j225", "wg", "wireguard-go"):
                binary = kit / "bin" / name
                binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                binary.chmod(0o755)
                binaries[name] = binary

            args = matrix.argparse.Namespace(
                kit=str(kit),
                out=str(root / "results"),
                gotatun_binary=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={binaries['shipped']}",
                    f"{matrix.J225_GOTATUN_ID}={binaries['j225']}",
                ],
                source=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={matrix.SHIPPED_GOTATUN_ENGINE['source_sha']}",
                    f"{matrix.J225_GOTATUN_ID}={matrix.J225_GOTATUN_ENGINE['source_sha']}",
                ],
                engine_label=[],
                select_gotatun=[matrix.SHIPPED_GOTATUN_ID, matrix.J225_GOTATUN_ID],
                engine_order=[
                    matrix.SHIPPED_GOTATUN_ID,
                    matrix.J225_GOTATUN_ID,
                    "wireguard-go",
                    "kernel-plain",
                ],
                calibration_variant=matrix.SHIPPED_GOTATUN_ID,
                wg_bin=str(binaries["wg"]),
                wireguard_go_bin=str(binaries["wireguard-go"]),
                calibration_only=False,
                calibrate=False,
                batch=1,
                scenario="best-lan",
                tcp_flow=[8],
            )
            selected_specs = matrix.matrix_engine_specs(args, kit)
            ordered_specs = matrix.order_engine_specs(selected_specs, args.engine_order)
            output = Path(args.out)
            calibration_dir = output / "calibration"
            calibration_dir.mkdir(parents=True)
            (calibration_dir / "calibration-status.json").write_text(json.dumps({
                "status": "failed",
                "report": {},
                "variant_id": matrix.SHIPPED_GOTATUN_ID,
                "source": matrix.SHIPPED_GOTATUN_ENGINE["source_sha"],
                "binary_sha256": next(
                    spec["binary_sha256"] for spec in selected_specs
                    if spec["id"] == matrix.SHIPPED_GOTATUN_ID
                ),
            }), encoding="utf-8")
            (output / "matrix.json").write_text(json.dumps({
                "engine_specs": matrix.public_engine_specs(ordered_specs),
                "scenarios": {},
            }), encoding="utf-8")

            with mock.patch.object(matrix.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertEqual(matrix.run_matrix(args), 0)
            aggregate = json.loads(
                (output / "best-lan-tcp-flow-8" / "matrix.json").read_text()
            )
            self.assertEqual(aggregate["scenario"]["tcp_flows"], [8])
            self.assertIn(
                "TCP flow counts measured: 8.",
                (output / "best-lan-tcp-flow-8" / "summary.md").read_text(),
            )

            argv = run.call_args.args[0]
            actual_rows = [argv[index + 1] for index, value in enumerate(argv) if value == "--row"]
            self.assertIn("--tcp-flow", argv)
            self.assertEqual(argv[argv.index("--tcp-flow") + 1], "8")
            self.assertEqual(actual_rows, [
                f"{matrix.SHIPPED_GOTATUN_ID}-1=gotatun",
                f"{matrix.J225_GOTATUN_ID}-1=gotatun",
                "wireguard-go-1=wireguard-go",
                "kernel-plain-1=kernel-plain",
            ])

    def test_later_gotatun_candidates_use_the_same_five_window_contract(self) -> None:
        candidate = {
            "id": "gotatun-j316-coalescing",
            "label": "GotaTun (J316 coalescing, abc1234)",
            "runner_engine": "gotatun",
            "source_sha": "a" * 40,
            "source_aliases": [],
        }
        specs = (*matrix.DEFAULT_ENGINE_SPECS, candidate)
        batches = matrix.matrix_batches(specs)

        self.assertEqual(len(batches), 5)
        self.assertTrue(all(len(batch) == len(matrix.DEFAULT_ENGINE_SPECS) + 1 for batch in batches))
        self.assertEqual(
            [engine for _, engine in matrix.matrix_rows(specs)].count(candidate["id"]),
            5,
        )
        self.assertEqual(
            matrix.matrix_row_arguments(batches[0], specs)[-2:],
            ["--row", "gotatun-j316-coalescing-1=gotatun"],
        )

    def test_shipped_data_path_alias_is_not_accepted_as_a_second_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-source-alias-") as temporary:
            root = Path(temporary)
            binary = root / "gotatun"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            args = matrix.argparse.Namespace(
                gotatun_binary=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={binary}",
                    f"{matrix.J88I_GOTATUN_ID}={binary}",
                    f"gotatun-2bb5347={binary}",
                ],
                source=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={matrix.SHIPPED_GOTATUN_ENGINE['source_sha']}",
                    f"{matrix.J88I_GOTATUN_ID}={matrix.J88I_GOTATUN_ENGINE['source_sha']}",
                    "gotatun-2bb5347=2bb5347a8cddf3c31df64be1f52466e1a02bf75b",
                ],
                engine_label=[],
                calibration_variant=matrix.SHIPPED_GOTATUN_ID,
                wg_bin=None,
                wireguard_go_bin=None,
            )

            with self.assertRaisesRegex(ValueError, "must not be measured twice"):
                matrix.matrix_engine_specs(args, root)

    def test_full_matrix_requires_all_pinned_candidate_sources(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-required-sources-") as temporary:
            root = Path(temporary)
            args = matrix.argparse.Namespace(
                gotatun_binary=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={root / 'shipped'}",
                    f"{matrix.J88I_GOTATUN_ID}={root / 'j88i'}",
                ],
                source=[
                    f"{matrix.SHIPPED_GOTATUN_ID}={matrix.SHIPPED_GOTATUN_ENGINE['source_sha']}",
                    f"{matrix.J88I_GOTATUN_ID}={matrix.J88I_GOTATUN_ENGINE['source_sha']}",
                ],
                engine_label=[],
                calibration_variant=matrix.SHIPPED_GOTATUN_ID,
                wg_bin=None,
                wireguard_go_bin=None,
            )

            with self.assertRaisesRegex(ValueError, "full matrix requires every pinned GotaTun source row"):
                matrix.matrix_engine_specs(args, root)

    def test_perf_all_receives_the_canonical_matrix_rows(self) -> None:
        self.assertEqual(matrix.matrix_row_arguments(matrix.matrix_batches()[0]), [
            "--row", "kernel-plain-1=kernel-plain",
            "--row", "wireguard-go-1=wireguard-go",
            "--row", f"{matrix.SHIPPED_GOTATUN_ID}-1=gotatun",
            "--row", f"{matrix.J88I_GOTATUN_ID}-1=gotatun",
            "--row", f"{matrix.J316_GOTATUN_ID}-1=gotatun",
            "--row", f"{matrix.J225_GOTATUN_ID}-1=gotatun",
            "--row", f"{matrix.J324_GOTATUN_ID}-1=gotatun",
        ])

    def test_owner_directed_rows_report_the_calibration_spread(self) -> None:
        result = {
            "scenario": {"id": "best-lan", "description": "LAN baseline."},
            "calibration_status": "uncalibrated, owner-directed",
            "calibration_evidence": {
                "status": "failed",
                "spread_pct": {
                    "throughput_gbit_s": {"8": 0.813},
                    "p99_loss_aware_ms": {"1": 9.9},
                },
                "spread_limits_pct": {
                    "throughput_gbit_s": {"8": 0.8},
                    "p99_loss_aware_ms": {"1": 3.2},
                },
                "owner_reported_prior_spreads": [
                    {"metric": "throughput_gbit_s", "flows": "8", "spread_pct": 0.813, "limit_pct": 0.8},
                    {"metric": "p99_loss_aware_ms", "flows": "1", "spread_pct": 9.9, "limit_pct": 3.2},
                ],
            },
            "engines": {
                engine: {"complete_count": 5, "repeat_count": 5, "metrics": {}}
                for engine in ("kernel-plain", "wireguard-go", "gotatun")
            },
        }

        summary = matrix.render_summary(result)

        self.assertIn("uncalibrated, owner-directed", summary)
        self.assertIn("8-flow throughput spread 0.813% (limit 0.8%)", summary)
        self.assertIn("1-flow loss-aware p99 spread 9.9% (limit 3.2%)", summary)
        self.assertIn("owner-reported prior 8-flow throughput 0.813% (limit 0.8%)", summary)
        self.assertIn("owner-reported prior 1-flow loss-aware p99 9.9% (limit 3.2%)", summary)

    def test_aggregate_rows_reads_each_balanced_window(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-matrix-windows-") as temporary:
            root = Path(temporary)
            specs = {str(spec["id"]): spec for spec in matrix.DEFAULT_ENGINE_SPECS}
            for tag, engine_id in matrix.matrix_batches()[0]:
                implementation = specs[engine_id]["runner_engine"]
                case = root / "window-01" / tag / f"mesh-{implementation}"
                case.mkdir(parents=True)
                (case / "matrix-row.json").write_text(json.dumps({
                    "row_tag": tag,
                    "engine": implementation,
                    "scenario": "best-lan",
                    "status": "complete",
                    "calibration_status": "uncalibrated, owner-directed",
                    "metrics": {"tcp_1_gbit_s": 1.0},
                    "measurements": [f"{tag}/mesh-{implementation}/matrix/tcp-1-throughput.json"],
                }), encoding="utf-8")
                (case / "status.json").write_text(json.dumps({"exit": 0}), encoding="utf-8")

            result = matrix.aggregate_rows(
                root, "best-lan", "uncalibrated, owner-directed",
                engine_specs=matrix.DEFAULT_ENGINE_SPECS,
            )

            self.assertEqual(result["engines"]["kernel-plain"]["complete_count"], 1)
            self.assertEqual(result["engines"]["kernel-plain"]["repeat_count"], 5)
            measured = next(row for row in result["rows"] if row["status"] == "complete")
            self.assertEqual(measured["window"], "window-01")
            self.assertTrue(measured["measurements"][0].startswith("window-01/"))
            shipped = next(
                row for row in result["rows"] if row["engine"] == matrix.SHIPPED_GOTATUN_ID
            )
            self.assertEqual(shipped["source_sha"], matrix.SHIPPED_GOTATUN_ENGINE["source_sha"])
            self.assertEqual(
                shipped["source_aliases"][0]["source_sha"],
                "2bb5347a8cddf3c31df64be1f52466e1a02bf75b",
            )
            self.assertEqual(
                result["engines"][matrix.SHIPPED_GOTATUN_ID]["label"],
                "GotaTun (shipped, 84b7bb2)",
            )

    def test_failed_and_missing_repeats_are_not_treated_as_zero(self) -> None:
        summary = matrix.aggregate_metrics(
            [
                {"status": "complete", "metrics": {"throughput_gbit_s": 2.0}},
                {"status": "failed", "metrics": {"throughput_gbit_s": 1000.0}},
                {"status": "complete", "metrics": {"throughput_gbit_s": 4.0}},
            ]
        )
        self.assertEqual(summary["throughput_gbit_s"]["median"], 3.0)
        self.assertEqual(summary["throughput_gbit_s"]["n"], 2)

    def test_loss_aware_infinite_percentiles_participate_in_repeat_median(self) -> None:
        rows = [
            {"status": "complete", "metrics": {"loaded_1_p99_ms": 2.0},
             "latency": {"loaded_tcp_1": {"infinite_at": []}}},
            {"status": "complete", "metrics": {"loaded_1_p99_ms": None},
             "latency": {"loaded_tcp_1": {"infinite_at": ["p99"]}}},
        ]

        summary = matrix.aggregate_metrics(rows)["loaded_1_p99_ms"]

        self.assertEqual(summary["n"], 2)
        self.assertEqual(summary["infinite_n"], 1)
        self.assertTrue(summary["median_is_infinite"])
        self.assertIsNone(summary["median"])
        self.assertEqual(summary["min"], 2.0)
        self.assertIsNone(summary["max"])
        self.assertTrue(summary["max_is_infinite"])
        json.dumps(summary, allow_nan=False)

    def test_infinite_tail_does_not_hide_a_finite_odd_repeat_median(self) -> None:
        summary = matrix.aggregate_metrics([
            {"status": "complete", "metrics": {"loaded_1_p99_ms": 2.0},
             "latency": {"loaded_tcp_1": {"infinite_at": []}}},
            {"status": "complete", "metrics": {"loaded_1_p99_ms": 4.0},
             "latency": {"loaded_tcp_1": {"infinite_at": []}}},
            {"status": "complete", "metrics": {"loaded_1_p99_ms": None},
             "latency": {"loaded_tcp_1": {"infinite_at": ["p99"]}}},
        ])["loaded_1_p99_ms"]

        self.assertEqual(summary["n"], 3)
        self.assertEqual(summary["infinite_n"], 1)
        self.assertFalse(summary["median_is_infinite"])
        self.assertEqual(summary["median"], 4.0)
        self.assertIsNone(summary["max"])
        self.assertTrue(summary["max_is_infinite"])

    def test_infinite_latency_median_renders_as_infinity(self) -> None:
        result = {
            "scenario": {"id": "wan-test", "description": "Test loss."},
            "calibration_status": "passed",
            "engines": {
                engine: {
                    "complete_count": 2,
                    "repeat_count": 2,
                    "metrics": {
                        "loaded_1_p99_ms": {
                            "n": 2, "median": None, "min": 2.0, "max": None,
                            "infinite_n": 1, "median_is_infinite": True,
                            "max_is_infinite": True,
                        },
                    },
                }
                for engine in ("kernel-plain", "wireguard-go", "gotatun")
            },
        }

        summary = matrix.render_summary(result)

        self.assertIn("loaded 1-flow p50 / p99 / p99.9 ms | n/a / ∞ / n/a", summary)

    def test_idle_small_udp_infinite_rank_survives_row_collection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-idle-udp-loss-") as temporary:
            case = Path(temporary) / "mesh-gotatun"
            measurements = case / "matrix"
            measurements.mkdir(parents=True)
            (measurements / "idle-latency-64.json").write_text(json.dumps({
                "loss_aware_rtt_ms": {"p50": 1.0, "p99": None, "p999": None,
                                      "infinite_at": ["p99", "p999"]},
                "sent": 100, "received": 98, "lost": 2,
            }), encoding="utf-8")
            (measurements / "udp-64-pps.json").write_text(json.dumps({
                "loss_aware_rtt_ms": {"p50": 1.0, "p99": None, "p999": None,
                                      "infinite_at": ["p99", "p999"]},
                "sent": 100, "received": 98, "lost": 2,
            }), encoding="utf-8")
            (measurements / "udp-64-cpu.json").write_text(json.dumps({
                "status": "measured", "machine_cpu_s_per_gbit": 4.25,
            }), encoding="utf-8")

            row = matrix.collect_row(
                case, engine="gotatun", tag="gotatun-a", scenario="small-udp", calibration="passed"
            )

            self.assertEqual(row["latency"]["idle_udp_64"]["infinite_at"], ["p99", "p999"])
            self.assertEqual(row["latency"]["loaded_udp_64"]["infinite_at"], ["p99", "p999"])
            self.assertEqual(row["metrics"]["cpu_s_per_gbit_udp_64"], 4.25)
            summary = matrix.aggregate_metrics([row])
            self.assertEqual(summary["idle_udp_64_p99_ms"]["infinite_n"], 1)
            self.assertEqual(summary["loaded_udp_64_p99_ms"]["infinite_n"], 1)

    def test_udp_cpu_per_gbit_uses_received_payload_and_matching_cpu_window(self) -> None:
        summary = matrix.cpu_window_summary(
            {"busy_jiffies": 1000, "monotonic_ns": 2_000_000_000, "hz": 100},
            {"busy_jiffies": 1500, "monotonic_ns": 5_000_000_000, "hz": 100},
            {"received": 100_000, "payload_bytes": 64},
        )

        self.assertEqual(summary["status"], "measured")
        self.assertEqual(summary["machine_cpu_busy_s"], 5.0)
        self.assertAlmostEqual(summary["transferred_payload_gbit"], 0.0512)
        self.assertAlmostEqual(summary["machine_cpu_s_per_gbit"], 97.65625)
        json.dumps(summary, allow_nan=False)

        unavailable = matrix.cpu_window_summary(
            {"busy_jiffies": 1000, "monotonic_ns": 2_000_000_000, "hz": 100},
            {"busy_jiffies": 1100, "monotonic_ns": 3_000_000_000, "hz": 100},
            {"received": 0, "payload_bytes": 64},
        )
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertIsNone(unavailable["machine_cpu_s_per_gbit"])

    def test_unavailable_metrics_remain_explicitly_unavailable(self) -> None:
        summary = matrix.aggregate_metrics(
            [{"status": "complete", "metrics": {
                "syscalls_per_gbit_1": None,
                "udp_64_syscalls_per_gbit": None,
            }}]
        )
        self.assertEqual(summary["syscalls_per_gbit_1"]["n"], 0)
        self.assertIsNone(summary["syscalls_per_gbit_1"]["median"])
        self.assertEqual(summary["udp_64_syscalls_per_gbit"]["n"], 0)
        self.assertIsNone(summary["udp_64_syscalls_per_gbit"]["median"])

    def test_row_without_cleanup_status_is_not_counted_as_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-matrix-status-") as temporary:
            root = Path(temporary)
            case = root / "kernel-a" / "mesh-kernel-plain"
            case.mkdir(parents=True)
            (case / "matrix-row.json").write_text(
                json.dumps({"row_tag": "kernel-a", "engine": "kernel-plain",
                            "status": "complete", "metrics": {"tcp_1_gbit_s": 9.0}}),
                encoding="utf-8",
            )

            result = matrix.aggregate_rows(root, "best-lan", "passed")

            self.assertEqual(result["rows"][0]["status"], "failed-or-missing")
            self.assertEqual(result["engines"]["kernel-plain"]["complete_count"], 0)

    def write_attempt(self, root: Path, window: str, exit_code: int, with_row: bool) -> None:
        """Create one window's `kernel-a` case directory with a given exit status."""
        case = root / window / "kernel-a" / "mesh-kernel-plain"
        case.mkdir(parents=True)
        (case / "status.json").write_text(json.dumps({"exit": exit_code}), encoding="utf-8")
        if with_row:
            (case / "matrix-row.json").write_text(
                json.dumps({"row_tag": "kernel-a", "engine": "kernel-plain",
                            "status": "complete", "metrics": {"tcp_1_gbit_s": 3.0}}),
                encoding="utf-8",
            )

    def kernel_a_row(self, result: dict) -> dict:
        return next(row for row in result["rows"] if row["row_tag"] == "kernel-a")

    def test_a_completed_retry_supersedes_one_failed_attempt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-matrix-retry-") as temporary:
            root = Path(temporary)
            self.write_attempt(root, "window-01a", 1, with_row=False)
            self.write_attempt(root, "window-01r", 0, with_row=True)
            row = self.kernel_a_row(matrix.aggregate_rows(
                root, "best-lan", "passed", row_order=(("kernel-a", "kernel-plain"),)))
            self.assertEqual(row["status"], "complete")
            self.assertEqual(row["window"], "window-01r")
            self.assertEqual(row["superseded_failed_attempts"], ["window-01a"])

    def test_two_completed_attempts_are_still_a_duplicate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-matrix-dup-") as temporary:
            root = Path(temporary)
            self.write_attempt(root, "window-01a", 0, with_row=True)
            self.write_attempt(root, "window-01r", 0, with_row=True)
            row = self.kernel_a_row(matrix.aggregate_rows(
                root, "best-lan", "passed", row_order=(("kernel-a", "kernel-plain"),)))
            self.assertEqual(row["status"], "failed")
            self.assertIn("duplicate", row["failure_reason"])

    def test_two_failed_attempts_say_that_none_completed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-matrix-failed-") as temporary:
            root = Path(temporary)
            self.write_attempt(root, "window-01a", 1, with_row=False)
            self.write_attempt(root, "window-01r", 1, with_row=False)
            row = self.kernel_a_row(matrix.aggregate_rows(
                root, "best-lan", "passed", row_order=(("kernel-a", "kernel-plain"),)))
            self.assertEqual(row["status"], "failed")
            self.assertIn("no completed attempt among 2 attempts", row["failure_reason"])

    def test_missing_scenario_directory_still_gets_an_explicit_empty_table(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-empty-scenario-") as temporary:
            scenario_root = Path(temporary) / "not-started"

            result = matrix.aggregate_rows(scenario_root, "best-lan", "failed")

            self.assertTrue((scenario_root / "matrix.json").is_file())
            self.assertTrue((scenario_root / "summary.md").is_file())
            self.assertEqual(result["engines"][matrix.SHIPPED_GOTATUN_ID]["complete_count"], 0)

    def test_peer_scale_row_retains_each_peer_count_workload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-scale-") as temporary:
            case = Path(temporary) / "mesh-gotatun"
            measurements = case / "matrix"
            measurements.mkdir(parents=True)
            for peers, rate in ((1, 1.0), (100, 2.0), (1000, 3.0)):
                (measurements / f"peer-{peers}-memory.json").write_text(json.dumps({
                    "userspace_rss_mib": rate,
                    "kernel_peer_memory_bytes": peers * 4096,
                    "kernel_peer_memory_basis": "delta of WireGuard-named /proc/slabinfo caches",
                }), encoding="utf-8")
                (measurements / f"peer-{peers}-throughput.json").write_text(
                    json.dumps({"gbit_per_s": rate, "machine_cpu_s_per_gbit": rate / 10}),
                    encoding="utf-8",
                )
                (measurements / f"peer-{peers}-tcp-1-latency.json").write_text(
                    json.dumps({"loss_aware_rtt_ms": {"p50": rate, "p99": rate + 1,
                                                       "p999": rate + 2, "infinite_at": []}}),
                    encoding="utf-8",
                )
                (measurements / f"peer-{peers}-tcp-1-syscalls.json").write_text(
                    json.dumps({"syscalls_per_gbit": rate * 1000}), encoding="utf-8"
                )

            row = matrix.collect_row(
                case, engine="gotatun", tag="gotatun-a", scenario="peer-scale", calibration="passed"
            )

            self.assertEqual(row["metrics"]["peer_1_tcp_gbit_s"], 1.0)
            self.assertEqual(row["metrics"]["peer_100_tcp_gbit_s"], 2.0)
            self.assertEqual(row["metrics"]["peer_1000_tcp_gbit_s"], 3.0)
            self.assertEqual(row["metrics"]["peer_1000_loaded_p999_ms"], 5.0)
            self.assertEqual(row["metrics"]["peer_1000_syscalls_per_gbit"], 3000.0)
            self.assertEqual(row["metrics"]["kernel_memory_delta_bytes_100"], 409600)

    def test_rss_and_kernel_peer_memory_report_bytes_per_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-per-peer-") as temporary:
            case = Path(temporary) / "mesh-gotatun"
            measurements = case / "matrix"
            measurements.mkdir(parents=True)
            for peers, rss_mib in ((1, 2.0), (100, 20.0), (1000, 80.0)):
                (measurements / f"peer-{peers}-memory.json").write_text(json.dumps({
                    "userspace_rss_mib": rss_mib,
                    "kernel_peer_memory_bytes": None,
                    "kernel_peer_memory_basis": "peer state is in userspace",
                }), encoding="utf-8")

            row = matrix.collect_row(
                case, engine="gotatun", tag="gotatun-1", scenario="peer-scale", calibration="uncalibrated, owner-directed"
            )

            self.assertEqual(row["metrics"]["rss_bytes_per_peer_1"], 2 * 1024 * 1024)
            self.assertEqual(row["metrics"]["rss_bytes_per_peer_100"], 20 * 1024 * 1024 / 100)
            self.assertIsNone(row["metrics"]["kernel_memory_bytes_per_peer_100"])

    def test_peer_scale_reports_idle_and_loaded_rss_for_each_peer_count(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-peer-memory-states-") as temporary:
            case = Path(temporary) / "mesh-gotatun"
            measurements = case / "matrix"
            measurements.mkdir(parents=True)
            for peers in (1, 100, 1000):
                for state, rss_mib, pss_mib in (
                    ("idle", 10.0 + peers / 100, 5.0 + peers / 100),
                    ("loaded", 12.0 + peers / 100, 7.0 + peers / 100),
                ):
                    (measurements / f"peer-{peers}-{state}-memory.json").write_text(json.dumps({
                        "measurement_state": state,
                        "userspace_rss_mib": rss_mib,
                        "userspace_pss_kb": pss_mib * 1024,
                        "kernel_peer_memory_bytes": peers * 4096,
                        "kernel_peer_memory_basis": "delta of WireGuard-named /proc/slabinfo caches",
                    }), encoding="utf-8")

            row = matrix.collect_row(
                case, engine="gotatun", tag="gotatun-1", scenario="peer-scale", calibration="passed"
            )

            for peers in (1, 100, 1000):
                self.assertEqual(row["metrics"][f"rss_idle_mib_{peers}"], 10.0 + peers / 100)
                self.assertEqual(row["metrics"][f"rss_loaded_mib_{peers}"], 12.0 + peers / 100)
                self.assertEqual(
                    row["metrics"][f"rss_loaded_bytes_per_peer_{peers}"],
                    (12.0 + peers / 100) * 1024 * 1024 / peers,
                )
                self.assertEqual(row["metrics"][f"pss_idle_mib_{peers}"], 5.0 + peers / 100)
                self.assertEqual(row["metrics"][f"pss_loaded_mib_{peers}"], 7.0 + peers / 100)
                self.assertEqual(
                    row["metrics"][f"pss_loaded_bytes_per_peer_{peers}"],
                    (7.0 + peers / 100) * 1024 * 1024 / peers,
                )
                self.assertEqual(row["peer_memory"][str(peers)]["measurement_state"], "idle")
                self.assertEqual(row["peer_memory_loaded"][str(peers)]["measurement_state"], "loaded")

        metric_labels = {label for label, _, _ in matrix.TABLE_METRICS}
        self.assertIn("RSS idle MiB 1 / 100 / 1,000 peers", metric_labels)
        self.assertIn("RSS loaded MiB 1 / 100 / 1,000 peers", metric_labels)
        self.assertIn("userspace RSS bytes per peer, loaded at 1 / 100 / 1,000", metric_labels)
        self.assertIn("userspace PSS idle MiB 1 / 100 / 1,000 peers", metric_labels)
        self.assertIn("userspace PSS loaded MiB 1 / 100 / 1,000 peers", metric_labels)
        self.assertIn("userspace PSS bytes per peer, loaded at 1 / 100 / 1,000", metric_labels)

    def test_scenario_summary_uses_engine_columns_and_metric_rows(self) -> None:
        engines = {
            engine: {
                "complete_count": 2,
                "repeat_count": 2,
                "metrics": {
                    "tcp_1_gbit_s": {"n": 2, "median": rate},
                    "tcp_8_gbit_s": {"n": 2, "median": rate * 2},
                    "udp_64_gbit_s": {"n": 2, "median": rate / 10},
                    "udp_256_gbit_s": {"n": 2, "median": rate / 20},
                    "cpu_s_per_gbit_udp_64": {"n": 2, "median": rate / 2},
                    "cpu_s_per_gbit_udp_256": {"n": 2, "median": rate / 4},
                    "pss_idle_mib_1": {"n": 2, "median": rate},
                    "pss_idle_mib_100": {"n": 2, "median": rate + 0.1},
                    "pss_idle_mib_1000": {"n": 2, "median": rate + 0.2},
                },
            }
            for engine, rate in (("kernel-plain", 1.0), ("wireguard-go", 2.0), ("gotatun", 3.0))
        }
        summary = matrix.render_summary({
            "scenario": {"id": "best-lan", "description": "LAN baseline."},
            "calibration_status": "passed",
            "engines": engines,
        })

        self.assertIn("| Metric | plain kernel WireGuard | wireguard-go | GotaTun |", summary)
        self.assertIn("| TCP Gbit/s 1 / 8 | 1.000 / 2.000 | 2.000 / 4.000 | 3.000 / 6.000 |", summary)
        self.assertIn("| UDP payload Gbit/s 64 / 256 | 0.100 / 0.050 | 0.200 / 0.100 | 0.300 / 0.150 |", summary)
        self.assertIn("| UDP CPU s/Gbit 64 / 256 | 0.5000 / 0.2500 | 1.0000 / 0.5000 | 1.5000 / 0.7500 |", summary)
        self.assertIn("| userspace PSS idle MiB 1 / 100 / 1,000 peers | 1.00 / 1.10 / 1.20 | 2.00 / 2.10 / 2.20 | 3.00 / 3.10 / 3.20 |", summary)
        self.assertIn("| UDP syscalls/Gbit 64 B / 256 B |", summary)
        self.assertIn("Loaded peer-count memory is measured in the peer-scale scenario", summary)

    def test_scenario_summary_names_full_source_sha_for_each_engine(self) -> None:
        engine_order = [dict(spec) for spec in matrix.DEFAULT_ENGINE_SPECS]
        engines = {
            spec["id"]: {"complete_count": 5, "repeat_count": 5, "metrics": {}}
            for spec in engine_order
        }

        summary = matrix.render_summary({
            "scenario": {"id": "best-lan", "description": "LAN baseline."},
            "row_calibration_label": matrix.OWNER_DIRECTED_CALIBRATION_LABEL,
            "calibration_status": "failed",
            "engine_order": engine_order,
            "engines": engines,
        })

        self.assertIn("GotaTun (shipped, 84b7bb2)", summary)
        self.assertIn("GotaTun (J316 coalescing, pre-checksum-fix, b678934)", summary)
        self.assertIn("GotaTun (J225 + J316 stack, release, 3a70a7d21)", summary)
        self.assertIn("GotaTun (J324 memory pools, b36d575)", summary)
        for spec in engine_order:
            if spec.get("source_sha"):
                self.assertIn(spec["source_sha"], summary)
        self.assertIn("uncalibrated, owner-directed", summary)

    def test_kernel_artifact_row_retains_module_and_image_disk_footprints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="h2h-kernel-artifacts-") as temporary:
            case = Path(temporary) / "mesh-kernel-plain"
            measurements = case / "matrix"
            measurements.mkdir(parents=True)
            (measurements / "artifacts.json").write_text(json.dumps({
                "engine_binary_size_bytes": None,
                "engine_binary_disk_bytes": None,
                "in_kernel_artifact": {
                    "module": {"size_bytes": 1000, "disk_bytes": 1024},
                    "kernel_image": {"size_bytes": 5000, "disk_bytes": 5120},
                },
            }), encoding="utf-8")

            row = matrix.collect_row(
                case, engine="kernel-plain", tag="kernel-a", scenario="best-lan", calibration="passed"
            )

            self.assertEqual(row["metrics"]["kernel_module_disk_bytes"], 1024)
            self.assertEqual(row["metrics"]["kernel_image_disk_bytes"], 5120)


class CalibratedSamplingTest(unittest.TestCase):
    """Protect the calibrated best-LAN sampling and the honest row label."""

    def test_best_lan_15k_keeps_every_probe_inside_the_load_window(self) -> None:
        """15,000 probes at 5 ms last 75 s, so the 85 s load covers all of them."""
        config = matrix.SCENARIOS["best-lan-15k"]
        probe_seconds = config["latency_probes"] * config["loaded_latency_interval_us"] / 1e6
        self.assertEqual(config["latency_probes"], 15000)
        self.assertLess(probe_seconds, config["tput_seconds"])
        # The default LAN scenario is unchanged until the controls pass twice.
        self.assertEqual(matrix.SCENARIOS["best-lan"]["latency_probes"], 3600)
        self.assertEqual(matrix.SCENARIOS["best-lan"]["tput_seconds"], 10)

    def test_rows_are_called_calibrated_only_after_the_controls_pass(self) -> None:
        """A failed or missing calibration keeps the owner-directed label."""
        self.assertEqual(matrix.row_calibration_label("passed"), "calibrated")
        for status in ("failed", "uncalibrated", "", "unavailable"):
            with self.subTest(status=status):
                self.assertEqual(matrix.row_calibration_label(status), matrix.OWNER_DIRECTED_CALIBRATION_LABEL)


class WindowPartTest(unittest.TestCase):
    """A window can run as two shorter holds without changing its row order."""

    ROWS = (("a-1", "a"), ("b-1", "b"), ("c-1", "c"), ("d-1", "d"))

    def test_halves_keep_order_and_cover_the_window(self) -> None:
        first, first_suffix = matrix.batch_part(self.ROWS, 1)
        second, second_suffix = matrix.batch_part(self.ROWS, 2)
        self.assertEqual(first + second, self.ROWS)
        self.assertEqual((first_suffix, second_suffix), ("a", "b"))
        self.assertEqual(matrix.batch_part(self.ROWS, None), (self.ROWS, ""))

    def test_retry_runs_only_the_named_rows_into_their_own_directory(self) -> None:
        rows, suffix = matrix.batch_part(self.ROWS, None, ["c-1"])
        self.assertEqual((rows, suffix), ((("c-1", "c"),), "r-c-1"))
        with self.assertRaises(ValueError):
            matrix.batch_part(self.ROWS, None, ["zzz-9"])
        with self.assertRaises(ValueError):
            matrix.batch_part(self.ROWS, 1, ["a-1"])

    def test_bad_parts_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            matrix.batch_part(self.ROWS, 3)
        with self.assertRaises(ValueError):
            matrix.batch_part(self.ROWS[:1], 1)


class MobileProfileTest(unittest.TestCase):
    """The lossy mobile profiles keep every probe loaded and describe their netem exactly."""

    NAMES = ("mobile-40ms-loss-1", "mobile-80ms-jitter-loss-2-50mbit", "mobile-150ms-gemodel-5")

    def test_each_profile_has_a_per_packet_scenario_and_a_labelled_legacy_one(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                corrected = matrix.SCENARIOS[name]
                legacy = matrix.SCENARIOS[f"{name}-legacy-egress"]
                self.assertEqual(corrected["shaping"], "per-packet")
                self.assertEqual(legacy["shaping"], "legacy")
                self.assertIn("legacy", legacy["description"])
                changed = {key for key in corrected if corrected[key] != legacy.get(key)}
                self.assertEqual(changed, {"shaping", "description"})

    def test_every_probe_is_inside_the_load_and_uses_icmp(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                config = matrix.SCENARIOS[name]
                probe_seconds = config["latency_probes"] * config["loaded_latency_interval_us"] / 1e6
                self.assertEqual(config["latency_probe"], "icmp")
                self.assertLess(probe_seconds, config["tput_seconds"])
                self.assertEqual(config["tcp_flows"], [1, 8])
                self.assertLessEqual(
                    config["idle_latency_probes"] * config["idle_latency_interval_us"] / 1e6, 30
                )

    def test_profiles_match_the_requested_round_trip_loss_jitter_and_rate(self) -> None:
        forty = matrix.SCENARIOS["mobile-40ms-loss-1"]
        self.assertEqual((forty["delay_each_direction_ms"] * 2, forty["loss_each_direction_percent"]), (40, 1))
        eighty = matrix.SCENARIOS["mobile-80ms-jitter-loss-2-50mbit"]
        self.assertEqual(
            (eighty["delay_each_direction_ms"] * 2, eighty["jitter_each_direction_ms"],
             eighty["loss_each_direction_percent"], eighty["rate_each_direction_mbit"]),
            (80, 10, 2, 50),
        )
        burst = matrix.SCENARIOS["mobile-150ms-gemodel-5"]
        self.assertEqual(burst["delay_each_direction_ms"] * 2, 150)
        enter, leave, loss_in_bad, loss_in_good = (float(item.rstrip("%")) for item in burst["loss_gemodel"].split())
        self.assertAlmostEqual(100 * enter / (enter + leave), 5.0, delta=0.05)
        self.assertEqual((loss_in_bad, loss_in_good), (100.0, 0.0))
        self.assertAlmostEqual(100 / leave, 5.0, delta=0.01)

    def test_latency_values_keep_received_only_p99_and_probe_loss(self) -> None:
        values = matrix._latency_values({
            "sent": 1000, "received": 900, "lost": 100,
            "loss_aware_rtt_ms": {"p50": 80.1, "p99": None, "p999": None, "infinite_at": ["p99", "p999"]},
            "rtt_ms": {"p99": 190.5},
        })
        self.assertIsNone(values["p99_ms"])
        self.assertEqual(values["p99_received_ms"], 190.5)
        self.assertEqual(values["probe_loss_pct"], 10.0)
        self.assertEqual(values["infinite_at"], ["p99", "p999"])


if __name__ == "__main__":
    unittest.main()
