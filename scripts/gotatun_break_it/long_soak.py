"""Run a one- or two-hour loaded-latency soak as bounded perf-lock windows."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


# Keep one continuous agent-pair run inside the requested one-to-two-hour range.
MIN_SOAK_SECONDS = 3_600
MAX_SOAK_SECONDS = 7_200


def plan_soak_windows(total_seconds: int) -> list[int]:
    """Use one continuous perf hold so resource drift belongs to the same agent pair."""
    if type(total_seconds) is not int or not MIN_SOAK_SECONDS <= total_seconds <= MAX_SOAK_SECONDS:
        raise ValueError("the loaded-latency soak must run for 3600–7200 seconds")
    return [total_seconds]


def build_perf_window_command(
    *,
    perf_runner: Path,
    perf: Path,
    window_runner: Path,
    window_output: Path,
    perf_output: Path,
    duration_seconds: int,
    kit: Path,
    coordinator: Path,
    binary: Path,
    underlay_rate_mbit: int = 800,
) -> list[str]:
    """Build the single root perf hold that contains the complete continuous soak."""
    if not MIN_SOAK_SECONDS <= duration_seconds <= MAX_SOAK_SECONDS:
        raise ValueError("the continuous perf hold must run for 3600–7200 seconds")
    if type(underlay_rate_mbit) is not int or not 100 <= underlay_rate_mbit <= 10_000:
        raise ValueError("the underlay rate must be between 100 and 10000 Mbit/s")
    command = [
        str(perf_runner),
        "--root",
        "--out",
        str(perf_output),
        "--",
        "env",
        f"PERF={perf}",
        str(window_runner),
        str(window_output),
        str(duration_seconds),
        str(kit),
        str(coordinator),
        str(binary),
        "--underlay-rate-mbit",
        str(underlay_rate_mbit),
        "--queue-depth-sampling",
    ]
    return command


def _write_index(path: Path, index: dict[str, Any]) -> None:
    """Write the current window ledger atomically after every bounded perf hold."""
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _window_report(path: Path) -> dict[str, Any] | None:
    """Read a window report when the runner produced one, leaving failures visible."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return report if isinstance(report, dict) else None


def main() -> None:
    """Run one continuous product pair and retain its trace and perf-run receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("total_seconds", type=int)
    parser.add_argument("kit", type=Path)
    parser.add_argument("coordinator", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--perf", type=Path, default=os.environ.get("PERF"))
    parser.add_argument("--underlay-rate-mbit", type=int, default=800)
    arguments = parser.parse_args()
    try:
        durations = plan_soak_windows(arguments.total_seconds)
    except ValueError as error:
        parser.error(str(error))
    if not 100 <= arguments.underlay_rate_mbit <= 10_000:
        parser.error("the underlay rate must be between 100 and 10000 Mbit/s")
    if arguments.perf is None or not arguments.perf.is_file() or not os.access(arguments.perf, os.X_OK):
        parser.error("set PERF to the executable perf binary or pass --perf")
    perf_runner = shutil.which("perf-run")
    if perf_runner is None:
        parser.error("perf-run is required for the continuous isolated measurement hold")
    window_runner = Path(__file__).with_name("run_loaded_latency_window.sh")
    if not window_runner.is_file() or not os.access(window_runner, os.X_OK):
        parser.error(f"loaded-latency window runner is missing: {window_runner}")
    for executable in (arguments.kit / "bin/h2h", arguments.coordinator, arguments.binary):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error(f"required executable is missing or not executable: {executable}")
    if arguments.output.exists():
        parser.error(f"output already exists; choose a fresh directory: {arguments.output}")

    arguments.output.mkdir(parents=True)
    index_path = arguments.output / "index.json"
    index: dict[str, Any] = {
        "case": "single-flow-loaded-latency-soak",
        "platform": "linux",
        "total_seconds_requested": arguments.total_seconds,
        "continuous_process_pair": True,
        "underlay_rate_mbit": arguments.underlay_rate_mbit,
        "queue_depth_sampling_enabled": True,
        "status": "running",
        "manual_fixes": [],
        "windows": [],
    }
    _write_index(index_path, index)

    for duration_seconds in durations:
        window_output = arguments.output / "continuous-soak"
        perf_output = arguments.output / "perf-run"
        command = build_perf_window_command(
            perf_runner=Path(perf_runner),
            perf=arguments.perf,
            window_runner=window_runner,
            window_output=window_output,
            perf_output=perf_output,
            duration_seconds=duration_seconds,
            kit=arguments.kit,
            coordinator=arguments.coordinator,
            binary=arguments.binary,
            underlay_rate_mbit=arguments.underlay_rate_mbit,
        )
        result = subprocess.run(command, check=False)
        report = _window_report(window_output / "report.json")
        index["windows"].append(
            {
                "window": 1,
                "duration_seconds": duration_seconds,
                "exit_code": result.returncode,
                "report": str(window_output / "report.json"),
                "report_correlation_status": (
                    report.get("correlation_status") if report is not None else None
                ),
                "probe_count": report.get("probe_count") if report is not None else None,
                "probe_loss_count": report.get("probe_loss_count") if report is not None else None,
            }
        )
        _write_index(index_path, index)

    complete = all(
        row["exit_code"] == 0 and row["report_correlation_status"] == "complete"
        for row in index["windows"]
    )
    index["status"] = "complete" if complete else "incomplete"
    _write_index(index_path, index)
    print(f"loaded-latency soak index: {index_path}")
    if not complete:
        sys.exit(1)


if __name__ == "__main__":
    main()
