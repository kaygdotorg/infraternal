"""Run one continuous loaded-latency soak on compute01 with scheduler counters."""

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
    """Keep the same product pair alive so resource drift belongs to one process lifetime."""
    if type(total_seconds) is not int or not MIN_SOAK_SECONDS <= total_seconds <= MAX_SOAK_SECONDS:
        raise ValueError("the loaded-latency soak must run for 3600–7200 seconds")
    return [total_seconds]


def build_compute_window_command(
    *,
    unshare: Path,
    python: Path,
    soak_runner: Path,
    window_output: Path,
    duration_seconds: int,
    kit: Path,
    coordinator: Path,
    binary: Path,
    underlay_rate_mbit: int = 800,
) -> list[str]:
    """Build one rootless app soak with queue and scheduler counters on compute01."""
    if not MIN_SOAK_SECONDS <= duration_seconds <= MAX_SOAK_SECONDS:
        raise ValueError("the continuous soak must run for 3600–7200 seconds")
    if type(underlay_rate_mbit) is not int or not 100 <= underlay_rate_mbit <= 10_000:
        raise ValueError("the underlay rate must be between 100 and 10000 Mbit/s")
    command = [
        str(unshare),
        "-Urn",
        str(python),
        "-I",
        str(soak_runner),
        "--binary",
        str(binary),
        "--coordinator",
        str(coordinator),
        "--kit-dir",
        str(kit),
        "--output",
        str(window_output),
        "--duration-seconds",
        str(duration_seconds),
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
    """Read a run record when the runner produced one, leaving failures visible."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return report if isinstance(report, dict) else None


def main() -> None:
    """Run one continuous product pair and retain its probe and counter evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("total_seconds", type=int)
    parser.add_argument("kit", type=Path)
    parser.add_argument("coordinator", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--underlay-rate-mbit", type=int, default=800)
    arguments = parser.parse_args()
    try:
        durations = plan_soak_windows(arguments.total_seconds)
    except ValueError as error:
        parser.error(str(error))
    if not 100 <= arguments.underlay_rate_mbit <= 10_000:
        parser.error("the underlay rate must be between 100 and 10000 Mbit/s")
    unshare = shutil.which("unshare")
    if unshare is None:
        parser.error("unshare is required for the isolated product pair")
    soak_runner = Path(__file__).with_name("loaded_latency_soak.py")
    if not soak_runner.is_file():
        parser.error(f"loaded-latency runner is missing: {soak_runner}")
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
        "scheduler_sample_source": "procfs-thread-schedstat",
        "scheduler_sample_clock": "host-monotonic-counter-sample",
        "status": "running",
        "manual_fixes": [],
        "windows": [],
    }
    _write_index(index_path, index)

    for duration_seconds in durations:
        window_output = arguments.output / "continuous-soak"
        command = build_compute_window_command(
            unshare=Path(unshare),
            python=Path(sys.executable),
            soak_runner=soak_runner,
            window_output=window_output,
            duration_seconds=duration_seconds,
            kit=arguments.kit,
            coordinator=arguments.coordinator,
            binary=arguments.binary,
            underlay_rate_mbit=arguments.underlay_rate_mbit,
        )
        result = subprocess.run(command, check=False)
        run_record = _window_report(window_output / "run.json")
        index["windows"].append(
            {
                "window": 1,
                "duration_seconds": duration_seconds,
                "exit_code": result.returncode,
                "run_record": str(window_output / "run.json"),
                "integrity_ok": (
                    run_record.get("integrity_ok") if run_record is not None else None
                ),
            }
        )
        _write_index(index_path, index)

    complete = all(
        row["exit_code"] == 0 and row["integrity_ok"] is True
        for row in index["windows"]
    )
    index["status"] = "complete" if complete else "incomplete"
    _write_index(index_path, index)
    print(f"loaded-latency soak index: {index_path}")
    if not complete:
        sys.exit(1)


if __name__ == "__main__":
    main()
